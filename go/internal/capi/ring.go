package capi

// The drain_logs ring: myotis_engine.h's myotis_drain_logs drains "up to
// max buffered tracing lines, oldest first, newline-joined; empty when
// idle", so the engine's slog output is mirrored into a bounded ring
// here. Lines are formatted like the CLI's text handler so a host log
// reads the same whichever engine produced it.

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
)

const ringCap = 4096

type ringHandler struct {
	mu    sync.Mutex
	lines []string // newest last; capped at ringCap by dropping oldest
}

func (h *ringHandler) Enabled(_ context.Context, lvl slog.Level) bool {
	return lvl >= slog.LevelInfo
}

func (h *ringHandler) Handle(_ context.Context, r slog.Record) error {
	var buf bytes.Buffer
	if err := slog.NewTextHandler(&buf, nil).Handle(context.Background(), r); err != nil {
		return err
	}
	line := strings.TrimSuffix(buf.String(), "\n")
	h.mu.Lock()
	h.lines = append(h.lines, line)
	if over := len(h.lines) - ringCap; over > 0 {
		h.lines = append(h.lines[:0], h.lines[over:]...)
	}
	h.mu.Unlock()
	return nil
}

// WithAttrs/WithGroup keep the same ring: engine logs are flat, and a
// derived handler must still land in the shared buffer.
func (h *ringHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *ringHandler) WithGroup(_ string) slog.Handler      { return h }

// drain returns up to max lines, oldest first, newline-joined, and
// removes them (the pump semantics: whatever the host drained is gone).
func (h *ringHandler) drain(max int) string {
	if max <= 0 {
		return ""
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	n := min(max, len(h.lines))
	if n == 0 {
		return ""
	}
	out := strings.Join(h.lines[:n], "\n")
	h.lines = append(h.lines[:0], h.lines[n:]...)
	return out
}
