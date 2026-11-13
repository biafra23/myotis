package capi

// The drain_logs ring: myotis_engine.h's myotis_drain_logs drains "up
// to max buffered tracing lines, oldest first, newline-joined; empty
// when idle", so the engine's slog output is mirrored into a bounded
// ring here. Lines are formatted like the CLI's text handler so a host
// log reads the same whichever engine produced it.
//
// WithAttrs/WithGroup return VIEWS over one shared buffer (PR #827
// review: the first draft returned the bare handler and silently
// dropped attributes — the engine's component="dialer" markers went
// into the ring unnamed). A view carries the accumulated attrs/group;
// appending formats a record CLONE with them added, exactly like
// slog's text handler renders derived loggers.

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
)

const ringCap = 4096

// ringBuffer is the one shared line store per logger family; views
// share the pointer.
type ringBuffer struct {
	mu    sync.Mutex
	lines []string // newest last; capped at ringCap by dropping oldest
}

type ringHandler struct {
	buf   *ringBuffer
	attrs []slog.Attr // WithAttrs, with the then-current group baked into names
	group string      // dotted group path, "" when ungrouped
}

func newRingHandler() *ringHandler { return &ringHandler{buf: &ringBuffer{}} }

func (h *ringHandler) Enabled(_ context.Context, lvl slog.Level) bool {
	return lvl >= slog.LevelInfo
}

func (h *ringHandler) Handle(_ context.Context, r slog.Record) error {
	if len(h.attrs) > 0 {
		rc := r.Clone()
		rc.AddAttrs(h.attrs...)
		r = rc
	}
	var buf bytes.Buffer
	if err := slog.NewTextHandler(&buf, nil).Handle(context.Background(), r); err != nil {
		return err
	}
	line := strings.TrimSuffix(buf.String(), "\n")
	h.buf.mu.Lock()
	h.buf.lines = append(h.buf.lines, line)
	if over := len(h.buf.lines) - ringCap; over > 0 {
		h.buf.lines = append(h.buf.lines[:0], h.buf.lines[over:]...)
	}
	h.buf.mu.Unlock()
	return nil
}

// WithAttrs returns a view that stamps these attrs (group-prefixed,
// as the text handler renders them) onto every line, still landing in
// the shared buffer.
func (h *ringHandler) WithAttrs(as []slog.Attr) slog.Handler {
	prefix := ""
	if h.group != "" {
		prefix = h.group + "."
	}
	stamped := make([]slog.Attr, 0, len(as))
	for _, a := range as {
		stamped = append(stamped, slog.Attr{Key: prefix + a.Key, Value: a.Value})
	}
	attrs := make([]slog.Attr, 0, len(h.attrs)+len(stamped))
	attrs = append(attrs, h.attrs...)
	attrs = append(attrs, stamped...)
	return &ringHandler{buf: h.buf, attrs: attrs, group: h.group}
}

func (h *ringHandler) WithGroup(g string) slog.Handler {
	group := g
	if h.group != "" {
		group = h.group + "." + g
	}
	return &ringHandler{buf: h.buf, attrs: h.attrs, group: group}
}

// drain returns up to max lines, oldest first, newline-joined, and
// removes them (the pump semantics: whatever the host drained is
// gone). Views drain the shared buffer.
func (h *ringHandler) drain(max int) string {
	if max <= 0 {
		return ""
	}
	h.buf.mu.Lock()
	defer h.buf.mu.Unlock()
	n := min(max, len(h.buf.lines))
	if n == 0 {
		return ""
	}
	out := strings.Join(h.buf.lines[:n], "\n")
	h.buf.lines = append(h.buf.lines[:0], h.buf.lines[n:]...)
	return out
}
