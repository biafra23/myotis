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
// into the ring unnamed). The view delegates to a TextHandler built
// once over the shared buffer and derives it with the attrs/group, so
// attribute rendering (including group prefixes) is the text
// handler's own, and no handler is allocated per record.

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
)

const ringCap = 4096

// ringBuffer is the one shared line store per logger family; views
// share the pointer. TextHandler performs exactly one Write per
// record, so one record is one line here.
type ringBuffer struct {
	mu    sync.Mutex
	lines []string // newest last; capped at ringCap by dropping oldest
}

var _ io.Writer = (*ringBuffer)(nil)

func (b *ringBuffer) Write(p []byte) (int, error) {
	line := strings.TrimSuffix(string(p), "\n")
	b.mu.Lock()
	b.lines = append(b.lines, line)
	if over := len(b.lines) - ringCap; over > 0 {
		b.lines = append(b.lines[:0], b.lines[over:]...)
	}
	b.mu.Unlock()
	return len(p), nil
}

type ringHandler struct {
	buf   *ringBuffer
	inner slog.Handler // text handler over buf, derived with this view's attrs/group
}

func newRingHandler() *ringHandler {
	b := &ringBuffer{}
	return &ringHandler{buf: b, inner: slog.NewTextHandler(b, nil)}
}

func (h *ringHandler) Enabled(ctx context.Context, lvl slog.Level) bool {
	return h.inner.Enabled(ctx, lvl)
}

func (h *ringHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.inner.Handle(ctx, r)
}

func (h *ringHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &ringHandler{buf: h.buf, inner: h.inner.WithAttrs(as)}
}

func (h *ringHandler) WithGroup(g string) slog.Handler {
	return &ringHandler{buf: h.buf, inner: h.inner.WithGroup(g)}
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
