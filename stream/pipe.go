// Package stream provides cancellation-aware bidirectional byte copying.
package stream

import (
	"context"
	"io"
	"net"
)

// Pipe owns both connections until completion. Cancellation closes both ends,
// including blocked writes. Half-close is preserved when the adapter supports it.
func Pipe(ctx context.Context, a, b net.Conn) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// A stream can expire after its read half has already returned clean EOF.
	// In that case no further Read will report the cancellation, so observe the
	// stream lifetime directly instead of waiting on a silent local socket.
	for _, c := range []net.Conn{a, b} {
		if scoped, ok := c.(interface{ Context() context.Context }); ok {
			stop := context.AfterFunc(scoped.Context(), cancel)
			defer stop()
		}
	}
	defer func() { _ = a.Close(); _ = b.Close() }()
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if err != nil {
			// RST, cancellation and failed writes are not graceful FIN. Closing
			// both directions also releases a silent local client holding Read.
			_ = a.Close()
			_ = b.Close()
		} else if half, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		} else {
			_ = dst.Close()
		}
		done <- struct{}{}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	for n := 0; n < 2; n++ {
		select {
		case <-done:
		case <-ctx.Done():
			_ = a.Close()
			_ = b.Close()
			for ; n < 2; n++ {
				<-done
			}
			return
		}
	}
}
