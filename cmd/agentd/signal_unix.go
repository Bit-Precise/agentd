//go:build !windows

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"agentd/internal/agent"
)

func reloadOnHUP(ctx context.Context, a *agent.Agent) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	defer signal.Stop(ch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			_ = a.Reload()
		}
	}
}
