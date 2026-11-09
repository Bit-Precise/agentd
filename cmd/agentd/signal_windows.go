//go:build windows

package main

import (
	"context"

	"agentd/internal/agent"
)

func reloadOnHUP(ctx context.Context, a *agent.Agent) {}
