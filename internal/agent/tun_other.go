//go:build !linux && !darwin && !windows

package agent

import (
	"context"
	"errors"
)

func (a *Agent) startTUN(ctx context.Context, cfg *Config) error {
	return errors.New("TUN mode is available on macOS, Linux and Windows; on this platform use the http/socks5 proxies or `agentd connect`")
}
