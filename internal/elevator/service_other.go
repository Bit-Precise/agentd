//go:build !windows

package elevator

import "context"

// RunService runs the server (only Windows has a service manager protocol).
func RunService(ctx context.Context, s *Server) error { return s.Run(ctx) }
