//go:build linux || darwin

package elevator

// DefaultSocket is where the elevator listens.
const DefaultSocket = "/var/run/agentd-elevator.sock"
