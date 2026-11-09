// Package adminapi implements the agentserver admin API defined in
// docs/agentserver-openapi.yaml. api.gen.go is generated from that document.
package adminapi

//go:generate go tool oapi-codegen -config oapi-codegen.yaml ../../docs/agentserver-openapi.yaml
