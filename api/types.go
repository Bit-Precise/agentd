// Package api defines the agent registration wire contract.
package api

import (
	"github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/credentials"
	"time"
)

type Agent struct {
	ID              string               `json:"id"`
	WorkspaceID     string               `json:"workspaceId"`
	Workspace       string               `json:"workspace"`
	UserID          string               `json:"userId"`
	Name            string               `json:"name"`
	Status          string               `json:"status"`
	Desired         config.Config        `json:"desired"`
	Approval        credentials.Approval `json:"approval"`
	CreatedAt       time.Time            `json:"createdAt"`
	Roles           []string             `json:"roles"`
	PendingApproval bool                 `json:"pendingApproval"`
}
type EnrollRequest struct {
	EnrollmentKey string        `json:"enrollmentKey"`
	Config        config.Config `json:"config"`
}
type EnrollResponse struct {
	Agent       Agent                   `json:"agent"`
	Credentials credentials.Credentials `json:"credentials"`
}
