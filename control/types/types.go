// Package types defines control-plane records shared by persistence, policy and APIs.
package types

import (
	"errors"
	"github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/connection"
	"github.com/bit-precise/agentd/credentials"
	"github.com/bit-precise/agentd/policy"
	"time"
)

type User struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Admin     bool      `json:"admin"`
	Disabled  bool      `json:"disabled"`
	CreatedAt time.Time `json:"createdAt"`
}
type Workspace struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}
type Membership struct {
	WorkspaceID string `json:"workspaceId"`
	UserID      string `json:"userId"`
	Role        string `json:"role"`
}
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
type EnrollmentKey struct {
	ID          string    `json:"id"`
	WorkspaceID string    `json:"workspaceId"`
	UserID      string    `json:"userId"`
	Roles       []string  `json:"roles"`
	AutoApprove bool      `json:"autoApprove"`
	Uses        int       `json:"uses"`
	MaxUses     int       `json:"maxUses"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Revoked     bool      `json:"revoked"`
}
type Service struct {
	ID          string `json:"id"`
	WorkspaceID string `json:"workspaceId"`
	AgentID     string `json:"agentId"`
	Name        string `json:"name"`
	Hostname    string `json:"hostname"`
	Enabled     bool   `json:"enabled"`
}
type EgressRoute struct {
	ID          string      `json:"id"`
	WorkspaceID string      `json:"workspaceId"`
	AgentID     string      `json:"agentId"`
	Name        string      `json:"name"`
	Rule        policy.Rule `json:"rule"`
	Priority    int         `json:"priority"`
	Enabled     bool        `json:"enabled"`
}
type Grant struct {
	ID           string    `json:"id"`
	WorkspaceID  string    `json:"workspaceId"`
	ResourceType string    `json:"resourceType"`
	ResourceID   string    `json:"resourceId"`
	SubjectType  string    `json:"subjectType"`
	SubjectID    string    `json:"subjectId,omitempty"`
	StartsAt     time.Time `json:"startsAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
	Revoked      bool      `json:"revoked"`
}
type Audit struct {
	ID         string    `json:"id"`
	At         time.Time `json:"at"`
	ActorID    string    `json:"actorId"`
	Action     string    `json:"action"`
	ResourceID string    `json:"resourceId"`
	Detail     string    `json:"detail"`
}

// Token hashes are persistence-only and are never returned in API snapshots.
type Token struct {
	ID          string
	Hash        string
	Kind        string
	UserID      string
	AgentID     string
	WorkspaceID string
	ExpiresAt   time.Time
	Revoked     bool
}
type Identity struct {
	TokenID     string
	Kind        string
	UserID      string
	AgentID     string
	WorkspaceID string
	Workspace   string
	ExpiresAt   time.Time
}
type Snapshot struct {
	Revision       uint64          `json:"revision"`
	Users          []User          `json:"users"`
	Workspaces     []Workspace     `json:"workspaces"`
	Memberships    []Membership    `json:"memberships"`
	Agents         []Agent         `json:"agents"`
	EnrollmentKeys []EnrollmentKey `json:"enrollmentKeys"`
	Services       []Service       `json:"services"`
	EgressRoutes   []EgressRoute   `json:"egressRoutes"`
	Grants         []Grant         `json:"grants"`
	Audit          []Audit         `json:"audit"`
	Tokens         []Token         `json:"-"`
}
type EnrollRequest struct {
	EnrollmentKey string        `json:"enrollmentKey"`
	Config        config.Config `json:"config"`
}
type EnrollResponse struct {
	Agent       Agent                   `json:"agent"`
	Credentials credentials.Credentials `json:"credentials"`
}
type Decision struct {
	ResourceType   string
	ResourceID     string
	WorkspaceID    string
	Workspace      string
	AgentID        string
	ServiceName    string
	Hostname       string
	UserID         string
	Destination    connection.Destination
	Revision       uint64
	PolicyRevision uint64
	ExpiresAt      time.Time
}

type ErrorKind string

const (
	KindInvalid      ErrorKind = "invalid"
	KindUnauthorized ErrorKind = "unauthorized"
	KindForbidden    ErrorKind = "forbidden"
	KindNotFound     ErrorKind = "not_found"
	KindConflict     ErrorKind = "conflict"
	KindExpired      ErrorKind = "expired"
	KindUnavailable  ErrorKind = "unavailable"
)

type Error struct {
	Kind    ErrorKind `json:"kind"`
	Message string    `json:"message"`
}

func (e *Error) Error() string { return e.Message }
func KindOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return string(e.Kind)
	}
	return "internal"
}
