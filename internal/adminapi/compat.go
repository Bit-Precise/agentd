package adminapi

// This file contains a small source compatibility layer for callers that used
// the pre-v0.31 Go client.  The HTTP contract is generated from the current
// OpenAPI document; these aliases keep the in-repository simulation helpers
// buildable while they migrate to the UUID based resource paths.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Cert is the old workspace-certificate projection.  It is intentionally kept
// out of the current OpenAPI surface.
type CertState string

const (
	CertStatePending  CertState = "pending"
	CertStateReady    CertState = "ready"
	CertStateRenewing CertState = "renewing"
	CertStateFailed   CertState = "failed"
	CertStateExpired  CertState = "expired"
	CertStateRevoked  CertState = "revoked"
)

type Cert struct {
	Workspace string    `json:"workspace"`
	Domain    string    `json:"domain"`
	State     CertState `json:"state"`
	Issuer    *string   `json:"issuer,omitempty"`
	NotBefore *Time     `json:"not_before,omitempty"`
	NotAfter  *Time     `json:"not_after,omitempty"`
	LastError *string   `json:"last_error,omitempty"`
	Relays    *[]string `json:"relays,omitempty"`
}

// Time is only used by the compatibility projection.  Keeping the field type
// opaque avoids pulling the old generated model back into the new API types.
type Time = time.Time

// Instance is the old aggregate endpoint projection.
type Instance struct {
	Domains            []InstanceDomain    `json:"domains"`
	DnsProviders       []DNSProvider       `json:"dns_providers"`
	CertificateIssuers []CertificateIssuer `json:"certificate_issuers"`
	AuthProviders      []AuthProvider      `json:"auth_providers"`
	Rbac               *InstanceRBAC       `json:"rbac,omitempty"`
}

type InstanceRBAC struct {
	Audiences      []Audience      `json:"audiences"`
	InstanceRoles  []InstanceRole  `json:"instance_roles"`
	WorkspaceRoles []WorkspaceRole `json:"workspace_roles"`
}

type GetInstanceRequestObject struct{}
type GetInstanceResponseObject interface {
	VisitGetInstanceResponse(http.ResponseWriter) error
}
type GetInstance200JSONResponse Instance

func (response GetInstance200JSONResponse) VisitGetInstanceResponse(w http.ResponseWriter) error {
	return writeCompatJSON(w, http.StatusOK, response)
}

type GetInstanceResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *Instance
}

func (r *GetInstanceResponse) StatusCode() int {
	if r == nil || r.HTTPResponse == nil {
		return 0
	}
	return r.HTTPResponse.StatusCode
}

// GetInstanceWithResponse is the old aggregate client helper.  It calls the
// compatibility endpoint mounted by control.Admin; current clients should use
// the generated collection operations instead.
func (c *ClientWithResponses) GetInstanceWithResponse(ctx context.Context, editors ...RequestEditorFn) (*GetInstanceResponse, error) {
	base, ok := c.ClientInterface.(*Client)
	if !ok {
		return nil, fmt.Errorf("unsupported client implementation")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base.Server, "/")+"/instance", nil)
	if err != nil {
		return nil, err
	}
	for _, ed := range append(append([]RequestEditorFn{}, base.RequestEditors...), editors...) {
		if err := ed(ctx, req); err != nil {
			return nil, err
		}
	}
	rsp, err := base.Client.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(rsp.Body)
	rsp.Body.Close()
	if err != nil {
		return nil, err
	}
	out := &GetInstanceResponse{Body: body, HTTPResponse: rsp}
	if rsp.StatusCode == http.StatusOK {
		var v Instance
		if err := json.Unmarshal(body, &v); err != nil {
			return nil, err
		}
		out.JSON200 = &v
	}
	return out, nil
}

type UpdateWorkspaceRequestObject struct {
	Ws   string
	Body *struct {
		Relay *string `json:"relay,omitempty"`
	}
}
type UpdateWorkspaceResponseObject interface {
	VisitUpdateWorkspaceResponse(http.ResponseWriter) error
}
type UpdateWorkspace200JSONResponse Workspace

func (response UpdateWorkspace200JSONResponse) VisitUpdateWorkspaceResponse(w http.ResponseWriter) error {
	return writeCompatJSON(w, http.StatusOK, response)
}

type UpdateWorkspace400JSONResponse struct{ BadRequestJSONResponse }

func (response UpdateWorkspace400JSONResponse) VisitUpdateWorkspaceResponse(w http.ResponseWriter) error {
	return writeCompatJSON(w, http.StatusBadRequest, response)
}

type UpdateWorkspace404JSONResponse struct{ NotFoundJSONResponse }

func (response UpdateWorkspace404JSONResponse) VisitUpdateWorkspaceResponse(w http.ResponseWriter) error {
	return writeCompatJSON(w, http.StatusNotFound, response)
}

type ListCertsRequestObject struct{ Ws string }
type ListCertsResponseObject interface {
	VisitListCertsResponse(http.ResponseWriter) error
}
type ListCerts200JSONResponse []Cert

func (response ListCerts200JSONResponse) VisitListCertsResponse(w http.ResponseWriter) error {
	return writeCompatJSON(w, http.StatusOK, response)
}

type RenewCertRequestObject struct{ Ws string }
type RenewCertResponseObject interface {
	VisitRenewCertResponse(http.ResponseWriter) error
}
type RenewCert202JSONResponse Cert

func (response RenewCert202JSONResponse) VisitRenewCertResponse(w http.ResponseWriter) error {
	return writeCompatJSON(w, http.StatusAccepted, response)
}

type RenewCert404JSONResponse struct{ NotFoundJSONResponse }

func (response RenewCert404JSONResponse) VisitRenewCertResponse(w http.ResponseWriter) error {
	return writeCompatJSON(w, http.StatusNotFound, response)
}

// writeCompatJSON is deliberately private to this compatibility file.
func writeCompatJSON(w http.ResponseWriter, status int, value any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(value)
}
