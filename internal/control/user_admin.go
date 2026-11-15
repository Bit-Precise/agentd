package control

import (
	"context"
	"errors"

	"agentd/internal/adminapi"
	"agentd/internal/store"
)

func apiUserIdentity(v store.UserIdentity) adminapi.UserIdentity {
	return adminapi.UserIdentity{Id: v.ID, UserId: idFor("user", v.UserSubject), ProviderId: v.ProviderID, Subject: v.Subject, Status: adminapi.UserIdentityStatus(v.Status), EmailVerified: v.EmailVerified, LastLoginAt: v.LastLoginAt, CreatedAt: v.CreatedAt}
}

func (a *Admin) ListUserIdentities(ctx context.Context, req adminapi.ListUserIdentitiesRequestObject) (adminapi.ListUserIdentitiesResponseObject, error) {
	u, err := a.resolveUser(ctx, req.UserId)
	if err != nil {
		return adminapi.ListUserIdentities404JSONResponse{NotFoundJSONResponse: notFoundErr("user")}, nil
	}
	items, err := a.C.st.ListUserIdentities(ctx, u.Subject)
	if err != nil {
		return nil, err
	}
	out := adminapi.ListUserIdentities200JSONResponse{}
	for _, v := range items {
		out = append(out, apiUserIdentity(v))
	}
	return out, nil
}

func (a *Admin) LinkUserIdentity(ctx context.Context, req adminapi.LinkUserIdentityRequestObject) (adminapi.LinkUserIdentityResponseObject, error) {
	u, err := a.resolveUser(ctx, req.UserId)
	if err != nil {
		return adminapi.LinkUserIdentity404JSONResponse{NotFoundJSONResponse: notFoundErr("user")}, nil
	}
	if req.Body == nil || req.Body.ProviderId == "" || req.Body.Subject == "" {
		return adminapi.LinkUserIdentity400JSONResponse{BadRequestJSONResponse: badRequest("provider_id and subject are required")}, nil
	}
	v := store.UserIdentity{UserSubject: u.Subject, ProviderID: req.Body.ProviderId, Subject: req.Body.Subject, EmailVerified: req.Body.EmailVerified}
	if err := a.C.st.AddUserIdentity(ctx, v); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return adminapi.LinkUserIdentity409JSONResponse{ConflictJSONResponse: conflictErr("IDENTITY_IN_USE", err.Error())}, nil
		}
		if errors.Is(err, store.ErrNotFound) {
			return adminapi.LinkUserIdentity404JSONResponse{NotFoundJSONResponse: notFoundErr("provider")}, nil
		}
		return nil, err
	}
	items, _ := a.C.st.ListUserIdentities(ctx, u.Subject)
	for _, item := range items {
		if item.ProviderID == v.ProviderID && item.Subject == v.Subject {
			return adminapi.LinkUserIdentity201JSONResponse(apiUserIdentity(item)), nil
		}
	}
	return nil, errors.New("identity was created but could not be read")
}

func (a *Admin) UnlinkUserIdentity(ctx context.Context, req adminapi.UnlinkUserIdentityRequestObject) (adminapi.UnlinkUserIdentityResponseObject, error) {
	u, err := a.resolveUser(ctx, req.UserId)
	if err != nil {
		return adminapi.UnlinkUserIdentity404JSONResponse{NotFoundJSONResponse: notFoundErr("user")}, nil
	}
	if err := a.C.st.DeleteUserIdentity(ctx, u.Subject, req.IdentityId); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return adminapi.UnlinkUserIdentity409JSONResponse{ConflictJSONResponse: conflictErr("CONFLICT", err.Error())}, nil
		}
		return adminapi.UnlinkUserIdentity404JSONResponse{NotFoundJSONResponse: notFoundErr("identity")}, nil
	}
	return adminapi.UnlinkUserIdentity204Response{}, nil
}

func (a *Admin) SetUserInstanceAdmin(ctx context.Context, req adminapi.SetUserInstanceAdminRequestObject) (adminapi.SetUserInstanceAdminResponseObject, error) {
	u, err := a.resolveUser(ctx, req.UserId)
	if err != nil {
		return adminapi.SetUserInstanceAdmin404JSONResponse{NotFoundJSONResponse: notFoundErr("user")}, nil
	}
	if req.Body == nil {
		return adminapi.SetUserInstanceAdmin400JSONResponse{BadRequestJSONResponse: badRequest("instance_admin is required")}, nil
	}
	if err := a.C.st.SetUserInstanceAdmin(ctx, u.Subject, req.Body.InstanceAdmin); err != nil {
		return nil, err
	}
	u.InstanceAdmin = req.Body.InstanceAdmin
	return adminapi.SetUserInstanceAdmin200JSONResponse(apiUser(u)), nil
}
