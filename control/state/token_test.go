package state

import (
	"testing"
	"time"

	"github.com/bit-precise/agentd/control/db"
	"github.com/bit-precise/agentd/control/types"
)

func TestAgentTokenRefreshIsReadOnlyUntilNearExpiry(t *testing.T) {
	f := setup(t)
	enrolled := f.enroll(t, true)
	before, _ := f.s.SnapshotForUser(f.admin.ID)
	for i := 0; i < 2; i++ {
		if _, err := f.s.GetAgentCredentials(enrolled.Credentials.ControlToken); err != nil {
			t.Fatal(err)
		}
	}
	after, _ := f.s.SnapshotForUser(f.admin.ID)
	if before.Revision != after.Revision {
		t.Fatal("ordinary two-second polling wrote control state")
	}
	near := time.Now().Add(6 * 24 * time.Hour).UTC()
	if err := f.s.mutate(func(snap *types.Snapshot) error {
		for i := range snap.Tokens {
			token := &snap.Tokens[i]
			if token.AgentID == enrolled.Agent.ID {
				token.ExpiresAt = near
				if token.Kind == "access" {
					token.Revoked = true
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	storedBefore, err := f.s.store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.GetAgentCredentials(enrolled.Credentials.ControlToken); err != nil {
		t.Fatal(err)
	}
	storedAfter, err := f.s.store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if storedAfter.Revision != storedBefore.Revision+1 {
		t.Fatal("near-expiry token renewal did not commit once")
	}
	for _, old := range storedBefore.Tokens {
		if old.AgentID != enrolled.Agent.ID {
			continue
		}
		found := false
		for _, renewed := range storedAfter.Tokens {
			if old.ID != renewed.ID {
				continue
			}
			found = true
			if old.Hash != renewed.Hash {
				t.Fatal("renewal changed an established session token")
			}
			if old.Revoked {
				if !renewed.Revoked || !renewed.ExpiresAt.Equal(old.ExpiresAt) {
					t.Fatal("revoked role token was renewed")
				}
			} else if !renewed.ExpiresAt.After(time.Now().Add(29 * 24 * time.Hour)) {
				t.Fatal("active role token was not extended")
			}
		}
		if !found {
			t.Fatal("renewal replaced stable token ID")
		}
	}
	if _, err = f.s.GetAgentCredentials(enrolled.Credentials.ControlToken); err != nil {
		t.Fatal(err)
	}
	last, _ := f.s.store.Load(t.Context())
	if last.Revision != storedAfter.Revision {
		t.Fatal("revoked near-expiry token caused repeated renewal writes")
	}
	if err = f.s.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(t.Context(), db.Options{DSN: f.path}, "instance.test")
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	id, err := again.Identity(enrolled.Credentials.ProviderToken)
	if err != nil || !id.ExpiresAt.After(time.Now().Add(29*24*time.Hour)) {
		t.Fatalf("extended token did not survive restart: %+v %v", id, err)
	}
}

func TestExpiredOrRevokedControlTokenCannotRenew(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		t.Run(map[bool]string{false: "expired", true: "revoked"}[revoked], func(t *testing.T) {
			f := setup(t)
			enrolled := f.enroll(t, true)
			if err := f.s.mutate(func(snap *types.Snapshot) error {
				for i := range snap.Tokens {
					token := &snap.Tokens[i]
					if token.AgentID == enrolled.Agent.ID {
						token.ExpiresAt = time.Now().Add(-time.Second)
						if token.Kind == "control" && revoked {
							token.ExpiresAt = time.Now().Add(time.Hour)
							token.Revoked = true
						}
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			before, _ := f.s.store.Load(t.Context())
			if _, err := f.s.GetAgentCredentials(enrolled.Credentials.ControlToken); err == nil {
				t.Fatal("unusable control credential renewed itself")
			}
			after, _ := f.s.store.Load(t.Context())
			if before.Revision != after.Revision {
				t.Fatal("failed authentication modified token lifetime")
			}
		})
	}
}

func TestUserRotationRetainsIdentityAndBootstrapDoesNotResurrect(t *testing.T) {
	f := setup(t)
	f.enroll(t, true)
	other, _, err := f.s.CreateUser(f.admin.ID, "other", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.RotateUserToken(other.ID, f.user.ID); err == nil {
		t.Fatal("unrelated user rotated another identity")
	}
	newToken, err := f.s.RotateUserToken(f.user.ID, f.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.Identity(f.userToken); err == nil {
		t.Fatal("old user token still authenticates")
	}
	if !f.s.KnownToken(f.userToken) {
		t.Fatal("old platform token lost leak protection")
	}
	id, err := f.s.Identity(newToken)
	if err != nil || id.UserID != f.user.ID {
		t.Fatal("rotation changed stable user identity")
	}
	if _, err = f.s.ResolveServe("demo.w1.instance.test", f.user.ID); err != nil {
		t.Fatal("rotation removed existing grants")
	}
	newAdmin, err := f.s.RotateUserToken(f.admin.ID, f.admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.Identity("bootstrap-token-for-state-tests"); err == nil {
		t.Fatal("old bootstrap token still authenticates")
	}
	if err = f.s.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(t.Context(), db.Options{DSN: f.path}, "instance.test")
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if _, err = again.BootstrapAdmin("bootstrap-token-for-state-tests"); err != nil {
		t.Fatalf("historical bootstrap identity prevented server restart: %v", err)
	}
	if _, err = again.Identity("bootstrap-token-for-state-tests"); err == nil {
		t.Fatal("bootstrap startup revived revoked user token")
	}
	id, err = again.Identity(newAdmin)
	if err != nil || id.UserID != f.admin.ID {
		t.Fatal("new admin credential not durable")
	}
}

func TestDisabledHistoricalBootstrapAdminDoesNotPreventStartup(t *testing.T) {
	f := setup(t)
	replacement, token, err := f.s.CreateUser(f.admin.ID, "replacement-admin", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.SetMembership(f.admin.ID, f.workspace.ID, replacement.ID, "owner"); err != nil {
		t.Fatal(err)
	}
	if err = f.s.RemoveMembership(replacement.ID, f.workspace.ID, f.admin.ID); err != nil {
		t.Fatal(err)
	}
	if err = f.s.DisableUser(replacement.ID, f.admin.ID); err != nil {
		t.Fatal(err)
	}
	if err = f.s.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(t.Context(), db.Options{DSN: f.path}, "instance.test")
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	historical, err := again.BootstrapAdmin("bootstrap-token-for-state-tests")
	if err != nil || !historical.Disabled {
		t.Fatalf("historical bootstrap state was reset: %+v %v", historical, err)
	}
	if _, err = again.Identity("bootstrap-token-for-state-tests"); err == nil {
		t.Fatal("disabled bootstrap administrator regained API access")
	}
	if _, err = again.Identity(token); err != nil {
		t.Fatalf("replacement administrator lost access: %v", err)
	}
}
