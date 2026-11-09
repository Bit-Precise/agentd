// Package store persists agentserver state in PostgreSQL.
package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"agentd/internal/identity"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Errors returned by the store.
var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("already exists")
)

// StatusOf maps an error to a protocol status.
func StatusOf(err error) pb.Status { return wire.StatusOf(err) }

// Store is the PostgreSQL-backed state.
type Store struct {
	pool *pgxpool.Pool
	box  keybox
}

// Open connects, applies migrations and returns a Store. stateKey (32 bytes)
// encrypts private keys at rest; nil stores them unencrypted.
func Open(ctx context.Context, url string, stateKey []byte) (*Store, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}
	box, err := newKeybox(stateKey)
	if err != nil {
		pool.Close()
		return nil, err
	}
	s := &Store{pool: pool, box: box}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// Ping checks the database connection.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

func (s *Store) migrate(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	// Serialise concurrent agentserver starts.
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(727274)`); err != nil {
		return err
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock(727274)`)
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	entries, err := fs.ReadDir(migrations, "migrations")
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		v, err := strconv.Atoi(strings.SplitN(e.Name(), "_", 2)[0])
		if err != nil {
			return fmt.Errorf("migration %s: bad name", e.Name())
		}
		var exists bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, v).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		sql, _ := migrations.ReadFile("migrations/" + e.Name())
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("migration %s: %w", e.Name(), err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES ($1)`, v); err != nil {
			tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

func isUnique(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

func isFK(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23503"
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// HashToken returns the SHA-256 of a token; only hashes are stored.
func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// ---------------------------------------------------------------- keybox

type keybox struct{ aead cipher.AEAD }

func newKeybox(key []byte) (keybox, error) {
	if len(key) == 0 {
		return keybox{}, nil
	}
	if len(key) != 32 {
		return keybox{}, fmt.Errorf("state key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return keybox{}, err
	}
	aead, err := cipher.NewGCM(block)
	return keybox{aead: aead}, err
}

func (b keybox) seal(plain []byte) []byte {
	if b.aead == nil {
		return append([]byte{0}, plain...)
	}
	nonce := make([]byte, b.aead.NonceSize())
	_, _ = rand.Read(nonce)
	out := append([]byte{1}, nonce...)
	return b.aead.Seal(out, nonce, plain, nil)
}

func (b keybox) open(sealed []byte) ([]byte, error) {
	if len(sealed) == 0 {
		return nil, errors.New("empty sealed value")
	}
	switch sealed[0] {
	case 0:
		return sealed[1:], nil
	case 1:
		if b.aead == nil {
			return nil, errors.New("value is encrypted but no state key is configured")
		}
		ns := b.aead.NonceSize()
		if len(sealed) < 1+ns {
			return nil, errors.New("sealed value too short")
		}
		plain, err := b.aead.Open(nil, sealed[1:1+ns], sealed[1+ns:], nil)
		if err != nil {
			return nil, errors.New("cannot decrypt stored key (wrong state key?)")
		}
		return plain, nil
	default:
		return nil, errors.New("unknown sealed value format")
	}
}

func (b keybox) sealKey(priv ed25519.PrivateKey) []byte { return b.seal(priv.Seed()) }

func (b keybox) openKey(sealed []byte) (ed25519.PrivateKey, error) {
	seed, err := b.open(sealed)
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("stored key has wrong length")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// ServerKey returns agentserver's own key, creating it on first use.
func (s *Store) ServerKey(ctx context.Context) (ed25519.PrivateKey, error) {
	var sealed []byte
	err := s.pool.QueryRow(ctx, `SELECT private_key FROM server_state WHERE id=1`).Scan(&sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		priv, err := identity.GenerateKey()
		if err != nil {
			return nil, err
		}
		if _, err := s.pool.Exec(ctx, `INSERT INTO server_state(id, private_key) VALUES (1, $1) ON CONFLICT (id) DO NOTHING`, s.box.sealKey(priv)); err != nil {
			return nil, err
		}
		return s.ServerKey(ctx)
	}
	if err != nil {
		return nil, err
	}
	return s.box.openKey(sealed)
}

// SetServerKey stores a configured server key (key_file), replacing any.
func (s *Store) SetServerKey(ctx context.Context, priv ed25519.PrivateKey) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO server_state(id, private_key) VALUES (1,$1) ON CONFLICT (id) DO UPDATE SET private_key=EXCLUDED.private_key`, s.box.sealKey(priv))
	return err
}

// CA returns the stored self-signed CA (dev certificate issuer), if any.
func (s *Store) CA(ctx context.Context) (certPEM, keyPEM []byte, err error) {
	var sealed []byte
	err = s.pool.QueryRow(ctx, `SELECT cert_pem, key_pem FROM ca WHERE id=1`).Scan(&certPEM, &sealed)
	if err != nil {
		return nil, nil, notFound(err)
	}
	keyPEM, err = s.box.open(sealed)
	return certPEM, keyPEM, err
}

// SetCA stores the self-signed CA if none exists and returns the stored one.
func (s *Store) SetCA(ctx context.Context, certPEM, keyPEM []byte) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO ca(id, cert_pem, key_pem) VALUES (1,$1,$2) ON CONFLICT (id) DO NOTHING`, certPEM, s.box.seal(keyPEM))
	return err
}

// backupTables lists the tables exported by Backup, parents first.
var backupTables = []string{"schema_migrations", "server_state", "ca", "relays", "relay_tokens", "workspaces", "join_tokens", "nodes",
	"groups", "group_members", "routes", "policies", "services", "certs", "revocations", "acme_accounts", "autocert_cache"}

// Backup writes every table as JSON lines {"table":…,"row":…}. Private keys
// stay sealed by the state key, so the export is only as sensitive as that.
func (s *Store) Backup(ctx context.Context, w io.Writer) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, t := range backupTables {
		rows, err := tx.Query(ctx, `SELECT row_to_json(t)::text FROM `+pgx.Identifier{t}.Sanitize()+` t`)
		if err != nil {
			return fmt.Errorf("%s: %w", t, err)
		}
		for rows.Next() {
			var row string
			if err := rows.Scan(&row); err != nil {
				rows.Close()
				return err
			}
			if _, err := fmt.Fprintf(w, "{\"table\":%q,\"row\":%s}\n", t, row); err != nil {
				rows.Close()
				return err
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
	}
	return nil
}
