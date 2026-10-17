package rbac

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Migrations are the SQL files that create and upgrade the package's tables, for a host that
// runs its migrations with a tool of its own: apply each once, in order of their names, in a
// transaction. Migrate applies them itself.
func Migrations() fs.FS {
	sub, err := fs.Sub(migrations, "migrations")
	if err != nil {
		panic(err)
	}
	return sub
}

// Migrate creates or upgrades the package's tables, prefixed rbac_, in the current schema: the
// first in the search_path that exists. It records what it applied in rbac_migrations, applies
// what is pending in one transaction, is safe to call from several replicas at once, and never
// runs by itself.
func Migrate(ctx context.Context, db DB) error {
	return pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		var schema *string
		if err := tx.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
			return err
		}
		if schema == nil {
			return errors.New("rbac: no schema in the search_path exists to migrate in")
		}
		// One migration at a time in the schema, under a key named as the change locks' are.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(`+lockKey+`)`, "migrate"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS rbac_migrations (
			version    integer     PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
			return err
		}
		var applied int
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(version), 0) FROM rbac_migrations`).Scan(&applied); err != nil {
			return err
		}
		names, err := fs.Glob(Migrations(), "*.sql")
		if err != nil {
			return err
		}
		for _, name := range names {
			prefix, _, _ := strings.Cut(name, "_")
			version, err := strconv.Atoi(prefix)
			if err != nil {
				return fmt.Errorf("rbac: migration %s has no version", name)
			}
			if version <= applied {
				continue
			}
			sql, err := fs.ReadFile(Migrations(), name)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return fmt.Errorf("rbac: migration %s: %w", name, err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO rbac_migrations (version) VALUES ($1)`, version); err != nil {
				return err
			}
		}
		return nil
	})
}
