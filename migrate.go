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
// transaction of its own or at READ COMMITTED, in a database whose encoding is UTF8: one that
// waits for the writes in flight to the tables reads them once they end, which a stricter
// transaction's snapshot, taken by an earlier statement, doesn't. They hold no backslash, so they
// mean the same whatever the session's standard_conforming_strings. Migrate applies them itself.
func Migrations() fs.FS {
	sub, err := fs.Sub(migrations, "migrations")
	if err != nil {
		panic(err)
	}
	return sub
}

// Migrate creates or upgrades the package's tables, prefixed rbac_, in the current schema: the
// first in the search_path that exists, in a database whose encoding is UTF8. It records what it
// applied in rbac_migrations, applies what is pending in one transaction, is safe to call from
// several replicas at once, and never runs by itself. On a host's transaction it runs at that
// transaction's isolation, and refuses any but READ COMMITTED: a stricter one's snapshot, taken by
// an earlier statement, reads the versions from before it waited for another replica, and the rows
// it records as they were before the writes it waited for.
func Migrate(ctx context.Context, db DB) error {
	// At READ COMMITTED, so a replica that waited for the lock reads the versions another applied
	// meanwhile: a stricter snapshot, taken before the lock, would apply them again.
	return begin(ctx, db, func(tx pgx.Tx) error {
		var schema *string
		var level, conforming string
		if err := tx.QueryRow(ctx, `SELECT current_schema(), current_setting('transaction_isolation'),
			current_setting('standard_conforming_strings')`).Scan(&schema, &level, &conforming); err != nil {
			return err
		}
		if err := readCommitted("Migrate", level); err != nil {
			return err
		}
		if schema == nil {
			return errors.New("rbac: no schema in the search_path exists to migrate in")
		}
		// A session with it off reads a backslash in a literal as an escape, so a pattern would check
		// another thing than its migration says. None holds one, but Migrate doesn't rely on that.
		if _, err := tx.Exec(ctx, `SET LOCAL standard_conforming_strings = on`); err != nil {
			return err
		}
		// A database in another encoding can give back text that isn't UTF-8, as SQL_ASCII gives
		// back whatever was stored: history would record it, and no export could chain it, so every
		// export would stop there.
		var encoding string
		if err := tx.QueryRow(ctx, `SELECT current_setting('server_encoding')`).Scan(&encoding); err != nil {
			return err
		}
		if encoding != "UTF8" {
			return fmt.Errorf("rbac: the database's encoding is %s, not UTF8", encoding)
		}
		// One migration at a time in the schema, under a key named as the change locks' are: by the
		// schema it migrates, as the tables may not exist yet, which is the one they are in once
		// they do.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(current_schema() || '/rbac/' || $1, 0))`, "migrate"); err != nil {
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
		fsys := Migrations()
		names, err := fs.Glob(fsys, "*.sql")
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
			sql, err := fs.ReadFile(fsys, name)
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
		// As it was, for what a host's transaction runs after.
		_, err = tx.Exec(ctx, `SELECT set_config('standard_conforming_strings', $1, true)`, conforming)
		return err
	})
}
