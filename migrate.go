package rbac

import (
	"context"
	"embed"
	"io/fs"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/parallelworks/foundation/pgdb"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Migrate creates or upgrades the package's tables in the pool's schema, which must exist
// (pgdb.Migrate creates it). The tables are prefixed rbac_ and their migrations are recorded
// in their own version table, beside the application's. It is safe to call from several
// replicas at once, and never runs by itself.
func Migrate(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) error {
	fsys, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return err
	}
	return pgdb.MigrateFS(ctx, pool, fsys, "rbac_goose_db_version", logger)
}
