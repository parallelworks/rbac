package rbac

import (
	"context"
	"embed"
	"fmt"
	"hash/fnv"
	"io/fs"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/parallelworks/foundation/pgdb"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Migrate creates or upgrades the package's tables in the pool's schema, which must exist
// (pgdb.Migrate creates it). The tables are prefixed rbac_, and their migrations keep their
// own version table, so they sit beside the application's own. It is safe to call from
// several replicas at once.
func Migrate(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	fsys, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return err
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte("rbac/" + pgdb.Schema(pool)))
	locker, err := lock.NewPostgresSessionLocker(lock.WithLockID(int64(h.Sum64()))) //nolint:gosec // any 64 bits will do as a lock key
	if err != nil {
		return err
	}
	db := stdlib.OpenDBFromPool(pool)
	defer db.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, db, fsys,
		goose.WithTableName("rbac_goose_db_version"),
		goose.WithSessionLocker(locker),
		goose.WithDisableGlobalRegistry(true),
	)
	if err != nil {
		return fmt.Errorf("rbac: goose: %w", err)
	}
	results, err := provider.Up(ctx)
	if err != nil {
		return fmt.Errorf("rbac: migrate: %w", err)
	}
	for _, r := range results {
		logger.InfoContext(ctx, "applied rbac migration", "version", r.Source.Version, "duration", r.Duration)
	}
	return nil
}
