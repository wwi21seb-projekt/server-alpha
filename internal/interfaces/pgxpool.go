// Package interfaces defines interfaces for abstracting database operations.
package interfaces

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgxPoolIface abstracts interactions with a PostgreSQL database connection pool.
// It provides methods to begin a transaction, query the database, and acquire a connection.
type PgxPoolIface interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
	Acquire(ctx context.Context) (*pgxpool.Conn, error)
	Close()
}
