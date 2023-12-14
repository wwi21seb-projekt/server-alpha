package utils

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http"
	"server-alpha/internal/schemas"
	"time"
)

func BeginTransaction(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool) (pgx.Tx, context.Context, context.CancelFunc) {
	// Begin a new transaction
	transactionCtx, cancel := context.WithDeadline(r.Context(), time.Now().Add(5*time.Second))

	tx, err := pool.Begin(transactionCtx)
	if err != nil {
		WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError)
		cancel()
		return nil, nil, nil
	}

	return tx, transactionCtx, cancel
}

func RollbackTransaction(w http.ResponseWriter, tx pgx.Tx, ctx context.Context) {
	err := tx.Rollback(ctx)
	if err != nil {
		WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError)
	}
}

func CommitTransaction(w http.ResponseWriter, tx pgx.Tx, ctx context.Context) {
	err := tx.Commit(ctx)
	if err != nil {
		WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError)
	}
}
