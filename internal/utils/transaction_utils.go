package utils

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"log"
	"net/http"
	"server-alpha/internal/schemas"
	"time"
)

func BeginTransaction(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool) (pgx.Tx, context.Context, context.CancelFunc) {
	// Begin a new transaction
	transactionCtx, cancel := context.WithDeadline(r.Context(), time.Now().Add(5*time.Second))

	tx, err := pool.Begin(transactionCtx)
	if err != nil {
		WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		cancel()
		return nil, nil, nil
	}

	return tx, transactionCtx, cancel
}

func RollbackTransaction(w http.ResponseWriter, tx pgx.Tx, ctx context.Context, cancel context.CancelFunc) {
	err := tx.Rollback(ctx)

	if err != nil {
		if errors.Is(err, pgx.ErrTxClosed) {
			return
		}

		cancel()
		WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
	}
}

func CommitTransaction(w http.ResponseWriter, tx pgx.Tx, ctx context.Context, cancel context.CancelFunc) error {
	err := tx.Commit(ctx)
	defer cancel()

	if err != nil {
		log.Println(err)
		WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return err
	}

	return nil
}
