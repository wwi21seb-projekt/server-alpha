package utils

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	log "github.com/sirupsen/logrus"
	"net/http"
	"server-alpha/internal/interfaces"
	"server-alpha/internal/schemas"
	"time"
)

func BeginTransaction(w http.ResponseWriter, r *http.Request, pool interfaces.PgxPoolIface) (pgx.Tx, context.Context, context.CancelFunc) {
	// Begin a new transaction
	transactionCtx, cancel := context.WithDeadline(r.Context(), time.Now().Add(10*time.Second))

	tx, err := pool.Begin(transactionCtx)
	if err != nil {
		WriteAndLogError(transactionCtx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		cancel()
		return nil, nil, nil
	}

	return tx, transactionCtx, cancel
}

func RollbackTransaction(w http.ResponseWriter, tx pgx.Tx, ctx context.Context, cancel context.CancelFunc, err error) {
	if err != nil {
		log.Debug("Rolling back transaction due to error: ", err)
		err = tx.Rollback(ctx)

		if err != nil {
			if errors.Is(err, pgx.ErrTxClosed) {
				return
			}

			cancel()
			log.Debug("Context canceled")
			WriteAndLogError(ctx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		}
		log.Debug("Transaction rolled back")
	}
}

func CommitTransaction(w http.ResponseWriter, tx pgx.Tx, ctx context.Context, cancel context.CancelFunc) error {
	log.Info("Committing transaction")
	err := tx.Commit(ctx)
	defer func() {
		if err := ctx.Err(); err != nil {
			log.Debug("Context error: ", err)
		}
		cancel()
		log.Debug("Context canceled")
	}()

	if err != nil {
		log.Debug("Rolling back transaction due to error: ", err)
		WriteAndLogError(ctx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return err
	}

	log.Info("Transaction committed")
	return nil
}
