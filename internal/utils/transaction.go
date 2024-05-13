package utils

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/wwi21seb-projekt/errors-go/goerrors"
	"github.com/wwi21seb-projekt/server-alpha/internal/interfaces"
)

// BeginTransaction begins a new database transaction with a context deadline.
// It returns the transaction object, the transaction context, and a cancel function for the context.
// If the transaction fails to begin, it logs and sends an error response.
func BeginTransaction(ctx *gin.Context, pool interfaces.PgxPoolIface) pgx.Tx {
	LogMessageWithFields(ctx, "debug", "Beginning transaction...")

	tx, err := pool.Begin(ctx)
	if err != nil {
		LogMessageWithFieldsAndError(ctx, "error", "Error beginning transaction", err)
		WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
		return nil
	}

	return tx
}

// RollbackTransaction rolls back the given transaction if an error occurred.
// It cancels the context and logs any errors that occur during the rollback, except if the transaction is already closed.
func RollbackTransaction(ctx *gin.Context, tx pgx.Tx, err error) {
	LogMessageWithFields(ctx, "debug", "Rolling back transaction...")

	if err != nil {
		LogMessageWithFieldsAndError(ctx, "error", "Error rolling back transaction", err)
		err = tx.Rollback(ctx)

		if err != nil {
			if errors.Is(err, pgx.ErrTxClosed) {
				return
			}

			LogMessageWithFields(ctx, "debug", "Context canceled")
			WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
		}
		LogMessageWithFields(ctx, "debug", "Transaction rolled back")
	}
}

// CommitTransaction attempts to commit the given transaction.
// If the commit fails, it logs the error, sends an error response, and returns the error.
// If the commit is successful, it logs the success and cancels the context.
func CommitTransaction(ctx *gin.Context, tx pgx.Tx) error {
	LogMessageWithFields(ctx, "debug", "Committing transaction...")
	err := tx.Commit(ctx)
	defer func() {
		if err := ctx.Err(); err != nil {
			LogMessageWithFieldsAndError(ctx, "debug", "Context error", err)
		}
	}()

	if err != nil {
		LogMessageWithFieldsAndError(ctx, "error", "Error committing transaction", err)
		WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
		return err
	}

	LogMessageWithFields(ctx, "debug", "Transaction committed")
	return nil
}
