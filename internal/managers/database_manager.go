// package managers handles the business logic and orchestrates interactions between the application and the database.
package managers

import (
	log "github.com/sirupsen/logrus"
	"server-alpha/internal/interfaces"
)

// DatabaseMgr defines the interface for database management.
// It provides methods for interacting with the database connection pool.
type DatabaseMgr interface {
	GetPool() interfaces.PgxPoolIface
}

// DatabaseManager is responsible for managing the database connection pool.
// It implements the DatabaseMgr interface and provides methods to interact with the database.
type DatabaseManager struct {
	Pool interfaces.PgxPoolIface
}

// GetPool returns the database connection pool managed by the DatabaseManager.
// This pool is used for executing database operations.
func (dbMgr *DatabaseManager) GetPool() interfaces.PgxPoolIface {
	return dbMgr.Pool
}

// NewDatabaseManager creates and initializes a new instance of DatabaseManager with the provided database connection pool.
// It logs the initialization process and returns the newly created DatabaseManager.
func NewDatabaseManager(pool interfaces.PgxPoolIface) DatabaseMgr {
	log.Info("Initializing database manager")
	return &DatabaseManager{Pool: pool}
}
