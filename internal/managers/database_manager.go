// Package managers is responsible for orchestrating interactions between the application and the database.
// It encapsulates the business logic, providing a layer of abstraction over the database operations.
package managers

import (
	log "github.com/sirupsen/logrus"
	"github.com/wwi21seb-projekt/server-alpha/internal/interfaces"
)

// DatabaseMgr is an interface that defines the contract for database management.
// It abstracts the database operations, providing a method to retrieve the database connection pool.
type DatabaseMgr interface {
	GetPool() interfaces.PgxPoolIface
}

// DatabaseManager is a concrete implementation of the DatabaseMgr interface.
// It manages the database connection pool and provides methods to interact with the database.
type DatabaseManager struct {
	Pool interfaces.PgxPoolIface
}

// GetPool retrieves the database connection pool managed by the DatabaseManager.
// This pool can be used by other components of the application to execute database operations.
func (dbMgr *DatabaseManager) GetPool() interfaces.PgxPoolIface {
	return dbMgr.Pool
}

// NewDatabaseManager constructs a new instance of DatabaseManager with the provided database connection pool.
// It logs the initialization process and returns the newly created DatabaseManager.
// This function is used during the initialization phase of the application.
func NewDatabaseManager(pool interfaces.PgxPoolIface) DatabaseMgr {
	log.Info("Initializing database manager")
	return &DatabaseManager{Pool: pool}
}
