// Package managers is responsible for orchestrating interactions between the application and the database.
// It encapsulates the business logic, providing a layer of abstraction over the database operations.
package managers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"server-alpha/internal/interfaces"
	"server-alpha/internal/utils"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"

	"github.com/go-jet/jet/v2/generator/postgres"
)

// DatabaseMgr is an interface that defines the contract for database management.
// It abstracts the database operations, providing a method to retrieve the database connection pool.
type DatabaseMgr interface {
	GetPool() interfaces.PgxPoolIface
	GenerateCode(destDir string, schemaName string) error
	ClosePool() error
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

// ClosePool closes the database connection pool managed by the DatabaseManager.
// This method should be called when the application is shutting down to release the resources.
func (dbMgr *DatabaseManager) ClosePool() error {
	utils.LogMessage("info", "Closing database connection pool")
	dbMgr.Pool.Close()
	utils.LogMessage("info", "Closed database connection pool")
	return nil
}

// connect connects to the PostgreSQL database and initializes the connection pool.
func (dbMgr *DatabaseManager) connect() error {
	utils.LogMessage("info", "Initializing database")

	var (
		dbHost     = os.Getenv("DB_HOST")
		dbPort     = os.Getenv("DB_PORT")
		dbUser     = os.Getenv("DB_USER")
		dbPassword = os.Getenv("DB_PASS")
		dbName     = os.Getenv("DB_NAME")
	)

	if dbHost == "" || dbPort == "" || dbUser == "" || dbPassword == "" || dbName == "" {
		utils.LogMessage("fatal", "Database environment variables not set")
		return errors.New("database environment variables not set")
	}

	url := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", dbHost, dbPort, dbUser, dbPassword, dbName)
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		utils.LogMessage("fatal", "Error configuring database")
		return err
	}

	config.MinConns = 5
	config.MaxConns = 30
	config.MaxConnIdleTime = time.Minute * 2
	config.HealthCheckPeriod = time.Minute * 1

	dbMgr.Pool, err = pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		utils.LogMessage("fatal", "Error connecting to database")
		return err
	}

	utils.LogMessage("info", "Initialized database")
	return nil
}

func (dbMgr *DatabaseManager) GenerateCode(destDir string, schemaName string) error {
	// Get the connection details from the database pool.
	var (
		dbHost     = os.Getenv("DB_HOST")
		dbPort     = os.Getenv("DB_PORT")
		dbUser     = os.Getenv("DB_USER")
		dbPassword = os.Getenv("DB_PASS")
		dbName     = os.Getenv("DB_NAME")
	)

	// Construct the DBConnection struct from the connection details.
	dbPortInt, _ := strconv.Atoi(dbPort)
	dbConn := postgres.DBConnection{
		Host:       dbHost,
		Port:       dbPortInt,
		User:       dbUser,
		Password:   dbPassword,
		SslMode:    "disable",
		DBName:     dbName,
		SchemaName: schemaName,
	}

	// Call the Generate function to generate the Go code.
	utils.LogMessage("info", "Generating Go code for database schema")
	return postgres.Generate(destDir, dbConn)
}

// NewDatabaseManager constructs a new instance of DatabaseManager with the provided database connection pool.
// It logs the initialization process and returns the newly created DatabaseManager.
// This function is used during the initialization phase of the application.
func NewDatabaseManager() (DatabaseMgr, error) {
	log.Info("Initializing database manager")

	dbMgr := &DatabaseManager{}
	err := dbMgr.connect()
	if err != nil {
		return nil, err
	}

	return dbMgr, nil
}
