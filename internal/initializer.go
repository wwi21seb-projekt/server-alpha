// package internal contains the core functionality and configurations of the server.
package internal

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wwi21seb-projekt/server-alpha/internal/managers"
	"github.com/wwi21seb-projekt/server-alpha/internal/utils"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/wwi21seb-projekt/server-alpha/internal/routing"
)

const (
	port    = ":8080"
	envFile = ".env"
)

// Init initializes the server by loading environment variables, setting up logging, connecting to the database,
// initializing managers (Database, Mail, JWT), setting up routing, and starting the HTTP server.
func Init() {
	err := godotenv.Load(envFile)
	if err != nil {
		utils.LogMessage("info", "No .env file found, using environment variables from system")
	} else {
		utils.LogMessage("info", "Loaded environment variables from .env file")
	}

	logLevel := os.Getenv("LOG_LEVEL")
	setLogLevel(logLevel)
	utils.LogMessage("debug", fmt.Sprintf("Environment variables: %v", os.Environ()))

	// Connect to database
	pool := initializeDatabase()

	defer pool.Close()

	// Initialize database manager
	databaseMgr := managers.NewDatabaseManager(pool)

	// Initialize mail manager
	mailMgr := managers.NewMailManager()

	// Initialize JWT manager
	jwtMgr, err := managers.NewJWTManagerFromFile()
	if err != nil {
		panic(err)
	}

	// Initialize router
	r := routing.InitRouter(databaseMgr, mailMgr, jwtMgr)
	utils.LogMessage("info", "Initialized router")

	// Handle interrupt signal gracefully
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)

		<-c
		utils.LogMessage("info", "Shutting down server...")
		os.Exit(0)
	}()

	// Start server on the specified port
	utils.LogMessage("info", fmt.Sprintf("Starting server on port %s...", port))
	err = http.ListenAndServe(port, r)
	if err != nil {
		utils.LogMessage("fatal", "Error starting server")
		panic(err)
	}
}

// initializeDatabase sets up the connection pool for the PostgreSQL database.
// It reads the database configuration from environment variables and establishes a connection.
func initializeDatabase() *pgxpool.Pool {
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
		panic("Database environment variables not set")
	}

	url := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", dbHost, dbPort, dbUser, dbPassword, dbName)
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		utils.LogMessage("fatal", "Error configuring database")
		panic(err)
	}

	config.MinConns = 5
	config.MaxConns = 30
	config.MaxConnIdleTime = time.Minute * 2
	config.HealthCheckPeriod = time.Minute * 1

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		utils.LogMessage("fatal", "Error connecting to database")
		panic(err)
	}
	utils.LogMessage("info", "Initialized database")
	return pool
}

// setLogLevel configures the logging level based on the LOG_LEVEL environment variable.
// It also sets the logger to write to standard output and include the caller information.
func setLogLevel(logLevel string) {
	switch logLevel {
	case "DEBUG":
		log.SetLevel(log.DebugLevel)
	case "INFO":
		log.SetLevel(log.InfoLevel)
	case "WARN":
		log.SetLevel(log.WarnLevel)
	case "ERROR":
		log.SetLevel(log.ErrorLevel)
	case "FATAL":
		log.SetLevel(log.FatalLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}

	log.SetReportCaller(true)
	log.SetFormatter(&utils.CustomTextFormatter{})
	log.SetOutput(os.Stdout)
}
