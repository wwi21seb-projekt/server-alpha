package internal

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"os/signal"
	"server-alpha/internal/managers"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"server-alpha/internal/routing"
)

const (
	port    = ":8080"
	envFile = ".env"
)

func Init() {
	err := godotenv.Load(envFile)
	if err != nil {
		log.Info("No .env file found, using environment variables from system")
	} else {
		log.Info("Loaded environment variables from .env file")
	}

	logLevel := os.Getenv("LOG_LEVEL")
	setLogLevel(logLevel)
	log.Debugf("Environment variables: %v", os.Environ())

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
	log.Println("Initialized router")

	// Handle interrupt signal gracefully
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)

		<-c
		log.Println("Server shutting down...")
		os.Exit(0)
	}()

	// Start server on the specified port
	log.Printf("Starting server on port %s...\n", port)
	err = http.ListenAndServe(port, r)
	if err != nil {
		log.Fatal("Error starting server: ", err)
	}
}

func initializeDatabase() *pgxpool.Pool {
	log.Info("Initializing database")

	var (
		dbHost     = os.Getenv("DB_HOST")
		dbPort     = os.Getenv("DB_PORT")
		dbUser     = os.Getenv("DB_USER")
		dbPassword = os.Getenv("DB_PASS")
		dbName     = os.Getenv("DB_NAME")
	)

	if dbHost == "" || dbPort == "" || dbUser == "" || dbPassword == "" || dbName == "" {
		log.Fatal("database environment variables not set")
	}

	url := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", dbHost, dbPort, dbUser, dbPassword, dbName)
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		log.Fatal("error configuring database: ", err)
	}

	config.MinConns = 5
	config.MaxConns = 30
	config.MaxConnIdleTime = time.Minute * 2
	config.HealthCheckPeriod = time.Minute * 1

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		log.Fatal("error connecting to database: ", err)
	}
	log.Info("Connected to database")
	return pool
}

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

	log.SetOutput(os.Stdout)

}
