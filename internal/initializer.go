package internal

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
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
	// Load environment variables
	err := godotenv.Load(envFile)
	if err != nil {
		log.Printf("Error loading .env file: ", err)
	} else {
		log.Println("Loaded environment variables from .env file")
	}

	// Connect to database
	pool, err := initializeDatabase()
	if err != nil {
		log.Fatal("Error connecting to database: ", err)
	}
	log.Println("Connected to database")
	defer pool.Close()

	// Initialize router
	r := routing.InitRouter(pool)
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

func initializeDatabase() (*pgxpool.Pool, error) {
	var (
		dbHost     = os.Getenv("LOCAL_DB_HOST")
		dbPort     = os.Getenv("LOCAL_DB_PORT")
		dbUser     = os.Getenv("LOCAL_DB_USER")
		dbPassword = os.Getenv("LOCAL_DB_PASSWORD")
		dbName     = os.Getenv("LOCAL_DB_NAME")
	)

	if dbHost == "" || dbPort == "" || dbUser == "" || dbPassword == "" || dbName == "" {
		return nil, fmt.Errorf("database environment variables not set")
	}

	url := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", dbHost, dbPort, dbUser, dbPassword, dbName)
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}

	config.MinConns = 5
	config.MaxConns = 30
	config.MaxConnIdleTime = time.Minute * 2
	config.HealthCheckPeriod = time.Minute * 1

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		log.Fatal("Error connecting to database: ", err)
		return nil, err
	}

	return pool, nil
}
