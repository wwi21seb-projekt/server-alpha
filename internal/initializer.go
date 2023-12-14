package internal

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"server-alpha/internal/managers"
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
		log.Fatal("Error loading .env file: ", err)
	}
	log.Println("Loaded environment variables")

	// Initialize JWT manager
	jwtMgr, err := managers.NewJWTManager()
	if err != nil {
		log.Fatal("Error initializing JWT manager: ", err)
	}

	// Initialize cron job
	scheduler, err := initCronJob(jwtMgr)
	if err != nil {
		log.Fatal("Error initializing cron job: ", err)
	}
	defer shutdownCronJob(*scheduler)

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

func initCronJob(jwtMgr managers.JWTMgr) (*gocron.Scheduler, error) {
	scheduler, err := gocron.NewScheduler()
	if err != nil {
		return nil, err
	}

	_, err = scheduler.NewJob(
		gocron.DurationJob(3*time.Hour),
		gocron.NewTask(jwtMgr.RotateKeys),
	)
	if err != nil {
		return nil, err
	}

	scheduler.Start()
	return &scheduler, nil
}

func shutdownCronJob(scheduler gocron.Scheduler) {
	err := scheduler.Shutdown()
	if err != nil {
		log.Fatal("Error shutting down cron job: ", err)
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
