// package internal contains the core functionality and configurations of the server.
package internal

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"server-alpha/internal/managers"
	"server-alpha/internal/utils"

	log "github.com/sirupsen/logrus"

	"server-alpha/internal/routing"

	"github.com/joho/godotenv"
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

	// Initialize database manager
	databaseMgr, err := managers.NewDatabaseManager()
	if err != nil {
		panic(err)
	}
	defer databaseMgr.ClosePool()

	// Generate sql builder files
	err = databaseMgr.GenerateCode("internal/gen", "alpha_schema")
	if err != nil {
		utils.LogMessage("fatal", "Error generating SQL builder files: "+err.Error())
	}

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
