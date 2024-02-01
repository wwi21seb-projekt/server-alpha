package utils

import (
	"context"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"os"
)

func GenerateTraceId() string {
	return uuid.New().String()
}

func logEntry(entry *log.Entry, level, message string) {
	switch level {
	case "debug":
		entry.Debug(message)
	case "info":
		entry.Info(message)
	case "warn":
		entry.Warn(message)
	case "error":
		entry.Error(message)
	case "fatal":
		entry.Fatal(message)
	case "panic":
		entry.Panic(message)
	default:
		entry.Info(message)
	}
}

func LogMessage(level, message string) {
	service := "PR-" + os.Getenv("PR_NUMBER")

	if service == "PR-" {
		service = "main"
	}

	entry := log.WithFields(log.Fields{
		"service": service,
	})

	logEntry(entry, level, message)
}

func LogMessageWithFields(ctx context.Context, level, message string) {
	traceId := ctx.Value(TraceIdKey).(string)
	service := "PR-" + os.Getenv("PR_NUMBER")

	if service == "PR-" {
		service = "main"
	}

	entry := log.WithFields(log.Fields{
		"traceId": traceId,
		"service": service,
	})

	logEntry(entry, level, message)
}
