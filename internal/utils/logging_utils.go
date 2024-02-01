package utils

import (
	"context"
	"errors"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
)

type CustomTextFormatter struct{}

func (f *CustomTextFormatter) Format(entry *log.Entry) ([]byte, error) {
	// Format should be: [timestamp] [level] [service] [traceId] message
	// Example: [2021-05-01 12:00:00] [info] [PR-1] [123e4567-e89b-12d3-a456-426614174000] Request received
	// If service is not set, use "main" as default, if traceId is not set, use "none" as default
	timestamp := entry.Time.Format("2006-01-02 15:04:05")
	level := entry.Level.String()
	service := entry.Data["service"]
	traceId := entry.Data["traceId"]
	message := entry.Message

	if service == nil {
		service = "main"
	}
	if traceId == nil {
		traceId = "none"
	}

	if message == "" {
		return nil, errors.New("message is empty")
	}

	return []byte("[" + timestamp + "] [" + level + "] [" + service.(string) + "] [" + traceId.(string) + "] " +
		message + "\n"), nil
}

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

func extractServiceName() string {
	service := "PR-" + os.Getenv("PR_NUMBER")

	if service == "PR-" {
		service = "main"
	}

	return service
}

func LogMessage(level, message string) {
	service := extractServiceName()

	entry := log.WithFields(log.Fields{
		"service": service,
	})

	logEntry(entry, level, message)
}

func LogMessageWithFields(ctx context.Context, level, message string) {
	traceId := ctx.Value(TraceIdKey).(string)
	service := extractServiceName()

	entry := log.WithFields(log.Fields{
		"traceId": traceId,
		"service": service,
	})

	logEntry(entry, level, message)
}

func LogMessageWithFieldsAndError(ctx context.Context, level, message string, err error) {
	traceId := ctx.Value(TraceIdKey).(string)
	service := extractServiceName()
	message = message + ": " + err.Error()

	entry := log.WithFields(log.Fields{
		"traceId": traceId,
		"service": service,
	})

	logEntry(entry, level, message)
}

func LogRequest(ctx context.Context, r *http.Request) {
	traceId := ctx.Value(TraceIdKey).(string)
	service := extractServiceName()
	message := "Request received: " + r.Method + " " + r.URL.Path

	entry := log.WithFields(log.Fields{
		"traceId": traceId,
		"service": service,
	})

	logEntry(entry, "info", message)
}
