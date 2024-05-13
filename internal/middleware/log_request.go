package middleware

import (
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/wwi21seb-projekt/server-alpha/internal/utils"
)

func LogRequest() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		traceId := ctx.Value(utils.TraceIdKey.String()).(string)
		service := utils.ExtractServiceName()
		message := "Request received: " + ctx.Request.Method + " " + ctx.Request.URL.Path
		entry := log.WithFields(log.Fields{
			"traceId": traceId,
			"service": service,
		})
		utils.LogEntry(entry, "info", message)
		ctx.Next()
	}
}
