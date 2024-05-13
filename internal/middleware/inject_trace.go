package middleware

import (
	"github.com/wwi21seb-projekt/server-alpha/internal/utils"

	"github.com/gin-gonic/gin"
)

func InjectTrace() gin.HandlerFunc {
	return func(c *gin.Context) {
		traceId := utils.GenerateTraceId()
		c.Set(utils.TraceIdKey.String(), traceId)
		c.Header("X-Trace-Id", traceId)
		c.Next()
	}
}
