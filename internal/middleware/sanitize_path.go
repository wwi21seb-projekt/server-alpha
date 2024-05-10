package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/microcosm-cc/bluemonday"
)

func SanitizePath() gin.HandlerFunc {
	return func(c *gin.Context) {
		p := bluemonday.StrictPolicy()
		c.Request.URL.Path = p.Sanitize(c.Request.URL.Path)
		c.Next()
	}
}
