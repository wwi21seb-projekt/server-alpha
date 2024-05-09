package middleware

import "github.com/gin-gonic/gin"

func LogRequest() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Log the request
		log.Infof("Received %s request to %s", c.Request.Method, c.Request.URL.Path)
		c.Next()
	}
}
