package middleware

import (
	"net/http"
	"server-alpha/internal/schemas"
	"server-alpha/internal/utils"
	"server-alpha/internal/validators"

	"github.com/gin-gonic/gin"
)

func ValidateAndSanitizeStruct(obj interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := c.ShouldBindJSON(obj); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, &schemas.ErrorDTO{Error: *schemas.Unauthorized})
			return
		}
		validator := validators.GetValidator()
		// Sanitize the data
		if err := validator.SanitizeData(obj); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, &schemas.ErrorDTO{Error: *schemas.Unauthorized})
			return
		}

		if err := validator.Validate.Struct(obj); err != nil {
			// Handle validation errors as before
			c.AbortWithStatusJSON(http.StatusBadRequest, &schemas.ErrorDTO{Error: *schemas.Unauthorized})
			return
		}
		// Set the sanitized object in the context
		c.Set(utils.SanitizedPayloadKey.String(), obj)
		c.Next()
	}
}
