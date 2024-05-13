package middleware

import (
	"github.com/wwi21seb-projekt/server-alpha/internal/schemas"
	"github.com/wwi21seb-projekt/server-alpha/internal/utils"
	"github.com/wwi21seb-projekt/server-alpha/internal/validators"
	"net/http"

	"github.com/gin-gonic/gin"
)

func ValidateAndSanitizeStruct(obj interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := c.ShouldBindJSON(obj); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, &schemas.ErrorDTO{Error: *schemas.BadRequest})
			return
		}
		validator := validators.GetValidator()
		// Sanitize the data
		if err := validator.SanitizeData(obj); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, &schemas.ErrorDTO{Error: *schemas.BadRequest})
			return
		}

		if err := validator.Validate.Struct(obj); err != nil {
			// Handle validation errors as before
			c.AbortWithStatusJSON(http.StatusBadRequest, &schemas.ErrorDTO{Error: *schemas.BadRequest})
			return
		}
		// Set the sanitized object in the context
		c.Set(utils.SanitizedPayloadKey.String(), obj)
		c.Next()
	}
}
