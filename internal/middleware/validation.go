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
		if err := c.ShouldBindJSON(&obj); err != nil {
			c.JSON(http.StatusBadRequest, schemas.BadRequest)
			return
		}
		// Sanitize the data
		validator := validators.GetValidator()
		validator.SanitizeData(obj)

		if err := validator.Validate.Struct(obj); err != nil {
			// Handle validation errors as before
			c.JSON(http.StatusBadRequest, schemas.BadRequest)
			return
		}
		// Set the sanitized object in the context
		c.Set(utils.SanitizedPayloadKey.String(), obj)
		c.Next()
	}
}
