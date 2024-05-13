package middleware

import (
	"net/http"

	"github.com/wwi21seb-projekt/errors-go/goerrors"
	"github.com/wwi21seb-projekt/server-alpha/internal/schemas"
	"github.com/wwi21seb-projekt/server-alpha/internal/utils"
	"github.com/wwi21seb-projekt/server-alpha/internal/validators"

	"github.com/gin-gonic/gin"
)

func ValidateAndSanitizeStruct(obj interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := c.ShouldBindJSON(obj); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, &schemas.ErrorDTO{Error: *goerrors.BadRequest})
			return
		}
		validator := validators.GetValidator()
		// Sanitize the data
		if err := validator.SanitizeData(obj); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, &schemas.ErrorDTO{Error: *goerrors.BadRequest})
			return
		}

		if err := validator.Validate.Struct(obj); err != nil {
			// Handle validation errors as before
			c.AbortWithStatusJSON(http.StatusBadRequest, &schemas.ErrorDTO{Error: *goerrors.BadRequest})
			return
		}
		// Set the sanitized object in the context
		c.Set(utils.SanitizedPayloadKey.String(), obj)
		c.Next()
	}
}
