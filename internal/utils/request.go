package utils

import (
	"github.com/gin-gonic/gin"
	"server-alpha/internal/schemas"
)

// WriteAndLogResponse encodes the response object to JSON and writes it to the HTTP response.
// It also sets the provided status code. If encoding fails, it logs and sends an InternalServerError response.
func WriteAndLogResponse(ctx *gin.Context, response interface{}, statusCode int) {
	LogMessageWithFields(ctx, "info", "Returning response")
	ctx.JSON(statusCode, response)
}

// WriteAndLogError logs the provided error and sends an error response with the specified status code and error details.
// If encoding the error response fails, it logs and sends an InternalServerError response.
func WriteAndLogError(c *gin.Context, customErr *schemas.CustomError, statusCode int, err error) {
	LogMessageWithFields(c, "error", "Error occurred: "+err.Error())
	LogMessageWithFields(c, "error", "Returning "+customErr.Code+" / "+customErr.Message)
	errorDto := &schemas.ErrorDTO{
		Error: *customErr,
	}
	c.JSON(statusCode, errorDto)
}
