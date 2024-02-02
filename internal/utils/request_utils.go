package utils

import (
	"encoding/json"
	"log"
	"net/http"
	"server-alpha/internal/schemas"
)

// DecodeRequestBody decodes the JSON-encoded request body into the target interface.
// If decoding fails, it logs and sends an error response with a BadRequest status.
func DecodeRequestBody(w http.ResponseWriter, r *http.Request, target interface{}) error {
	if err := json.NewDecoder(r.Body).Decode(&target); err != nil {
		WriteAndLogError(w, schemas.BadRequest, http.StatusBadRequest, err)
		return err
	}

	return nil
}

// WriteAndLogResponse encodes the response object to JSON and writes it to the HTTP response.
// It also sets the provided status code. If encoding fails, it logs and sends an InternalServerError response.
func WriteAndLogResponse(w http.ResponseWriter, response interface{}, statusCode int) {
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// WriteAndLogError logs the provided error and sends an error response with the specified status code and error details.
// If encoding the error response fails, it logs and sends an InternalServerError response.
func WriteAndLogError(w http.ResponseWriter, error *schemas.CustomError, statusCode int, err error) {
	w.WriteHeader(statusCode)
	log.Println("Error occurred: " + err.Error())
	log.Println("Returning: " + error.Code + " / " + error.Message)
	errorDto := &schemas.ErrorDTO{
		Error: *error,
	}

	if err := json.NewEncoder(w).Encode(errorDto); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// ValidateStruct validates the struct pointed to by target using the package-level validator.
// If validation fails, it logs and sends a BadRequest error response.
func ValidateStruct(w http.ResponseWriter, target interface{}) error {
	if err := GetValidator().Validate.Struct(target); err != nil {
		WriteAndLogError(w, schemas.BadRequest, http.StatusBadRequest, err)
		return err
	}

	return nil
}
