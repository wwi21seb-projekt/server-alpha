package utils

import (
	"encoding/json"
	"log"
	"net/http"
	"server-alpha/internal/schemas"
)

func DecodeRequestBody(w http.ResponseWriter, r *http.Request, target interface{}) error {
	if err := json.NewDecoder(r.Body).Decode(&target); err != nil {
		WriteAndLogError(w, schemas.BadRequest, http.StatusBadRequest, err)
		return err
	}

	return nil
}

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

func ValidateStruct(w http.ResponseWriter, target interface{}) error {
	if err := GetValidator().Validate.Struct(target); err != nil {
		WriteAndLogError(w, schemas.BadRequest, http.StatusBadRequest, err)
		return err
	}

	return nil
}
