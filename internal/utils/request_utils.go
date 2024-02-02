package utils

import (
	"context"
	"encoding/json"
	"net/http"
	"server-alpha/internal/schemas"
)

func DecodeRequestBody(ctx context.Context, w http.ResponseWriter, r *http.Request, target interface{}) error {
	if err := json.NewDecoder(r.Body).Decode(&target); err != nil {
		WriteAndLogError(ctx, w, schemas.BadRequest, http.StatusBadRequest, err)
		return err
	}

	return nil
}

func WriteAndLogResponse(ctx context.Context, w http.ResponseWriter, response interface{}, statusCode int) {
	w.WriteHeader(statusCode)
	LogMessageWithFields(ctx, "info", "Returning response")

	if err := json.NewEncoder(w).Encode(response); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func WriteAndLogError(ctx context.Context, w http.ResponseWriter, customErr *schemas.CustomError, statusCode int, err error) {
	w.WriteHeader(statusCode)
	LogMessageWithFields(ctx, "error", "Error occurred: "+err.Error())
	LogMessageWithFields(ctx, "error", "Returning "+customErr.Code+" / "+customErr.Message)

	errorDto := &schemas.ErrorDTO{
		Error: *customErr,
	}

	if err := json.NewEncoder(w).Encode(errorDto); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func ValidateStruct(ctx context.Context, w http.ResponseWriter, target interface{}) error {
	if err := GetValidator().Validate.Struct(target); err != nil {
		WriteAndLogError(ctx, w, schemas.BadRequest, http.StatusBadRequest, err)
		return err
	}

	return nil
}
