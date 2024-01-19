package utils

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"server-alpha/internal/schemas"
	"strconv"
)

func ParsePaginationParams(r *http.Request) (int, int, error) {
	offsetString := r.URL.Query().Get(OffsetParamKey)
	if offsetString == "" {
		offsetString = "0"
	}
	offset, err := strconv.Atoi(offsetString)
	if err != nil {
		offset = 0
	}

	if offset < 0 {
		offset = 0
	}

	limitString := r.URL.Query().Get(LimitParamKey)
	if limitString == "" {
		limitString = "10"
	}
	limit, err := strconv.Atoi(limitString)
	if err != nil {
		limit = 10
	}

	if limit < 0 {
		limit = 0
	}

	return offset, limit, nil
}

func SendPaginatedResponse(w http.ResponseWriter, records interface{}, offset, limit, totalRecords int) {
	// Get a reflect.Value of records.
	v := reflect.ValueOf(records)

	end := offset + limit
	if end > v.Len() {
		end = v.Len()
	}

	if v.Len() == 0 {
		offset = 0
	}

	if offset > v.Len() {
		offset = v.Len() - 1
	}

	// Check if v is not a slice.
	if v.Kind() != reflect.Slice {
		WriteAndLogError(w, schemas.BadRequest, http.StatusBadRequest, errors.New("records not a valid list"))
		return
	}

	var subset interface{}
	// subset only if records is not empty
	if v.Len() > 0 {
		// Use reflect's slice method to get a subset of records.
		subset = v.Slice(offset, end).Interface()
	} else {
		// If the records slice was empty, subset is an empty slice too
		subset = records
	}

	// Create Pagination DTO
	paginationDto := schemas.Pagination{
		Offset:  offset,
		Limit:   limit,
		Records: totalRecords,
	}

	// Create Paginated Response
	paginatedResponse := schemas.PaginatedResponse{
		Records:    subset,
		Pagination: paginationDto,
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(paginatedResponse); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		WriteAndLogError(w, schemas.InternalServerError, http.StatusInternalServerError, err)
		return
	}
}
