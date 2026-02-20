package gap

import (
	"errors"
	"fmt"
)

// APIError represents an error response from the GAP Management API.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("gap api error (status %d): %s", e.StatusCode, e.Message)
}

// IsNotFound returns true if the error is a 404 Not Found API error.
func IsNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == 404
}

// IsConflict returns true if the error is a 409 Conflict API error.
func IsConflict(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == 409
}

// IsUnauthorized returns true if the error is a 401 Unauthorized API error.
func IsUnauthorized(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == 401
}

// IsBadRequest returns true if the error is a 400 Bad Request API error.
func IsBadRequest(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == 400
}
