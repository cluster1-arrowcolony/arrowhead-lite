// Package pkg provides Arrowhead Framework 4.x compatible data models and error types.
//
// This file defines a structured error handling system with HTTP status code mapping
// for consistent API error responses across all Arrowhead core services.
package pkg

import (
	"fmt"
	"net/http"
)

// AppError represents a structured application error with HTTP status code mapping.
// This type is used throughout the Arrowhead Lite application for consistent
// error handling and API error responses.
type AppError struct {
	Code    int    `json:"code"`              // HTTP status code
	Message string `json:"message"`           // Human-readable error message
	Details string `json:"details,omitempty"` // Optional detailed error information
}

// Error implements the error interface, returning a formatted error message.
func (e *AppError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s", e.Message, e.Details)
	}
	return e.Message
}

// StatusCode returns the HTTP status code associated with this error.
func (e *AppError) StatusCode() int {
	return e.Code
}

// Type returns a string representation of the error type based on the HTTP status code.
func (e *AppError) Type() string {
	switch e.Code {
	case http.StatusBadRequest:
		return "BAD_REQUEST"
	case http.StatusUnauthorized:
		return "UNAUTHORIZED"
	case http.StatusForbidden:
		return "FORBIDDEN"
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusConflict:
		return "CONFLICT"
	case http.StatusInternalServerError:
		return "INTERNAL_SERVER_ERROR"
	default:
		return "UNKNOWN_ERROR"
	}
}

// NewAppError creates a new AppError with the specified HTTP status code, message, and details.
// This is the primary constructor for creating application errors.
func NewAppError(code int, message, details string) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Details: details,
	}
}

var (
	ErrServiceNotFound      = NewAppError(http.StatusNotFound, "Service not found", "")
	ErrSystemNotFound       = NewAppError(http.StatusNotFound, "System not found", "")
	ErrAuthRuleNotFound     = NewAppError(http.StatusNotFound, "Authorization rule not found", "")
	ErrSubscriptionNotFound = NewAppError(http.StatusNotFound, "Subscription not found", "")

	ErrServiceAlreadyExists = NewAppError(http.StatusConflict, "Service already exists", "")
	ErrSystemAlreadyExists  = NewAppError(http.StatusConflict, "System already exists", "")

	ErrInvalidRequest     = NewAppError(http.StatusBadRequest, "Invalid request", "")
	ErrInvalidCredentials = NewAppError(http.StatusUnauthorized, "Invalid credentials", "")
	ErrUnauthorized       = NewAppError(http.StatusUnauthorized, "Unauthorized", "")
	ErrForbidden          = NewAppError(http.StatusForbidden, "Forbidden", "")

	ErrInternalServer   = NewAppError(http.StatusInternalServerError, "Internal server error", "")
	ErrDatabaseError    = NewAppError(http.StatusInternalServerError, "Database error", "")
	ErrCertificateError = NewAppError(http.StatusInternalServerError, "Certificate error", "")
)

// BadRequestError creates a 400 Bad Request error for invalid client requests.
// Use this when the client sends malformed data, missing required fields,
// or invalid parameter values.
func BadRequestError(message string) *AppError {
	return NewAppError(http.StatusBadRequest, message, "")
}

// UnauthorizedError creates a 401 Unauthorized error for authentication failures.
// Use this when authentication credentials are missing, invalid, or expired.
func UnauthorizedError(message string) *AppError {
	return NewAppError(http.StatusUnauthorized, message, "")
}

// ForbiddenError creates a 403 Forbidden error for access control violations.
// Use this when the client is authenticated but lacks permission for the requested resource.
func ForbiddenError(message string) *AppError {
	return NewAppError(http.StatusForbidden, message, "")
}

// NotFoundError creates a 404 Not Found error for missing resources.
// Use this when a requested system, service, or authorization rule does not exist.
func NotFoundError(message string) *AppError {
	return NewAppError(http.StatusNotFound, message, "")
}

// ConflictError creates a 409 Conflict error for resource conflicts.
// Use this when attempting to create a resource that already exists or
// when concurrent modifications conflict.
func ConflictError(message string) *AppError {
	return NewAppError(http.StatusConflict, message, "")
}

// InternalServerError creates a 500 Internal Server Error for unexpected failures.
// Use this for unrecoverable errors that are not the client's fault.
func InternalServerError(message string) *AppError {
	return NewAppError(http.StatusInternalServerError, message, "")
}

// DatabaseError wraps a database error as a 500 Internal Server Error.
// The original error message is included in the Details field.
func DatabaseError(err error) *AppError {
	return NewAppError(http.StatusInternalServerError, "Database error", err.Error())
}

// ConfigurationError creates a 500 Internal Server Error for configuration issues.
// Use this when the application is misconfigured (missing keys, invalid settings, etc.).
func ConfigurationError(message string) *AppError {
	return NewAppError(http.StatusInternalServerError, "Configuration error", message)
}
