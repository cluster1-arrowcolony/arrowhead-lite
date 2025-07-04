package pkg

import (
	"fmt"
	"net/http"
)

// A custom error type for Arrowhead
type AppError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func (e *AppError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s", e.Message, e.Details)
	}
	return e.Message
}

func (e *AppError) StatusCode() int {
	return e.Code
}

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

// BadRequestError error for invalid requests
func BadRequestError(message string) *AppError {
	return NewAppError(http.StatusBadRequest, message, "")
}

// InvalidCredentials error for authentication failures
func UnauthorizedError(message string) *AppError {
	return NewAppError(http.StatusUnauthorized, message, "")
}

// ForbiddenError error for access control violations
func ForbiddenError(message string) *AppError {
	return NewAppError(http.StatusForbidden, message, "")
}

// NotFoundError error for resources that cannot be found
func NotFoundError(message string) *AppError {
	return NewAppError(http.StatusNotFound, message, "")
}

// ConflictError error for resource conflicts (e.g., duplicate entries)
func ConflictError(message string) *AppError {
	return NewAppError(http.StatusConflict, message, "")
}

// Internal server error
func InternalServerError(message string) *AppError {
	return NewAppError(http.StatusInternalServerError, message, "")
}

// DatabaseError error
func DatabaseError(err error) *AppError {
	return NewAppError(http.StatusInternalServerError, "Database error", err.Error())
}

func ConfigurationError(message string) *AppError {
	return NewAppError(http.StatusInternalServerError, "Configuration error", message)
}
