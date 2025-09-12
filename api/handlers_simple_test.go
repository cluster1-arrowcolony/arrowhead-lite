package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestHandlersErrorHandling(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("JSON Parsing Error", func(t *testing.T) {
		// Test that invalid JSON returns proper error response
		req := httptest.NewRequest("POST", "/test", bytes.NewReader([]byte("{invalid json}")))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		var testReq pkg.SystemRegistration
		err := c.ShouldBindJSON(&testReq)

		// Verify that invalid JSON causes binding error
		assert.Error(t, err)
	})

	t.Run("Valid JSON Parsing", func(t *testing.T) {
		// Test that valid JSON parses correctly
		validReq := pkg.SystemRegistration{
			SystemName: "test-system",
			Address:    "192.168.1.100",
			Port:       8080,
		}

		reqBody, _ := json.Marshal(validReq)
		req := httptest.NewRequest("POST", "/test", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		var parsedReq pkg.SystemRegistration
		err := c.ShouldBindJSON(&parsedReq)

		assert.NoError(t, err)
		assert.Equal(t, validReq.SystemName, parsedReq.SystemName)
		assert.Equal(t, validReq.Address, parsedReq.Address)
		assert.Equal(t, validReq.Port, parsedReq.Port)
	})
}

func TestAppErrorTypes(t *testing.T) {
	t.Run("Error Types and Codes", func(t *testing.T) {
		badReqErr := pkg.BadRequestError("Bad request")
		assert.Equal(t, http.StatusBadRequest, badReqErr.StatusCode())
		assert.Equal(t, "Bad request", badReqErr.Error())

		notFoundErr := pkg.NotFoundError("Not found")
		assert.Equal(t, http.StatusNotFound, notFoundErr.StatusCode())
		assert.Equal(t, "Not found", notFoundErr.Error())

		conflictErr := pkg.ConflictError("Conflict")
		assert.Equal(t, http.StatusConflict, conflictErr.StatusCode())
		assert.Equal(t, "Conflict", conflictErr.Error())
	})
}

func TestGinContextHelpers(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Context Value Setting", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		// Test setting and getting context values (used in auth middleware)
		c.Set("is_admin", true)
		c.Set("system_name", "test-system")
		c.Set("system_id", 123)

		assert.True(t, c.GetBool("is_admin"))
		assert.Equal(t, "test-system", c.GetString("system_name"))
		assert.Equal(t, 123, c.GetInt("system_id"))
	})
}