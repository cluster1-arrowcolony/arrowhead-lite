package database

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewDatabase(t *testing.T) {
	t.Run("SQLite Database Creation", func(t *testing.T) {
		db, err := NewDatabase("sqlite", ":memory:")

		assert.NoError(t, err)
		assert.NotNil(t, db)

		// Clean up
		if db != nil {
			db.Close()
		}
	})

	t.Run("PostgreSQL Database Creation - Invalid Connection", func(t *testing.T) {
		// This should fail with an invalid connection string
		db, err := NewDatabase("postgresql", "invalid-connection-string")

		assert.Error(t, err)
		assert.Nil(t, db)
	})

	t.Run("Unsupported Database Type", func(t *testing.T) {
		db, err := NewDatabase("mongodb", "some-connection")

		assert.Error(t, err)
		assert.Nil(t, db)
		assert.Contains(t, err.Error(), "unsupported database type")
	})
}
