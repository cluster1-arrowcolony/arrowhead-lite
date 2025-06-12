package tests

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig_Defaults(t *testing.T) {
	// Test loading config with default values (no config file)
	config, err := internal.LoadConfig("")
	require.NoError(t, err)
	require.NotNil(t, config)

	// Verify default server config
	assert.Equal(t, "0.0.0.0", config.Server.Host)
	assert.Equal(t, 8443, config.Server.Port)
	assert.Equal(t, 30*time.Second, config.Server.ReadTimeout)
	assert.Equal(t, 30*time.Second, config.Server.WriteTimeout)
	assert.False(t, config.Server.TLS.Enabled)
	assert.Equal(t, []string{"*"}, config.Server.CORS.AllowOrigins)
	assert.Contains(t, config.Server.CORS.AllowMethods, "GET")
	assert.Contains(t, config.Server.CORS.AllowMethods, "POST")

	// Verify default database config
	assert.Equal(t, "sqlite", config.Database.Type)
	assert.Equal(t, "./arrowhead.db", config.Database.Path)
	assert.Equal(t, "localhost", config.Database.Host)
	assert.Equal(t, 5432, config.Database.Port)
	assert.Equal(t, "arrowhead", config.Database.Username)
	assert.Equal(t, "arrowhead", config.Database.Password)
	assert.Equal(t, "arrowhead", config.Database.Name)

	// Verify default auth config
	assert.Equal(t, "arrowhead-lite-secret", config.Auth.JWTSecret)
	assert.Equal(t, 24*time.Hour, config.Auth.TokenDuration)

	// Verify default logging config
	assert.Equal(t, "warn", config.Logging.Level)
	assert.Equal(t, "text", config.Logging.Format)

	// Verify default health config
	assert.Equal(t, 1*time.Minute, config.Health.CheckInterval)
	assert.Equal(t, 5*time.Minute, config.Health.InactiveTimeout)
	assert.Equal(t, 10*time.Minute, config.Health.CleanupInterval)
}

func TestLoadConfig_FromFile(t *testing.T) {
	// Create a temporary config file
	configContent := `
server:
  host: "127.0.0.1"
  port: 9443
  read_timeout: "60s"
  write_timeout: "60s"
  tls:
    enabled: true
    cert_file: "/path/to/cert.pem"
    key_file: "/path/to/key.pem"
  cors:
    allow_origins: ["https://example.com"]
    allow_methods: ["GET", "POST"]
    allow_headers: ["Authorization", "Content-Type"]

database:
  type: "postgresql"
  host: "db.example.com"
  port: 5433
  username: "test_user"
  password: "test_pass"
  name: "test_db"

auth:
  jwt_secret: "custom-secret-key"
  token_duration: "12h"
  private_key_file: "/path/to/private.key"
  public_key_file: "/path/to/public.key"

logging:
  level: "debug"
  format: "text"
  file: "/var/log/arrowhead.log"

health:
  check_interval: "30s"
  inactive_timeout: "2m"
  cleanup_interval: "5m"
`

	// Create temporary directory and file
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.yaml")

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)

	// Load config from file
	config, err := internal.LoadConfig(configFile)
	require.NoError(t, err)
	require.NotNil(t, config)

	// Verify server config
	assert.Equal(t, "127.0.0.1", config.Server.Host)
	assert.Equal(t, 9443, config.Server.Port)
	assert.Equal(t, 60*time.Second, config.Server.ReadTimeout)
	assert.Equal(t, 60*time.Second, config.Server.WriteTimeout)
	assert.True(t, config.Server.TLS.Enabled)
	assert.Equal(t, "/path/to/cert.pem", config.Server.TLS.CertFile)
	assert.Equal(t, "/path/to/key.pem", config.Server.TLS.KeyFile)
	assert.Equal(t, []string{"https://example.com"}, config.Server.CORS.AllowOrigins)
	assert.Equal(t, []string{"GET", "POST"}, config.Server.CORS.AllowMethods)
	assert.Equal(t, []string{"Authorization", "Content-Type"}, config.Server.CORS.AllowHeaders)

	// Verify database config
	assert.Equal(t, "postgresql", config.Database.Type)
	assert.Equal(t, "db.example.com", config.Database.Host)
	assert.Equal(t, 5433, config.Database.Port)
	assert.Equal(t, "test_user", config.Database.Username)
	assert.Equal(t, "test_pass", config.Database.Password)
	assert.Equal(t, "test_db", config.Database.Name)

	// Verify auth config
	assert.Equal(t, "custom-secret-key", config.Auth.JWTSecret)
	assert.Equal(t, 12*time.Hour, config.Auth.TokenDuration)
	assert.Equal(t, "/path/to/private.key", config.Auth.PrivateKeyFile)
	assert.Equal(t, "/path/to/public.key", config.Auth.PublicKeyFile)

	// Verify logging config
	assert.Equal(t, "debug", config.Logging.Level)
	assert.Equal(t, "text", config.Logging.Format)
	assert.Equal(t, "/var/log/arrowhead.log", config.Logging.File)

	// Verify health config
	assert.Equal(t, 30*time.Second, config.Health.CheckInterval)
	assert.Equal(t, 2*time.Minute, config.Health.InactiveTimeout)
	assert.Equal(t, 5*time.Minute, config.Health.CleanupInterval)
}

func TestLoadConfig_PartialFile(t *testing.T) {
	// Test with a config file that only overrides some values
	configContent := `
server:
  port: 8080
  tls:
    enabled: true

database:
  type: "postgresql"
  host: "custom-db-host"

logging:
  level: "error"
`

	// Create temporary directory and file
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.yaml")

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)

	// Load config from file
	config, err := internal.LoadConfig(configFile)
	require.NoError(t, err)
	require.NotNil(t, config)

	// Verify overridden values
	assert.Equal(t, 8080, config.Server.Port)
	assert.True(t, config.Server.TLS.Enabled)
	assert.Equal(t, "postgresql", config.Database.Type)
	assert.Equal(t, "custom-db-host", config.Database.Host)
	assert.Equal(t, "error", config.Logging.Level)

	// Verify default values are still present for non-overridden settings
	assert.Equal(t, "0.0.0.0", config.Server.Host)             // Default
	assert.Equal(t, 30*time.Second, config.Server.ReadTimeout) // Default
	assert.Equal(t, 5432, config.Database.Port)                // Default
	assert.Equal(t, "arrowhead", config.Database.Username)     // Default
	assert.Equal(t, "text", config.Logging.Format)             // Default
}

func TestLoadConfig_InvalidFile(t *testing.T) {
	// Test with an invalid YAML file
	configContent := `
server:
  port: invalid_port_value
  tls:
    enabled: not_a_boolean
invalid_yaml_structure
`

	// Create temporary directory and file
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.yaml")

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)

	// Load config from file - should return error
	config, err := internal.LoadConfig(configFile)
	assert.Error(t, err)
	assert.Nil(t, config)
}

func TestLoadConfig_NonExistentFile(t *testing.T) {
	// Test with a non-existent file path
	config, err := internal.LoadConfig("/non/existent/path/config.yaml")
	assert.Error(t, err)
	assert.Nil(t, config)
}

func TestLoadConfig_EnvironmentVariables(t *testing.T) {
	// Set environment variables to override config
	originalPort := os.Getenv("ARROWHEAD_SERVER_PORT")
	originalHost := os.Getenv("ARROWHEAD_SERVER_HOST")
	originalDBType := os.Getenv("ARROWHEAD_DATABASE_TYPE")
	originalLogLevel := os.Getenv("ARROWHEAD_LOGGING_LEVEL")

	defer func() {
		// Restore original environment
		if originalPort != "" {
			os.Setenv("ARROWHEAD_SERVER_PORT", originalPort)
		} else {
			os.Unsetenv("ARROWHEAD_SERVER_PORT")
		}
		if originalHost != "" {
			os.Setenv("ARROWHEAD_SERVER_HOST", originalHost)
		} else {
			os.Unsetenv("ARROWHEAD_SERVER_HOST")
		}
		if originalDBType != "" {
			os.Setenv("ARROWHEAD_DATABASE_TYPE", originalDBType)
		} else {
			os.Unsetenv("ARROWHEAD_DATABASE_TYPE")
		}
		if originalLogLevel != "" {
			os.Setenv("ARROWHEAD_LOGGING_LEVEL", originalLogLevel)
		} else {
			os.Unsetenv("ARROWHEAD_LOGGING_LEVEL")
		}
	}()

	// Set test environment variables
	os.Setenv("ARROWHEAD_SERVER_PORT", "9999")
	os.Setenv("ARROWHEAD_SERVER_HOST", "test-host")
	os.Setenv("ARROWHEAD_DATABASE_TYPE", "postgresql")
	os.Setenv("ARROWHEAD_LOGGING_LEVEL", "debug")

	// Load config (environment variables should override defaults)
	config, err := internal.LoadConfig("")
	require.NoError(t, err)
	require.NotNil(t, config)

	// Verify environment variables took effect
	assert.Equal(t, 9999, config.Server.Port)
	assert.Equal(t, "test-host", config.Server.Host)
	assert.Equal(t, "postgresql", config.Database.Type)
	assert.Equal(t, "debug", config.Logging.Level)

	// Verify non-overridden defaults are still present
	assert.Equal(t, 30*time.Second, config.Server.ReadTimeout)
	assert.Equal(t, "arrowhead-lite-secret", config.Auth.JWTSecret)
}

func TestLoadConfig_MixedFileAndEnvironment(t *testing.T) {
	// Test config file with environment variable overrides
	configContent := `
server:
  host: "file-host"
  port: 8888
  tls:
    enabled: true

database:
  type: "sqlite"
  path: "/file/path/db.sqlite"

logging:
  level: "info"
  format: "json"
`

	// Create temporary directory and file
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.yaml")

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)

	// Set environment variables to override some config file values
	originalPort := os.Getenv("ARROWHEAD_SERVER_PORT")
	originalDBPath := os.Getenv("ARROWHEAD_DATABASE_PATH")
	originalLogLevel := os.Getenv("ARROWHEAD_LOGGING_LEVEL")

	defer func() {
		// Restore original environment
		if originalPort != "" {
			os.Setenv("ARROWHEAD_SERVER_PORT", originalPort)
		} else {
			os.Unsetenv("ARROWHEAD_SERVER_PORT")
		}
		if originalDBPath != "" {
			os.Setenv("ARROWHEAD_DATABASE_PATH", originalDBPath)
		} else {
			os.Unsetenv("ARROWHEAD_DATABASE_PATH")
		}
		if originalLogLevel != "" {
			os.Setenv("ARROWHEAD_LOGGING_LEVEL", originalLogLevel)
		} else {
			os.Unsetenv("ARROWHEAD_LOGGING_LEVEL")
		}
	}()

	os.Setenv("ARROWHEAD_SERVER_PORT", "7777")                  // Override file value
	os.Setenv("ARROWHEAD_DATABASE_PATH", "/env/path/db.sqlite") // Override file value
	os.Setenv("ARROWHEAD_LOGGING_LEVEL", "error")               // Override file value

	// Load config from file
	config, err := internal.LoadConfig(configFile)
	require.NoError(t, err)
	require.NotNil(t, config)

	// Verify environment variables override file values
	assert.Equal(t, 7777, config.Server.Port)                    // Env override
	assert.Equal(t, "/env/path/db.sqlite", config.Database.Path) // Env override
	assert.Equal(t, "error", config.Logging.Level)               // Env override

	// Verify file values that weren't overridden by environment
	assert.Equal(t, "file-host", config.Server.Host) // From file
	assert.True(t, config.Server.TLS.Enabled)        // From file
	assert.Equal(t, "sqlite", config.Database.Type)  // From file
	assert.Equal(t, "json", config.Logging.Format)   // From file

	// Verify defaults for values not in file or environment
	assert.Equal(t, 30*time.Second, config.Server.ReadTimeout)      // Default
	assert.Equal(t, "arrowhead-lite-secret", config.Auth.JWTSecret) // Default
}

func TestLoadConfig_TimeoutParsing(t *testing.T) {
	// Test various time duration formats
	configContent := `
server:
  read_timeout: "45s"
  write_timeout: "2m"

auth:
  token_duration: "48h"

health:
  check_interval: "90s"
  inactive_timeout: "10m"
  cleanup_interval: "1h"
`

	// Create temporary directory and file
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.yaml")

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)

	// Load config from file
	config, err := internal.LoadConfig(configFile)
	require.NoError(t, err)
	require.NotNil(t, config)

	// Verify time duration parsing
	assert.Equal(t, 45*time.Second, config.Server.ReadTimeout)
	assert.Equal(t, 2*time.Minute, config.Server.WriteTimeout)
	assert.Equal(t, 48*time.Hour, config.Auth.TokenDuration)
	assert.Equal(t, 90*time.Second, config.Health.CheckInterval)
	assert.Equal(t, 10*time.Minute, config.Health.InactiveTimeout)
	assert.Equal(t, 1*time.Hour, config.Health.CleanupInterval)
}
