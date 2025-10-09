# Development Guide

## Getting Started

This guide covers setting up your development environment, understanding the codebase, and contributing to Arrowhead Lite.

## Development Environment Setup

### Prerequisites

#### Required Software
- **Go**: Version 1.23 or later
- **Git**: For version control
- **Make**: For build automation
- **Docker**: (Optional) For containerized testing

#### Recommended Tools
- **VS Code** or **GoLand**: IDE with Go support
- **golangci-lint**: Linting tool
- **dlv**: Go debugger
- **curl** or **httpie**: API testing
- **jq**: JSON processing

### Installation

#### 1. Install Go

```bash
# Linux/macOS
wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# macOS with Homebrew
brew install go

# Verify installation
go version
```

#### 2. Clone Repository

```bash
# Clone the repository
git clone https://github.com/your-org/arrowhead-lite.git
cd arrowhead-lite

# Create your feature branch
git checkout -b feature/your-feature-name
```

#### 3. Install Dependencies

```bash
# Download Go modules
go mod download

# Install development tools
make install-tools

# This installs:
# - golangci-lint
# - staticcheck
# - gosec
# - govulncheck
# - mockgen
# - swag (for Swagger docs)
```

#### 4. Setup Pre-commit Hooks

```bash
# Install pre-commit
pip install pre-commit

# Install the git hooks
pre-commit install

# Run against all files (first time)
pre-commit run --all-files
```

`.pre-commit-config.yaml`:
```yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files

  - repo: https://github.com/golangci/golangci-lint
    rev: v1.54.2
    hooks:
      - id: golangci-lint

  - repo: local
    hooks:
      - id: go-fmt
        name: go fmt
        entry: go fmt ./...
        language: system
        pass_filenames: false

      - id: go-test
        name: go test
        entry: go test ./...
        language: system
        pass_filenames: false
```

## Project Structure

```
arrowhead-lite/
├── cmd/                    # Application entrypoints
│   └── main.go            # Main application
├── internal/              # Private application code
│   ├── auth/             # Authentication service
│   ├── ca/               # Certificate Authority
│   ├── config/           # Configuration management
│   ├── database/         # Database layer
│   ├── orchestration/    # Orchestration service
│   └── registry/         # Service registry
├── pkg/                   # Public libraries
│   ├── models/           # Data models
│   ├── errors/           # Error definitions
│   └── utils/            # Utility functions
├── api/                   # API definitions
│   ├── handlers/         # HTTP handlers
│   ├── middleware/       # HTTP middleware
│   └── routes/           # Route definitions
├── web/                   # Web UI (if applicable)
├── scripts/              # Build and utility scripts
├── tests/                # Integration tests
├── docs/                 # Documentation
├── docker/               # Docker configurations
├── deployments/          # Deployment configurations
├── migrations/           # Database migrations
├── config/               # Configuration files
├── certs/                # Development certificates
├── Makefile              # Build automation
├── go.mod                # Go module definition
└── README.md             # Project documentation
```

## Building and Running

### Build Commands

```bash
# Build the binary
make build

# Build with race detection
make build-race

# Build for different platforms
make build-linux
make build-windows
make build-darwin

# Build Docker image
make docker-build

# Clean build artifacts
make clean
```

### Running Locally

```bash
# Run with default settings (development mode)
make dev

# Run with custom configuration
./bin/arrowhead-lite --config config.dev.yaml

# Run with verbose logging
./bin/arrowhead-lite --disable-tls --verbose

# Run with environment variables
ARROWHEAD_LOG_LEVEL=debug \
ARROWHEAD_DATABASE_TYPE=sqlite \
./bin/arrowhead-lite
```

### Development Server

```bash
# Start development server with hot reload
make dev-watch

# This uses air for hot reloading
# Install air first:
go install github.com/air-verse/air@latest

# Configuration in .air.toml
```

`.air.toml`:
```toml
root = "."
tmp_dir = "tmp"

[build]
  bin = "./tmp/main"
  cmd = "go build -o ./tmp/main ./cmd/main.go"
  delay = 1000
  exclude_dir = ["assets", "tmp", "vendor", "tests"]
  exclude_file = []
  exclude_regex = ["_test.go"]
  exclude_unchanged = false
  follow_symlink = false
  full_bin = ""
  include_dir = []
  include_ext = ["go", "tpl", "tmpl", "html"]
  kill_delay = "0s"
  log = "build-errors.log"
  send_interrupt = false
  stop_on_error = true

[color]
  app = ""
  build = "yellow"
  main = "magenta"
  runner = "green"
  watcher = "cyan"

[log]
  time = false

[misc]
  clean_on_exit = false
```

## Testing

### Test Structure

```
tests/
├── unit/              # Unit tests
├── integration/       # Integration tests
├── e2e/              # End-to-end tests
├── performance/      # Performance tests
├── fixtures/         # Test data
└── mocks/           # Mock implementations
```

### Running Tests

```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run specific package tests
go test ./internal/registry/...

# Run with race detection
go test -race ./...

# Run with verbose output
go test -v ./...

# Run specific test
go test -run TestServiceRegistration ./internal/registry

# Run benchmarks
go test -bench=. ./...

# Run with timeout
go test -timeout 30s ./...
```

### Writing Tests

#### Unit Test Example

```go
// internal/registry/service_test.go
package registry

import (
    "testing"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
)

func TestRegisterService(t *testing.T) {
    // Arrange
    mockDB := new(MockDatabase)
    registry := NewRegistry(mockDB)

    service := &Service{
        Name: "temperature-sensor",
        Port: 8080,
    }

    mockDB.On("CreateService", service).Return(nil)

    // Act
    err := registry.RegisterService(service)

    // Assert
    assert.NoError(t, err)
    mockDB.AssertExpectations(t)
}

func TestRegisterService_DuplicateName(t *testing.T) {
    // Test duplicate service name handling
    mockDB := new(MockDatabase)
    registry := NewRegistry(mockDB)

    service := &Service{
        Name: "existing-service",
    }

    mockDB.On("CreateService", service).
        Return(ErrServiceExists)

    err := registry.RegisterService(service)

    assert.Error(t, err)
    assert.Equal(t, ErrServiceExists, err)
}
```

#### Integration Test Example

```go
// tests/integration/api_test.go
package integration

import (
    "net/http/httptest"
    "testing"
    "github.com/gin-gonic/gin"
)

func TestServiceRegistrationFlow(t *testing.T) {
    // Setup test server
    router := setupTestRouter()

    // Register a system
    w := httptest.NewRecorder()
    req := httptest.NewRequest("POST", "/serviceregistry/register",
        strings.NewReader(`{
            "system": {
                "systemName": "test-system",
                "address": "127.0.0.1",
                "port": 8080
            }
        }`))
    router.ServeHTTP(w, req)

    assert.Equal(t, 201, w.Code)

    // Query for the service
    w = httptest.NewRecorder()
    req = httptest.NewRequest("POST", "/serviceregistry/query",
        strings.NewReader(`{
            "serviceDefinitionRequirement": "test-system"
        }`))
    router.ServeHTTP(w, req)

    assert.Equal(t, 200, w.Code)

    var result QueryResult
    json.Unmarshal(w.Body.Bytes(), &result)
    assert.Len(t, result.Services, 1)
}
```

#### Table-Driven Tests

```go
func TestValidateSystemName(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected bool
    }{
        {"valid name", "system-123", true},
        {"with underscore", "system_123", true},
        {"with dot", "system.123", true},
        {"empty", "", false},
        {"with space", "system 123", false},
        {"with special char", "system@123", false},
        {"too long", strings.Repeat("a", 256), false},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := ValidateSystemName(tt.input)
            assert.Equal(t, tt.expected, result)
        })
    }
}
```

### Test Coverage

```bash
# Generate coverage report
make test-coverage

# View coverage in browser
go tool cover -html=coverage.out

# Coverage requirements
# - Minimum 80% overall coverage
# - Critical paths must have 95%+ coverage
# - New code must have tests
```

## Code Quality

### Linting

```bash
# Run all linters
make lint

# Run specific linter
golangci-lint run

# Fix auto-fixable issues
golangci-lint run --fix

# Run security checks
make security
```

`.golangci.yml`:
```yaml
linters:
  enable:
    - gofmt
    - golint
    - govet
    - errcheck
    - ineffassign
    - staticcheck
    - gosec
    - gocyclo
    - dupl
    - misspell
    - unparam
    - prealloc
    - bodyclose
    - goimports

linters-settings:
  gocyclo:
    min-complexity: 15
  dupl:
    threshold: 100
  goconst:
    min-len: 3
    min-occurrences: 3

issues:
  exclude-rules:
    - path: _test\.go
      linters:
        - dupl
        - gosec
```

### Code Formatting

```bash
# Format code
make fmt

# Check formatting
gofmt -l .

# Format imports
goimports -w .

# Format and simplify code
gofmt -s -w .
```

## Debugging

### Using Delve

```bash
# Install delve
go install github.com/go-delve/delve/cmd/dlv@latest

# Debug the application
dlv debug ./cmd/main.go -- --disable-tls

# Debug a test
dlv test ./internal/registry

# Attach to running process
dlv attach <PID>
```

### VS Code Debug Configuration

`.vscode/launch.json`:
```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Launch Application",
      "type": "go",
      "request": "launch",
      "mode": "auto",
      "program": "${workspaceFolder}/cmd/main.go",
      "args": ["--disable-tls", "--verbose"],
      "env": {
        "ARROWHEAD_LOG_LEVEL": "debug"
      }
    },
    {
      "name": "Debug Test",
      "type": "go",
      "request": "launch",
      "mode": "test",
      "program": "${workspaceFolder}/internal/registry",
      "args": ["-test.v"]
    },
    {
      "name": "Attach to Process",
      "type": "go",
      "request": "attach",
      "mode": "local",
      "processId": "${command:pickProcess}"
    }
  ]
}
```

### Logging for Debugging

```go
// Use structured logging for debugging
import "github.com/sirupsen/logrus"

func ProcessRequest(req *Request) error {
    logger := logrus.WithFields(logrus.Fields{
        "request_id": req.ID,
        "method": req.Method,
        "path": req.Path,
    })

    logger.Debug("Processing request")

    // Add timing information
    start := time.Now()
    defer func() {
        logger.WithField("duration", time.Since(start)).
            Debug("Request processed")
    }()

    // Log important state changes
    logger.WithField("state", "validation").Debug("Validating request")

    if err := validate(req); err != nil {
        logger.WithError(err).Error("Validation failed")
        return err
    }

    return nil
}
```

## API Development

### Adding New Endpoints

1. **Define the handler**:
```go
// api/handlers/new_feature.go
func (h *Handlers) NewFeatureHandler(c *gin.Context) {
    var req NewFeatureRequest

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    result, err := h.service.ProcessNewFeature(req)
    if err != nil {
        c.JSON(500, gin.H{"error": err.Error()})
        return
    }

    c.JSON(200, result)
}
```

2. **Add route**:
```go
// api/routes/routes.go
func SetupRoutes(router *gin.Engine, handlers *Handlers) {
    api := router.Group("/api")
    {
        api.POST("/new-feature", handlers.NewFeatureHandler)
    }
}
```

3. **Add tests**:
```go
// api/handlers/new_feature_test.go
func TestNewFeatureHandler(t *testing.T) {
    // Test implementation
}
```

### API Documentation

```bash
# Generate Swagger documentation
swag init -g cmd/main.go

# Add Swagger comments
// @Summary Create new feature
// @Description Process a new feature request
// @Tags feature
// @Accept json
// @Produce json
// @Param request body NewFeatureRequest true "Feature request"
// @Success 200 {object} NewFeatureResponse
// @Failure 400 {object} ErrorResponse
// @Router /api/new-feature [post]
```

## Database Development

### Creating Migrations

```bash
# Create new migration
make migration name=add_feature_table

# This creates:
# migrations/TIMESTAMP_add_feature_table.up.sql
# migrations/TIMESTAMP_add_feature_table.down.sql
```

Example migration:
```sql
-- migrations/20250115120000_add_feature_table.up.sql
CREATE TABLE IF NOT EXISTS features (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_features_name ON features(name);
CREATE INDEX idx_features_enabled ON features(enabled);

-- migrations/20250115120000_add_feature_table.down.sql
DROP TABLE IF EXISTS features;
```

### Database Testing

```go
// Use test database
func setupTestDB(t *testing.T) *sql.DB {
    db, err := sql.Open("sqlite3", ":memory:")
    require.NoError(t, err)

    // Run migrations
    err = RunMigrations(db)
    require.NoError(t, err)

    return db
}

func TestDatabaseOperation(t *testing.T) {
    db := setupTestDB(t)
    defer db.Close()

    // Test database operations
}
```

## Performance Optimization

### Profiling

```bash
# CPU profiling
go test -cpuprofile=cpu.prof -bench=.
go tool pprof cpu.prof

# Memory profiling
go test -memprofile=mem.prof -bench=.
go tool pprof mem.prof

# Run pprof web interface
go tool pprof -http=:8080 cpu.prof
```

### Benchmarking

```go
func BenchmarkServiceRegistration(b *testing.B) {
    registry := setupRegistry()
    service := createTestService()

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        registry.RegisterService(service)
    }
}

func BenchmarkParallel(b *testing.B) {
    registry := setupRegistry()

    b.RunParallel(func(pb *testing.PB) {
        for pb.Next() {
            registry.QueryServices(QueryRequest{})
        }
    })
}
```

## Contributing

### Development Workflow

1. **Fork and Clone**
```bash
git clone https://github.com/YOUR_USERNAME/arrowhead-lite.git
cd arrowhead-lite
git remote add upstream https://github.com/ORIGINAL_OWNER/arrowhead-lite.git
```

2. **Create Feature Branch**
```bash
git checkout -b feature/your-feature
```

3. **Make Changes**
```bash
# Make your changes
# Add tests
# Update documentation
```

4. **Run Tests**
```bash
make check  # Runs fmt, vet, lint, test
```

5. **Commit Changes**
```bash
git add .
git commit -m "feat: add new feature

- Detailed description
- Closes #123"
```

6. **Push and Create PR**
```bash
git push origin feature/your-feature
# Create pull request on GitHub
```

### Commit Guidelines

Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `style:` Code style changes
- `refactor:` Code refactoring
- `test:` Test changes
- `chore:` Build process or auxiliary tool changes

### Code Review Checklist

- [ ] Tests pass
- [ ] Coverage maintained or improved
- [ ] Documentation updated
- [ ] Linting passes
- [ ] Security scan passes
- [ ] Performance impact considered
- [ ] Backward compatibility maintained
- [ ] Error handling appropriate
- [ ] Logging added where needed

## Development Tools

### Makefile Targets

```makefile
# Development
make dev          # Run development server
make build        # Build binary
make test         # Run tests
make lint         # Run linters
make fmt          # Format code

# Docker
make docker-build # Build Docker image
make docker-run   # Run in Docker
make docker-test  # Test in Docker

# Database
make migrate-up   # Run migrations
make migrate-down # Rollback migrations
make migration    # Create new migration

# Tools
make install-tools # Install dev tools
make clean        # Clean build artifacts
make help         # Show help
```

### Useful Scripts

```bash
# scripts/dev-setup.sh
#!/bin/bash
# Complete development environment setup

set -e

echo "Setting up development environment..."

# Install Go tools
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest

# Setup pre-commit
pip install pre-commit
pre-commit install

# Generate certificates
./scripts/generate-certs.sh

# Setup test database
./scripts/setup-test-db.sh

echo "Development environment ready!"
```

## Troubleshooting Development Issues

### Common Problems

#### Go Module Issues
```bash
# Clear module cache
go clean -modcache

# Download dependencies again
go mod download

# Tidy dependencies
go mod tidy
```

#### Build Failures
```bash
# Clean and rebuild
make clean
make build

# Verbose build
go build -v ./cmd/main.go
```

#### Test Failures
```bash
# Run tests with more detail
go test -v -count=1 ./...

# Disable test caching
GOCACHE=off go test ./...
```

## Resources

### Documentation
- [Go Documentation](https://go.dev/doc/)
- [Gin Framework](https://gin-gonic.com/docs/)
- [Arrowhead Framework](https://www.arrowhead.eu/)

### Tools
- [VS Code Go Extension](https://marketplace.visualstudio.com/items?itemName=golang.Go)
- [GoLand IDE](https://www.jetbrains.com/go/)
- [Postman](https://www.postman.com/) for API testing
- [TablePlus](https://tableplus.com/) for database management

### Learning Resources
- [Effective Go](https://go.dev/doc/effective_go)
- [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- [Go Proverbs](https://go-proverbs.github.io/)