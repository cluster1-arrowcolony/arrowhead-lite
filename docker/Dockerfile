# Build stage
FROM golang:1.21 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    git \
    gcc \
    libc6-dev \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -a -ldflags '-extldflags "-static"' -o arrowhead-lite ./cmd/main.go

# Production stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates sqlite wget

# Create non-root user
RUN addgroup -g 1001 -S arrowhead && \
    adduser -u 1001 -S arrowhead -G arrowhead

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/arrowhead-lite .

# Copy configuration files
COPY --from=builder /app/configs ./configs
COPY --from=builder /app/web ./web

# Create data directory
RUN mkdir -p /app/data && chown -R arrowhead:arrowhead /app

# Switch to non-root user
USER arrowhead

# Expose ports
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8443/health || exit 1

# Set default environment variables
ENV ARROWHEAD_SERVER_HOST=0.0.0.0
ENV ARROWHEAD_SERVER_PORT=8443
ENV ARROWHEAD_DATABASE_PATH=/app/data/arrowhead.db
ENV ARROWHEAD_LOGGING_LEVEL=info

# Run the application
CMD ["./arrowhead-lite"]
