#!/bin/bash

# PostgreSQL Setup Script for arrowhead-lite
# This script sets up a PostgreSQL database for local development

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Setting up PostgreSQL for arrowhead-lite...${NC}"

# Default configuration
DB_HOST="${ARROWHEAD_DATABASE_HOST:-localhost}"
DB_PORT="${ARROWHEAD_DATABASE_PORT:-5432}"
DB_NAME="${ARROWHEAD_DATABASE_NAME:-arrowhead}"
DB_USER="${ARROWHEAD_DATABASE_USERNAME:-arrowhead}"
DB_PASS="${ARROWHEAD_DATABASE_PASSWORD:-arrowhead}"

# Check if PostgreSQL is installed
if ! command -v psql &> /dev/null; then
    echo -e "${RED}PostgreSQL client (psql) is not installed!${NC}"
    echo "Please install PostgreSQL:"
    echo "  macOS: brew install postgresql"
    echo "  Ubuntu: sudo apt-get install postgresql-client postgresql"
    exit 1
fi

# Check if PostgreSQL server is running
if ! pg_isready -h "$DB_HOST" -p "$DB_PORT" &> /dev/null; then
    echo -e "${YELLOW}PostgreSQL server is not running on $DB_HOST:$DB_PORT${NC}"
    echo "Please start PostgreSQL server:"
    echo "  macOS: brew services start postgresql"
    echo "  Ubuntu: sudo nodectl start postgresql"
    echo "  Docker: docker run -d --name postgres -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:15-alpine"
    exit 1
fi

echo -e "${GREEN}PostgreSQL server is running!${NC}"

# Create database and user
echo "Creating database and user..."

# Connect as postgres user to create database and user
PGPASSWORD="${POSTGRES_PASSWORD:-postgres}" psql -h "$DB_HOST" -p "$DB_PORT" -U postgres -c "
CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';
CREATE DATABASE $DB_NAME OWNER $DB_USER;
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
" 2>/dev/null || echo -e "${YELLOW}Database and user might already exist (this is ok)${NC}"

# Test connection
echo "Testing connection..."
PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT version();" > /dev/null

echo -e "${GREEN}PostgreSQL setup completed successfully!${NC}"
echo ""
echo "Connection details:"
echo "  Host: $DB_HOST"
echo "  Port: $DB_PORT"
echo "  Database: $DB_NAME"
echo "  Username: $DB_USER"
echo "  Password: $DB_PASS"
echo ""
echo "You can now start the Arrowhead server with:"
echo "  arrowhead-lite"
echo ""
echo "Or use Docker Compose:"
echo "  cd docker && docker-compose up -d"
