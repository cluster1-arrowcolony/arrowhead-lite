#!/bin/bash

# RabbitMQ Setup Script for arrowhead-lite MQTT Support
# This script sets up RabbitMQ with MQTT plugin for local development

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}Setting up RabbitMQ with MQTT support for arrowhead-lite...${NC}"

# Default configuration
RABBITMQ_HOST="${ARROWHEAD_MQTT_HOST:-localhost}"
RABBITMQ_PORT="${ARROWHEAD_MQTT_PORT:-1883}"
RABBITMQ_WS_PORT="${ARROWHEAD_MQTT_WS_PORT:-15675}"
RABBITMQ_MGMT_PORT="${ARROWHEAD_RABBITMQ_MGMT_PORT:-15672}"
RABBITMQ_USER="${ARROWHEAD_MQTT_USERNAME:-arrowhead}"
RABBITMQ_PASS="${ARROWHEAD_MQTT_PASSWORD:-arrowhead}"
RABBITMQ_VHOST="${ARROWHEAD_MQTT_VHOST:-arrowhead}"

# Check if RabbitMQ is installed
if ! command -v rabbitmq-server &> /dev/null && ! command -v docker &> /dev/null; then
    echo -e "${RED}Neither RabbitMQ nor Docker is installed!${NC}"
    echo "Please install one of the following:"
    echo "  macOS: brew install rabbitmq"
    echo "  Ubuntu: sudo apt-get install rabbitmq-server"
    echo "  Docker: docker run -d --name rabbitmq -p 1883:1883 -p 15672:15672 rabbitmq:3-management"
    exit 1
fi

# Function to setup RabbitMQ with Docker
setup_docker_rabbitmq() {
    echo -e "${BLUE}Setting up RabbitMQ using Docker...${NC}"
    
    # Check if container already exists
    if docker ps -a --format "table {{.Names}}" | grep -q "^arrowhead-rabbitmq$"; then
        echo -e "${YELLOW}RabbitMQ container already exists. Stopping and removing...${NC}"
        docker stop arrowhead-rabbitmq 2>/dev/null || true
        docker rm arrowhead-rabbitmq 2>/dev/null || true
    fi
    
    # Run RabbitMQ container with MQTT support
    echo "Starting RabbitMQ container..."
    docker run -d \
        --name arrowhead-rabbitmq \
        -p ${RABBITMQ_PORT}:1883 \
        -p ${RABBITMQ_WS_PORT}:15675 \
        -p ${RABBITMQ_MGMT_PORT}:15672 \
        -e RABBITMQ_DEFAULT_USER=${RABBITMQ_USER} \
        -e RABBITMQ_DEFAULT_PASS=${RABBITMQ_PASS} \
        -e RABBITMQ_DEFAULT_VHOST=${RABBITMQ_VHOST} \
        rabbitmq:3-management
    
    # Wait for RabbitMQ to start
    echo "Waiting for RabbitMQ to start..."
    sleep 10
    
    # Enable MQTT plugin
    echo "Enabling MQTT plugin..."
    docker exec arrowhead-rabbitmq rabbitmq-plugins enable rabbitmq_mqtt
    docker exec arrowhead-rabbitmq rabbitmq-plugins enable rabbitmq_web_mqtt
    
    # Wait for plugins to be enabled
    sleep 5
    
    # Create virtual host and user
    echo "Setting up virtual host and user..."
    docker exec arrowhead-rabbitmq rabbitmqctl add_vhost ${RABBITMQ_VHOST} 2>/dev/null || echo "Virtual host already exists"
    docker exec arrowhead-rabbitmq rabbitmqctl add_user ${RABBITMQ_USER} ${RABBITMQ_PASS} 2>/dev/null || echo "User already exists"
    docker exec arrowhead-rabbitmq rabbitmqctl set_user_tags ${RABBITMQ_USER} administrator
    docker exec arrowhead-rabbitmq rabbitmqctl set_permissions -p ${RABBITMQ_VHOST} ${RABBITMQ_USER} ".*" ".*" ".*"
    
    echo -e "${GREEN}RabbitMQ container setup completed!${NC}"
}

# Function to setup local RabbitMQ
setup_local_rabbitmq() {
    echo -e "${BLUE}Setting up local RabbitMQ installation...${NC}"
    
    # Check if RabbitMQ is running
    if ! pgrep -f rabbitmq-server &> /dev/null; then
        echo -e "${YELLOW}RabbitMQ server is not running${NC}"
        echo "Please start RabbitMQ server:"
        echo "  macOS: brew services start rabbitmq"
        echo "  Ubuntu: sudo nodectl start rabbitmq-server"
        echo "  Manual: rabbitmq-server -detached"
        exit 1
    fi
    
    echo -e "${GREEN}RabbitMQ server is running!${NC}"
    
    # Enable MQTT plugin
    echo "Enabling MQTT plugin..."
    rabbitmq-plugins enable rabbitmq_mqtt
    rabbitmq-plugins enable rabbitmq_web_mqtt
    rabbitmq-plugins enable rabbitmq_management
    
    # Wait for plugins to be enabled
    sleep 3
    
    # Create virtual host and user
    echo "Setting up virtual host and user..."
    rabbitmqctl add_vhost ${RABBITMQ_VHOST} 2>/dev/null || echo "Virtual host already exists"
    rabbitmqctl add_user ${RABBITMQ_USER} ${RABBITMQ_PASS} 2>/dev/null || echo "User already exists"
    rabbitmqctl set_user_tags ${RABBITMQ_USER} administrator
    rabbitmqctl set_permissions -p ${RABBITMQ_VHOST} ${RABBITMQ_USER} ".*" ".*" ".*"
    
    echo -e "${GREEN}Local RabbitMQ setup completed!${NC}"
}

# Determine setup method
if command -v docker &> /dev/null; then
    echo -e "${BLUE}Docker detected. Choose setup method:${NC}"
    echo "1) Use Docker (recommended)"
    echo "2) Use local RabbitMQ installation"
    read -p "Enter choice [1-2]: " choice
    
    case $choice in
        1)
            setup_docker_rabbitmq
            ;;
        2)
            if command -v rabbitmq-server &> /dev/null; then
                setup_local_rabbitmq
            else
                echo -e "${RED}RabbitMQ is not installed locally!${NC}"
                echo "Install with: brew install rabbitmq (macOS) or sudo apt-get install rabbitmq-server (Ubuntu)"
                exit 1
            fi
            ;;
        *)
            echo -e "${RED}Invalid choice. Using Docker by default.${NC}"
            setup_docker_rabbitmq
            ;;
    esac
elif command -v rabbitmq-server &> /dev/null; then
    setup_local_rabbitmq
else
    echo -e "${RED}Neither Docker nor RabbitMQ is available!${NC}"
    exit 1
fi

# Test MQTT connection
echo "Testing MQTT connection..."
sleep 2

# Try to connect to MQTT port
if command -v nc &> /dev/null; then
    if nc -z ${RABBITMQ_HOST} ${RABBITMQ_PORT} 2>/dev/null; then
        echo -e "${GREEN}MQTT port ${RABBITMQ_PORT} is accessible!${NC}"
    else
        echo -e "${YELLOW}MQTT port ${RABBITMQ_PORT} is not yet accessible. This might be normal during startup.${NC}"
    fi
else
    echo -e "${YELLOW}netcat (nc) not available for port testing. Skipping connection test.${NC}"
fi

echo ""
echo -e "${GREEN}RabbitMQ MQTT setup completed successfully!${NC}"
echo ""
echo "Connection details:"
echo "  MQTT Host: ${RABBITMQ_HOST}"
echo "  MQTT Port: ${RABBITMQ_PORT}"
echo "  MQTT WebSocket Port: ${RABBITMQ_WS_PORT}"
echo "  Management UI: http://${RABBITMQ_HOST}:${RABBITMQ_MGMT_PORT}"
echo "  Username: ${RABBITMQ_USER}"
echo "  Password: ${RABBITMQ_PASS}"
echo "  Virtual Host: ${RABBITMQ_VHOST}"
echo ""
echo "Environment variables for Arrowhead:"
echo "  export ARROWHEAD_MQTT_HOST=${RABBITMQ_HOST}"
echo "  export ARROWHEAD_MQTT_PORT=${RABBITMQ_PORT}"
echo "  export ARROWHEAD_MQTT_USERNAME=${RABBITMQ_USER}"
echo "  export ARROWHEAD_MQTT_PASSWORD=${RABBITMQ_PASS}"
echo ""
echo "You can now start the Arrowhead server with MQTT relay support:"
echo "  ./bin/arrowhead-lite"
echo ""
echo "Or use Docker Compose:"
echo "  cd docker && docker-compose up -d"
echo ""
echo -e "${BLUE}Access RabbitMQ Management UI at: http://${RABBITMQ_HOST}:${RABBITMQ_MGMT_PORT}${NC}"
echo "Login with username: ${RABBITMQ_USER}, password: ${RABBITMQ_PASS}"
