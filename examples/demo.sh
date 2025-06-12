#!/bin/bash

# --- Configuration ---
SERVER_BINARY="./bin/arrowhead-lite"
SERVER_URL="http://localhost:8443"
SERVER_PID=""
USING_EXTERNAL_SERVER=false

# --- Cleanup Function ---
# This function is called when the script exits, ensuring the server is stopped.
cleanup() {
    echo ""
    if [ "$USING_EXTERNAL_SERVER" = "false" ] && [ -n "$SERVER_PID" ] && ps -p $SERVER_PID > /dev/null; then
        echo "🛑 Stopping arrowhead-lite server (PID: $SERVER_PID)..."
        kill $SERVER_PID
        # Wait a moment for the process to terminate
        sleep 1
    elif [ "$USING_EXTERNAL_SERVER" = "true" ]; then
        echo "📡 External server remains running"
    fi
    echo "👋 Exiting."
}

# Trap the EXIT signal to run the cleanup function automatically.
# This works for normal exit, Ctrl+C (SIGINT), and kill (SIGTERM).
trap cleanup EXIT

# Change to the project root directory
cd "$(dirname "$0")/.."

# --- Script Start ---
echo "🚀 Arrowhead Lite Demo"
echo "======================"
echo ""

# Check if server is already running
echo "🔍 Checking if arrowhead-lite server is already running..."
if curl -s --fail ${SERVER_URL}/health > /dev/null 2>&1; then
    echo "✅ Found existing arrowhead-lite server at ${SERVER_URL}"
    echo "📡 Using existing server for demo"
    USING_EXTERNAL_SERVER=true
else
    echo "🏗️  No server found, will start local instance"
    
    # Clean up any existing database to prevent conflicts (only if starting new server)
    if [ -f "./arrowhead.db" ]; then
        echo "🧹 Cleaning up existing database..."
        rm -f ./arrowhead.db
    fi

    # Check if arrowhead-lite is built
    if [ ! -f "$SERVER_BINARY" ]; then
        echo "📦 Building arrowhead-lite..."
        make build
        echo ""
    fi

    # Start arrowhead-lite server in background
    echo "🔧 Starting arrowhead-lite server in the background..."
    $SERVER_BINARY &
    SERVER_PID=$!
    echo "✅ arrowhead-lite server starting (PID: $SERVER_PID)"

    # Wait for server to become healthy with a timeout
    echo "⏳ Waiting for server to become available at ${SERVER_URL}/health..."
    for i in {1..10}; do
        if curl -s --fail ${SERVER_URL}/health > /dev/null; then
            echo "✅ Server is up!"
            break
        fi
        if [ $i = 10 ]; then
          echo "❌ Failed to start arrowhead-lite server after 10 seconds."
          # The trap will automatically call cleanup() on exit
          exit 1
        fi
        sleep 1
    done
fi
echo ""

# Run all the API tests

echo "🧪 Testing Go API..."
echo ""

echo "1. Health check..."
HEALTH=$(curl -s ${SERVER_URL}/health)
STATUS=$(echo $HEALTH | python3 -c "import sys, json; print(json.load(sys.stdin)['status'])" 2>/dev/null || echo "unknown")
echo "   Server status: $STATUS"

echo "2. Initial metrics..."
METRICS=$(curl -s ${SERVER_URL}/api/v1/metrics)
INITIAL_NODES=$(echo $METRICS | python3 -c "import sys, json; print(json.load(sys.stdin)['total_nodes'])" 2>/dev/null || echo "0")
echo "   Initial nodes: $INITIAL_NODES"

echo "3. Database information..."
if [ "$USING_EXTERNAL_SERVER" = "true" ]; then
    echo "   Database: Using external server (likely Docker/PostgreSQL or existing SQLite)"
else
    if [ -f "./arrowhead.db" ]; then
        DB_SIZE=$(ls -lh ./arrowhead.db | awk '{print $5}')
        echo "   Database: ./arrowhead.db (size: $DB_SIZE)"
    else
        echo "   Database: ./arrowhead.db (will be created)"
    fi
fi

echo "4. Ensuring mining IoT devices are registered..."

# Function to register or get existing node
register_or_get_node() {
    local name=$1
    local address=$2
    local port=$3
    
    # First check if node already exists
    local existing_id=$(curl -s ${SERVER_URL}/api/v1/registry/nodes | python3 -c "
import sys, json
data = json.load(sys.stdin)
for node in data['nodes']:
    if node['name'] == '$name':
        print(node['id'])
        exit(0)
" 2>/dev/null)
    
    if [ ! -z "$existing_id" ]; then
        echo "   ℹ️  Already exists: $name" >&2
        echo "$existing_id"
        return 0
    fi
    
    # Try to register the node
    local response=$(curl -s -X POST ${SERVER_URL}/api/v1/registry/nodes -H "Content-Type: application/json" -d "{\"node\": {\"name\": \"$name\", \"address\": \"$address\", \"port\": $port}}" -w "HTTPSTATUS:%{http_code}")
    
    local status_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    local body=$(echo "$response" | sed 's/HTTPSTATUS:[0-9]*$//')
    
    if [ "$status_code" = "201" ]; then
        echo "   ✅ Registered: $name" >&2
        echo "$body" | python3 -c "import sys, json; print(json.load(sys.stdin)['id'])" 2>/dev/null
    else
        echo "   ❌ Failed to register: $name (status: $status_code)" >&2
        return 1
    fi
}

GAS_SENSOR_ID=$(register_or_get_node "gas-detector-tunnel-a1" "10.0.1.101" 8080)
VIBRATION_MONITOR_ID=$(register_or_get_node "vibration-monitor-shaft-1" "10.0.1.102" 8081)
CONVEYOR_CONTROLLER_ID=$(register_or_get_node "conveyor-belt-ctrl-01" "10.0.1.103" 8082)
EMERGENCY_NODE_ID=$(register_or_get_node "emergency-alert-node" "10.0.1.104" 8083)
MINING_OPS_CONTROLLER_ID=$(register_or_get_node "mining-ops-controller" "10.0.1.105" 8084)
PERSONNEL_TRACKER_ID=$(register_or_get_node "personnel-tracker-main" "10.0.1.106" 8085)

echo "5. Testing admin authentication..."
AUTH_RESPONSE=$(curl -s -X POST ${SERVER_URL}/api/v1/auth/admin -H "Content-Type: application/json" -d '{"username": "admin"}')
ACCESS_TOKEN=$(echo $AUTH_RESPONSE | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)

if [ -z "$ACCESS_TOKEN" ]; then
    echo "   ❌ Admin authentication failed. Aborting further tests."
    # The trap will handle cleanup, so we can just exit.
    exit 1
fi
echo "   ✅ Admin authentication successful"

echo "6. Ensuring mining device interaction services are registered..."

# Function to register or get existing service
register_or_get_service() {
    local name=$1
    local node_id=$2
    local definition=$3
    local uri=$4
    local method=$5
    
    # First check if service already exists
    local existing_id=$(curl -s ${SERVER_URL}/api/v1/registry/services | python3 -c "
import sys, json
data = json.load(sys.stdin)
for service in data['services']:
    if service['name'] == '$name':
        print(service['id'])
        exit(0)
" 2>/dev/null)
    
    if [ ! -z "$existing_id" ]; then
        echo "   ℹ️  Already exists: $name" >&2
        echo "$existing_id"
        return 0
    fi
    
    # Try to register the service
    local response=$(curl -s -X POST ${SERVER_URL}/api/v1/registry/services -H "Content-Type: application/json" -H "Authorization: Bearer $ACCESS_TOKEN" -d "{\"service\": {\"name\": \"$name\", \"node_id\": \"$node_id\", \"definition\": \"$definition\", \"uri\": \"$uri\", \"method\": \"$method\"}}" -w "HTTPSTATUS:%{http_code}")
    
    local status_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    local body=$(echo "$response" | sed 's/HTTPSTATUS:[0-9]*$//')
    
    if [ "$status_code" = "201" ]; then
        echo "   ✅ Registered: $name" >&2
        # Extract ID from the response body
        echo "$body" | python3 -c "import sys, json; print(json.load(sys.stdin)['id'])" 2>/dev/null
    else
        echo "   ❌ Failed to register: $name (status: $status_code)" >&2
        return 1
    fi
}

GAS_DETECTION_SERVICE_ID=$(register_or_get_service "gas-detection-data" "$GAS_SENSOR_ID" "methane-co-gas-detector" "/sensors/gas-levels" "GET")
VIBRATION_SERVICE_ID=$(register_or_get_service "vibration-monitoring" "$VIBRATION_MONITOR_ID" "structural-integrity-monitor" "/sensors/vibration" "GET")
CONVEYOR_SERVICE_ID=$(register_or_get_service "conveyor-belt-control" "$CONVEYOR_CONTROLLER_ID" "material-transport-controller" "/control/conveyor" "POST")
EMERGENCY_SERVICE_ID=$(register_or_get_service "emergency-alerts" "$EMERGENCY_NODE_ID" "mine-safety-alert-node" "/alerts/emergency" "POST")
MINING_OPS_SERVICE_ID=$(register_or_get_service "mining-operations-mgmt" "$MINING_OPS_CONTROLLER_ID" "mine-operation-coordinator" "/control/mining-ops" "POST")
PERSONNEL_SERVICE_ID=$(register_or_get_service "personnel-tracking" "$PERSONNEL_TRACKER_ID" "worker-safety-location-tracker" "/tracking/personnel" "GET")

echo "7. Ensuring mining safety and operational device interaction rules exist..."

# Function to create or check existing auth rule
create_or_check_auth_rule() {
    local consumer_id=$1
    local provider_id=$2
    local service_id=$3
    local rule_name=$4
    
    # Check if we have all required IDs
    if [ -z "$consumer_id" ] || [ -z "$provider_id" ] || [ -z "$service_id" ]; then
        echo "   ❌ Failed to create: $rule_name (missing IDs: consumer=$consumer_id, provider=$provider_id, service=$service_id)"
        return 1
    fi
    
    local status_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST ${SERVER_URL}/api/v1/auth/rules -H "Content-Type: application/json" -H "Authorization: Bearer $ACCESS_TOKEN" -d "{\"consumer_id\": \"$consumer_id\", \"provider_id\": \"$provider_id\", \"service_id\": \"$service_id\"}")
    
    if [ "$status_code" = "201" ]; then
        echo "   ✅ Created: $rule_name"
    elif [ "$status_code" = "409" ]; then
        echo "   ℹ️  Already exists: $rule_name"
    else
        echo "   ❌ Failed to create: $rule_name (status: $status_code)"
    fi
}

create_or_check_auth_rule "$MINING_OPS_CONTROLLER_ID" "$GAS_SENSOR_ID" "$GAS_DETECTION_SERVICE_ID" "Mining Ops → Gas Detection"
create_or_check_auth_rule "$EMERGENCY_NODE_ID" "$GAS_SENSOR_ID" "$GAS_DETECTION_SERVICE_ID" "Emergency → Gas Detection"
create_or_check_auth_rule "$MINING_OPS_CONTROLLER_ID" "$VIBRATION_MONITOR_ID" "$VIBRATION_SERVICE_ID" "Mining Ops → Vibration Monitor"
create_or_check_auth_rule "$EMERGENCY_NODE_ID" "$VIBRATION_MONITOR_ID" "$VIBRATION_SERVICE_ID" "Emergency → Vibration Monitor"
create_or_check_auth_rule "$MINING_OPS_CONTROLLER_ID" "$CONVEYOR_CONTROLLER_ID" "$CONVEYOR_SERVICE_ID" "Mining Ops → Conveyor Control"
create_or_check_auth_rule "$EMERGENCY_NODE_ID" "$CONVEYOR_CONTROLLER_ID" "$CONVEYOR_SERVICE_ID" "Emergency → Conveyor Control"
create_or_check_auth_rule "$MINING_OPS_CONTROLLER_ID" "$PERSONNEL_TRACKER_ID" "$PERSONNEL_SERVICE_ID" "Mining Ops → Personnel Tracking"
create_or_check_auth_rule "$EMERGENCY_NODE_ID" "$PERSONNEL_TRACKER_ID" "$PERSONNEL_SERVICE_ID" "Emergency → Personnel Tracking"

echo "8. Final checks..."
METRICS=$(curl -s ${SERVER_URL}/api/v1/metrics)
FINAL_NODES=$(echo $METRICS | python3 -c "import sys, json; print(json.load(sys.stdin)['total_nodes'])" 2>/dev/null || echo "0")
FINAL_SERVICES=$(echo $METRICS | python3 -c "import sys, json; print(json.load(sys.stdin)['total_services'])" 2>/dev/null || echo "0")
AUTH_RULES=$(curl -s ${SERVER_URL}/api/v1/auth/rules)
RULE_COUNT=$(echo $AUTH_RULES | python3 -c "import sys, json; print(len(json.load(sys.stdin)['rules']))" 2>/dev/null || echo "0")

echo "   Total nodes: $FINAL_NODES | Total services: $FINAL_SERVICES | Auth rules: $RULE_COUNT"

# --- Final Instructions ---
echo ""
echo "🎉 Demo completed successfully!"
echo ""
echo "🌐 Server endpoints:"
echo "   Dashboard:     ${SERVER_URL}"
echo "   API:           ${SERVER_URL}/api/v1"
echo ""
echo "🔐 Mining Operation IoT Device Interactions Created:"
echo "   ✅ Mining Operations Controller ↔ Gas/Vibration/Conveyor/Personnel"
echo "   ✅ Emergency Alert Node ↔ Gas/Vibration/Conveyor/Personnel"
echo "   💡 View these critical mining safety relationships in the 'Network Graph' on the Dashboard."
echo ""
echo "--------------------------------------------------------"
if [ "$USING_EXTERNAL_SERVER" = "true" ]; then
    echo " Used existing arrowhead-lite server (e.g., Docker Compose)."
    echo " The server will continue running after this demo exits."
    echo " Press [Ctrl+C] to exit the demo."
else
    echo " The arrowhead-lite server is running in the background."
    echo " Press [Ctrl+C] to stop the server and exit."
fi
echo "--------------------------------------------------------"
echo ""

# Wait for the server process to end (only if we started it)
# This will block the script from exiting until the user presses Ctrl+C
if [ "$USING_EXTERNAL_SERVER" = "false" ] && [ -n "$SERVER_PID" ]; then
    wait $SERVER_PID
else
    # For external servers, just wait for user to press Ctrl+C
    echo "🎯 Demo data has been created! Press [Ctrl+C] to exit..."
    while true; do
        sleep 1
    done
fi
