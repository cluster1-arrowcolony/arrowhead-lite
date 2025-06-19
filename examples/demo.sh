#!/bin/bash

# Change to the project root directory to ensure paths are correct
cd "$(dirname "$0")/.."

# --- Configuration ---
SERVER_BINARY="./bin/arrowhead-lite"
SERVER_URL="http://localhost:8443"
USING_EXTERNAL_SERVER=false

# --- Helper function for curl with optional mTLS ---
make_curl_request() {
    local method=$1
    local url=$2
    local content_type=$3
    local data=$4
    local status_code_only=${5:-false}
    
    local curl_cmd="curl -s"
    
    if [ "$method" != "GET" ]; then
        curl_cmd="$curl_cmd -X $method"
    fi
    
    if [ ! -z "$content_type" ]; then
        curl_cmd="$curl_cmd -H \"Content-Type: $content_type\""
    fi
    
    if [ ! -z "$data" ]; then
        curl_cmd="$curl_cmd -d '$data'"
    fi
    
    curl_cmd="$curl_cmd $url"
    
    if [ "$status_code_only" = "true" ]; then
        curl_cmd="$curl_cmd -o /dev/null -w %{http_code}"
    else
        curl_cmd="$curl_cmd -w HTTPSTATUS:%{http_code}"
    fi
    
    eval $curl_cmd
}

# --- Script Start ---
echo "🚀 Arrowhead Lite Demo"
echo "======================"
echo ""

function check_health() {
  curl -s --fail ${SERVER_URL}/health > /dev/null
}

# Function to register a system
register_system() {
    local system_name=$1
    local address=$2
    local port=$3
    
    local payload="{\"systemName\": \"$system_name\", \"address\": \"$address\", \"port\": $port, \"authenticationInfo\": \"\"}"
    local response=$(make_curl_request "POST" "${SERVER_URL}/serviceregistry/mgmt/systems" "application/json" "$payload")
    
    local status_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    local body=$(echo "$response" | sed 's/HTTPSTATUS:[0-9]*$//')
    
    if [ "$status_code" = "201" ]; then
        local system_id=$(echo "$body" | python3 -c "import sys, json; print(json.load(sys.stdin)['id'])")
        echo "   ✅ Registered: $system_name (ID: $system_id)" >&2
        echo "$system_id"
    else
        echo "   ❌ Failed to register: $system_name (status: $status_code)" >&2
        return 1
    fi
}

# Function to register a service, fetching provider details first
register_service() {
    local service_definition=$1
    local provider_system_id=$2
    local service_uri=$3
    
    if [ -z "$provider_system_id" ]; then echo "   ❌ Invalid provider system ID for $service_definition" >&2; return 1; fi
    
    # Fetch the full provider system object to build the correct payload
    local provider_response=$(make_curl_request "GET" "${SERVER_URL}/serviceregistry/mgmt/systems/${provider_system_id}")
    local provider_body=$(echo "$provider_response" | sed 's/HTTPSTATUS:[0-9]*$//')
    
    local provider_name=$(echo "$provider_body" | python3 -c "import sys, json; print(json.load(sys.stdin)['systemName'])")
    local provider_address=$(echo "$provider_body" | python3 -c "import sys, json; print(json.load(sys.stdin)['address'])")
    local provider_port=$(echo "$provider_body" | python3 -c "import sys, json; print(json.load(sys.stdin)['port'])")
    
    local payload="{
        \"serviceDefinition\": \"$service_definition\",
        \"providerSystem\": {
            \"systemName\": \"$provider_name\",
            \"address\": \"$provider_address\", 
            \"port\": $provider_port,
            \"authenticationInfo\": \"\"
        },
        \"serviceUri\": \"$service_uri\",
        \"interfaces\": [\"HTTP-SECURE-JSON\"]
    }"
    
    local response=$(make_curl_request "POST" "${SERVER_URL}/serviceregistry/mgmt/services" "application/json" "$payload")
    local status_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    local body=$(echo "$response" | sed 's/HTTPSTATUS:[0-9]*$//')
    
    if [ "$status_code" = "201" ]; then
        local service_id=$(echo "$body" | python3 -c "import sys, json; print(json.load(sys.stdin)['id'])")
        echo "   ✅ Registered service: $service_definition (ID: $service_id)" >&2
        echo "$service_id"
    else
        echo "   ❌ Failed to register service: $service_definition (status: $status_code)" >&2
        return 1
    fi
}

# Function to create an authorization rule
create_auth_rule() {
    local consumer_id=$1
    local provider_id=$2
    local service_id=$3
    local rule_name=$4
    
    if [ -z "$consumer_id" ] || [ -z "$provider_id" ] || [ -z "$service_id" ]; then return 1; fi
    
    # Get the Service Definition ID from the service object
    local service_obj_response=$(make_curl_request "GET" "${SERVER_URL}/serviceregistry/mgmt/services/${service_id}")
    local service_def_id=$(echo "$service_obj_response" | sed 's/HTTPSTATUS:[0-9]*$//' | python3 -c "import sys, json; print(json.load(sys.stdin)['serviceDefinition']['id'])" 2>/dev/null)
    
    if [ -z "$service_def_id" ]; then echo "   ❌ Failed to get Service Definition ID for service $service_id" >&2; return 1; fi
    
    local payload="{\"consumerId\": $consumer_id, \"providerIds\": [$provider_id], \"serviceDefinitionIds\": [$service_def_id], \"interfaceIds\": [1]}"
    local status_code=$(make_curl_request "POST" "${SERVER_URL}/authorization/mgmt/intracloud" "application/json" "$payload" "true")
    
    if [ "$status_code" = "201" ] || [ "$status_code" = "409" ]; then
        echo "   ✅ Rule created/verified: $rule_name"
    else
        echo "   ❌ Failed to create rule: $rule_name (status: $status_code)"
    fi
}

# Check if server is already running, or start it
echo "🔍 Checking for running arrowhead-lite server..."
if check_health; then
    echo "✅ Found existing server at ${SERVER_URL}"
    USING_EXTERNAL_SERVER=true
else
    echo "🏗️  No server found. Starting a local instance..."
    [ -f "./arrowhead.db" ] && echo "🧹 Cleaning up old database..." && rm -f ./arrowhead.db
    [ ! -f "$SERVER_BINARY" ] && echo "📦 Building application..." && make build
    
    $SERVER_BINARY --disable-tls &
    SERVER_PID=$!
    echo "✅ Server starting (PID: $SERVER_PID)"
    
    echo "⏳ Waiting for server to become available..."
    for i in {1..10}; do
        if check_health; then
            echo "✅ Server is up!"
            break
        fi
        [ $i = 10 ] && echo "❌ Failed to start server." && exit 1
        sleep 1;
    done

    # --- Cleanup Function ---
    # This function is called when the script exits, ensuring the server is stopped if we started it.
    cleanup() {
        echo ""
        if [ "$USING_EXTERNAL_SERVER" = "false" ] && [ -n "$SERVER_PID" ] && ps -p "$SERVER_PID" > /dev/null; then
            echo "🛑 Stopping arrowhead-lite server (PID: $SERVER_PID)..."
            kill "$SERVER_PID"
            sleep 1
        elif [ "$USING_EXTERNAL_SERVER" = "true" ]; then
            echo "📡 External server remains running."
        fi
        echo "👋 Demo finished."
    }
    trap cleanup EXIT
fi
echo ""

# --- API Tests ---
echo "🧪 Testing Arrowhead 4.x API..."
echo ""

echo "1. Registering mining IoT systems..."
GAS_SENSOR_ID=$(register_system "gas-detector-tunnel-a1" "10.0.1.101" 8080)
VIBRATION_MONITOR_ID=$(register_system "vibration-monitor-shaft-1" "10.0.1.102" 8081)
CONVEYOR_CONTROLLER_ID=$(register_system "conveyor-belt-ctrl-01" "10.0.1.103" 8082)
EMERGENCY_NODE_ID=$(register_system "emergency-alert-node" "10.0.1.104" 8083)
MINING_OPS_CONTROLLER_ID=$(register_system "mining-ops-controller" "10.0.1.105" 8084)
PERSONNEL_TRACKER_ID=$(register_system "personnel-tracker-main" "10.0.1.106" 8085)

echo ""
echo "2. Registering mining device services..."

GAS_DETECTION_SERVICE_ID=$(register_service "methane-co-gas-detector" "$GAS_SENSOR_ID" "/sensors/gas-levels")
VIBRATION_SERVICE_ID=$(register_service "structural-integrity-monitor" "$VIBRATION_MONITOR_ID" "/sensors/vibration")
CONVEYOR_SERVICE_ID=$(register_service "material-transport-controller" "$CONVEYOR_CONTROLLER_ID" "/control/conveyor")
EMERGENCY_SERVICE_ID=$(register_service "mine-safety-alert-node" "$EMERGENCY_NODE_ID" "/alerts/emergency")
MINING_OPS_SERVICE_ID=$(register_service "mine-operation-coordinator" "$MINING_OPS_CONTROLLER_ID" "/control/mining-ops")
PERSONNEL_SERVICE_ID=$(register_service "worker-safety-location-tracker" "$PERSONNEL_TRACKER_ID" "/tracking/personnel")

echo ""
echo "3. Creating authorization rules..."

create_auth_rule "$MINING_OPS_CONTROLLER_ID" "$GAS_SENSOR_ID" "$GAS_DETECTION_SERVICE_ID" "Mining Ops → Gas Detection"
create_auth_rule "$EMERGENCY_NODE_ID" "$GAS_SENSOR_ID" "$GAS_DETECTION_SERVICE_ID" "Emergency → Gas Detection"
create_auth_rule "$MINING_OPS_CONTROLLER_ID" "$VIBRATION_MONITOR_ID" "$VIBRATION_SERVICE_ID" "Mining Ops → Vibration Monitor"

echo ""
echo "4. Testing orchestration..."
ORCHESTRATION_PAYLOAD="{
    \"requestedService\": { \"serviceDefinitionRequirement\": \"methane-co-gas-detector\" },
    \"requesterSystem\": { \"systemName\": \"mining-ops-controller\", \"address\": \"10.0.1.105\", \"port\": 8084 },
    \"orchestrationFlags\": {\"matchmaking\": true, \"overrideStore\": true}
}"

ORCH_RESPONSE=$(make_curl_request "POST" "${SERVER_URL}/orchestrator/orchestration" "application/json" "$ORCHESTRATION_PAYLOAD")
ORCH_STATUS=$(echo "$ORCH_RESPONSE" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
echo "   Orchestration request status: $ORCH_STATUS"

# --- Final Instructions ---
echo ""
echo "🎉 Arrowhead 4.x Demo completed successfully!"
echo ""
echo "🌐 Dashboard:         ${SERVER_URL}"
echo ""
echo "🔐 Mining Operation IoT Device Interactions Created:"
echo "   ✅ Systems registered for gas detection, vibration monitoring, conveyor control"
echo "   ✅ Services registered for each system with proper Arrowhead 4.x format"
echo "   ✅ Authorization rules created for mining operations and emergency systems"
echo ""
echo "--------------------------------------------------------"
if [ "$USING_EXTERNAL_SERVER" = "true" ]; then
    echo "Used existing arrowhead-lite server (e.g., Docker Compose)."
    echo "The server will continue running after this demo exits."
    echo "Press [Ctrl+C] to exit the demo."
else
    echo "The arrowhead-lite server is running in the background."
    echo "Press [Ctrl+C] to stop the server and exit."
fi
while true; do sleep 1; done
