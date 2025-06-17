#!/bin/bash

echo "🚀 Starting Arrowhead IoT Service Mesh"
echo "====================================="

# Check if binary exists
if [ ! -f "bin/arrowhead-lite" ]; then
    echo "📦 Building application..."
    make build
fi

echo "🔧 Starting server..."
echo "Dashboard:        http://localhost:8443"
echo "Service Registry: http://localhost:8443/serviceregistry/mgmt"
echo "Authorization:    http://localhost:8443/authorization/mgmt/intracloud"
echo "Orchestration:    http://localhost:8443/orchestrator/orchestration"
echo "Health:           http://localhost:8443/health"
echo "Metrics:          http://localhost:8443/metrics"
echo ""
echo "Press Ctrl+C to stop"
echo ""

./bin/arrowhead-lite
