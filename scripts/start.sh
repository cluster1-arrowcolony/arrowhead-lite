#!/bin/bash

echo "🚀 Starting Arrowhead IoT Service Mesh"
echo "====================================="

# Check if binary exists
if [ ! -f "bin/arrowhead-lite" ]; then
    echo "📦 Building application..."
    make build
fi

echo "🔧 Starting server..."
echo "Dashboard: http://localhost:8443"
echo "API: http://localhost:8443/api/v1"
echo "Health: http://localhost:8443/health"
echo "Metrics: http://localhost:8443/metrics"
echo ""
echo "Press Ctrl+C to stop"
echo ""

./bin/arrowhead-lite
