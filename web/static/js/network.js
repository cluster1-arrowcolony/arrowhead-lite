// Network graph functionality using vis.js
console.log('Network.js loaded');

let networks = {};

function loadGraph(type) {
    const containerId = type + 'sGraph';
    const container = document.getElementById(containerId);
    
    if (!container) return;

    let nodes = [], edges = [];
    
    switch (type) {
        case 'node':
            nodes = currentData.nodes.map((node, index) => ({
                id: 'node_' + node.id,
                label: node.name,
                title: `IoT Device: ${node.name}\nStatus: ${node.status || 'offline'}\nAddress: ${node.address}:${node.port}`,
                shape: 'box',
                size: 60,
                widthConstraint: { minimum: 200, maximum: 200 },
                heightConstraint: { minimum: 100, maximum: 100 },
                shapeProperties: {
                    borderRadius: 12
                },
                color: {
                    background: node.status === 'active' ? '#667eea' : '#a0aec0',
                    border: node.status === 'active' ? '#4c51bf' : '#718096'
                },
                font: { color: 'white', size: 18, strokeWidth: 2, strokeColor: '#000', multi: false },
                type: 'node',
                originalData: node
            }));
            break;
            
        case 'service':
            nodes = currentData.services.map((service, index) => ({
                id: 'service_' + service.id,
                label: service.name,
                title: `Service: ${service.name}\nDefinition: ${service.definition}\nURI: ${service.uri}`,
                shape: 'box',
                size: 40,
                widthConstraint: { minimum: 150, maximum: 150 },
                heightConstraint: { minimum: 80, maximum: 80 },
                shapeProperties: {
                    borderRadius: 10
                },
                color: {
                    background: service.status === 'active' ? '#48bb78' : '#e53e3e',
                    border: service.status === 'active' ? '#38a169' : '#c53030'
                },
                font: { color: 'white', size: 14, strokeWidth: 1, strokeColor: '#000', multi: false },
                type: 'service',
                originalData: service
            }));
            break;
            
        case 'authRule':
            // Show nodes connected by auth rules
            const nodeIds = new Set();
            currentData.authRules.forEach(rule => {
                nodeIds.add(rule.consumer_id);
                nodeIds.add(rule.provider_id);
            });
            
            // Add node nodes
            nodeIds.forEach(nodeId => {
                const node = currentData.nodes.find(s => s.id === nodeId);
                if (node) {
                    nodes.push({
                        id: 'node_' + node.id,
                        label: node.name,
                        title: `IoT Device: ${node.name}\nStatus: ${node.status || 'offline'}`,
                        shape: 'box',
                        size: 50,
                        widthConstraint: { minimum: 180, maximum: 180 },
                        heightConstraint: { minimum: 90, maximum: 90 },
                        shapeProperties: {
                            borderRadius: 10
                        },
                        color: {
                            background: node.status === 'active' ? '#667eea' : '#a0aec0',
                            border: node.status === 'active' ? '#4c51bf' : '#718096'
                        },
                        font: { color: 'white', size: 18, strokeWidth: 2, strokeColor: '#000', multi: false },
                        type: 'node',
                        originalData: node
                    });
                }
            });
            
            // Add auth rule edges
            currentData.authRules.forEach(rule => {
                edges.push({
                    id: 'auth_' + rule.id,
                    from: 'node_' + rule.consumer_id,
                    to: 'node_' + rule.provider_id,
                    color: '#391b78',
                    width: 3,
                    arrows: { to: { enabled: true, scaleFactor: 1.2 } },
                    title: `Authorization: ${rule.consumer_id} → ${rule.provider_id}`,
                    type: 'authorization',
                    originalData: rule
                });
            });
            break;
    }

    if (nodes.length > 0) {
        createVisNetwork(containerId, nodes, edges);
    }
}

async function loadNetworkGraph() {
    try {
        // Load all data if not already loaded
        await Promise.all([
            currentData.nodes.length === 0 ? loadNodes() : Promise.resolve(),
            currentData.services.length === 0 ? loadServices() : Promise.resolve(),
            currentData.authRules.length === 0 ? loadAuthRules() : Promise.resolve()
        ]);

        updateNetworkGraph();
    } catch (error) {
        console.error('Failed to load network graph:', error);
    }
}

function updateNetworkGraph() {
    console.log('Updating network graph with filter:', document.getElementById('networkFilter').value);
    console.log('Current data:', {
        nodes: currentData.nodes.length,
        services: currentData.services.length,
        authRules: currentData.authRules.length
    });
    
    const filter = document.getElementById('networkFilter').value;
    let nodes = [], edges = [];

    // Group services by node for better organization
    const servicesByNode = {};
    currentData.services.forEach(service => {
        if (!servicesByNode[service.node_id]) {
            servicesByNode[service.node_id] = [];
        }
        servicesByNode[service.node_id].push(service);
    });

    // Calculate grid layout for nodes
    const nodeCount = currentData.nodes.length;
    const nodesPerRow = Math.ceil(Math.sqrt(nodeCount));
    const xGridSpacing = 360; // Reduced from 400 to 280
    const yGridSpacing = 200; // Reduced from 400 to 280
    const startX = -((nodesPerRow - 1) * xGridSpacing) / 2;
    const startY = -((Math.ceil(nodeCount / nodesPerRow) - 1) * yGridSpacing) / 2;

    // Add node nodes (IoT devices) with fixed positions
    if (filter === 'all' || filter === 'nodes') {
        currentData.nodes.forEach((node, index) => {
            const row = Math.floor(index / nodesPerRow);
            const col = index % nodesPerRow;
            const x = startX + col * xGridSpacing;
            const y = startY + row * yGridSpacing;

            nodes.push({
                id: 'node_' + node.id,
                label: node.name,
                title: `IoT Device: ${node.name}\nStatus: ${node.status || 'offline'}\nAddress: ${node.address}:${node.port}`,
                x: x,
                y: y,
                fixed: true,
                shape: 'box',
                size: 80,
                widthConstraint: { minimum: 240, maximum: 240 },
                heightConstraint: { minimum: 160, maximum: 160 },
                shapeProperties: {
                    borderRadius: 15
                },
                color: {
                    background: node.status === 'active' ? '#667eea' : '#a0aec0',
                    border: node.status === 'active' ? '#4c51bf' : '#718096',
                    highlight: { background: '#5a67d8', border: '#4c51bf' }
                },
                font: { 
                    color: 'white', 
                    size: 20, 
                    face: 'Arial',
                    strokeWidth: 2,
                    strokeColor: '#000',
                    vadjust: -50,  // Move text to top of taller rectangle
                    multi: false
                },
                type: 'node',
                originalData: node,
                level: 0  // Lower level for background
            });

            // Add service nodes positioned at the bottom of their node rectangle
            const nodeServices = servicesByNode[node.id] || [];
            const maxServicesPerRow = 2;
            const serviceWidth = 115;
            const serviceHeight = 40;
            const servicePadding = 10;
            
            nodeServices.forEach((service, serviceIndex) => {
                const row = Math.floor(serviceIndex / maxServicesPerRow);
                const col = serviceIndex % maxServicesPerRow;
                
                // Calculate position at bottom of the node rectangle, ensuring services are inside
                const startX = x - 90; // Center services in node (240/2 = 120, minus half of total service area)
                const startY = y + 15; // Position services in bottom area but inside node bounds
                
                const serviceX = startX + col * (serviceWidth + servicePadding);
                const serviceY = startY + row * (serviceHeight + servicePadding);

                nodes.push({
                    id: 'service_' + service.id,
                    label: service.name,
                    title: `Service: ${service.name}\nDefinition: ${service.definition}\nURI: ${service.uri}\nMethod: ${service.method}\nStatus: ${service.status || 'inactive'}`,
                    x: serviceX,
                    y: serviceY,
                    fixed: true,
                    shape: 'box',
                    size: 20,
                    widthConstraint: { minimum: serviceWidth, maximum: serviceWidth },
                    heightConstraint: { minimum: serviceHeight, maximum: serviceHeight },
                    shapeProperties: {
                        borderRadius: 8
                    },
                    color: {
                        background: service.status === 'active' ? '#48bb78' : '#e53e3e',
                        border: service.status === 'active' ? '#38a169' : '#c53030',
                        highlight: { 
                            background: service.status === 'active' ? '#68d391' : '#fc8181',
                            border: service.status === 'active' ? '#38a169' : '#c53030'
                        }
                    },
                    font: { 
                        color: 'white', 
                        size: 14, 
                        face: 'Arial',
                        strokeWidth: 1,
                        strokeColor: '#000',
                        multi: false,
                        maxWdt: serviceWidth - 10
                    },
                    type: 'service',
                    nodeId: node.id,
                    originalData: service,
                    level: 1  // Higher level so services appear above nodes
                });
            });
        });
    }

    // Add authorization edges - consumer nodes to specific services
    if (filter === 'all' || filter === 'auth') {
        currentData.authRules.forEach(rule => {
            let targetServiceId = null;
            
            // If the rule specifies a service, connect to that specific service
            if (rule.service_id && rule.service_id !== 'Any') {
                const targetService = currentData.services.find(s => s.id === rule.service_id);
                if (targetService) {
                    targetServiceId = 'service_' + rule.service_id;
                }
            } else {
                // If no specific service, connect to the first service of the provider node
                const providerServices = servicesByNode[rule.provider_id] || [];
                if (providerServices.length > 0) {
                    targetServiceId = 'service_' + providerServices[0].id;
                }
            }

            if (targetServiceId) {
              edges.push({
                id: 'auth_' + rule.id,
                from: 'node_' + rule.consumer_id,
                to: targetServiceId,
                color: { color: '#48bb78', opacity: 0.9 }, // Changed from 0.8 to 0.9
                width: 6, // Changed from 5 to 6
                arrows: { 
                    to: { 
                        enabled: true, 
                        scaleFactor: 2.0, // Changed from 1.5 to 2.0
                        type: 'arrow'
                    } 
                },
                smooth: { type: 'curvedCW', roundness: 0.3 },
                physics: false,
                shadow: {
                    enabled: true,
                    color: 'rgba(0,0,0,0.5)', // Changed from 0.3 to 0.5
                    size: 5, // Changed from 3 to 5
                    x: 3, // Changed from 2 to 3
                    y: 3  // Changed from 2 to 3
                },
                title: `Authorization: ${rule.consumer_id} → ${rule.provider_id}${rule.service_id !== 'Any' ? ' (' + rule.service_id + ')' : ''}`,
                type: 'authorization',
                originalData: rule,
                chosen: {
                    edge: true
                },
                selectionWidth: 3, // Changed from 2 to 3
                level: 2 // ADD THIS LINE - forces edges on top
              });
            }
        });
    }

    createVisNetwork('networkGraph', nodes, edges);
}

function createVisNetwork(containerId, nodes, edges) {
    const container = document.getElementById(containerId);
    console.log('Creating vis.js network with', nodes.length, 'nodes and', edges.length, 'edges');
    
    // Destroy existing network if it exists
    if (networks[containerId]) {
        networks[containerId].destroy();
    }
    
    // Remove loading class
    container.classList.remove('loading');
    
    const data = { 
        nodes: new vis.DataSet(nodes), 
        edges: new vis.DataSet(edges) 
    };
    
    const options = {
        nodes: {
            borderWidth: 3,
            shadow: {
                enabled: true,
                color: 'rgba(0,0,0,0.2)',
                size: 5,
                x: 2,
                y: 2
            },
            font: {
                strokeWidth: 2,
                strokeColor: '#000000',
                multi: false
            },
            chosen: {
                node: function(values, id, selected, hovering) {
                    values.borderWidth = 4;
                }
            }
        },
        edges: {
            font: { 
                size: 12, 
                color: '#2d3748',
                strokeWidth: 2,
                strokeColor: 'white'
            },
            shadow: {
                enabled: true,
                color: 'rgba(0,0,0,0.3)',
                size: 4,
                x: 2,
                y: 2
            },
            chosen: {
                edge: function(values, id, selected, hovering) {
                    values.width = 6;
                    values.opacity = 1.0;
                }
            }
        },
        layout: {
            improvedLayout: false,
            hierarchical: {
                enabled: false
            }
        },
        physics: {
            enabled: false, // Disabled since we're using fixed positions
            stabilization: { enabled: false }
        },
        interaction: {
            hover: true,
            tooltipDelay: 200,
            hideEdgesOnDrag: false,
            hideEdgesOnZoom: false,
            zoomView: true,
            dragView: true,
            selectConnectedEdges: false
        },
        configure: {
            enabled: false
        },
        groups: {
            nodes: {
                level: 0
            },
            services: {
                level: 1
            },
            edges: {
                level: 2
            }
        }
    };

    const network = new vis.Network(container, data, options);
    networks[containerId] = network;

    setTimeout(() => {
        network.redraw();
        // Force edges to be drawn on top by updating their properties
        const edgeUpdate = edges.map(edge => ({
            ...edge,
            level: 2
        }));
        network.setData({
            nodes: new vis.DataSet(nodes),
            edges: new vis.DataSet(edgeUpdate)
        });
    }, 100);
    
    console.log('vis.js network created successfully');

    // Add click event handlers
    network.on('click', function(params) {
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            const node = data.nodes.get(nodeId);
            showVisNodeDetails(node);
        }
    });
    
    // Add hover effects
    network.on('hoverNode', function(params) {
        container.style.cursor = 'pointer';
    });
    
    network.on('blurNode', function(params) {
        container.style.cursor = 'default';
    });
}

function showNodeDetails(nodeId) {
    // Extract type and ID from nodeId (format: "type_id")
    const [type, id] = nodeId.split('_');
    console.log(`${type} details:`, id);
}

function showVisNodeDetails(node) {
    const type = node.type;
    const originalData = node.originalData;
    
    console.log(`${type} clicked:`, originalData);
    
    // Create a detailed info popup
    let details = '';
    if (type === 'node') {
        details = `IoT Device: ${originalData.name} | Status: ${originalData.status || 'offline'} | Address: ${originalData.address}:${originalData.port}`;
    } else if (type === 'service') {
        details = `Service: ${originalData.name} | Definition: ${originalData.definition} | URI: ${originalData.uri} | Method: ${originalData.method}`;
    }
    
    // Show details in a toast
    if (details) {
        showToast(details, 'info');
    }
}
