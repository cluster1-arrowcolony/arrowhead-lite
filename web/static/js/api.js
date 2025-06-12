// API data loading and management functions
console.log('API.js loaded');

async function loadInitialData() {
    try {
        await Promise.all([
            loadMetrics(),
            loadHealth(),
            loadActivityFeed()
        ]);
    } catch (error) {
        updateConnectionStatus(false);
    }
}

async function refreshData() {
    try {
        // Always load metrics, health, and activity feed
        await Promise.all([
            loadMetrics(),
            loadHealth(),
            loadActivityFeed()
        ]);
        
        // Refresh current view data
        switch (currentView) {
            case 'dashboard':
                // Dashboard data is already loaded above
                break;
            case 'nodes':
                await loadNodes();
                break;
            case 'services':
                await loadServices();
                break;
            case 'auth-rules':
                await loadAuthRules();
                break;
            case 'events':
                await loadEvents();
                break;
            case 'network':
                await loadNetworkGraph();
                break;
        }
        
        updateConnectionStatus(true);
    } catch (error) {
        console.error('Refresh failed:', error);
        updateConnectionStatus(false);
    }
}

async function loadMetrics() {
    try {
        const response = await fetch('/api/v1/metrics');
        if (!response.ok) {
            throw new Error('Failed to fetch metrics');
        }
        const metrics = await response.json();
        currentData.metrics = metrics;
        updateMetricsDisplay(metrics);
    } catch (error) {
        console.error('Failed to load metrics:', error);
        throw error;
    }
}

async function loadHealth() {
    try {
        const response = await fetch('/api/v1/health');
        if (!response.ok) {
            throw new Error('Failed to fetch health');
        }
        const health = await response.json();
        currentData.health = health;
    } catch (error) {
        console.error('Failed to load health:', error);
        throw error;
    }
}

async function loadActivityFeed() {
    try {
        // Load recent events to simulate activity feed
        const response = await fetch('/api/v1/events?limit=10');
        if (!response.ok) {
            throw new Error('Failed to fetch events');
        }
        const data = await response.json();
        const events = data.events || [];
        
        const feed = document.getElementById('activityFeed');
        if (events.length === 0) {
            feed.innerHTML = '<div class="empty-state"><i>📡</i><h3>No recent activity</h3><p>Events will appear here when they occur.</p></div>';
            return;
        }

        feed.innerHTML = events.map(event => `
            <div class="activity-item">
                <div class="activity-icon create">
                    📡
                </div>
                <div class="activity-content">
                    <div class="activity-title">Event published to "${event.topic}"</div>
                    <div class="activity-time">${formatDate(event.created_at)}</div>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Failed to load activity feed:', error);
        const feed = document.getElementById('activityFeed');
        feed.innerHTML = '<div class="empty-state"><i>❌</i><h3>Failed to load activity</h3><p>Please check your connection and try again.</p></div>';
    }
}

async function loadNodes() {
    try {
        const response = await fetch('/api/v1/registry/nodes');
        if (!response.ok) {
            throw new Error('Failed to fetch nodes');
        }
        const data = await response.json();
        currentData.nodes = data.nodes || [];
        displayNodes(currentData.nodes);
    } catch (error) {
        console.error('Failed to load nodes:', error);
        document.getElementById('nodesListView').innerHTML = 
            '<div class="empty-state"><i>❌</i><h3>Failed to load nodes</h3><p>Please check your connection and try again.</p></div>';
    }
}

async function loadServices() {
    try {
        const response = await fetch('/api/v1/registry/services');
        if (!response.ok) {
            throw new Error('Failed to fetch services');
        }
        const data = await response.json();
        currentData.services = data.services || [];
        displayServices(currentData.services);
    } catch (error) {
        console.error('Failed to load services:', error);
        document.getElementById('servicesListView').innerHTML = 
            '<div class="empty-state"><i>❌</i><h3>Failed to load services</h3><p>Please check your connection and try again.</p></div>';
    }
}

async function loadAuthRules() {
    try {
        const response = await fetch('/api/v1/auth/rules');
        if (!response.ok) {
            throw new Error('Failed to fetch auth rules');
        }
        const data = await response.json();
        console.log('Auth rules API response:', data);
        currentData.authRules = data.rules || [];
        console.log('Auth rules array:', currentData.authRules);
        displayAuthRules(currentData.authRules);
    } catch (error) {
        console.error('Failed to load auth rules:', error);
        document.getElementById('authRulesListView').innerHTML = 
            '<div class="empty-state"><i>❌</i><h3>Failed to load authorization rules</h3><p>Please check your connection and try again.</p></div>';
    }
}

async function loadEvents() {
    try {
        const response = await fetch('/api/v1/events');
        if (!response.ok) {
            throw new Error('Failed to fetch events');
        }
        const data = await response.json();
        currentData.events = data.events || [];
        displayEvents(currentData.events);
    } catch (error) {
        console.error('Failed to load events:', error);
        document.getElementById('eventsListView').innerHTML = 
            '<div class="empty-state"><i>❌</i><h3>Failed to load events</h3><p>Please check your connection and try again.</p></div>';
    }
}

function updateMetricsDisplay(metrics) {
    document.getElementById('totalNodes').textContent = metrics.total_nodes || 0;
    document.getElementById('activeNodes').textContent = metrics.active_nodes || 0;
    document.getElementById('totalServices').textContent = metrics.total_services || 0;
    document.getElementById('activeServices').textContent = metrics.active_services || 0;
    document.getElementById('totalEvents').textContent = metrics.total_events || 0;
}

async function submitForm() {
    const form = document.getElementById('addForm');
    const type = form.dataset.type;
    const formData = new FormData(form);
    
    const data = {};
    for (let [key, value] of formData.entries()) {
        data[key] = value;
    }

    try {
        let endpoint, method = 'POST';
        let payload = {};

        switch (type) {
            case 'node':
                endpoint = '/api/v1/registry/nodes';
                payload = { 
                    node: data,
                    service: {} // Empty service object as required by API
                };
                break;
            case 'service':
                endpoint = '/api/v1/registry/services';
                payload = { 
                    service: data,
                    node: {} // Empty node object as required by API
                };
                break;
            case 'auth-rule':
                endpoint = '/api/v1/auth/rules';
                payload = data;
                break;
        }

        // Get authentication token for protected endpoints
        const token = getAuthToken();
        const headers = {
            'Content-Type': 'application/json'
        };
        
        // Add auth header for protected endpoints (services and auth-rules)
        if ((type === 'service' || type === 'auth-rule') && token) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        const response = await fetch(endpoint, {
            method: method,
            headers: headers,
            body: JSON.stringify(payload)
        });

        if (response.ok) {
            closeModal();
            refreshData();
        } else if (response.status === 401) {
            showToast('Authentication required. Please login first.', 'error');
        } else {
            const error = await response.json().catch(() => ({}));
            showToast(error.error || `Failed to create item (Status: ${response.status})`, 'error');
        }
    } catch (error) {
        showToast('Network error occurred', 'error');
        console.error('Submit error:', error);
    }
}

async function performDelete(type, id) {
    try {
        let endpoint;
        switch (type) {
            case 'node':
                endpoint = `/api/v1/registry/nodes/${id}`;
                break;
            case 'service':
                endpoint = `/api/v1/registry/services/${id}`;
                break;
            case 'auth-rule':
                endpoint = `/api/v1/auth/rules/${id}`;
                break;
        }

        // Get authentication token for protected endpoints
        const token = getAuthToken();
        console.log('Delete operation - Token:', token ? 'Found' : 'Not found');
        const headers = {
            'Content-Type': 'application/json'
        };
        
        // Add auth header for protected endpoints (all delete operations require auth)
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
            console.log('Added Authorization header');
        } else {
            console.log('No token available, skipping Authorization header');
        }

        const response = await fetch(endpoint, { 
            method: 'DELETE',
            headers: headers
        });

        if (response.ok) {
            refreshData();
        } else if (response.status === 401) {
            showToast('Authentication required for this operation', 'error');
            // Don't refresh data since the operation likely failed
        } else {
            const error = await response.json().catch(() => ({}));
            showToast(error.error || `Failed to delete item (Status: ${response.status})`, 'error');
        }
    } catch (error) {
        showToast('Network error occurred', 'error');
        console.error('Delete error:', error);
    }
}
