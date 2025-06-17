// API data loading and management functions for Arrowhead 4.x
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
            case 'systems':
                await loadSystems();
                break;
            case 'services':
                await loadServices();
                break;
            case 'auth-rules':
                await loadAuthRules();
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
        // Load basic registry data to calculate metrics
        const [systemsResp, servicesResp, authsResp] = await Promise.all([
            fetch('/serviceregistry/mgmt/systems'),
            fetch('/serviceregistry/mgmt/services'),
            fetch('/authorization/mgmt/intracloud')
        ]);
        
        let totalSystems = 0, totalServices = 0, totalAuths = 0;
        
        if (systemsResp.ok) {
            const systemsData = await systemsResp.json();
            totalSystems = systemsData.count || 0;
        }
        
        if (servicesResp.ok) {
            const servicesData = await servicesResp.json();
            totalServices = servicesData.count || 0;
        }
        
        if (authsResp.ok) {
            const authsData = await authsResp.json();
            totalAuths = authsData.count || 0;
        }
        
        // Create simplified metrics object
        const metrics = {
            total_systems: totalSystems,
            active_systems: totalSystems, // All registered systems are considered active
            total_services: totalServices,
            active_services: totalServices, // All registered services are considered active
            total_authorizations: totalAuths
        };
        
        currentData.metrics = metrics;
        updateMetricsDisplay(metrics);
    } catch (error) {
        console.error('Failed to load metrics:', error);
        // Create fallback metrics
        const fallbackMetrics = {
            total_systems: 0,
            active_systems: 0,
            total_services: 0,
            active_services: 0,
            total_authorizations: 0
        };
        currentData.metrics = fallbackMetrics;
        updateMetricsDisplay(fallbackMetrics);
        throw error;
    }
}

async function loadHealth() {
    try {
        const response = await fetch('/health');
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
        // Since events are removed, create a simulated activity feed from recent system/service activity
        const systemsResp = await fetch('/serviceregistry/mgmt/systems?sort_field=createdAt&direction=DESC');
        const servicesResp = await fetch('/serviceregistry/mgmt/services?sort_field=createdAt&direction=DESC');
        
        const activities = [];
        
        if (systemsResp.ok) {
            const systemsData = await systemsResp.json();
            const recentSystems = (systemsData.data || []).slice(0, 3);
            recentSystems.forEach(system => {
                activities.push({
                    type: 'system',
                    title: `System "${system.systemName}" registered`,
                    time: system.createdAt,
                    icon: '🖥️'
                });
            });
        }
        
        if (servicesResp.ok) {
            const servicesData = await servicesResp.json();
            const recentServices = (servicesData.data || []).slice(0, 3);
            recentServices.forEach(service => {
                activities.push({
                    type: 'service',
                    title: `Service "${service.serviceDefinition.serviceDefinition}" registered`,
                    time: service.createdAt,
                    icon: '⚙️'
                });
            });
        }
        
        // Sort by time and take most recent 6
        activities.sort((a, b) => new Date(b.time) - new Date(a.time));
        const recentActivities = activities.slice(0, 6);
        
        const feed = document.getElementById('activityFeed');
        if (recentActivities.length === 0) {
            feed.innerHTML = '<div class="empty-state"><i>📡</i><h3>No recent activity</h3><p>System and service registrations will appear here.</p></div>';
            return;
        }

        feed.innerHTML = recentActivities.map(activity => `
            <div class="activity-item">
                <div class="activity-icon create">
                    ${activity.icon}
                </div>
                <div class="activity-content">
                    <div class="activity-title">${activity.title}</div>
                    <div class="activity-time">${formatDate(activity.time)}</div>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Failed to load activity feed:', error);
        const feed = document.getElementById('activityFeed');
        feed.innerHTML = '<div class="empty-state"><i>❌</i><h3>Failed to load activity</h3><p>Please check your connection and try again.</p></div>';
    }
}

async function loadSystems() {
    try {
        const response = await fetch('/serviceregistry/mgmt/systems');
        if (!response.ok) {
            throw new Error('Failed to fetch systems');
        }
        const data = await response.json();
        currentData.systems = data.data || [];
        displaySystems(currentData.systems);
    } catch (error) {
        console.error('Failed to load systems:', error);
        document.getElementById('systemsListView').innerHTML = 
            '<div class="empty-state"><i>❌</i><h3>Failed to load systems</h3><p>Please check your connection and try again.</p></div>';
    }
}

async function loadServices() {
    try {
        const response = await fetch('/serviceregistry/mgmt/services');
        if (!response.ok) {
            throw new Error('Failed to fetch services');
        }
        const data = await response.json();
        currentData.services = data.data || [];
        displayServices(currentData.services);
    } catch (error) {
        console.error('Failed to load services:', error);
        document.getElementById('servicesListView').innerHTML = 
            '<div class="empty-state"><i>❌</i><h3>Failed to load services</h3><p>Please check your connection and try again.</p></div>';
    }
}

async function loadAuthRules() {
    try {
        const response = await fetch('/authorization/mgmt/intracloud');
        if (!response.ok) {
            throw new Error('Failed to fetch auth rules');
        }
        const data = await response.json();
        console.log('Auth rules API response:', data);
        currentData.authRules = data.data || [];
        console.log('Auth rules array:', currentData.authRules);
        displayAuthRules(currentData.authRules);
    } catch (error) {
        console.error('Failed to load auth rules:', error);
        document.getElementById('authRulesListView').innerHTML = 
            '<div class="empty-state"><i>❌</i><h3>Failed to load authorization rules</h3><p>Please check your connection and try again.</p></div>';
    }
}

function updateMetricsDisplay(metrics) {
    document.getElementById('totalNodes').textContent = metrics.total_systems || 0;
    document.getElementById('activeNodes').textContent = metrics.active_systems || 0;
    document.getElementById('totalServices').textContent = metrics.total_services || 0;
    document.getElementById('activeServices').textContent = metrics.active_services || 0;
    // Remove total events as it no longer exists
    const totalEventsElement = document.getElementById('totalEvents');
    if (totalEventsElement) {
        totalEventsElement.textContent = metrics.total_authorizations || 0;
        // Update the label to reflect that this is now authorization rules count
        const eventsLabel = totalEventsElement.parentElement.querySelector('.metric-label');
        if (eventsLabel && eventsLabel.textContent.includes('Events')) {
            eventsLabel.textContent = 'Authorization Rules';
        }
    }
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
            case 'system':
                endpoint = '/serviceregistry/mgmt/systems';
                // Convert to SystemRegistration format
                payload = {
                    systemName: data.name || data.systemName,
                    address: data.address,
                    port: parseInt(data.port),
                    authenticationInfo: data.authenticationInfo || '',
                    metadata: data.metadata ? JSON.parse(data.metadata) : {}
                };
                break;
            case 'service':
                endpoint = '/serviceregistry/mgmt/services';
                // Convert to ServiceRegistrationRequest format
                payload = {
                    serviceDefinition: data.definition || data.serviceDefinition,
                    providerSystem: {
                        systemName: data.providerSystemName || 'temp',
                        address: data.address || '127.0.0.1',
                        port: parseInt(data.port) || 8080,
                        authenticationInfo: '',
                        metadata: {}
                    },
                    serviceUri: data.uri || data.serviceUri,
                    endOfValidity: data.endOfValidity || '',
                    secure: data.secure || 'NOT_SECURE',
                    metadata: data.metadata ? JSON.parse(data.metadata) : {},
                    version: data.version || '1',
                    interfaces: data.interfaces ? data.interfaces.split(',').map(i => i.trim()) : ['HTTP-SECURE-JSON']
                };
                break;
            case 'auth-rule':
                endpoint = '/authorization/mgmt/intracloud';
                // Convert to AddAuthorizationRequest format
                payload = {
                    consumerId: parseInt(data.consumerId),
                    providerIds: [parseInt(data.providerId)],
                    serviceDefinitionIds: [parseInt(data.serviceDefinitionId)],
                    interfaceIds: data.interfaceIds ? data.interfaceIds.split(',').map(id => parseInt(id.trim())) : [1]
                };
                break;
        }

        const headers = {
            'Content-Type': 'application/json'
        };

        const response = await fetch(endpoint, {
            method: method,
            headers: headers,
            body: JSON.stringify(payload)
        });

        if (response.ok) {
            closeModal();
            refreshData();
            showToast(`${type === 'system' ? 'System' : type === 'auth-rule' ? 'Authorization rule' : 'Service'} created successfully`, 'success');
        } else {
            const error = await response.json().catch(() => ({}));
            showToast(error.message || error.error || `Failed to create ${type} (Status: ${response.status})`, 'error');
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
            case 'system':
                endpoint = `/serviceregistry/mgmt/systems/${id}`;
                break;
            case 'service':
                endpoint = `/serviceregistry/mgmt/services/${id}`;
                break;
            case 'auth-rule':
                endpoint = `/authorization/mgmt/intracloud/${id}`;
                break;
        }

        const headers = {
            'Content-Type': 'application/json'
        };

        const response = await fetch(endpoint, { 
            method: 'DELETE',
            headers: headers
        });

        if (response.ok) {
            refreshData();
            showToast(`${type === 'system' ? 'System' : type === 'auth-rule' ? 'Authorization rule' : 'Service'} deleted successfully`, 'success');
        } else {
            const error = await response.json().catch(() => ({}));
            showToast(error.message || error.error || `Failed to delete ${type} (Status: ${response.status})`, 'error');
        }
    } catch (error) {
        showToast('Network error occurred', 'error');
        console.error('Delete error:', error);
    }
}