// View management and display functions
console.log('Views.js loaded');

function showView(viewName) {
    console.log('showView called with:', viewName);
    // Update active nav link
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    document.querySelector(`[data-view="${viewName}"]`).classList.add('active');

    // Hide all views
    document.querySelectorAll('.view').forEach(view => {
        view.classList.add('hidden');
    });

    // Show selected view (convert hyphenated names to camelCase)
    const camelCaseViewName = viewName.replace(/-([a-z])/g, (match, letter) => letter.toUpperCase());
    const targetViewId = camelCaseViewName + 'View';
    console.log('Looking for view with ID:', targetViewId);
    const targetView = document.getElementById(targetViewId);
    console.log('Target view element:', targetView);
    if (targetView) {
        targetView.classList.remove('hidden');
        targetView.classList.add('fade-in');
        console.log('View should now be visible');
    } else {
        console.error('View not found:', targetViewId);
    }

    // Update page title
    const titles = {
        'dashboard': 'Dashboard',
        'nodes': 'Nodes',
        'services': 'Services',
        'auth-rules': 'Authorization Rules',
        'events': 'Events',
        'network': 'Network Graph'
    };
    document.getElementById('pageTitle').textContent = titles[viewName] || viewName;

    currentView = viewName;

    // Load view-specific data
    switch (viewName) {
        case 'nodes':
            loadNodes();
            break;
        case 'services':
            loadServices();
            break;
        case 'auth-rules':
            loadAuthRules();
            break;
        case 'events':
            loadEvents();
            break;
        case 'network':
            loadNetworkGraph();
            break;
    }

    // Hide mobile menu
    document.getElementById('sidebar').classList.remove('show');
}

function switchTab(viewId, tabType) {
    const parent = document.getElementById(viewId);
    
    // Update active tab
    parent.querySelectorAll('.view-tab').forEach(tab => {
        tab.classList.remove('active');
    });
    parent.querySelector(`[data-tab="${tabType}"]`).classList.add('active');

    // Show/hide content
    const listView = parent.querySelector(`[id$="ListView"]`);
    const graphView = parent.querySelector(`[id$="GraphView"]`);

    if (tabType === 'list') {
        listView.classList.remove('hidden');
        graphView.classList.add('hidden');
    } else {
        listView.classList.add('hidden');
        graphView.classList.remove('hidden');
        // Load graph for this view
        const viewType = viewId.replace('View', '').replace('s', ''); // nodes -> node
        loadGraph(viewType);
    }
}

function displayNodes(nodes) {
    const container = document.getElementById('nodesListView');
    
    if (!nodes || nodes.length === 0) {
        container.innerHTML = '<div class="empty-state"><i>🖥️</i><h3>No nodes found</h3><p>Register your first node to get started.</p></div>';
        return;
    }

    const table = `
        <table class="data-table">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Address</th>
                    <th>Port</th>
                    <th>Status</th>
                    <th>Registered</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${nodes.map(node => `
                    <tr>
                        <td>
                            <div class="name-with-id">
                                <strong>${node.name || 'Unknown'}</strong>
                                <small class="text-muted">${node.id}</small>
                            </div>
                        </td>
                        <td>${node.address || 'N/A'}</td>
                        <td>${node.port || 'N/A'}</td>
                        <td><span class="status-badge status-${node.status || 'offline'}">${node.status || 'offline'}</span></td>
                        <td>${formatDate(node.created_at)}</td>
                        <td>
                            <div class="actions">
                                <button class="btn btn-secondary btn-sm" onclick="editItem('node', '${node.id}')">✏️</button>
                                <button class="btn btn-danger btn-sm" onclick="deleteItem('node', '${node.id}', '${node.name}')">🗑️</button>
                            </div>
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
    
    container.innerHTML = table;
}

function displayServices(services) {
    const container = document.getElementById('servicesListView');
    
    if (!services || services.length === 0) {
        container.innerHTML = '<div class="empty-state"><i>⚡</i><h3>No services found</h3><p>Register your first service to get started.</p></div>';
        return;
    }

    const table = `
        <table class="data-table">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Node ID</th>
                    <th>Definition</th>
                    <th>URI</th>
                    <th>Method</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${services.map(service => `
                    <tr>
                        <td>
                            <div class="name-with-id">
                                <strong>${service.name || 'Unknown'}</strong>
                                <small class="text-muted">${service.id}</small>
                            </div>
                        </td>
                        <td>${service.node_id || 'N/A'}</td>
                        <td>${service.definition || 'N/A'}</td>
                        <td><code>${service.uri || 'N/A'}</code></td>
                        <td><span class="status-badge">${service.method || 'GET'}</span></td>
                        <td><span class="status-badge status-${service.status || 'inactive'}">${service.status || 'inactive'}</span></td>
                        <td>
                            <div class="actions">
                                <button class="btn btn-secondary btn-sm" onclick="editItem('service', '${service.id}')">✏️</button>
                                <button class="btn btn-danger btn-sm" onclick="deleteItem('service', '${service.id}', '${service.name}')">🗑️</button>
                            </div>
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
    
    container.innerHTML = table;
}

function displayAuthRules(rules) {
    console.log('displayAuthRules called with:', rules);
    const container = document.getElementById('authRulesListView');
    
    if (!rules || rules.length === 0) {
        console.log('No rules to display');
        container.innerHTML = '<div class="empty-state"><i>🔐</i><h3>No authorization rules found</h3><p>Create your first authorization rule to control access.</p></div>';
        return;
    }

    const table = `
        <table class="data-table">
            <thead>
                <tr>
                    <th>Consumer</th>
                    <th>Provider</th>
                    <th>Service</th>
                    <th>Created</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${rules.map(rule => `
                    <tr>
                        <td>
                            <div class="name-with-id">
                                <strong>${rule.consumer_name || 'Unknown'}</strong>
                                <small class="text-muted">${rule.consumer_id}</small>
                            </div>
                        </td>
                        <td>
                            <div class="name-with-id">
                                <strong>${rule.provider_name || 'Unknown'}</strong>
                                <small class="text-muted">${rule.provider_id}</small>
                            </div>
                        </td>
                        <td>
                            <div class="name-with-id">
                                <strong>${rule.service_name || 'Unknown'}</strong>
                                <small class="text-muted">${rule.service_id}</small>
                            </div>
                        </td>
                        <td>${formatDate(rule.created_at)}</td>
                        <td>
                            <div class="actions">
                                <button class="btn btn-danger btn-sm" onclick="deleteItem('auth-rule', '${rule.id}', 'authorization rule')">🗑️</button>
                            </div>
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
    
    console.log('Setting container innerHTML with table:', table.length, 'characters');
    console.log('Container element:', container);
    container.innerHTML = table;
    console.log('Container innerHTML after setting:', container.innerHTML.length, 'characters');
}

function displayEvents(events) {
    const container = document.getElementById('eventsListView');
    
    if (!events || events.length === 0) {
        container.innerHTML = '<div class="empty-state"><i>📡</i><h3>No events found</h3><p>Events will appear here when published or subscribed to.</p></div>';
        return;
    }

    const table = `
        <table class="data-table">
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Topic</th>
                    <th>Publisher ID</th>
                    <th>Timestamp</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${events.map(event => `
                    <tr>
                        <td><span class="status-badge">${event.type || 'unknown'}</span></td>
                        <td><strong>${event.topic || 'N/A'}</strong></td>
                        <td>${event.publisher_id || 'Node'}</td>
                        <td>${formatDate(event.created_at)}</td>
                        <td>
                            <div class="actions">
                                <button class="btn btn-secondary btn-sm" onclick="viewEventDetails('${event.id}')">👁️</button>
                            </div>
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
    
    container.innerHTML = table;
}

function filterData(view, searchTerm, filterValue) {
    // Implement filtering logic for each view
    const dataKey = view === 'authRules' ? 'authRules' : view;
    let data = currentData[dataKey] || [];

    if (searchTerm) {
        data = data.filter(item => 
            Object.values(item).some(value => 
                String(value).toLowerCase().includes(searchTerm.toLowerCase())
            )
        );
    }

    if (filterValue) {
        if (filterValue === 'active' || filterValue === 'inactive') {
            data = data.filter(item => item.status === filterValue);
        } else if (filterValue === 'online' || filterValue === 'offline') {
            data = data.filter(item => item.status === filterValue);
        }
    }

    // Update display
    switch (view) {
        case 'nodes':
            displayNodes(data);
            break;
        case 'services':
            displayServices(data);
            break;
        case 'authRules':
            displayAuthRules(data);
            break;
        case 'events':
            displayEvents(data);
            break;
    }
}

function showAddModal(type) {
    const modal = document.getElementById('addModal');
    const title = document.getElementById('modalTitle');
    const fields = document.getElementById('formFields');

    title.textContent = `Add ${type.charAt(0).toUpperCase() + type.slice(1).replace('-', ' ')}`;
    
    let fieldsHtml = '';
    switch (type) {
        case 'node':
            fieldsHtml = `
                <div class="form-group">
                    <label class="form-label">Node Name *</label>
                    <input type="text" class="form-input" name="name" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Address *</label>
                    <input type="text" class="form-input" name="address" value="localhost" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Port *</label>
                    <input type="number" class="form-input" name="port" min="1" max="65535" required>
                </div>
            `;
            break;
        case 'service':
            fieldsHtml = `
                <div class="form-group">
                    <label class="form-label">Service Name *</label>
                    <input type="text" class="form-input" name="name" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Node *</label>
                    <select class="form-input" name="node_id" required>
                        <option value="">Select a node</option>
                        ${currentData.nodes.map(node => 
                            `<option value="${node.id}">${node.name}</option>`
                        ).join('')}
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Definition *</label>
                    <input type="text" class="form-input" name="definition" required>
                </div>
                <div class="form-group">
                    <label class="form-label">URI *</label>
                    <input type="text" class="form-input" name="uri" placeholder="/api/endpoint" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Method</label>
                    <select class="form-input" name="method">
                        <option value="GET">GET</option>
                        <option value="POST">POST</option>
                        <option value="PUT">PUT</option>
                        <option value="DELETE">DELETE</option>
                    </select>
                </div>
            `;
            break;
        case 'auth-rule':
            fieldsHtml = `
                <div class="form-group">
                    <label class="form-label">Consumer Node *</label>
                    <select class="form-input" name="consumer_id" required>
                        <option value="">Select consumer</option>
                        ${currentData.nodes.map(node => 
                            `<option value="${node.id}">${node.name}</option>`
                        ).join('')}
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Provider Node *</label>
                    <select class="form-input" name="provider_id" required>
                        <option value="">Select provider</option>
                        ${currentData.nodes.map(node => 
                            `<option value="${node.id}">${node.name}</option>`
                        ).join('')}
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Service</label>
                    <select class="form-input" name="service_id">
                        <option value="">Any service</option>
                        ${currentData.services.map(service => 
                            `<option value="${service.id}">${service.name}</option>`
                        ).join('')}
                    </select>
                </div>
            `;
            break;
    }

    fields.innerHTML = fieldsHtml;
    document.getElementById('addForm').dataset.type = type;
    modal.style.display = 'block';
}

function closeModal() {
    document.getElementById('addModal').style.display = 'none';
    document.getElementById('addForm').reset();
}

function deleteItem(type, id, name) {
    const modal = document.getElementById('confirmModal');
    const message = document.getElementById('confirmMessage');
    const confirmBtn = document.getElementById('confirmButton');

    message.innerHTML = `<p>Are you sure you want to delete the ${type} "<strong>${name}</strong>"?</p><p>This action cannot be undone.</p>`;
    
    confirmBtn.onclick = function() {
        performDelete(type, id);
        closeConfirmModal();
    };

    modal.style.display = 'block';
}

function closeConfirmModal() {
    document.getElementById('confirmModal').style.display = 'none';
}

function editItem(type, id) {
    // For now, show a message that editing is not implemented
    console.log('Edit functionality coming soon for', type, id);
}

function viewEventDetails(id) {
    console.log('Event details view coming soon for event', id);
}

function exportGraph() {
    const canvas = document.querySelector('#networkGraph canvas');
    if (canvas) {
        const link = document.createElement('a');
        link.download = 'arrowhead-service-mesh.png';
        link.href = canvas.toDataURL('image/png');
        link.click();
        console.log('Service mesh graph exported successfully');
    } else {
        console.log('No graph to export - canvas not found');
    }
}
