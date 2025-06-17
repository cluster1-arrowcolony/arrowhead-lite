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
        'systems': 'Systems',
        'services': 'Services',
        'auth-rules': 'Authorization Rules',
        'network': 'Network Graph'
    };
    document.getElementById('pageTitle').textContent = titles[viewName] || viewName;

    currentView = viewName;

    // Load view-specific data
    switch (viewName) {
        case 'systems':
            loadSystems();
            break;
        case 'services':
            loadServices();
            break;
        case 'auth-rules':
            loadAuthRules();
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
        const viewType = viewId.replace('View', '').replace('s', ''); // systems -> system
        loadGraph(viewType);
    }
}

function displaySystems(systems) {
    const container = document.getElementById('systemsListView');
    
    if (!systems || systems.length === 0) {
        container.innerHTML = '<div class="empty-state"><i>🖥️</i><h3>No systems found</h3><p>Register your first system to get started.</p></div>';
        return;
    }

    const table = `
        <table class="data-table">
            <thead>
                <tr>
                    <th>System Name</th>
                    <th>Address</th>
                    <th>Port</th>
                    <th>Status</th>
                    <th>Registered</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${systems.map(system => `
                    <tr>
                        <td>
                            <div class="name-with-id">
                                <strong>${system.systemName || 'Unknown'}</strong>
                                <small class="text-muted">ID: ${system.id}</small>
                            </div>
                        </td>
                        <td>${system.address || 'N/A'}</td>
                        <td>${system.port || 'N/A'}</td>
                        <td><span class="status-badge status-active">active</span></td>
                        <td>${formatDate(system.createdAt)}</td>
                        <td>
                            <div class="actions">
                                <button class="btn btn-secondary btn-sm" onclick="editItem('system', '${system.id}')">✏️</button>
                                <button class="btn btn-danger btn-sm" onclick="deleteItem('system', '${system.id}', '${system.systemName}')">🗑️</button>
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
                    <th>Service Definition</th>
                    <th>Provider System</th>
                    <th>URI</th>
                    <th>Interfaces</th>
                    <th>Security</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${services.map(service => `
                    <tr>
                        <td>
                            <div class="name-with-id">
                                <strong>${service.serviceDefinition?.serviceDefinition || 'Unknown'}</strong>
                                <small class="text-muted">ID: ${service.id}</small>
                            </div>
                        </td>
                        <td>
                            <div class="name-with-id">
                                <strong>${service.provider?.systemName || 'Unknown'}</strong>
                                <small class="text-muted">${service.provider?.address}:${service.provider?.port}</small>
                            </div>
                        </td>
                        <td><code>${service.serviceUri || 'N/A'}</code></td>
                        <td>
                            ${service.interfaces?.map(iface => 
                                `<span class="status-badge">${iface.interfaceName}</span>`
                            ).join(' ') || 'N/A'}
                        </td>
                        <td><span class="status-badge">${service.secure || 'NOT_SECURE'}</span></td>
                        <td><span class="status-badge status-active">active</span></td>
                        <td>
                            <div class="actions">
                                <button class="btn btn-secondary btn-sm" onclick="editItem('service', '${service.id}')">✏️</button>
                                <button class="btn btn-danger btn-sm" onclick="deleteItem('service', '${service.id}', '${service.serviceDefinition?.serviceDefinition}')">🗑️</button>
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
                    <th>Consumer System</th>
                    <th>Provider System</th>
                    <th>Service Definition</th>
                    <th>Interfaces</th>
                    <th>Created</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${rules.map(rule => `
                    <tr>
                        <td>
                            <div class="name-with-id">
                                <strong>${rule.consumerSystem?.systemName || 'Unknown'}</strong>
                                <small class="text-muted">ID: ${rule.consumerSystem?.id}</small>
                            </div>
                        </td>
                        <td>
                            <div class="name-with-id">
                                <strong>${rule.providerSystem?.systemName || 'Unknown'}</strong>
                                <small class="text-muted">ID: ${rule.providerSystem?.id}</small>
                            </div>
                        </td>
                        <td>
                            <div class="name-with-id">
                                <strong>${rule.serviceDefinition?.serviceDefinition || 'Unknown'}</strong>
                                <small class="text-muted">ID: ${rule.serviceDefinition?.id}</small>
                            </div>
                        </td>
                        <td>
                            ${rule.interfaces?.map(iface => 
                                `<span class="status-badge">${iface.interfaceName}</span>`
                            ).join(' ') || 'N/A'}
                        </td>
                        <td>${formatDate(rule.createdAt)}</td>
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
        case 'systems':
            displaySystems(data);
            break;
        case 'services':
            displayServices(data);
            break;
        case 'authRules':
            displayAuthRules(data);
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
        case 'system':
            fieldsHtml = `
                <div class="form-group">
                    <label class="form-label">System Name *</label>
                    <input type="text" class="form-input" name="systemName" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Address *</label>
                    <input type="text" class="form-input" name="address" value="localhost" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Port *</label>
                    <input type="number" class="form-input" name="port" min="1" max="65535" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Authentication Info</label>
                    <input type="text" class="form-input" name="authenticationInfo" placeholder="Optional">
                </div>
            `;
            break;
        case 'service':
            fieldsHtml = `
                <div class="form-group">
                    <label class="form-label">Service Definition *</label>
                    <input type="text" class="form-input" name="serviceDefinition" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Provider System Name *</label>
                    <input type="text" class="form-input" name="providerSystemName" placeholder="System that provides this service" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Service URI *</label>
                    <input type="text" class="form-input" name="serviceUri" placeholder="/api/endpoint" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Security Level</label>
                    <select class="form-input" name="secure">
                        <option value="NOT_SECURE">Not Secure</option>
                        <option value="CERTIFICATE">Certificate</option>
                        <option value="TOKEN">Token</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Interfaces</label>
                    <input type="text" class="form-input" name="interfaces" value="HTTP-SECURE-JSON" placeholder="Comma-separated list">
                </div>
                <div class="form-group">
                    <label class="form-label">Version</label>
                    <input type="text" class="form-input" name="version" value="1">
                </div>
            `;
            break;
        case 'auth-rule':
            fieldsHtml = `
                <div class="form-group">
                    <label class="form-label">Consumer System *</label>
                    <select class="form-input" name="consumerId" required>
                        <option value="">Select consumer system</option>
                        ${(currentData.systems || []).map(system => 
                            `<option value="${system.id}">${system.systemName}</option>`
                        ).join('')}
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Provider System *</label>
                    <select class="form-input" name="providerId" required>
                        <option value="">Select provider system</option>
                        ${(currentData.systems || []).map(system => 
                            `<option value="${system.id}">${system.systemName}</option>`
                        ).join('')}
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Service Definition ID *</label>
                    <input type="number" class="form-input" name="serviceDefinitionId" placeholder="Service Definition ID" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Interface IDs</label>
                    <input type="text" class="form-input" name="interfaceIds" value="1" placeholder="Comma-separated list of interface IDs">
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
