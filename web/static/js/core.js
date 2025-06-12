// Core application initialization and state management
console.log('Core.js loaded');

// Global state  
let currentView = 'dashboard';
let currentData = {
    nodes: [],
    services: [],
    authRules: [],
    events: [],
    subscriptions: [],
    metrics: {},
    health: {}
};

// Initialize app
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    setupEventListeners();
    loadInitialData();
});

function initializeApp() {
    // Mobile menu toggle
    document.getElementById('menuToggle').addEventListener('click', function() {
        const sidebar = document.getElementById('sidebar');
        sidebar.classList.toggle('show');
    });

    // Navigation links
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const view = this.dataset.view;
            if (view) {
                showView(view);
            }
        });
    });

    // View tabs
    document.querySelectorAll('.view-tab').forEach(tab => {
        tab.addEventListener('click', function() {
            const parent = this.closest('.view-controls');
            const viewId = parent.closest('.view').id;
            const tabType = this.dataset.tab;
            switchTab(viewId, tabType);
        });
    });

    // Search inputs
    setupSearchFilters();
}

function setupEventListeners() {
    // Auto refresh every 30 seconds
    setInterval(refreshData, 30000);

    // Form submission
    document.getElementById('addForm').addEventListener('submit', function(e) {
        e.preventDefault();
        const type = this.dataset.type;
        console.log('Form submitted with type:', type);
        if (type === 'login') {
            console.log('Calling handleLogin');
            handleLogin(new FormData(this));
        } else {
            console.log('Calling submitForm');
            submitForm();
        }
    });

    // Check authentication status on load
    checkAuthStatus();
}

function setupSearchFilters() {
    const searchInputs = ['nodesSearch', 'servicesSearch', 'authRulesSearch', 'eventsSearch'];
    const filterSelects = ['nodesFilter', 'servicesFilter', 'eventsFilter', 'networkFilter'];

    searchInputs.forEach(id => {
        const input = document.getElementById(id);
        if (input) {
            input.addEventListener('input', function() {
                const view = id.replace('Search', '');
                filterData(view, this.value, null);
            });
        }
    });

    filterSelects.forEach(id => {
        const select = document.getElementById(id);
        if (select) {
            select.addEventListener('change', function() {
                const view = id.replace('Filter', '');
                if (view === 'network') {
                    updateNetworkGraph();
                } else {
                    filterData(view, null, this.value);
                }
            });
        }
    });
}

function updateConnectionStatus(connected) {
    const status = document.getElementById('connectionStatus');
    if (connected) {
        status.textContent = 'Connected';
        status.className = 'status-badge status-healthy';
    } else {
        status.textContent = 'Disconnected';
        status.className = 'status-badge status-inactive';
    }
}

function formatDate(dateString) {
    if (!dateString) return 'N/A';
    try {
        return new Date(dateString).toLocaleString();
    } catch {
        return 'N/A';
    }
}

function showToast(message, type = 'success') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.remove();
    }, 3000);
}

// Close modals when clicking outside
window.onclick = function(event) {
    const addModal = document.getElementById('addModal');
    const confirmModal = document.getElementById('confirmModal');
    
    if (event.target === addModal) {
        closeModal();
    }
    if (event.target === confirmModal) {
        closeConfirmModal();
    }
}
