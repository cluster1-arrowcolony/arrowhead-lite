// Authentication functionality
console.log('Auth.js loaded');

// Handle login form submission
async function handleLogin(formData) {
    try {
        const username = formData.get('username');
        const password = formData.get('password');
        
        const response = await fetch('/api/v1/auth/admin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: username,
                password: password
            })
        });

        if (response.ok) {
            const data = await response.json();
            console.log('Admin login successful, storing token');
            setAuthToken(data.access_token);
            console.log('Token stored, verifying:', getAuthToken() ? 'Success' : 'Failed');
            updateLoginState(true, data.admin_user);
            closeModal();
        } else if (response.status === 401) {
            showToast('Invalid admin credentials', 'error');
        } else {
            const error = await response.json().catch(() => ({}));
            showToast(error.error || 'Login failed', 'error');
        }
    } catch (error) {
        showToast('Network error during login', 'error');
        console.error('Login error:', error);
    }
}

function updateLoginState(isLoggedIn, nodeName = '') {
    const headerActions = document.querySelector('.header-actions');
    
    if (isLoggedIn) {
        // Add logout button and user info
        const existingLoginBtn = document.getElementById('loginBtn');
        if (existingLoginBtn) {
            existingLoginBtn.remove();
        }
        
        const userInfo = document.createElement('div');
        userInfo.innerHTML = `
            <span style="margin-right: 10px; color: var(--text-secondary);">Mode: ${nodeName}</span>
            <button class="btn btn-secondary btn-sm" onclick="logout()">Exit</button>
        `;
        headerActions.insertBefore(userInfo, headerActions.firstChild);
    } else {
        // Add test mode button
        const existingUserInfo = headerActions.querySelector('div');
        if (existingUserInfo && existingUserInfo.innerHTML.includes('Mode:')) {
            existingUserInfo.remove();
        }
        
        const loginBtn = document.createElement('button');
        loginBtn.id = 'loginBtn';
        loginBtn.className = 'btn btn-primary btn-sm';
        loginBtn.textContent = 'Login';
        loginBtn.onclick = showLoginModal;
        headerActions.insertBefore(loginBtn, headerActions.firstChild);
    }
}

function logout() {
    clearAuthToken();
    updateLoginState(false);
}

// Check for existing token on page load
function checkAuthStatus() {
    const token = getAuthToken();
    if (token) {
        // TODO: Validate token or extract node name from token
        updateLoginState(true, 'Authenticated');
    } else {
        updateLoginState(false);
    }
}

function setAuthToken(token) {
    // Store token in sessionStorage for this session
    sessionStorage.setItem('auth_token', token);
}

function clearAuthToken() {
    sessionStorage.removeItem('auth_token');
    localStorage.removeItem('auth_token');
}

function getAuthToken() {
    // Return the stored token from sessionStorage
    return sessionStorage.getItem('auth_token');
}

function showLoginModal() {
    console.log('showLoginModal called');
    const modal = document.getElementById('addModal');
    const title = document.getElementById('modalTitle');
    const fields = document.getElementById('formFields');

    title.textContent = 'Login';
    
    fields.innerHTML = `
        <div class="form-group">
            <label class="form-label">Username *</label>
            <input type="text" class="form-input" name="username" value="admin" required>
        </div>
        <div class="form-group">
            <label class="form-label">Password (optional)</label>
            <input type="password" class="form-input" name="password" placeholder="Leave blank for demo">
        </div>
    `;

    document.getElementById('addForm').dataset.type = 'login';
    console.log('Login modal setup complete, showing modal');
    modal.style.display = 'block';
}
