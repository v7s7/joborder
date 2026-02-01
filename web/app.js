// =============================================================================
// AUTH STATE MANAGEMENT
// =============================================================================

let currentUser = null;

// DOM Elements
const loginModal = document.getElementById('loginModal');
const loginForm = document.getElementById('loginForm');
const loginError = document.getElementById('loginError');
const loginBtn = document.getElementById('loginBtn');
const loginTrigger = document.getElementById('loginTrigger');
const logoutBtn = document.getElementById('logoutBtn');
const userInfo = document.getElementById('userInfo');
const userName = document.getElementById('userName');
const userAvatar = document.getElementById('userAvatar');
const jobForm = document.getElementById('jobForm');

// =============================================================================
// AUTH FUNCTIONS
// =============================================================================

/**
 * Check current auth status on page load
 */
async function checkAuth() {
    try {
        const response = await fetch('/auth/me', {
            method: 'GET',
            credentials: 'include'
        });

        if (response.ok) {
            const data = await response.json();
            setLoggedIn(data.user);
        } else {
            setLoggedOut();
            showLoginModal();
        }
    } catch (error) {
        console.error('Auth check failed:', error);
        setLoggedOut();
        showLoginModal();
    }
}

/**
 * Handle login form submission
 */
async function handleLogin(e) {
    e.preventDefault();

    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;

    if (!username || !password) {
        showLoginError('Please enter both username and password');
        return;
    }

    // Set loading state
    loginBtn.disabled = true;
    loginBtn.classList.add('btn-loading');
    hideLoginError();

    try {
        const response = await fetch('/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include',
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok && data.ok) {
            setLoggedIn(data.user);
            hideLoginModal();
            loginForm.reset();
        } else if (response.status === 401) {
            showLoginError('Invalid username or password');
        } else if (response.status === 400) {
            showLoginError(data.error || 'Please provide valid credentials');
        } else {
            showLoginError(data.error || 'Login failed. Please try again.');
        }
    } catch (error) {
        console.error('Login error:', error);
        showLoginError('Unable to connect to server. Please try again.');
    } finally {
        loginBtn.disabled = false;
        loginBtn.classList.remove('btn-loading');
    }
}

/**
 * Handle logout
 */
async function handleLogout() {
    try {
        await fetch('/auth/logout', {
            method: 'POST',
            credentials: 'include'
        });
    } catch (error) {
        console.error('Logout error:', error);
    }

    setLoggedOut();
    showLoginModal();
}

/**
 * Update UI for logged in state
 */
function setLoggedIn(user) {
    currentUser = user;

    // Update user display
    userName.textContent = user.name || user.username;
    userAvatar.textContent = (user.name || user.username).charAt(0).toUpperCase();

    // Show/hide elements
    userInfo.style.display = 'flex';
    loginTrigger.style.display = 'none';

    // Show admin link only for admins
    const adminLink = document.getElementById('adminLink');
    if (adminLink) {
        adminLink.style.display = user.isAdmin ? 'inline-block' : 'none';
    }

    // Enable form
    jobForm.classList.remove('form-disabled');

    // Load signatures for dropdowns
    loadSignatures();
}

/**
 * Update UI for logged out state
 */
function setLoggedOut() {
    currentUser = null;

    // Show/hide elements
    userInfo.style.display = 'none';
    loginTrigger.style.display = 'block';

    // Hide admin link
    const adminLink = document.getElementById('adminLink');
    if (adminLink) adminLink.style.display = 'none';

    // Disable form
    jobForm.classList.add('form-disabled');
}

/**
 * Show login modal
 */
function showLoginModal() {
    loginModal.classList.add('active');
    document.getElementById('loginUsername').focus();
}

/**
 * Hide login modal
 */
function hideLoginModal() {
    loginModal.classList.remove('active');
    hideLoginError();
}

/**
 * Show login error message
 */
function showLoginError(message) {
    loginError.textContent = message;
    loginError.style.display = 'block';
}

/**
 * Hide login error message
 */
function hideLoginError() {
    loginError.style.display = 'none';
}

// =============================================================================
// SIGNATURE FUNCTIONS
// =============================================================================

let signaturesData = [];

/**
 * Load available signatures for dropdowns
 */
async function loadSignatures() {
    try {
        const response = await fetch('/api/signatures', {
            credentials: 'include'
        });

        if (!response.ok) return;

        const data = await response.json();
        signaturesData = data.signatures || [];

        // Populate both dropdowns
        const adminSelect = document.getElementById('admin_signature');
        const staffSelect = document.getElementById('staff_signature');

        if (adminSelect && staffSelect) {
            const optionsHtml = signaturesData.map(sig =>
                `<option value="${sig.userId}" data-url="${sig.signatureUrl}">${sig.name}</option>`
            ).join('');

            adminSelect.innerHTML = '<option value="">-- Select Signature --</option>' + optionsHtml;
            staffSelect.innerHTML = '<option value="">-- Select Signature --</option>' + optionsHtml;

            // Add change listeners for preview
            adminSelect.addEventListener('change', () => updateSignaturePreview('admin'));
            staffSelect.addEventListener('change', () => updateSignaturePreview('staff'));
        }
    } catch (error) {
        console.error('Error loading signatures:', error);
    }
}

/**
 * Update signature preview when selection changes
 */
function updateSignaturePreview(type) {
    const select = document.getElementById(`${type}_signature`);
    const preview = document.getElementById(`${type}SigPreview`);

    if (!select || !preview) return;

    const selectedOption = select.options[select.selectedIndex];
    const url = selectedOption?.dataset?.url;

    if (url) {
        preview.innerHTML = `<img src="${url}" alt="Signature preview">`;
    } else {
        preview.innerHTML = '';
    }
}

// =============================================================================
// JOB ORDER FUNCTIONS (Original)
// =============================================================================

async function fetchJobNumber() {
    try {
        const response = await fetch('/api/get-job-no', {
            credentials: 'include'
        });
        const data = await response.json();
        document.getElementById('job-number-display').textContent = data.job_no;
    } catch (error) {
        console.error('Error fetching job number:', error);
    }
}

async function handleGenerate(e) {
    e.preventDefault();

    // Check if logged in
    if (!currentUser) {
        showLoginModal();
        return;
    }

    const btn = document.getElementById('submitBtn');
    const statusText = document.getElementById('status-text');
    const statusIndicator = document.getElementById('status-indicator');

    // Set busy state
    btn.disabled = true;
    btn.textContent = "Processing...";
    statusText.textContent = "GENERATING PDF...";
    statusIndicator.className = "status-indicator processing";

    // Gather data
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData.entries());

    try {
        const response = await fetch('/api/generate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify(data),
        });

        // Check if unauthorized
        if (response.status === 401) {
            setLoggedOut();
            showLoginModal();
            return;
        }

        const result = await response.json();

        if (result.success) {
            alert('Success! Report Generated.\n' + result.file);
            // Refresh job number for next one
            fetchJobNumber();
        } else {
            alert('Error: ' + result.error);
        }

    } catch (error) {
        alert('System Error: ' + error);
    } finally {
        // Reset state
        btn.disabled = false;
        btn.textContent = "Generate PDF Report";
        statusText.textContent = "READY";
        statusIndicator.className = "status-indicator ready";
    }
}

function resetForm() {
    document.getElementById('jobForm').reset();
    const today = new Date().toISOString().split('T')[0];
    document.getElementById('main_date').value = today;
    document.getElementById('start_date').value = today;
    document.getElementById('end_date').value = today;

    // Clear signature previews
    const adminPreview = document.getElementById('adminSigPreview');
    const staffPreview = document.getElementById('staffSigPreview');
    if (adminPreview) adminPreview.innerHTML = '';
    if (staffPreview) staffPreview.innerHTML = '';
}

function clearDuration() {
    const radios = document.querySelectorAll('.duration-section input[type="radio"]');
    radios.forEach(radio => radio.checked = false);
}

// =============================================================================
// INITIALIZATION
// =============================================================================

document.addEventListener('DOMContentLoaded', () => {
    // Set default dates
    const today = new Date().toISOString().split('T')[0];
    document.getElementById('main_date').value = today;
    document.getElementById('start_date').value = today;
    document.getElementById('end_date').value = today;

    // Set current date in header
    const options = { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute:'2-digit' };
    document.getElementById('current-date').textContent = new Date().toLocaleDateString('en-US', options);

    // Fetch next job number
    fetchJobNumber();

    // Handle form submission
    document.getElementById('jobForm').addEventListener('submit', handleGenerate);

    // Auth event listeners
    loginForm.addEventListener('submit', handleLogin);
    logoutBtn.addEventListener('click', handleLogout);
    loginTrigger.addEventListener('click', showLoginModal);

    // Close modal on backdrop click
    loginModal.addEventListener('click', (e) => {
        if (e.target === loginModal && currentUser) {
            hideLoginModal();
        }
    });

    // Check auth status
    checkAuth();
});
