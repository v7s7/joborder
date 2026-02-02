// =============================================================================
// JOB ORDER FORM - MAIN APPLICATION SCRIPT
// =============================================================================

// State
let currentUser = null;
let jobNo = null;
let signatures = [];

// DOM Elements
const loginModal = document.getElementById('loginModal');
const loginForm = document.getElementById('loginForm');
const loginError = document.getElementById('loginError');
const loginBtn = document.getElementById('loginBtn');
const logoutBtn = document.getElementById('logoutBtn');
const successModal = document.getElementById('successModal');
const jobForm = document.getElementById('jobForm');

// =============================================================================
// INITIALIZATION
// =============================================================================

document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
});

async function initializeApp() {
    // Set current date
    updateCurrentDate();
    setDefaultDate();

    // Check authentication
    await checkAuth();

    // Setup event listeners
    setupEventListeners();
}

function updateCurrentDate() {
    const now = new Date();
    const dateDisplay = document.getElementById('currentDate');
    if (dateDisplay) {
        dateDisplay.textContent = now.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric',
            year: 'numeric'
        });
    }
}

function setDefaultDate() {
    const today = new Date().toISOString().split('T')[0];
    const mainDateInput = document.getElementById('main_date');
    const startDateInput = document.getElementById('start_date');
    const endDateInput = document.getElementById('end_date');

    if (mainDateInput && !mainDateInput.value) {
        mainDateInput.value = today;
    }
    if (startDateInput && !startDateInput.value) {
        startDateInput.value = today;
    }
    if (endDateInput && !endDateInput.value) {
        endDateInput.value = today;
    }
}

function setupEventListeners() {
    // Login form
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }

    // Logout button
    if (logoutBtn) {
        logoutBtn.addEventListener('click', handleLogout);
    }

    // Job form
    if (jobForm) {
        jobForm.addEventListener('submit', handleSubmit);
    }

    // Success modal
    const closeSuccessModal = document.getElementById('closeSuccessModal');
    const createAnotherBtn = document.getElementById('createAnotherBtn');

    if (closeSuccessModal) {
        closeSuccessModal.addEventListener('click', () => {
            successModal.classList.remove('active');
        });
    }

    if (createAnotherBtn) {
        createAnotherBtn.addEventListener('click', () => {
            successModal.classList.remove('active');
            resetForm();
            loadJobNumber();
        });
    }

    // Signature dropdowns
    const adminSigSelect = document.getElementById('admin_signature');
    const staffSigSelect = document.getElementById('staff_signature');

    if (adminSigSelect) {
        adminSigSelect.addEventListener('change', () => updateSignaturePreview('admin'));
    }

    if (staffSigSelect) {
        staffSigSelect.addEventListener('change', () => updateSignaturePreview('staff'));
    }
}

// =============================================================================
// AUTHENTICATION
// =============================================================================

async function checkAuth() {
    try {
        const response = await fetch('/auth/me', { credentials: 'include' });
        if (response.ok) {
            const data = await response.json();
            setLoggedIn(data.user);
        } else {
            showLoginModal();
        }
    } catch (error) {
        console.error('Auth check failed:', error);
        showLoginModal();
    }
}

async function handleLogin(e) {
    e.preventDefault();

    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;

    if (!username || !password) {
        showLoginError('Please enter both username and password');
        return;
    }

    loginBtn.disabled = true;
    loginBtn.classList.add('btn-loading');
    hideLoginError();

    try {
        const response = await fetch('/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok && data.ok) {
            setLoggedIn(data.user);
            hideLoginModal();
            loginForm.reset();
            showToast('Welcome back!', 'success');
        } else {
            showLoginError(data.error || 'Invalid credentials');
        }
    } catch (error) {
        showLoginError('Unable to connect to server');
    } finally {
        loginBtn.disabled = false;
        loginBtn.classList.remove('btn-loading');
    }
}

async function handleLogout() {
    try {
        await fetch('/auth/logout', { method: 'POST', credentials: 'include' });
    } catch (error) {
        console.error('Logout error:', error);
    }
    currentUser = null;
    showLoginModal();
}

function setLoggedIn(user) {
    currentUser = user;
    hideLoginModal();

    // Update sidebar user info
    const sidebarAvatar = document.getElementById('sidebarAvatar');
    const sidebarUserName = document.getElementById('sidebarUserName');
    const sidebarUserRole = document.getElementById('sidebarUserRole');

    if (sidebarAvatar) {
        sidebarAvatar.textContent = (user.name || user.username).charAt(0).toUpperCase();
    }
    if (sidebarUserName) {
        sidebarUserName.textContent = user.name || user.username;
    }
    if (sidebarUserRole) {
        // Show appropriate role label
        const roleLabel = user.isAdmin ? 'Administrator' : user.isLeader ? 'Leader' : 'Staff';
        sidebarUserRole.textContent = roleLabel;
    }

    // Show admin section if applicable (admins only)
    const adminSection = document.getElementById('adminSection');
    if (adminSection && user.isAdmin) {
        adminSection.style.display = 'block';
        loadPendingCount();
    }

    const isStaffOnly = !user.isAdmin && !user.isLeader;

    const reportsNav = document.getElementById('reportsNav');
    if (reportsNav && isStaffOnly) {
        reportsNav.style.display = 'none';
    }

    const newJobOrderNav = document.getElementById('newJobOrderNav');
    if (newJobOrderNav && isStaffOnly) {
        newJobOrderNav.style.display = 'none';
    }

    const navApprovalLabel = document.getElementById('navApprovalLabel');
    if (navApprovalLabel && isStaffOnly) {
        navApprovalLabel.textContent = 'My Signature Requests';
    }

    const staffNotice = document.getElementById('staffNotice');
    if (staffNotice) {
        staffNotice.style.display = isStaffOnly ? 'flex' : 'none';
    }

    if (jobForm) {
        jobForm.style.display = isStaffOnly ? 'none' : '';
    }

    if (!isStaffOnly) {
        loadJobNumber();
        loadSignatures();
    }

    loadApprovalsBadgeCount();
}

function showLoginModal() {
    if (loginModal) {
        loginModal.classList.add('active');
        const usernameInput = document.getElementById('loginUsername');
        if (usernameInput) {
            usernameInput.focus();
        }
    }
}

function hideLoginModal() {
    if (loginModal) {
        loginModal.classList.remove('active');
    }
}

function showLoginError(message) {
    if (loginError) {
        loginError.textContent = message;
        loginError.style.display = 'block';
    }
}

function hideLoginError() {
    if (loginError) {
        loginError.style.display = 'none';
    }
}

// =============================================================================
// JOB NUMBER
// =============================================================================

async function loadJobNumber() {
    try {
        const response = await fetch('/api/get-job-no', { credentials: 'include' });
        const data = await response.json();
        jobNo = data.job_no;

        const jobDisplay = document.getElementById('job-number-display');
        const currentJobNo = document.getElementById('currentJobNo');

        if (jobDisplay) {
            jobDisplay.textContent = jobNo;
        }
        if (currentJobNo) {
            currentJobNo.textContent = jobNo;
        }
    } catch (error) {
        console.error('Failed to load job number:', error);
    }
}

// =============================================================================
// SIGNATURES
// =============================================================================

async function loadSignatures() {
    try {
        const response = await fetch('/api/signatures', { credentials: 'include' });
        const data = await response.json();
        signatures = data.signatures || [];

        populateSignatureDropdowns();
    } catch (error) {
        console.error('Failed to load signatures:', error);
    }
}

function populateSignatureDropdowns() {
    const adminSelect = document.getElementById('admin_signature');
    const staffSelect = document.getElementById('staff_signature');

    const defaultOption = '<option value="">-- Select Signature --</option>';
    const options = signatures.map(sig =>
        `<option value="${sig.userId}" data-url="${sig.signatureUrl || ''}" data-has-signature="${sig.hasSignature}">${sig.name}</option>`
    ).join('');

    if (adminSelect) {
        adminSelect.innerHTML = defaultOption + options;
    }
    if (staffSelect) {
        staffSelect.innerHTML = defaultOption + options;
    }
}

function updateSignaturePreview(type) {
    const select = document.getElementById(`${type}_signature`);
    const preview = document.getElementById(`${type}SigPreview`);

    if (!select || !preview) return;

    const userId = select.value;

    if (!userId) {
        preview.innerHTML = '';
        return;
    }

    const sig = signatures.find(s => s.userId === userId);
    if (sig) {
        // Only show signature image if user has permission to view it
        if (sig.signatureUrl) {
            preview.innerHTML = `<img src="${sig.signatureUrl}" alt="${sig.name}'s signature">`;
        } else {
            // Show placeholder for non-admins who can't see signatures
            preview.innerHTML = `
                <div style="padding: 16px; text-align: center; background: var(--bg-tertiary); border-radius: 8px; color: var(--text-secondary);">
                    <div style="font-size: 12px; font-weight: 600; margin-bottom: 8px;">Restricted</div>
                    <div style="font-size: 12px;">${sig.name}'s Signature</div>
                    <div style="font-size: 11px; opacity: 0.7;">Signature protected</div>
                </div>
            `;
        }
    }
}

// =============================================================================
// FORM SUBMISSION
// =============================================================================

async function handleSubmit(e) {
    e.preventDefault();

    const submitBtn = document.getElementById('submitBtn');
    const statusIndicator = document.getElementById('statusIndicator');
    const statusText = document.getElementById('statusText');

    // Check if logged in
    if (!currentUser) {
        showLoginModal();
        return;
    }

    // Validate required fields
    const mainDate = document.getElementById('main_date');
    if (!mainDate.value) {
        showToast('Please enter the date of request', 'error');
        mainDate.focus();
        return;
    }

    // Update status
    if (statusIndicator) {
        statusIndicator.classList.remove('ready');
        statusIndicator.classList.add('processing');
    }
    if (statusText) {
        statusText.textContent = 'Processing...';
    }

    submitBtn.disabled = true;
    submitBtn.classList.add('btn-loading');

    // Collect form data
    const formData = new FormData(jobForm);
    const data = {};

    for (const [key, value] of formData.entries()) {
        data[key] = value;
    }

    // Check if staff signature is selected - requires approval workflow
    const staffSignature = data.staff_signature;
    const hasStaffSignature = staffSignature && staffSignature.trim() !== '';

    try {
        if (hasStaffSignature) {
            // Staff signature selected - request approval instead of generating
            await requestSignatureApproval(data, staffSignature);
        } else {
            // No staff signature - generate report directly
            await generateReport(data);
        }
    } catch (error) {
        console.error('Submit error:', error);
        showToast('Failed to submit. Please try again.', 'error');
    } finally {
        submitBtn.disabled = false;
        submitBtn.classList.remove('btn-loading');

        if (statusIndicator) {
            statusIndicator.classList.remove('processing');
            statusIndicator.classList.add('ready');
        }
        if (statusText) {
            statusText.textContent = 'Ready';
        }
    }
}

async function generateReport(data) {
    const response = await fetch('/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(data)
    });

    // Check if unauthorized
    if (response.status === 401) {
        showLoginModal();
        return;
    }

    const result = await response.json();

    if (result.success) {
        showSuccessModal(result.job_no);
        showToast(`Job order ${result.job_no} created successfully!`, 'success');
    } else {
        showToast(result.error || 'Failed to generate report', 'error');
    }
}

async function requestSignatureApproval(reportData, staffUserId) {
    const response = await fetch('/api/approvals/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
            staffUserId: staffUserId,
            reportData: reportData
        })
    });

    if (response.status === 401) {
        showLoginModal();
        return;
    }

    const result = await response.json();

    if (result.success) {
        showApprovalRequestedModal();
        showToast('Signature approval request sent!', 'success');
    } else {
        showToast(result.error || 'Failed to send approval request', 'error');
    }
}

function showApprovalRequestedModal() {
    // Use existing success modal with different message
    if (successModal) {
        const successMessage = document.getElementById('successMessage');
        if (successMessage) {
            successMessage.innerHTML = `
                <strong>Approval Request Sent</strong><br><br>
                The staff member will receive an email to approve their signature for this report.
                Once approved, you can generate the report from the <a href="/pending-approvals.html">Pending Approvals</a> page.
            `;
        }
        successModal.classList.add('active');
    }
}

function showSuccessModal(jobNumber) {
    if (successModal) {
        const successMessage = document.getElementById('successMessage');
        if (successMessage) {
            successMessage.textContent = `Job Order #${jobNumber} has been generated successfully.`;
        }
        successModal.classList.add('active');
    }
}

// =============================================================================
// FORM UTILITIES
// =============================================================================

function resetForm() {
    if (jobForm) {
        jobForm.reset();
    }
    setDefaultDate();

    // Clear signature previews
    const adminPreview = document.getElementById('adminSigPreview');
    const staffPreview = document.getElementById('staffSigPreview');
    if (adminPreview) adminPreview.innerHTML = '';
    if (staffPreview) staffPreview.innerHTML = '';
}

function clearDuration() {
    const durationInputs = document.querySelectorAll('input[name^="duration_"]');
    durationInputs.forEach(input => {
        input.checked = false;
    });
}

// Make functions available globally for onclick
window.clearDuration = clearDuration;
window.resetForm = resetForm;

// =============================================================================
// ADMIN FUNCTIONS
// =============================================================================

async function loadPendingCount() {
    try {
        const response = await fetch('/api/admin/pending-signatures', { credentials: 'include' });
        const data = await response.json();
        const count = data.signatures?.length || 0;

        const badge = document.getElementById('pendingBadge');
        if (badge) {
            if (count > 0) {
                badge.textContent = count;
                badge.style.display = 'inline';
            } else {
                badge.style.display = 'none';
            }
        }
    } catch (error) {
        console.error('Failed to load pending count:', error);
    }
}

async function loadApprovalsBadgeCount() {
    const badge = document.getElementById('approvalsBadge');
    if (!badge) return;

    try {
        const response = await fetch('/api/approvals/pending', { credentials: 'include' });
        if (!response.ok) {
            badge.style.display = 'none';
            return;
        }

        const data = await response.json();
        const pendingCount = (data.approvals || []).filter(approval => approval.status === 'pending').length;

        if (pendingCount > 0) {
            badge.textContent = pendingCount;
            badge.style.display = 'inline';
        } else {
            badge.style.display = 'none';
        }
    } catch (error) {
        console.error('Failed to load approval notifications:', error);
        badge.style.display = 'none';
    }
}

// =============================================================================
// TOAST NOTIFICATIONS
// =============================================================================

function showToast(message, type = 'success') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    toast.innerHTML = `<span>${message}</span>`;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = 'toastSlideIn 0.3s ease reverse';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}
