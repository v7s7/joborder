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
const settingsModal = document.getElementById('settingsModal');
const settingsForm = document.getElementById('settingsForm');
const settingsBtn = document.getElementById('settingsBtn');

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

    // Settings button
    if (settingsBtn) {
        settingsBtn.addEventListener('click', openSettingsModal);
    }

    // Settings modal close buttons
    const closeSettingsModal = document.getElementById('closeSettingsModal');
    const cancelSettingsBtn = document.getElementById('cancelSettingsBtn');

    if (closeSettingsModal) {
        closeSettingsModal.addEventListener('click', () => {
            settingsModal.classList.remove('active');
        });
    }

    if (cancelSettingsBtn) {
        cancelSettingsBtn.addEventListener('click', () => {
            settingsModal.classList.remove('active');
        });
    }

    // Settings form submit
    if (settingsForm) {
        settingsForm.addEventListener('submit', handleSaveSettings);
    }
    setupSavePathPicker();

    // Attachment handlers
    setupAttachmentHandlers();
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
// USER SETTINGS
// =============================================================================

async function openSettingsModal() {
    if (!settingsModal) return;

    // Load current settings
    try {
        const response = await fetch('/api/user/settings', { credentials: 'include' });
        const data = await response.json();

        if (data.success) {
            const savePathInput = document.getElementById('savePathInput');
            if (savePathInput) {
                savePathInput.value = data.settings.savePath || '';
            }
        }
    } catch (error) {
        console.error('Failed to load settings:', error);
    }

    settingsModal.classList.add('active');
}

async function handleSaveSettings(e) {
    e.preventDefault();

    const savePathInput = document.getElementById('savePathInput');
    const savePath = savePathInput ? savePathInput.value.trim() : '';

    try {
        const response = await fetch('/api/user/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ savePath })
        });

        const data = await response.json();

        if (data.success) {
            showToast('Settings saved successfully!', 'success');
            settingsModal.classList.remove('active');
        } else {
            showToast(data.error || 'Failed to save settings', 'error');
        }
    } catch (error) {
        console.error('Failed to save settings:', error);
        showToast('Failed to save settings', 'error');
    }
}

function setupSavePathPicker() {
    const browseBtn = document.getElementById('browseSavePathBtn');
    const savePathInput = document.getElementById('savePathInput');
    const savePathPicker = document.getElementById('savePathPicker');

    if (!browseBtn || !savePathInput) return;

    browseBtn.addEventListener('click', async () => {
        if (window.showDirectoryPicker) {
            try {
                const handle = await window.showDirectoryPicker();
                if (handle?.name) {
                    savePathInput.value = handle.name;
                }
                return;
            } catch (error) {
                if (error?.name !== 'AbortError') {
                    console.error('Failed to open directory picker:', error);
                }
            }
        }

        if (savePathPicker) {
            savePathPicker.click();
        }
    });

    if (savePathPicker) {
        savePathPicker.addEventListener('change', () => {
            const file = savePathPicker.files?.[0];
            if (!file) return;
            const path = getSelectedDirectoryPath(file);
            if (path) {
                savePathInput.value = path;
            }
            savePathPicker.value = '';
        });
    }
}

function getSelectedDirectoryPath(file) {
    if (!file) {
        return '';
    }
    if (file.path) {
        if (file.webkitRelativePath) {
            const normalizedPath = file.path.replace(/\\/g, '/');
            if (normalizedPath.endsWith(file.webkitRelativePath)) {
                const basePath = normalizedPath.slice(0, -file.webkitRelativePath.length);
                return basePath.replace(/\/$/, '');
            }
        }
        const lastSeparator = Math.max(file.path.lastIndexOf('/'), file.path.lastIndexOf('\\'));
        return lastSeparator >= 0 ? file.path.slice(0, lastSeparator) : file.path;
    }
    if (file.webkitRelativePath) {
        const segments = file.webkitRelativePath.split('/');
        return segments.length > 1 ? segments[0] : file.webkitRelativePath;
    }
    return file.name || '';
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

    const sortedSignatures = [...signatures].sort((a, b) =>
        (a.name || '').localeCompare(b.name || '', undefined, { sensitivity: 'base' })
    );

    const defaultOption = '<option value="">-- Select Signature --</option>';
    const options = sortedSignatures.map(sig =>
        `<option value="${sig.userId}" data-url="${sig.signatureUrl || ''}" data-has-signature="${sig.hasSignature}">${sig.name}</option>`
    ).join('');

    if (adminSelect) {
        adminSelect.innerHTML = defaultOption + options;

        if (currentUser) {
            const userEmail = currentUser.email?.toLowerCase();
            const userMatch = sortedSignatures.find(sig => {
                const signatureEmail = sig.email?.toLowerCase();
                const signatureUserId = sig.userId?.toLowerCase();
                return (userEmail && (signatureEmail === userEmail || signatureUserId === userEmail));
            });

            if (userMatch) {
                adminSelect.value = userMatch.userId;
                updateSignaturePreview('admin');
            }
        }
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
    // Use FormData to support file uploads
    const formData = new FormData();

    // Add form fields
    for (const [key, value] of Object.entries(data)) {
        formData.append(key, value);
    }

    // Add attachments
    for (const file of selectedFiles) {
        formData.append('attachments', file);
    }

    const response = await fetch('/api/generate', {
        method: 'POST',
        credentials: 'include',
        body: formData  // No Content-Type header - browser sets it with boundary
    });

    // Check if unauthorized
    if (response.status === 401) {
        showLoginModal();
        return;
    }

    const result = await response.json();

    if (result.success) {
        showSuccessModal(result.job_no, result.savedPath);
        showToast(`Job order ${result.job_no} created successfully!`, 'success');

        // Clear form after successful generation
        resetForm();
    } else {
        showToast(result.error || 'Failed to generate report', 'error');
    }
}

async function requestSignatureApproval(reportData, staffUserId) {
    // Use FormData to support file uploads (same as generateReport)
    const formData = new FormData();

    // Add report data as JSON string
    formData.append('reportData', JSON.stringify(reportData));
    formData.append('staffUserId', staffUserId);

    // Add attachments
    for (const file of selectedFiles) {
        formData.append('attachments', file);
    }

    const response = await fetch('/api/approvals/request', {
        method: 'POST',
        credentials: 'include',
        body: formData  // No Content-Type header - browser sets it with boundary
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

function showSuccessModal(jobNumber, savedPath) {
    if (successModal) {
        const successMessage = document.getElementById('successMessage');
        if (successMessage) {
            if (savedPath) {
                successMessage.innerHTML = `
                    Job Order <strong>#${jobNumber}</strong> has been generated successfully.<br><br>
                    <small>Saved to:</small><br>
                    <code style="font-size: 12px; background: var(--bg-secondary); padding: 8px; border-radius: 4px; display: block; margin-top: 8px; word-break: break-all;">${savedPath}</code>
                `;
            } else {
                successMessage.textContent = `Job Order #${jobNumber} has been generated successfully.`;
            }
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

    // Clear attachments
    clearAttachments();
}

function clearDuration() {
    const durationInputs = document.querySelectorAll('input[name^="duration_"]');
    durationInputs.forEach(input => {
        input.checked = false;
    });
}

// =============================================================================
// ATTACHMENT HANDLING
// =============================================================================

let selectedFiles = [];

function setupAttachmentHandlers() {
    const dropzone = document.getElementById('attachmentDropzone');
    const fileInput = document.getElementById('attachmentInput');
    const attachmentList = document.getElementById('attachmentList');

    if (!dropzone || !fileInput) return;

    // Prevent file input clicks from bubbling to dropzone (which would trigger another click)
    fileInput.addEventListener('click', (e) => e.stopPropagation());

    // Click to browse
    dropzone.addEventListener('click', () => fileInput.click());

    // File input change
    fileInput.addEventListener('change', (e) => {
        addFiles(e.target.files);
        fileInput.value = ''; // Reset to allow re-selecting same file
    });

    // Drag and drop events
    dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.classList.add('dragover');
    });

    dropzone.addEventListener('dragleave', () => {
        dropzone.classList.remove('dragover');
    });

    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
        addFiles(e.dataTransfer.files);
    });
}

function addFiles(fileList) {
    for (const file of fileList) {
        // Check for duplicates
        if (selectedFiles.some(f => f.name === file.name && f.size === file.size)) {
            continue;
        }
        selectedFiles.push(file);
    }
    renderAttachmentList();
}

function removeFile(index) {
    selectedFiles.splice(index, 1);
    renderAttachmentList();
}

function renderAttachmentList() {
    const list = document.getElementById('attachmentList');
    if (!list) return;

    if (selectedFiles.length === 0) {
        list.innerHTML = '';
        return;
    }

    list.innerHTML = selectedFiles.map((file, index) => {
        const ext = file.name.split('.').pop().toLowerCase();
        let iconClass = '';
        let iconText = ext.toUpperCase();

        if (['pdf'].includes(ext)) iconClass = 'pdf';
        else if (['doc', 'docx'].includes(ext)) iconClass = 'doc';
        else if (['xls', 'xlsx'].includes(ext)) iconClass = 'xls';
        else if (['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'].includes(ext)) {
            iconClass = 'img';
            iconText = 'IMG';
        }

        return `
            <div class="attachment-item">
                <div class="file-icon ${iconClass}">${iconText}</div>
                <div class="file-info">
                    <div class="file-name">${file.name}</div>
                    <div class="file-size">${formatFileSize(file.size)}</div>
                </div>
                <button type="button" class="remove-btn" onclick="removeFile(${index})">
                    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                    </svg>
                </button>
            </div>
        `;
    }).join('');
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function clearAttachments() {
    selectedFiles = [];
    renderAttachmentList();
}

// Make functions available globally for onclick
window.clearDuration = clearDuration;
window.resetForm = resetForm;
window.removeFile = removeFile;

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
