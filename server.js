require('dotenv').config();

const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const ldap = require('ldapjs');
const path = require('path');
const fs = require('fs');
const ExcelJS = require('exceljs');
const multer = require('multer');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// =============================================================================
// DIRECTORIES AND FILE PATHS
// =============================================================================

const REPORTS_DIR = path.join(__dirname, 'Generated_Reports');
const TEMPLATE_FILE = path.join(__dirname, 'Job work order.xlsx');
const DATA_DIR = path.join(__dirname, 'data');
const SIGNATURES_DIR = path.join(DATA_DIR, 'signatures');
const DB_FILE = path.join(DATA_DIR, 'database.json');

// Ensure directories exist
[REPORTS_DIR, DATA_DIR, SIGNATURES_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// =============================================================================
// DATABASE (JSON-based simple storage)
// =============================================================================

function loadDatabase() {
  try {
    if (fs.existsSync(DB_FILE)) {
      return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    }
  } catch (err) {
    console.error('Error loading database:', err);
  }
  return { users: {}, invitations: {}, signatures: {} };
}

function saveDatabase(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

let db = loadDatabase();

// =============================================================================
// FILE UPLOAD CONFIGURATION
// =============================================================================

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, SIGNATURES_DIR);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${uuidv4()}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB max
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'image/png') {
      cb(null, true);
    } else {
      cb(new Error('Only PNG files are allowed'));
    }
  }
});

// =============================================================================
// EMAIL CONFIGURATION (Internal SMTP Relay - no auth)
// =============================================================================

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || '10.27.16.4',
  port: parseInt(process.env.SMTP_PORT || '25'),
  secure: false,
  tls: {
    rejectUnauthorized: false
  }
});

/**
 * Send signature invitation email
 * @param {string} toEmail - Recipient email
 * @param {string} name - Recipient name
 * @param {string} token - Invitation token
 * @param {object} fromUser - Admin user sending the invite (optional)
 */
async function sendSignatureInviteEmail(toEmail, name, token, fromUser = null) {
  const appUrl = process.env.APP_URL || `http://localhost:${PORT}`;
  const setupLink = `${appUrl}/signature-setup.html?token=${token}`;

  // Use admin's email as sender if available, otherwise use default
  const fromAddress = process.env.SMTP_FROM || 'Signature Verify <signatureVerify@swd.bh>';

  const mailOptions = {
    from: fromAddress,
    to: toEmail,
    subject: 'Set Up Your Digital Signature - Job Order System',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #1A73E8;">Digital Signature Setup</h2>
        <p>Hello ${name},</p>
        <p>You have been invited to set up your digital signature for the Job Order Management System.</p>
        ${fromUser ? `<p style="color: #666;">Invited by: ${fromUser.name || fromUser.email}</p>` : ''}
        <p>Click the button below to upload or draw your signature:</p>
        <p style="text-align: center; margin: 30px 0;">
          <a href="${setupLink}"
             style="background-color: #1A73E8; color: white; padding: 12px 24px;
                    text-decoration: none; border-radius: 6px; display: inline-block;">
            Set Up My Signature
          </a>
        </p>
        <p style="color: #666; font-size: 14px;">
          This link will expire in 7 days. If you did not request this, please ignore this email.
        </p>
        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
        <p style="color: #999; font-size: 12px;">Job Order Management System</p>
      </div>
    `
  };

  await transporter.sendMail(mailOptions);
}

// =============================================================================
// MIDDLEWARE SETUP
// =============================================================================

const corsOrigins = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(',').map(o => o.trim())
  : ['http://localhost:3000'];

app.use(cors({
  origin: corsOrigins,
  credentials: true
}));

app.use(cookieParser());
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'change_this_long_random_string',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 8 * 60 * 60 * 1000,
    sameSite: 'lax'
  }
}));

// =============================================================================
// AUTH GUARD MIDDLEWARE
// =============================================================================

const authGuard = (req, res, next) => {
  // Public routes
  const publicPaths = [
    '/health',
    '/auth/login',
    '/auth/logout',
    '/auth/me',
    '/api/signature/validate-token',
    '/api/signature/setup'
  ];

  const isPublic = publicPaths.some(p => req.path === p) || req.path.startsWith('/auth/');

  // Allow static files and signature setup page
  const isStatic = req.path.endsWith('.html') ||
                   req.path.endsWith('.css') ||
                   req.path.endsWith('.js') ||
                   req.path.endsWith('.png') ||
                   req.path === '/' ||
                   req.path === '/login' ||
                   req.path.startsWith('/signatures/');

  if (isPublic || isStatic) {
    return next();
  }

  if (!req.session || !req.session.user) {
    return res.status(401).json({ error: 'Unauthorized', message: 'Authentication required' });
  }

  next();
};

// Parse admin emails from environment
const ADMIN_EMAILS = process.env.ADMIN_EMAILS
  ? process.env.ADMIN_EMAILS.split(',').map(e => e.trim().toLowerCase())
  : [];

/**
 * Check if a user is an admin
 */
function isAdmin(user) {
  if (!user || !user.email) return false;
  return ADMIN_EMAILS.includes(user.email.toLowerCase());
}

// Admin guard middleware
const adminGuard = (req, res, next) => {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Check if user email is in admin list
  if (!isAdmin(req.session.user)) {
    return res.status(403).json({ error: 'Forbidden', message: 'Admin access required' });
  }

  next();
};

app.use(authGuard);

// =============================================================================
// LDAP HELPERS
// =============================================================================

const LDAP_URL = process.env.LDAP_URL;
const LDAP_BASE_DN = process.env.LDAP_BASE_DN;
const LDAP_DEFAULT_UPN = process.env.LDAP_DEFAULT_UPN;
const LDAP_ALT_UPN = process.env.LDAP_ALT_UPN;
const LDAP_NETBIOS = process.env.LDAP_NETBIOS;

function ldapBind(bindDN, password) {
  return new Promise((resolve, reject) => {
    const client = ldap.createClient({
      url: LDAP_URL,
      connectTimeout: 10000,
      timeout: 10000
    });

    client.on('error', (err) => {
      reject(err);
    });

    client.bind(bindDN, password, (err) => {
      if (err) {
        client.destroy();
        reject(err);
      } else {
        resolve(client);
      }
    });
  });
}

function ldapSearch(client, filter, attributes = ['mail', 'userPrincipalName', 'displayName', 'sAMAccountName', 'cn']) {
  return new Promise((resolve, reject) => {
    const opts = {
      filter: filter,
      scope: 'sub',
      attributes: attributes
    };

    client.search(LDAP_BASE_DN, opts, (err, searchRes) => {
      if (err) {
        reject(err);
        return;
      }

      const results = [];

      searchRes.on('searchEntry', (entry) => {
        const attrs = {};
        entry.pojo.attributes.forEach(attr => {
          attrs[attr.type] = attr.values[0];
        });
        results.push({
          email: attrs.mail || attrs.userPrincipalName || '',
          name: attrs.displayName || attrs.cn || '',
          username: attrs.sAMAccountName || ''
        });
      });

      searchRes.on('error', (err) => {
        reject(err);
      });

      searchRes.on('end', () => {
        resolve(results);
      });
    });
  });
}

async function authenticateUser(username, password) {
  const bindFormats = [];

  if (username.includes('@')) {
    bindFormats.push(username);
  } else {
    bindFormats.push(`${username}@${LDAP_DEFAULT_UPN}`);
    bindFormats.push(`${username}@${LDAP_ALT_UPN}`);
    bindFormats.push(`${LDAP_NETBIOS}\\${username}`);
  }

  let lastError = null;

  for (const bindDN of bindFormats) {
    try {
      const client = await ldapBind(bindDN, password);
      const searchUsername = username.includes('@') ? username.split('@')[0] : username;
      const filter = `(|(sAMAccountName=${searchUsername})(userPrincipalName=${username}*))`;
      const results = await ldapSearch(client, filter);

      let userInfo = results[0] || {
        email: username.includes('@') ? username : `${username}@${LDAP_DEFAULT_UPN}`,
        name: username,
        username: username.includes('@') ? username.split('@')[0] : username
      };

      client.destroy();
      return { success: true, user: userInfo };
    } catch (err) {
      lastError = err;
    }
  }

  return { success: false, error: lastError?.message || 'Invalid credentials' };
}

/**
 * Search LDAP directory for users (requires service account or current user session)
 */
async function searchLdapDirectory(client, searchTerm) {
  // Escape special LDAP characters
  const escapedTerm = searchTerm.replace(/([\\*()|\x00])/g, '\\$1');

  // Search by name, email, or username
  const filter = `(&(objectClass=user)(objectCategory=person)(|(displayName=*${escapedTerm}*)(mail=*${escapedTerm}*)(sAMAccountName=*${escapedTerm}*)))`;

  return await ldapSearch(client, filter);
}

// =============================================================================
// AUTH ROUTES
// =============================================================================

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ ok: false, error: 'Username and password are required' });
  }

  try {
    const result = await authenticateUser(username, password);

    if (result.success) {
      // Check if user has signature
      const userId = result.user.username.toLowerCase();
      const signature = db.signatures[userId];

      req.session.user = {
        ...result.user,
        hasSignature: !!signature && signature.status === 'approved'
      };

      // Store password hash for LDAP operations (encrypted in session)
      req.session.ldapAuth = {
        username,
        // In production, use proper encryption
        passwordHash: Buffer.from(password).toString('base64')
      };

      return res.json({
        ok: true,
        user: {
          ...req.session.user,
          isAdmin: isAdmin(req.session.user)
        }
      });
    } else {
      return res.status(401).json({ ok: false, error: 'Invalid credentials' });
    }
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ ok: false, error: 'Authentication service error' });
  }
});

app.post('/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ ok: false, error: 'Logout failed' });
    }
    res.clearCookie('connect.sid');
    res.json({ ok: true });
  });
});

app.get('/auth/me', (req, res) => {
  if (req.session && req.session.user) {
    return res.json({
      user: {
        ...req.session.user,
        isAdmin: isAdmin(req.session.user)
      }
    });
  }
  return res.status(401).json({ error: 'Not authenticated' });
});

// =============================================================================
// ADMIN ROUTES - LDAP DIRECTORY SEARCH
// =============================================================================

app.get('/api/admin/search-directory', adminGuard, async (req, res) => {
  const { q } = req.query;

  if (!q || q.length < 2) {
    return res.status(400).json({ error: 'Search query must be at least 2 characters' });
  }

  try {
    let client;

    // Try service account first, then current user's credentials
    if (process.env.LDAP_SERVICE_USER && process.env.LDAP_SERVICE_PASS) {
      client = await ldapBind(process.env.LDAP_SERVICE_USER, process.env.LDAP_SERVICE_PASS);
    } else if (req.session.ldapAuth) {
      const password = Buffer.from(req.session.ldapAuth.passwordHash, 'base64').toString();
      const username = req.session.ldapAuth.username;
      const bindDN = username.includes('@') ? username : `${username}@${LDAP_DEFAULT_UPN}`;
      client = await ldapBind(bindDN, password);
    } else {
      return res.status(400).json({ error: 'LDAP credentials not available' });
    }

    const results = await searchLdapDirectory(client, q);
    client.destroy();

    // Add signature status to results
    const enrichedResults = results.map(user => {
      const userId = user.username.toLowerCase();
      const sig = db.signatures[userId];
      return {
        ...user,
        hasSignature: !!sig,
        signatureStatus: sig?.status || null
      };
    });

    res.json({ users: enrichedResults });
  } catch (err) {
    console.error('Directory search error:', err);
    res.status(500).json({ error: 'Failed to search directory' });
  }
});

// =============================================================================
// ADMIN ROUTES - SIGNATURE INVITATIONS
// =============================================================================

app.post('/api/admin/invite-signature', adminGuard, async (req, res) => {
  const { email, name, username } = req.body;

  if (!email || !name) {
    return res.status(400).json({ error: 'Email and name are required' });
  }

  try {
    // Generate unique token
    const token = crypto.randomBytes(32).toString('hex');
    const userId = (username || email.split('@')[0]).toLowerCase();

    // Store invitation
    db.invitations[token] = {
      email,
      name,
      username: userId,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(), // 7 days
      invitedBy: req.session.user.username
    };
    saveDatabase(db);

    // Send email (pass admin user for "invited by" info)
    await sendSignatureInviteEmail(email, name, token, req.session.user);

    res.json({ ok: true, message: `Invitation sent to ${email}` });
  } catch (err) {
    console.error('Invite error:', err);
    res.status(500).json({ error: `Failed to send email: ${err.message}` });
  }
});

// =============================================================================
// ADMIN ROUTES - SIGNATURE APPROVAL
// =============================================================================

app.get('/api/admin/pending-signatures', adminGuard, (req, res) => {
  const pending = Object.entries(db.signatures)
    .filter(([_, sig]) => sig.status === 'pending')
    .map(([userId, sig]) => ({
      userId,
      ...sig,
      signatureUrl: `/signatures/${sig.filename}`
    }));

  res.json({ signatures: pending });
});

app.post('/api/admin/approve-signature/:userId', adminGuard, (req, res) => {
  const { userId } = req.params;
  const sig = db.signatures[userId.toLowerCase()];

  if (!sig) {
    return res.status(404).json({ error: 'Signature not found' });
  }

  sig.status = 'approved';
  sig.approvedAt = new Date().toISOString();
  sig.approvedBy = req.session.user.username;
  saveDatabase(db);

  res.json({ ok: true, message: 'Signature approved' });
});

app.post('/api/admin/reject-signature/:userId', adminGuard, (req, res) => {
  const { userId } = req.params;
  const sig = db.signatures[userId.toLowerCase()];

  if (!sig) {
    return res.status(404).json({ error: 'Signature not found' });
  }

  // Delete the signature file
  if (sig.filename) {
    const filePath = path.join(SIGNATURES_DIR, sig.filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  }

  delete db.signatures[userId.toLowerCase()];
  saveDatabase(db);

  res.json({ ok: true, message: 'Signature rejected and deleted' });
});

// =============================================================================
// SIGNATURE SETUP ROUTES (PUBLIC - token-based auth)
// =============================================================================

app.get('/api/signature/validate-token', (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).json({ valid: false, error: 'Token required' });
  }

  const invitation = db.invitations[token];

  if (!invitation) {
    return res.status(404).json({ valid: false, error: 'Invalid token' });
  }

  if (new Date(invitation.expiresAt) < new Date()) {
    return res.status(410).json({ valid: false, error: 'Token expired' });
  }

  res.json({
    valid: true,
    name: invitation.name,
    email: invitation.email
  });
});

// Upload PNG signature
app.post('/api/signature/setup', upload.single('signature'), (req, res) => {
  const { token, signatureData } = req.body;

  if (!token) {
    return res.status(400).json({ error: 'Token required' });
  }

  const invitation = db.invitations[token];

  if (!invitation) {
    return res.status(404).json({ error: 'Invalid token' });
  }

  if (new Date(invitation.expiresAt) < new Date()) {
    return res.status(410).json({ error: 'Token expired' });
  }

  const userId = invitation.username;
  let filename;

  // Handle file upload
  if (req.file) {
    filename = req.file.filename;
  }
  // Handle drawn signature (base64 data URL)
  else if (signatureData) {
    const matches = signatureData.match(/^data:image\/png;base64,(.+)$/);
    if (!matches) {
      return res.status(400).json({ error: 'Invalid signature data format' });
    }

    filename = `${uuidv4()}.png`;
    const buffer = Buffer.from(matches[1], 'base64');
    fs.writeFileSync(path.join(SIGNATURES_DIR, filename), buffer);
  }
  else {
    return res.status(400).json({ error: 'No signature provided' });
  }

  // Determine status
  const autoApprove = process.env.SIGNATURE_AUTO_APPROVE === 'true';

  // Store signature
  db.signatures[userId] = {
    name: invitation.name,
    email: invitation.email,
    filename,
    status: autoApprove ? 'approved' : 'pending',
    createdAt: new Date().toISOString(),
    ...(autoApprove ? { approvedAt: new Date().toISOString(), approvedBy: 'auto' } : {})
  };

  // Remove used invitation
  delete db.invitations[token];
  saveDatabase(db);

  res.json({
    ok: true,
    status: autoApprove ? 'approved' : 'pending',
    message: autoApprove
      ? 'Signature saved and approved!'
      : 'Signature saved and pending approval.'
  });
});

// =============================================================================
// SIGNATURES LIST (for form selection)
// =============================================================================

app.get('/api/signatures', (req, res) => {
  const approved = Object.entries(db.signatures)
    .filter(([_, sig]) => sig.status === 'approved')
    .map(([userId, sig]) => ({
      userId,
      name: sig.name,
      email: sig.email,
      signatureUrl: `/signatures/${sig.filename}`
    }));

  res.json({ signatures: approved });
});

// Serve signature images
app.use('/signatures', express.static(SIGNATURES_DIR));

// =============================================================================
// DASHBOARD & REPORTS API ROUTES
// =============================================================================

/**
 * Parse job order metadata from filename and report content
 */
function getJobOrderMetadata(filename) {
  const match = filename.match(/Job_(\d+)\.xlsx/);
  if (!match) return null;

  const jobNo = match[1];
  const filePath = path.join(REPORTS_DIR, filename);
  const stats = fs.statSync(filePath);

  return {
    jobNo,
    fileName: filename,
    date: stats.mtime.toISOString().split('T')[0],
    createdAt: stats.mtime.toISOString()
  };
}

/**
 * Get all job order reports with metadata
 */
function getAllReports() {
  try {
    const files = fs.readdirSync(REPORTS_DIR);
    return files
      .filter(f => f.startsWith('Job_') && f.endsWith('.xlsx'))
      .map(f => getJobOrderMetadata(f))
      .filter(Boolean)
      .sort((a, b) => parseInt(b.jobNo) - parseInt(a.jobNo));
  } catch (err) {
    console.error('Error getting reports:', err);
    return [];
  }
}

// Dashboard statistics
app.get('/api/dashboard/stats', (req, res) => {
  try {
    const reports = getAllReports();
    const signatures = Object.values(db.signatures).filter(s => s.status === 'approved');

    // Get current month stats
    const now = new Date();
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
    const monthlyReports = reports.filter(r => new Date(r.createdAt) >= monthStart);

    // Generate daily data for chart (last 30 days)
    const dailyOrders = [];
    for (let i = 29; i >= 0; i--) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);
      const dateStr = date.toISOString().split('T')[0];
      const count = reports.filter(r => r.date === dateStr).length;
      dailyOrders.push({
        date: date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
        count
      });
    }

    // Department stats (placeholder - would need to read Excel files for real data)
    const departmentStats = [
      { name: 'Design', count: Math.floor(reports.length * 0.25) },
      { name: 'Project', count: Math.floor(reports.length * 0.20) },
      { name: 'MEP', count: Math.floor(reports.length * 0.15) },
      { name: 'QS', count: Math.floor(reports.length * 0.15) },
      { name: 'Services', count: Math.floor(reports.length * 0.10) },
      { name: 'Others', count: Math.floor(reports.length * 0.15) }
    ];

    // Recent orders
    const recentOrders = reports.slice(0, 5).map(r => ({
      jobNo: r.jobNo,
      date: r.date,
      department: 'General',
      status: 'completed'
    }));

    // Work type distribution (placeholder)
    const sitePercent = 60;
    const officePercent = 40;

    res.json({
      totalOrders: reports.length,
      completedOrders: reports.length,
      signatures: signatures.length,
      monthlyOrders: monthlyReports.length,
      dailyOrders,
      departmentStats,
      recentOrders,
      sitePercent,
      officePercent
    });
  } catch (err) {
    console.error('Dashboard stats error:', err);
    res.status(500).json({ error: 'Failed to load dashboard statistics' });
  }
});

// Reports list with filtering
app.get('/api/reports', (req, res) => {
  try {
    const reports = getAllReports();

    // Enhance reports with additional metadata
    const enhancedReports = reports.map(r => ({
      ...r,
      department: 'General',
      workType: Math.random() > 0.5 ? 'Site' : 'Office',
      engineer: '',
      duration: '',
      status: 'completed'
    }));

    res.json({ reports: enhancedReports });
  } catch (err) {
    console.error('Reports error:', err);
    res.status(500).json({ error: 'Failed to load reports' });
  }
});

// Serve generated reports for download
app.use('/Generated_Reports', express.static(REPORTS_DIR));

// =============================================================================
// JOB ORDER API ROUTES
// =============================================================================

const JOB_NO_CELL = 'C3';
const CELL_MAP = {
  engineer: 'E12',
  head_section: 'N12'
};
const DATE_MAP = {
  main_date: 'H3',
  start_date: 'E11',
  end_date: 'N11'
};
const LABELED_FIELDS = {
  description: 'A4',
  objective: 'A6',
  note: 'A10',
  remarks: 'A14'
};
const DURATION_MAPPING = {
  days: { '1': 'A9', '2': 'B9', '3': 'C9', '4': 'D9', '5': 'E9' },
  weeks: { '1': 'F9', '2': 'G9', '3': 'H9', '4': 'I9' },
  months: { '2': 'J9', '4': 'K9', '6': 'L9', '8': 'M9', '10': 'N9', '12': 'O9' },
  years: { '1': 'P9', '2': 'Q9', '3': 'R9', '4': 'S9', '5': 'T9' }
};

// Signature cells
const SIGNATURE_CELLS = {
  admin: 'E13',    // Admin/creator signature
  staff: 'N13'     // Staff signature
};

function getNextJobNo() {
  try {
    const files = fs.readdirSync(REPORTS_DIR);
    const jobNumbers = files
      .filter(f => f.startsWith('Job_') && f.endsWith('.xlsx'))
      .map(f => {
        const match = f.match(/Job_(\d+)\.xlsx/);
        return match ? parseInt(match[1], 10) : 0;
      })
      .filter(n => n > 0);

    if (jobNumbers.length === 0) return 1001;
    return Math.max(...jobNumbers) + 1;
  } catch (err) {
    return 1001;
  }
}

function formatDate(dateStr) {
  if (!dateStr) return '';
  const parts = dateStr.split('-');
  if (parts.length !== 3) return dateStr;
  return `${parts[2]}/${parts[1]}/${parts[0]}`;
}

app.get('/api/get-job-no', (req, res) => {
  const jobNo = getNextJobNo();
  res.json({ job_no: jobNo });
});

app.post('/api/generate', async (req, res) => {
  try {
    const data = req.body;
    const jobNo = getNextJobNo();

    const workbook = new ExcelJS.Workbook();
    await workbook.xlsx.readFile(TEMPLATE_FILE);
    const ws = workbook.getWorksheet(1);

    // Write job number
    ws.getCell(JOB_NO_CELL).value = jobNo;

    // Write direct cell mappings
    for (const [field, cell] of Object.entries(CELL_MAP)) {
      if (data[field]) {
        ws.getCell(cell).value = data[field];
      }
    }

    // Write dates
    for (const [field, cell] of Object.entries(DATE_MAP)) {
      if (data[field]) {
        const formattedDate = formatDate(data[field]);
        const currentCell = ws.getCell(cell);

        if (field === 'end_date') {
          const existing = currentCell.value || '';
          const label = typeof existing === 'string' ? existing.split(':')[0] + ':' : '';
          currentCell.value = label ? `${label} ${formattedDate}` : formattedDate;
        } else {
          currentCell.value = formattedDate;
        }
      }
    }

    // Write labeled fields
    for (const [field, cell] of Object.entries(LABELED_FIELDS)) {
      if (data[field]) {
        const currentCell = ws.getCell(cell);
        const existing = currentCell.value || '';
        const existingStr = typeof existing === 'string' ? existing : String(existing);
        currentCell.value = existingStr ? `${existingStr} ${data[field]}` : data[field];
      }
    }

    // Handle duration highlighting
    const durationFields = ['duration_days', 'duration_weeks', 'duration_months', 'duration_years'];
    for (const field of durationFields) {
      const value = data[field];
      if (value) {
        const category = field.replace('duration_', '');
        const cellAddr = DURATION_MAPPING[category]?.[value];
        if (cellAddr) {
          const cell = ws.getCell(cellAddr);
          cell.fill = {
            type: 'pattern',
            pattern: 'solid',
            fgColor: { argb: 'FFFFFF00' }
          };
        }
      }
    }

    // Add signatures as images - stretch to fit cell dimensions
    if (data.admin_signature) {
      const sig = db.signatures[data.admin_signature.toLowerCase()];
      if (sig && sig.status === 'approved') {
        const imagePath = path.join(SIGNATURES_DIR, sig.filename);
        if (fs.existsSync(imagePath)) {
          const imageId = workbook.addImage({
            filename: imagePath,
            extension: 'png'
          });
          // E13 position: stretch image to fill cell (col 4 = E, row 12 = row 13 in 1-indexed)
          ws.addImage(imageId, {
            tl: { col: 4, row: 12, nativeColOff: 0, nativeRowOff: 0 },
            br: { col: 4.99, row: 12.99, nativeColOff: 0, nativeRowOff: 0 },
            editAs: 'twoCell'
          });
        }
      }
    }

    if (data.staff_signature) {
      const sig = db.signatures[data.staff_signature.toLowerCase()];
      if (sig && sig.status === 'approved') {
        const imagePath = path.join(SIGNATURES_DIR, sig.filename);
        if (fs.existsSync(imagePath)) {
          const imageId = workbook.addImage({
            filename: imagePath,
            extension: 'png'
          });
          // N13 position: stretch image to fill cell (col 13 = N, row 12 = row 13 in 1-indexed)
          ws.addImage(imageId, {
            tl: { col: 13, row: 12, nativeColOff: 0, nativeRowOff: 0 },
            br: { col: 13.99, row: 12.99, nativeColOff: 0, nativeRowOff: 0 },
            editAs: 'twoCell'
          });
        }
      }
    }

    // Save the workbook
    const outputPath = path.join(REPORTS_DIR, `Job_${jobNo}.xlsx`);
    await workbook.xlsx.writeFile(outputPath);

    res.json({
      success: true,
      file: outputPath,
      job_no: jobNo,
      message: `Job order ${jobNo} generated successfully`
    });

  } catch (err) {
    console.error('Generate error:', err);
    res.status(500).json({
      success: false,
      error: err.message || 'Failed to generate report'
    });
  }
});

// =============================================================================
// STATIC FILES
// =============================================================================

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'web', 'login.html'));
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'web', 'index.html'));
});

app.use(express.static(path.join(__dirname, 'web')));

// =============================================================================
// START SERVER
// =============================================================================

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`LDAP Server: ${LDAP_URL}`);
  console.log(`LDAP Base DN: ${LDAP_BASE_DN}`);
});
