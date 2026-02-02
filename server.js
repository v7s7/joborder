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
  return { users: {}, invitations: {}, signatures: {}, pendingApprovals: {} };
}

// Ensure pendingApprovals exists in loaded database
function ensureDbStructure(db) {
  if (!db.pendingApprovals) db.pendingApprovals = {};
  return db;
}

function saveDatabase(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

let db = ensureDbStructure(loadDatabase());

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

/**
 * Send signature approval request email
 * @param {string} toEmail - Staff member email
 * @param {string} staffName - Staff member name
 * @param {string} token - Approval token
 * @param {object} reportInfo - Report details (jobNo, requestedBy, etc.)
 */
async function sendApprovalRequestEmail(toEmail, staffName, token, reportInfo) {
  const appUrl = process.env.APP_URL || `http://localhost:${PORT}`;
  const reviewLink = `${appUrl}/approval-review.html?token=${token}`;

  const fromAddress = process.env.SMTP_FROM || 'Signature Verify <signatureVerify@swd.bh>';

  const mailOptions = {
    from: fromAddress,
    to: toEmail,
    subject: `Signature Approval Required - Job Order #${reportInfo.jobNo}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #f8fafc; padding: 20px;">
        <div style="background: white; border-radius: 8px; padding: 32px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
          <h2 style="color: #1e293b; margin: 0 0 24px 0; font-size: 24px;">Signature Approval Request</h2>

          <p style="color: #475569; margin: 0 0 16px 0;">Hello ${staffName},</p>

          <p style="color: #475569; margin: 0 0 24px 0;">
            Your signature has been requested for a job order report. Please review the details below and approve or reject this request.
          </p>

          <div style="background: #f1f5f9; border-radius: 6px; padding: 16px; margin: 0 0 24px 0;">
            <table style="width: 100%; border-collapse: collapse;">
              <tr>
                <td style="color: #64748b; padding: 4px 0; font-size: 14px;">Job Order #:</td>
                <td style="color: #1e293b; padding: 4px 0; font-size: 14px; font-weight: 600;">${reportInfo.jobNo}</td>
              </tr>
              <tr>
                <td style="color: #64748b; padding: 4px 0; font-size: 14px;">Requested By:</td>
                <td style="color: #1e293b; padding: 4px 0; font-size: 14px; font-weight: 600;">${reportInfo.requestedBy}</td>
              </tr>
              <tr>
                <td style="color: #64748b; padding: 4px 0; font-size: 14px;">Date:</td>
                <td style="color: #1e293b; padding: 4px 0; font-size: 14px; font-weight: 600;">${reportInfo.date}</td>
              </tr>
            </table>
          </div>

          <p style="text-align: center; margin: 0 0 16px 0;">
            <a href="${reviewLink}"
               style="background: #6366f1; color: white; padding: 14px 32px;
                      text-decoration: none; border-radius: 6px; display: inline-block;
                      font-weight: 500; font-size: 16px;">
              Review and Respond
            </a>
          </p>

          <p style="color: #94a3b8; font-size: 13px; margin: 24px 0 0 0; text-align: center;">
            This request will expire in 7 days. If you did not expect this, please contact your administrator.
          </p>
        </div>

        <p style="color: #94a3b8; font-size: 12px; text-align: center; margin: 16px 0 0 0;">
          Job Order Management System
        </p>
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

  // Routes that are public with token (approval review via email)
  const isApprovalRoute = req.path.startsWith('/api/approvals/review/') ||
                          req.path.startsWith('/api/approvals/respond/');

  const isPublic = publicPaths.some(p => req.path === p) ||
                   req.path.startsWith('/auth/') ||
                   isApprovalRoute;

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

// Parse leader emails from environment (Head of Section/Department)
const DEFAULT_LEADER_EMAILS = ['h.hayat@swd.bh'];
const ENV_LEADER_EMAILS = process.env.LEADER_EMAILS
  ? process.env.LEADER_EMAILS.split(',').map(e => e.trim().toLowerCase())
  : [];
const LEADER_EMAILS = [...new Set([...DEFAULT_LEADER_EMAILS, ...ENV_LEADER_EMAILS])];

/**
 * Check if a user is an admin
 */
function isAdmin(user) {
  if (!user || !user.email) return false;
  return ADMIN_EMAILS.includes(user.email.toLowerCase());
}

/**
 * Check if a user is a leader (Head of Section/Department)
 */
function isLeader(user) {
  if (!user || !user.email) return false;
  return LEADER_EMAILS.includes(user.email.toLowerCase());
}

/**
 * Get user role
 */
function getUserRole(user) {
  if (isAdmin(user)) return 'admin';
  if (isLeader(user)) return 'leader';
  return 'staff';
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

// Leader or Admin guard middleware
const leaderGuard = (req, res, next) => {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const user = req.session.user;
  if (!isAdmin(user) && !isLeader(user)) {
    return res.status(403).json({ error: 'Forbidden', message: 'Leader access required' });
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
          isAdmin: isAdmin(req.session.user),
          isLeader: isLeader(req.session.user),
          role: getUserRole(req.session.user)
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
    const user = req.session.user;
    return res.json({
      user: {
        ...user,
        isAdmin: isAdmin(user),
        isLeader: isLeader(user),
        role: getUserRole(user)
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
  const user = req.session?.user;
  const userIsAdmin = isAdmin(user);
  const userEmail = user?.email?.toLowerCase();

  const approved = Object.entries(db.signatures)
    .filter(([_, sig]) => sig.status === 'approved')
    .map(([userId, sig]) => {
      // Only admins can see signature URLs
      // Staff can see their own signature URL
      const canSeeSignature = userIsAdmin || (userEmail && sig.email?.toLowerCase() === userEmail);

      return {
        userId,
        name: sig.name,
        email: sig.email,
        signatureUrl: canSeeSignature ? `/signatures/${sig.filename}` : null,
        hasSignature: true
      };
    });

  res.json({ signatures: approved });
});

// Serve signature images - only admins or signature owners can access
app.use('/signatures', (req, res, next) => {
  const user = req.session?.user;

  // Allow admins full access
  if (isAdmin(user)) {
    return next();
  }

  // Check if user owns this signature
  if (user?.email) {
    const filename = req.path.replace('/', '');
    const ownerSig = Object.values(db.signatures).find(sig => sig.filename === filename);
    if (ownerSig && ownerSig.email?.toLowerCase() === user.email.toLowerCase()) {
      return next();
    }
  }

  // Deny access
  return res.status(403).json({ error: 'Access denied' });
}, express.static(SIGNATURES_DIR));

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
app.get('/api/reports', leaderGuard, (req, res) => {
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
app.use('/Generated_Reports', leaderGuard, express.static(REPORTS_DIR));

// =============================================================================
// SIGNATURE APPROVAL API ROUTES
// =============================================================================

// Get pending approvals (admin or creator can see)
app.get('/api/approvals/pending', (req, res) => {
  try {
    const user = req.session.user;
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const userIsAdmin = isAdmin(user);
    const userEmail = user.email?.toLowerCase();

    // Filter approvals: admins see all, users see only their own requests
    const approvals = Object.entries(db.pendingApprovals || {})
      .filter(([_, approval]) => {
        if (userIsAdmin) return true;
        return approval.createdBy?.toLowerCase() === userEmail ||
               approval.staffEmail?.toLowerCase() === userEmail;
      })
      .map(([token, approval]) => ({
        token,
        ...approval,
        // Hide signature URL from non-admins unless they are the staff member
        signatureUrl: (userIsAdmin || approval.staffEmail?.toLowerCase() === userEmail)
          ? approval.signatureUrl
          : null
      }))
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    res.json({ approvals });
  } catch (err) {
    console.error('Get approvals error:', err);
    res.status(500).json({ error: 'Failed to load approvals' });
  }
});

// Request signature approval (when generating report with staff signature)
app.post('/api/approvals/request', leaderGuard, async (req, res) => {
  try {
    const user = req.session.user;
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { staffUserId, reportData } = req.body;

    if (!staffUserId) {
      return res.status(400).json({ error: 'Staff user ID is required' });
    }

    // Find the staff signature
    const staffSig = db.signatures[staffUserId.toLowerCase()];
    if (!staffSig || staffSig.status !== 'approved') {
      return res.status(400).json({ error: 'Staff signature not found or not approved' });
    }

    // Generate approval token
    const token = uuidv4();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

    // Store pending approval
    db.pendingApprovals[token] = {
      staffUserId: staffUserId.toLowerCase(),
      staffName: staffSig.name,
      staffEmail: staffSig.email,
      signatureUrl: `/signatures/${staffSig.filename}`,
      reportData: reportData,
      status: 'pending',
      createdBy: user.email,
      createdByName: user.name || user.username,
      createdAt: new Date().toISOString(),
      expiresAt: expiresAt.toISOString()
    };

    saveDatabase(db);

    // Send email to staff
    try {
      await sendApprovalRequestEmail(
        staffSig.email,
        staffSig.name,
        token,
        {
          jobNo: reportData.jobNo || 'Pending',
          requestedBy: user.name || user.username || user.email,
          date: new Date().toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
          })
        }
      );
    } catch (emailErr) {
      console.error('Failed to send approval email:', emailErr);
      // Continue anyway - approval is created
    }

    res.json({
      success: true,
      token,
      message: 'Approval request sent to staff member'
    });
  } catch (err) {
    console.error('Request approval error:', err);
    res.status(500).json({ error: 'Failed to create approval request' });
  }
});

// Get approval details by token (for review page - public with token)
app.get('/api/approvals/review/:token', (req, res) => {
  try {
    const { token } = req.params;
    const approval = db.pendingApprovals[token];

    if (!approval) {
      return res.status(404).json({ error: 'Approval request not found' });
    }

    // Check expiration
    if (new Date(approval.expiresAt) < new Date()) {
      return res.status(410).json({ error: 'Approval request has expired' });
    }

    res.json({
      approval: {
        staffName: approval.staffName,
        reportData: approval.reportData,
        status: approval.status,
        createdByName: approval.createdByName,
        createdAt: approval.createdAt
      }
    });
  } catch (err) {
    console.error('Get approval review error:', err);
    res.status(500).json({ error: 'Failed to load approval details' });
  }
});

// Respond to approval request (approve or reject)
app.post('/api/approvals/respond/:token', (req, res) => {
  try {
    const { token } = req.params;
    const { action } = req.body; // 'approve' or 'reject'

    if (!['approve', 'reject'].includes(action)) {
      return res.status(400).json({ error: 'Invalid action' });
    }

    const approval = db.pendingApprovals[token];

    if (!approval) {
      return res.status(404).json({ error: 'Approval request not found' });
    }

    // Check expiration
    if (new Date(approval.expiresAt) < new Date()) {
      return res.status(410).json({ error: 'Approval request has expired' });
    }

    // Check if already responded
    if (approval.status !== 'pending') {
      return res.status(400).json({ error: 'Approval has already been processed' });
    }

    // Update status
    approval.status = action === 'approve' ? 'approved' : 'rejected';
    approval.respondedAt = new Date().toISOString();

    saveDatabase(db);

    res.json({
      success: true,
      status: approval.status,
      message: action === 'approve'
        ? 'Signature approved. The report can now be generated.'
        : 'Signature request rejected.'
    });
  } catch (err) {
    console.error('Respond to approval error:', err);
    res.status(500).json({ error: 'Failed to process response' });
  }
});

// Delete/cancel approval request (admin or creator only)
app.delete('/api/approvals/:token', (req, res) => {
  try {
    const user = req.session.user;
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { token } = req.params;
    const approval = db.pendingApprovals[token];

    if (!approval) {
      return res.status(404).json({ error: 'Approval request not found' });
    }

    const userIsAdmin = isAdmin(user);
    const isCreator = approval.createdBy?.toLowerCase() === user.email?.toLowerCase();

    if (!userIsAdmin && !isCreator) {
      return res.status(403).json({ error: 'Not authorized to delete this request' });
    }

    delete db.pendingApprovals[token];
    saveDatabase(db);

    res.json({ success: true, message: 'Approval request deleted' });
  } catch (err) {
    console.error('Delete approval error:', err);
    res.status(500).json({ error: 'Failed to delete approval request' });
  }
});

// Generate report from approved request
app.post('/api/approvals/:token/generate', leaderGuard, async (req, res) => {
  try {
    const user = req.session.user;
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { token } = req.params;
    const approval = db.pendingApprovals[token];

    if (!approval) {
      return res.status(404).json({ error: 'Approval request not found' });
    }

    if (approval.status !== 'approved') {
      return res.status(400).json({ error: 'Signature has not been approved yet' });
    }

    // Check authorization
    const userIsAdmin = isAdmin(user);
    const isCreator = approval.createdBy?.toLowerCase() === user.email?.toLowerCase();

    if (!userIsAdmin && !isCreator) {
      return res.status(403).json({ error: 'Not authorized to generate this report' });
    }

    const reportData = {
      ...approval.reportData,
      staff_signature: approval.staffUserId,
      _approvalToken: token
    };

    const { jobNo, outputPath } = await generateJobOrderReport(reportData);

    approval.generatedAt = new Date().toISOString();
    saveDatabase(db);

    res.json({
      success: true,
      file: outputPath,
      job_no: jobNo,
      message: `Job order ${jobNo} generated successfully`
    });
  } catch (err) {
    console.error('Generate from approval error:', err);
    res.status(500).json({ error: 'Failed to process generation' });
  }
});

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

async function generateJobOrderReport(data) {
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
        // Just use the formatted date without any prefix
        currentCell.value = formattedDate;
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

  // Handle duration highlighting (only one highlight per category)
  const durationFields = ['duration_days', 'duration_weeks', 'duration_months', 'duration_years'];
  const highlightFill = {
    type: 'pattern',
    pattern: 'solid',
    fgColor: { argb: 'FFFFFF00' }
  };

  // Clear fill for ALL duration cells first (A9 to T9)
  const noFill = {
    type: 'pattern',
    pattern: 'none'
  };

  // Clear all cells in all duration categories
  Object.values(DURATION_MAPPING).forEach((categoryMap) => {
    Object.values(categoryMap).forEach((cellAddr) => {
      ws.getCell(cellAddr).fill = noFill;
    });
  });

  // Now apply highlight only to selected cells
  for (const field of durationFields) {
    const value = data[field];
    const category = field.replace('duration_', '');
    const categoryMap = DURATION_MAPPING[category] || {};

    if (value) {
      const cellAddr = categoryMap[value];
      if (cellAddr) {
        ws.getCell(cellAddr).fill = highlightFill;
      }
    }
  }

  const buildCheckboxRichText = (options, selectedKey) => {
    const richText = [];
    options.forEach((option, index) => {
      const isSelected = option.key === selectedKey;
      const box = isSelected ? '[X]' : '[  ]';
      const text = `${box} ${option.label}${index < options.length - 1 ? '\n' : ''}`;
      richText.push({
        text,
        font: {
          size: 11,
          bold: isSelected
        }
      });
    });
    return { richText };
  };

  // Fill type selections with text checkboxes
  const typeValue = (data.work_type || '').toLowerCase();
  const typeOptions = [
    { key: 'site', label: 'Site' },
    { key: 'office', label: 'Office' }
  ];
  const typeCell = ws.getCell('M3');
  typeCell.value = buildCheckboxRichText(typeOptions, typeValue);
  typeCell.alignment = { ...(typeCell.alignment || {}), wrapText: true, vertical: 'middle' };

  // Fill department selections with text checkboxes
  const departmentValue = (data.department || '').toLowerCase();
  const departmentOptions = [
    { key: 'servies', label: 'Services' },
    { key: 'design', label: 'Design' },
    { key: 'project', label: 'Project' },
    { key: 'qs', label: 'QS' },
    { key: 'mosque maint.', label: 'Mosque Maint.' },
    { key: 'investment maint.', label: 'Investment Maint.' },
    { key: 'cemetry', label: 'Cemetery' },
    { key: 'mep', label: 'MEP' },
    { key: 'others', label: 'Others' }
  ];
  const departmentCell = ws.getCell('Q3');
  departmentCell.value = buildCheckboxRichText(departmentOptions, departmentValue);
  departmentCell.alignment = { wrapText: true, vertical: 'center' };

  // Add signatures as images - stretch to fit merged cell dimensions
  // E13:I13 is merged (cols 4-8), N13:T13 is merged (cols 13-19)
  if (data.admin_signature) {
    const sig = db.signatures[data.admin_signature.toLowerCase()];
    if (sig && sig.status === 'approved') {
      const imagePath = path.join(SIGNATURES_DIR, sig.filename);
      if (fs.existsSync(imagePath)) {
        const imageId = workbook.addImage({
          filename: imagePath,
          extension: 'png'
        });
        // E13:I13 merged cell - stretch from col E (4) to end of col I (9)
        ws.addImage(imageId, {
          tl: { col: 4, row: 12 },
          br: { col: 9, row: 13 },
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
        // N13:T13 merged cell - stretch from col N (13) to end of col T (20)
        ws.addImage(imageId, {
          tl: { col: 13, row: 12 },
          br: { col: 20, row: 13 },
          editAs: 'twoCell'
        });
      }
    }
  }

  const outputPath = path.join(REPORTS_DIR, `Job_${jobNo}.xlsx`);
  await workbook.xlsx.writeFile(outputPath);

  return { jobNo, outputPath };
}

app.get('/api/get-job-no', (req, res) => {
  const jobNo = getNextJobNo();
  res.json({ job_no: jobNo });
});

app.post('/api/generate', leaderGuard, async (req, res) => {
  try {
    const data = req.body;
    const { jobNo, outputPath } = await generateJobOrderReport(data);

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
