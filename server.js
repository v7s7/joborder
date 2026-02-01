require('dotenv').config();

const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const ldap = require('ldapjs');
const path = require('path');
const fs = require('fs');
const ExcelJS = require('exceljs');

const app = express();
const PORT = process.env.PORT || 3000;

// =============================================================================
// MIDDLEWARE SETUP
// =============================================================================

// Parse CORS origins from env
const corsOrigins = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(',').map(o => o.trim())
  : ['http://localhost:3000'];

app.use(cors({
  origin: corsOrigins,
  credentials: true
}));

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'change_this_long_random_string',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 8 * 60 * 60 * 1000, // 8 hours
    sameSite: 'lax'
  }
}));

// =============================================================================
// AUTH GUARD MIDDLEWARE
// =============================================================================

const authGuard = (req, res, next) => {
  // Public routes
  const publicPaths = ['/health', '/auth/login', '/auth/logout', '/auth/me'];

  // Check if path starts with any public path
  const isPublic = publicPaths.some(p => req.path === p || req.path.startsWith('/auth/'));

  // Also allow static files for login page
  const isStatic = req.path.endsWith('.html') ||
                   req.path.endsWith('.css') ||
                   req.path.endsWith('.js') ||
                   req.path === '/' ||
                   req.path === '/login';

  if (isPublic || isStatic) {
    return next();
  }

  // Protected routes require authentication
  if (!req.session || !req.session.user) {
    return res.status(401).json({ error: 'Unauthorized', message: 'Authentication required' });
  }

  next();
};

app.use(authGuard);

// =============================================================================
// LDAP AUTHENTICATION HELPERS
// =============================================================================

const LDAP_URL = process.env.LDAP_URL;
const LDAP_BASE_DN = process.env.LDAP_BASE_DN;
const LDAP_DEFAULT_UPN = process.env.LDAP_DEFAULT_UPN;
const LDAP_ALT_UPN = process.env.LDAP_ALT_UPN;
const LDAP_NETBIOS = process.env.LDAP_NETBIOS;

/**
 * Attempt LDAP bind with given credentials
 */
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

/**
 * Search LDAP for user details after successful bind
 */
function ldapSearch(client, username) {
  return new Promise((resolve, reject) => {
    // Build search filter - search by sAMAccountName or userPrincipalName
    const searchUsername = username.includes('@') ? username.split('@')[0] : username;
    const filter = `(|(sAMAccountName=${searchUsername})(userPrincipalName=${username}*))`;

    const opts = {
      filter: filter,
      scope: 'sub',
      attributes: ['mail', 'userPrincipalName', 'displayName', 'sAMAccountName', 'cn']
    };

    client.search(LDAP_BASE_DN, opts, (err, searchRes) => {
      if (err) {
        reject(err);
        return;
      }

      let userInfo = null;

      searchRes.on('searchEntry', (entry) => {
        const attrs = {};
        entry.pojo.attributes.forEach(attr => {
          attrs[attr.type] = attr.values[0];
        });
        userInfo = {
          email: attrs.mail || attrs.userPrincipalName || '',
          name: attrs.displayName || attrs.cn || searchUsername,
          username: attrs.sAMAccountName || searchUsername
        };
      });

      searchRes.on('error', (err) => {
        reject(err);
      });

      searchRes.on('end', () => {
        resolve(userInfo);
      });
    });
  });
}

/**
 * Try multiple bind formats for authentication
 */
async function authenticateUser(username, password) {
  const bindFormats = [];

  if (username.includes('@')) {
    // Username already contains domain
    bindFormats.push(username);
  } else {
    // Try different formats in order
    bindFormats.push(`${username}@${LDAP_DEFAULT_UPN}`);
    bindFormats.push(`${username}@${LDAP_ALT_UPN}`);
    bindFormats.push(`${LDAP_NETBIOS}\\${username}`);
  }

  let lastError = null;

  for (const bindDN of bindFormats) {
    try {
      const client = await ldapBind(bindDN, password);

      // Search for user details
      let userInfo = await ldapSearch(client, username);

      // If search didn't return info, use defaults
      if (!userInfo) {
        userInfo = {
          email: username.includes('@') ? username : `${username}@${LDAP_DEFAULT_UPN}`,
          name: username,
          username: username.includes('@') ? username.split('@')[0] : username
        };
      }

      client.destroy();
      return { success: true, user: userInfo };
    } catch (err) {
      lastError = err;
      // Continue to next format
    }
  }

  // All formats failed
  return {
    success: false,
    error: lastError?.message || 'Invalid credentials'
  };
}

// =============================================================================
// AUTH ROUTES
// =============================================================================

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Login
app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      ok: false,
      error: 'Username and password are required'
    });
  }

  try {
    const result = await authenticateUser(username, password);

    if (result.success) {
      req.session.user = result.user;
      return res.json({ ok: true, user: result.user });
    } else {
      return res.status(401).json({
        ok: false,
        error: 'Invalid credentials'
      });
    }
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({
      ok: false,
      error: 'Authentication service error'
    });
  }
});

// Logout
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

// Get current user
app.get('/auth/me', (req, res) => {
  if (req.session && req.session.user) {
    return res.json({ user: req.session.user });
  }
  return res.status(401).json({ error: 'Not authenticated' });
});

// =============================================================================
// JOB ORDER API ROUTES
// =============================================================================

const REPORTS_DIR = path.join(__dirname, 'Generated_Reports');
const TEMPLATE_FILE = path.join(__dirname, 'Job work order.xlsx');

// Ensure reports directory exists
if (!fs.existsSync(REPORTS_DIR)) {
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
}

// Cell mappings (matching the original Python app)
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
const TYPE_MAPPING = { Site: 'site', Office: 'office' };
const TO_SECTION_MAPPING = {
  'servies': 'servies',
  'Design': 'Design',
  'project': 'project',
  'QS': 'QS',
  'Mosque Maint.': 'Mosque Maint.',
  'Investment Maint.': 'Investment Maint.',
  'Cemetry': 'Cemetry',
  'MEP': 'MEP',
  'Others': 'Others'
};

// Get next job number
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

// Format date from YYYY-MM-DD to DD/MM/YYYY
function formatDate(dateStr) {
  if (!dateStr) return '';
  const parts = dateStr.split('-');
  if (parts.length !== 3) return dateStr;
  return `${parts[2]}/${parts[1]}/${parts[0]}`;
}

// API: Get next job number
app.get('/api/get-job-no', (req, res) => {
  const jobNo = getNextJobNo();
  res.json({ job_no: jobNo });
});

// API: Generate report
app.post('/api/generate', async (req, res) => {
  try {
    const data = req.body;
    const jobNo = getNextJobNo();

    // Load template
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

        // For end_date, it's a labeled field
        if (field === 'end_date') {
          const existing = currentCell.value || '';
          const label = typeof existing === 'string' ? existing.split(':')[0] + ':' : '';
          currentCell.value = label ? `${label} ${formattedDate}` : formattedDate;
        } else {
          currentCell.value = formattedDate;
        }
      }
    }

    // Write labeled fields (append to existing label)
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
            fgColor: { argb: 'FFFFFF00' } // Yellow
          };
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

// Serve login page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'web', 'login.html'));
});

// Serve main app (index)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'web', 'index.html'));
});

// Serve static files from web directory
app.use(express.static(path.join(__dirname, 'web')));

// =============================================================================
// START SERVER
// =============================================================================

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`LDAP Server: ${LDAP_URL}`);
  console.log(`LDAP Base DN: ${LDAP_BASE_DN}`);
});
