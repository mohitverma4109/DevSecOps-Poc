/**
 * HARDENED APPLICATION (security-scan clean-baseline edition)
 * -------------------------------------------------------------
 * This is the fixed/secure counterpart of the deliberately vulnerable
 * training app. Use this version when you want a clean run through
 * the DevSecOps pipeline (Gitleaks, SonarQube, Dependency-Check,
 * Trivy, ZAP) to validate the pipeline mechanics themselves, without
 * the intentional findings blocking every stage.
 *
 * Fixes applied vs. the vulnerable version:
 *  - No hardcoded secrets - everything comes from environment variables
 *  - Parameterized SQL queries (no injection)
 *  - Passwords hashed with bcrypt, never stored/compared in plaintext
 *  - JWTs have an expiry and a pinned signing algorithm
 *  - Role is actually checked on admin-only routes
 *  - Output is HTML-escaped before being reflected (no XSS)
 *  - CORS restricted to an explicit allow-list instead of '*'
 *  - No eval, no dynamic code execution
 *  - No arbitrary file reads, no SSRF, no shell command execution
 *  - Generic error responses - no stack traces or env dumps leaked
 *  - lodash upgraded past the prototype-pollution CVE
 * -------------------------------------------------------------
 */
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const morgan = require('morgan');
const sqlite3 = require('sqlite3').verbose();
const helmet = require('helmet');

const app = express();
const PORT = process.env.PORT || 3000;

// -----------------------------------------------------------------
// Secrets come ONLY from the environment. Fail fast if missing rather
// than falling back to a hardcoded default.
// -----------------------------------------------------------------
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is not set.');
  process.exit(1);
}

// -----------------------------------------------------------------
// Restrictive security defaults
// -----------------------------------------------------------------
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').filter(Boolean);
app.use(cors({
  origin: ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS : false, // deny cross-origin by default
}));
app.use(helmet());
app.use(bodyParser.json({ limit: '100kb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '100kb' }));
app.use(morgan('combined'));

const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, role TEXT)');
  const seed = async () => {
    const adminHash = await bcrypt.hash('ChangeMe!123', 12);
    const userHash = await bcrypt.hash('ChangeMe!456', 12);
    db.run('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', ['admin', adminHash, 'admin']);
    db.run('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', ['alice', userHash, 'user']);
  };
  seed();
});

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

app.get('/', (req, res) => {
  res.json({ status: 'ok', app: 'devsecops-hardened-poc', version: '1.0.0' });
});

// -----------------------------------------------------------------
// Fixed: parameterized query - no SQL injection possible.
// -----------------------------------------------------------------
app.get('/api/users/search', (req, res) => {
  const username = req.query.username || '';
  db.all('SELECT id, username, role FROM users WHERE username = ?', [username], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Query failed' });
    res.json(rows);
  });
});

// -----------------------------------------------------------------
// Fixed: hashed password comparison, parameterized query, signed JWT
// with an explicit algorithm and expiry.
// -----------------------------------------------------------------
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '15m' }
    );
    res.json({ token });
  });
});

function requireRole(role) {
  return (req, res, next) => {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.replace('Bearer ', '');
    try {
      const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
      if (decoded.role !== role) return res.status(403).json({ error: 'Forbidden' });
      req.user = decoded;
      next();
    } catch (e) {
      res.status(401).json({ error: 'Unauthorized' });
    }
  };
}

// -----------------------------------------------------------------
// Fixed: role is actually enforced, not just "a valid token exists".
// -----------------------------------------------------------------
app.get('/api/admin/users', requireRole('admin'), (req, res) => {
  db.all('SELECT id, username, role FROM users', (err, rows) => {
    if (err) return res.status(500).json({ error: 'Query failed' });
    res.json(rows);
  });
});

// -----------------------------------------------------------------
// Fixed: output is HTML-escaped before being reflected - no XSS.
// -----------------------------------------------------------------
app.get('/api/greet', (req, res) => {
  const name = escapeHtml(req.query.name || 'guest');
  res.send(`<h1>Hello, ${name}!</h1>`);
});

// -----------------------------------------------------------------
// Fixed: no unsafe deep-merge of untrusted input; explicit allow-list
// of the only fields a client may set, no prototype-pollution vector.
// -----------------------------------------------------------------
app.post('/api/merge-config', (req, res) => {
  const { theme, notifications } = req.body || {};
  const merged = {
    theme: typeof theme === 'string' ? theme : 'light',
    notifications: typeof notifications === 'boolean' ? notifications : true,
  };
  res.json(merged);
});

// -----------------------------------------------------------------
// Generic error handler - no stack traces or internals leaked.
// -----------------------------------------------------------------
app.use((err, req, res, next) => {
  console.error(err); // full detail stays in server logs only
  res.status(500).json({ error: 'Internal server error' });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Hardened POC app listening on port ${PORT}`);
});

module.exports = app;
