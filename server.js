'use strict';

require('dotenv').config();

const path = require('node:path');
const crypto = require('node:crypto');
const fs = require('node:fs');
const express = require('express');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const connectPgSimple = require('connect-pg-simple');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const requiredEnvironment = ['DATABASE_URL', 'SESSION_SECRET', 'OTP_SECRET'];
const missingEnvironment = requiredEnvironment.filter(name => !process.env[name]);
if (missingEnvironment.length) {
  console.error(`Missing required environment values: ${missingEnvironment.join(', ')}`);
  console.error('Copy .env.example to .env and fill in the required values.');
  process.exit(1);
}

if (process.env.SESSION_SECRET.length < 32 || process.env.OTP_SECRET.length < 32) {
  console.error('SESSION_SECRET and OTP_SECRET must each be at least 32 characters long.');
  process.exit(1);
}

const app = express();
const port = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === 'production';
const isLocalDatabase = /localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL);
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isLocalDatabase ? false : { rejectUnauthorized: true },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const allowedSubjects = new Set([
  'Mathematics', 'English', 'Biology', 'Chemistry', 'Physics',
  'Individuals & Societies', 'Design', 'Arts', 'Language acquisition', 'Other'
]);

app.disable('x-powered-by');
if (isProduction) app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'self'"],
      fontSrc: ["'self'", 'data:'],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      imgSrc: ["'self'", 'data:'],
      objectSrc: ["'none'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"]
    }
  }
}));
app.use(express.json({ limit: '150kb' }));

const PgSessionStore = connectPgSimple(session);
app.use(session({
  name: 'study_desk.sid',
  store: new PgSessionStore({
    pool,
    tableName: 'study_desk_sessions',
    createTableIfMissing: true,
    pruneSessionInterval: 60 * 15
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000
  }
}));

app.use(express.static(path.join(__dirname, 'public'), {
  extensions: ['html'],
  maxAge: isProduction ? '1h' : 0
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 12,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many account attempts. Please wait a little and try again.' }
});
const verifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many code attempts. Please wait before trying again.' }
});

function normaliseEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function validEmail(value) {
  return value.length <= 120 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validDate(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T00:00:00.000Z`);
  return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === value;
}

function otpHash(userId, code) {
  return crypto.createHmac('sha256', process.env.OTP_SECRET)
    .update(`${userId}:${code}`)
    .digest('hex');
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[char]);
}

async function sendVerificationEmail(email, name, code) {
  if (!process.env.RESEND_API_KEY || !process.env.EMAIL_FROM) {
    throw new Error('Email service is not configured. Set RESEND_API_KEY and EMAIL_FROM.');
  }

  const safeName = escapeHtml(name);
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: process.env.EMAIL_FROM,
      to: [email],
      subject: 'Your Study Desk verification code',
      text: `Hi ${name},\n\nYour Study Desk verification code is ${code}. It expires in 10 minutes. If you did not request this, you can ignore this email.`,
      html: `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;color:#26332d;line-height:1.6"><h2>Verify your Study Desk account</h2><p>Hi ${safeName},</p><p>Enter this code in Study Desk to confirm your email address:</p><p style="font-size:32px;font-weight:700;letter-spacing:8px;background:#f1f5f0;padding:16px 20px;border-radius:8px;display:inline-block">${code}</p><p>This code expires in <strong>10 minutes</strong> and can only be used once.</p><p>If you did not create this account, you can ignore this email.</p></div>`
    })
  });

  if (!response.ok) {
    const details = await response.text().catch(() => '');
    console.error('Email provider returned an error:', response.status, details.slice(0, 500));
    throw new Error('The verification email could not be sent. Check your email provider setup.');
  }
}

async function sendNewCode(user) {
  const code = String(crypto.randomInt(0, 100000)).padStart(5, '0');
  const codeHash = otpHash(user.id, code);
  await pool.query(
    `UPDATE users
     SET verification_code_hash = $1,
         verification_expires_at = NOW() + INTERVAL '10 minutes',
         verification_attempts = 0,
         last_code_sent_at = NOW()
     WHERE id = $2`,
    [codeHash, user.id]
  );

  try {
    await sendVerificationEmail(user.email, user.name, code);
  } catch (error) {
    await pool.query(
      `UPDATE users SET verification_code_hash = NULL,
       verification_expires_at = NULL, last_code_sent_at = NULL
       WHERE id = $1`,
      [user.id]
    );
    throw error;
  }
}

function startUserSession(req, userId) {
  return new Promise((resolve, reject) => {
    req.session.regenerate(error => {
      if (error) return reject(error);
      req.session.userId = String(userId);
      req.session.save(saveError => saveError ? reject(saveError) : resolve());
    });
  });
}

function requireUser(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Please sign in to continue.' });
  }
  next();
}

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

app.get('/api/auth/me', asyncRoute(async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not signed in.' });
  const result = await pool.query(
    'SELECT id, name, email FROM users WHERE id = $1 AND email_verified_at IS NOT NULL',
    [req.session.userId]
  );
  if (!result.rowCount) {
    req.session.destroy(() => {});
    return res.status(401).json({ error: 'Please sign in again.' });
  }
  res.json({ user: result.rows[0] });
}));

app.post('/api/auth/signup', authLimiter, asyncRoute(async (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = normaliseEmail(req.body.email);
  const password = String(req.body.password || '');

  if (name.length < 2 || name.length > 50) return res.status(400).json({ error: 'Enter a name between 2 and 50 characters.' });
  if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (password.length < 8 || Buffer.byteLength(password, 'utf8') > 72) {
    return res.status(400).json({ error: 'Your password must be at least 8 characters and no longer than 72 bytes.' });
  }

  const existing = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  if (existing.rowCount && existing.rows[0].email_verified_at) {
    return res.status(409).json({ error: 'An account with this email already exists. Please sign in instead.' });
  }

  if (existing.rowCount && existing.rows[0].last_code_sent_at) {
    const lastSent = new Date(existing.rows[0].last_code_sent_at).getTime();
    if (Date.now() - lastSent < 60000) {
      return res.status(429).json({ error: 'A code was sent recently. Check your inbox or wait a minute before requesting another.' });
    }
  }

  const passwordHash = await bcrypt.hash(password, 12);
  let user;
  if (existing.rowCount) {
    const result = await pool.query(
      'UPDATE users SET name = $1, password_hash = $2 WHERE id = $3 RETURNING id, name, email',
      [name, passwordHash, existing.rows[0].id]
    );
    user = result.rows[0];
  } else {
    const result = await pool.query(
      'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email',
      [name, email, passwordHash]
    );
    user = result.rows[0];
  }

  try {
    await sendNewCode(user);
  } catch (error) {
    console.error('Could not send signup code:', error.message);
    return res.status(503).json({ error: 'The verification email could not be sent right now. Please try again later.' });
  }

  res.status(202).json({ message: 'A five-digit verification code has been sent.', email });
}));

app.post('/api/auth/resend-code', authLimiter, asyncRoute(async (req, res) => {
  const email = normaliseEmail(req.body.email);
  if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });

  const result = await pool.query(
    'SELECT id, name, email, email_verified_at, last_code_sent_at FROM users WHERE email = $1',
    [email]
  );
  if (!result.rowCount || result.rows[0].email_verified_at) {
    return res.json({ message: 'If the account needs verification, a new code will be sent.' });
  }

  const user = result.rows[0];
  if (user.last_code_sent_at && Date.now() - new Date(user.last_code_sent_at).getTime() < 60000) {
    return res.status(429).json({ error: 'Please wait one minute before requesting another code.' });
  }
  try {
    await sendNewCode(user);
  } catch (error) {
    console.error('Could not resend verification code:', error.message);
    return res.status(503).json({ error: 'The email could not be sent. Please try again later.' });
  }
  res.json({ message: 'A new code has been sent.' });
}));

app.post('/api/auth/verify-email', verifyLimiter, asyncRoute(async (req, res) => {
  const email = normaliseEmail(req.body.email);
  const code = String(req.body.code || '').trim();
  if (!validEmail(email) || !/^\d{5}$/.test(code)) {
    return res.status(400).json({ error: 'Enter the email address and the five-digit code.' });
  }

  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  if (!result.rowCount) return res.status(400).json({ error: 'That code could not be verified. Request a new one and try again.' });
  const user = result.rows[0];
  if (user.email_verified_at) {
    await startUserSession(req, user.id);
    return res.json({ user: { id: user.id, name: user.name, email: user.email } });
  }
  if (!user.verification_code_hash || !user.verification_expires_at || new Date(user.verification_expires_at).getTime() < Date.now()) {
    return res.status(400).json({ error: 'That code has expired. Request a new code.' });
  }
  if (user.verification_attempts >= 5) {
    return res.status(429).json({ error: 'Too many incorrect codes. Request a new code.' });
  }

  const submittedHash = otpHash(user.id, code);
  if (!safeEqual(submittedHash, user.verification_code_hash)) {
    await pool.query('UPDATE users SET verification_attempts = verification_attempts + 1 WHERE id = $1', [user.id]);
    return res.status(400).json({ error: 'That code is not correct. Check the email and try again.' });
  }

  await pool.query(
    `UPDATE users SET email_verified_at = NOW(), verification_code_hash = NULL,
     verification_expires_at = NULL, verification_attempts = 0, last_code_sent_at = NULL
     WHERE id = $1`,
    [user.id]
  );
  await startUserSession(req, user.id);
  res.json({ user: { id: user.id, name: user.name, email: user.email } });
}));

app.post('/api/auth/login', authLimiter, asyncRoute(async (req, res) => {
  const email = normaliseEmail(req.body.email);
  const password = String(req.body.password || '');
  if (!validEmail(email) || !password) return res.status(400).json({ error: 'Enter your email address and password.' });

  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  if (!result.rowCount) return res.status(401).json({ error: 'Email or password is incorrect.' });
  const user = result.rows[0];
  const passwordMatches = await bcrypt.compare(password, user.password_hash);
  if (!passwordMatches) return res.status(401).json({ error: 'Email or password is incorrect.' });
  if (!user.email_verified_at) {
    return res.status(403).json({
      code: 'EMAIL_NOT_VERIFIED',
      error: 'Please verify your email before signing in.'
    });
  }

  await startUserSession(req, user.id);
  res.json({ user: { id: user.id, name: user.name, email: user.email } });
}));

app.post('/api/auth/logout', asyncRoute(async (req, res) => {
  if (!req.session) return res.json({ message: 'Signed out.' });
  await new Promise(resolve => req.session.destroy(() => resolve()));
  res.clearCookie('study_desk.sid', {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax'
  });
  res.json({ message: 'Signed out.' });
}));

app.get('/api/workspace', requireUser, asyncRoute(async (req, res) => {
  const [assignmentResult, sessionResult] = await Promise.all([
    pool.query(
      `SELECT id, title, subject, to_char(due_date, 'YYYY-MM-DD') AS due,
       priority, completed FROM assignments WHERE user_id = $1 ORDER BY due_date, created_at`,
      [req.session.userId]
    ),
    pool.query(
      `SELECT id, topic, subject, to_char(session_date, 'YYYY-MM-DD') AS date,
       to_char(session_time, 'HH24:MI') AS time FROM study_sessions
       WHERE user_id = $1 ORDER BY session_date, session_time`,
      [req.session.userId]
    )
  ]);
  res.json({ assignments: assignmentResult.rows, sessions: sessionResult.rows });
}));

app.post('/api/assignments', requireUser, asyncRoute(async (req, res) => {
  const task = req.body || {};
  const id = String(task.id || '');
  const title = String(task.title || '').trim();
  const subject = String(task.subject || '');
  const due = String(task.due || '');
  const priority = String(task.priority || 'Normal');
  if (!id || id.length > 80 || !title || title.length > 100 || !allowedSubjects.has(subject) || !validDate(due) || !['Normal', 'Important', 'High'].includes(priority)) {
    return res.status(400).json({ error: 'Check the assignment details and try again.' });
  }
  await pool.query(
    `INSERT INTO assignments (user_id, id, title, subject, due_date, priority, completed)
     VALUES ($1, $2, $3, $4, $5, $6, FALSE)`,
    [req.session.userId, id, title, subject, due, priority]
  );
  res.status(201).json({ message: 'Assignment saved.' });
}));

app.patch('/api/assignments/:id', requireUser, asyncRoute(async (req, res) => {
  const id = String(req.params.id || '');
  if (!id || id.length > 80 || typeof req.body.completed !== 'boolean') {
    return res.status(400).json({ error: 'Invalid assignment update.' });
  }
  const result = await pool.query(
    'UPDATE assignments SET completed = $1 WHERE user_id = $2 AND id = $3',
    [req.body.completed, req.session.userId, id]
  );
  if (!result.rowCount) return res.status(404).json({ error: 'Assignment not found.' });
  res.json({ message: 'Assignment updated.' });
}));

app.delete('/api/assignments/:id', requireUser, asyncRoute(async (req, res) => {
  const id = String(req.params.id || '');
  if (!id || id.length > 80) return res.status(400).json({ error: 'Invalid assignment.' });
  await pool.query('DELETE FROM assignments WHERE user_id = $1 AND id = $2', [req.session.userId, id]);
  res.json({ message: 'Assignment deleted.' });
}));

app.post('/api/sessions', requireUser, asyncRoute(async (req, res) => {
  const item = req.body || {};
  const id = String(item.id || '');
  const topic = String(item.topic || '').trim();
  const subject = String(item.subject || '');
  const date = String(item.date || '');
  const time = String(item.time || '');
  if (!id || id.length > 80 || !topic || topic.length > 90 || !allowedSubjects.has(subject) || !validDate(date) || !/^([01]\d|2[0-3]):[0-5]\d$/.test(time)) {
    return res.status(400).json({ error: 'Check the study session details and try again.' });
  }
  await pool.query(
    `INSERT INTO study_sessions (user_id, id, topic, subject, session_date, session_time)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [req.session.userId, id, topic, subject, date, time]
  );
  res.status(201).json({ message: 'Study session saved.' });
}));

app.delete('/api/sessions/:id', requireUser, asyncRoute(async (req, res) => {
  const id = String(req.params.id || '');
  if (!id || id.length > 80) return res.status(400).json({ error: 'Invalid study session.' });
  await pool.query('DELETE FROM study_sessions WHERE user_id = $1 AND id = $2', [req.session.userId, id]);
  res.json({ message: 'Study session deleted.' });
}));

app.get(/.*/, (req, res, next) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'API route not found.' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((error, req, res, next) => {
  console.error('Request failed:', error);
  if (res.headersSent) return next(error);
  res.status(500).json({ error: 'Something went wrong. Please try again.' });
});

async function start() {
  const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  await pool.query(schema);
  app.listen(port, () => console.log(`Study Desk is running on port ${port}`));
}

start().catch(error => {
  console.error('Could not start Study Desk:', error);
  process.exit(1);
});

process.on('SIGTERM', async () => {
  await pool.end();
  process.exit(0);
});
