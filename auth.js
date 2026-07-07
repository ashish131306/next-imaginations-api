// auth.js — accounts, sessions and self-service data rights (MongoDB build).
// Ported from the v12 SQLite implementation with an identical HTTP contract:
// sign-up with explicit consent (DPDP Act, 2023) · login via password OR email
// OTP · optional email-OTP MFA · profile, orders, payments, tickets, referrals,
// data export and full account deletion.
//
// The static site lives on www.nextimaginations.com and this API on
// api.nextimaginations.com — SAME SITE (one registrable domain), so the
// httpOnly SameSite=Lax session cookie flows on fetch() as long as the
// frontend sends credentials (the api-base.js shim forces credentials:
// "include" for /api/ calls) and CORS allows credentials (server.js does).

import { Router } from 'express';
import bcrypt from 'bcryptjs';
import PDFDocument from 'pdfkit';
import { createHash, randomBytes, randomInt, timingSafeEqual, createHmac } from 'node:crypto';
import { sendMail, sendBranded, otpMail, mailConfigured } from './mailer.js';
import * as adb from './account-db.js';

export const CONSENT_VERSION = '2026-07';
const IS_PROD = process.env.NODE_ENV === 'production';
// Dev-OTP echoes the code in the HTTP response for local testing ONLY.
const DEV_OTP = !IS_PROD && !mailConfigured && process.env.ALLOW_DEV_OTP === 'true';
if (IS_PROD && !mailConfigured) {
  console.error('\n  ⚠  FATAL: NODE_ENV=production but SMTP is not configured.');
  console.error('     OTP emails cannot be sent. Set SMTP_* in the environment.\n');
  process.exit(1);
}

const router = Router();
const sha = (s) => createHash('sha256').update(String(s)).digest('hex');
const isEmail = (s) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s || '');
const clean = (s, n) => String(s || '').trim().slice(0, n);
const safeEq = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
};

/* ── shared validators ────────────────────────────────────────── */
const parseAmount = (v) => {
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 && n <= 1e12 && Number.isInteger(n) ? n : null;
};
const ORDER_STATUSES = new Set(['quoted', 'active', 'delivered', 'closed', 'cancelled']);
const PAYMENT_STATUSES = new Set(['received', 'pending', 'refunded']);
const PAYMENT_METHODS = new Set(['upi', 'bank', 'card', 'cash', 'gateway']);

const COMMON_PW = new Set(['12345678', '123456789', '1234567890', 'password', 'password1',
  'qwerty123', 'iloveyou', 'admin123', '11111111', '00000000', 'abc12345', 'password123',
  'letmein1', 'welcome1', 'monkey12', 'football', 'baseball', 'superman', 'princess1']);
function passwordProblem(pw) {
  const s = String(pw || '');
  if (s.length < 8) return 'Password must be at least 8 characters.';
  if (s.length > 200) return 'Password is too long.';
  if (COMMON_PW.has(s.toLowerCase())) return 'That password is too common. Please choose a stronger one.';
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((re) => re.test(s)).length;
  if (classes < 2) return 'Use a mix of letters and numbers (or symbols) for a stronger password.';
  return null;
}

/* ── admin auth: constant-time bearer-token check (shared) ─────── */
export function adminAuthOk(req) {
  const token = process.env.ADMIN_TOKEN;
  if (!token) return false;
  const header = req.get('authorization') || '';
  const expected = `Bearer ${token}`;
  return header.length === expected.length && safeEq(header, expected);
}

/* ── sessions via httpOnly cookie ─────────────────────────────── */
const COOKIE = 'ni_session';
// In production the site (www.…) and API (api.…) are different origins on the
// same registrable domain. SameSite=None + Secure + an explicit parent Domain
// is the configuration every browser honours for credentialed subdomain
// fetches (Firefox is stricter than Chrome about Lax here). CSRF is covered
// by the Origin allowlist middleware in server.js.
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || (IS_PROD ? '.nextimaginations.com' : '');
const cookieTail = () =>
  (IS_PROD ? '; SameSite=None; Secure' : '; SameSite=Lax') +
  (COOKIE_DOMAIN ? `; Domain=${COOKIE_DOMAIN}` : '');
const cookieOpts = () => `HttpOnly; Path=/; Max-Age=${30 * 86400}` + cookieTail();

function readCookie(req) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > -1 && part.slice(0, i).trim() === COOKIE) return part.slice(i + 1).trim();
  }
  return null;
}
async function startSession(res, req, userId) {
  const token = randomBytes(32).toString('base64url');
  await adb.createSession(sha(token), userId, req.ip || null, clean(req.get('user-agent'), 300));
  res.append('Set-Cookie', `${COOKIE}=${token}; ${cookieOpts()}`);
}
async function endSession(res, req) {
  const t = readCookie(req);
  if (t) await adb.revokeSession(sha(t));
  res.append('Set-Cookie', `${COOKIE}=; HttpOnly; Path=/; Max-Age=0` + cookieTail());
}
export async function currentUser(req) {
  const t = readCookie(req);
  if (!t) return null;
  const s = await adb.sessionByHash(sha(t));
  if (!s) return null;
  return (await adb.userById(s.user_id)) || null;
}
function requireAuth(req, res, next) {
  currentUser(req).then((u) => {
    if (!u) return res.status(401).json({ ok: false, error: 'Please sign in.' });
    req.user = u;
    next();
  }).catch(next);
}

/* ── OTP issue / check ────────────────────────────────────────── */
async function issueOtp(email, purpose) {
  if ((await adb.recentOtps(email)) >= 8) {
    return { ok: false, error: 'Too many codes requested. Please try again in an hour.' };
  }
  const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
  await adb.createOtp(email, purpose, sha(code));
  const m = otpMail(code, purpose);
  const r = await sendMail({ to: email, subject: m.subject, text: m.text, html: m.html });
  const mailFailed = r && r.dev === false && r.ok === false;
  return { ok: true, mailFailed, ...(DEV_OTP ? { devOtp: code } : {}) };
}
async function checkOtp(email, purpose, code) {
  const row = await adb.freshOtp(email, purpose);
  if (!row) return { ok: false, error: 'Code expired or not found. Request a new one.' };
  if (row.attempts >= 5) return { ok: false, error: 'Too many attempts. Request a new code.' };
  await adb.bumpOtp(row.id);
  if (!safeEq(sha(clean(code, 6)), row.code_hash)) return { ok: false, error: 'Incorrect code.' };
  await adb.consumeOtp(row.id);
  return { ok: true };
}
const publicUser = (u) => ({
  id: u.id, name: u.name, email: u.email, phone: u.phone || '', company: u.company || '',
  emailVerified: Boolean(u.email_verified_at), mfaEnabled: Boolean(u.mfa_enabled),
  marketingOptin: Boolean(u.marketing_optin),
  consentVersion: u.consent_version, consentAt: u.consent_at, createdAt: u.created_at,
});

const notify = (to, subject, text) => sendMail({ to, subject, text }).catch(() => {});
const OWNER = () => process.env.NOTIFY_EMAIL || process.env.SMTP_USER || null;
const SITE = () => process.env.PUBLIC_URL || 'https://www.nextimaginations.com';

function sendWelcome(u) {
  return sendBranded({
    to: u.email,
    subject: 'Welcome to Next Imaginations',
    heading: `Welcome, ${String(u.name || '').split(' ')[0] || 'there'} 👋`,
    lines: [
      'Your account is verified and ready. Thanks for choosing Next Imaginations.',
      'From your dashboard you can track projects through every stage, view and download invoices, raise support tickets, and manage your details — all in one place.',
      'Whenever you want to start something, just reply to this email or open a conversation on the site. A principal reads every message, and we reply within one business day.',
    ],
    cta: { label: 'Open your dashboard', url: `${SITE()}/account.html` },
  });
}

/* ── registration (explicit consent required) ─────────────────── */
router.post('/register', async (req, res) => {
  const b = req.body || {};
  const name = clean(b.name, 120), email = clean(b.email, 200).toLowerCase();
  const password = String(b.password || '');
  if (!name) return res.status(400).json({ ok: false, error: 'Please enter your name.' });
  if (!isEmail(email)) return res.status(400).json({ ok: false, error: 'Please enter a valid email address.' });
  const pwErr = passwordProblem(password);
  if (pwErr) return res.status(400).json({ ok: false, error: pwErr });
  if (b.consent !== true) {
    return res.status(400).json({ ok: false, error: 'Please accept the Terms of Service and Privacy Policy to create an account.' });
  }
  if (await adb.userByEmail(email)) return res.status(409).json({ ok: false, error: 'An account with this email already exists. Try signing in.' });

  const refCode = clean(b.ref, 20) || null;
  const newId = await adb.createUser({
    name, email, phone: clean(b.phone, 30) || null, company: clean(b.company, 200) || null,
    password_hash: bcrypt.hashSync(password, 11),
    consent_version: CONSENT_VERSION,
    marketing_optin: b.marketing === true ? 1 : 0,
  });
  if (refCode && await adb.userByRef(refCode)) {
    await adb.setReferredBy(newId, refCode);
  }
  // Records are claimed only AFTER email verification — never here.
  const sent = await issueOtp(email, 'verify');
  console.log(`[account ${newId}] registered ${email}`);
  return res.json({ ok: true, next: 'verify',
    ...(sent.mailFailed ? { warning: 'Account created, but we couldn\'t send the verification email. Please contact us or try again shortly.' } : {}),
    ...(sent.devOtp ? { devOtp: sent.devOtp } : {}) });
});

router.post('/verify-email', async (req, res) => {
  const email = clean(req.body?.email, 200).toLowerCase();
  const r = await checkOtp(email, 'verify', req.body?.code);
  if (!r.ok) return res.status(400).json(r);
  const u = await adb.userByEmail(email);
  if (!u) return res.status(404).json({ ok: false, error: 'Account not found.' });
  await adb.verifyEmail(u.id);
  await adb.claimOrders(u.id, email);      // safe now: inbox control proven
  await adb.claimPayments(u.id, email);
  sendWelcome(u).catch(() => {});
  await startSession(res, req, u.id);
  return res.json({ ok: true, user: publicUser(await adb.userById(u.id)) });
});

router.post('/verify-email/resend', async (req, res) => {
  const email = clean(req.body?.email, 200).toLowerCase();
  if (!isEmail(email)) return res.status(400).json({ ok: false, error: 'Please enter a valid email address.' });
  const u = await adb.userByEmail(email);
  let dev = {};
  if (u && !u.email_verified_at) {
    const sent = await issueOtp(email, 'verify');
    if (!sent.ok) return res.status(429).json(sent);
    if (sent.devOtp) dev = { devOtp: sent.devOtp };
  }
  // Same response whether or not the account exists — no address probing.
  return res.json({ ok: true, message: 'If this email needs verification, a new code has been sent.', ...dev });
});

/* ── login: password (± MFA) ──────────────────────────────────── */
router.post('/login', async (req, res) => {
  const email = clean(req.body?.email, 200).toLowerCase();
  const u = await adb.userByEmail(email);
  const hash = u ? u.password_hash : '$2a$11$invalidinvalidinvalidinvalidinvalidinvalidinvalidinva';
  const good = bcrypt.compareSync(String(req.body?.password || ''), hash);
  if (!u || !good) return res.status(401).json({ ok: false, error: 'Incorrect email or password.' });
  if (!u.email_verified_at) {
    const sent = await issueOtp(email, 'verify');
    return res.status(403).json({ ok: false, next: 'verify', email,
      error: 'Please verify your email address first. We\'ve sent you a new code.',
      ...(sent.devOtp ? { devOtp: sent.devOtp } : {}) });
  }
  if (u.mfa_enabled) {
    const sent = await issueOtp(email, 'mfa');
    if (!sent.ok) return res.status(429).json(sent);
    return res.json({ ok: true, next: 'mfa', ...(sent.devOtp ? { devOtp: sent.devOtp } : {}) });
  }
  await startSession(res, req, u.id);
  return res.json({ ok: true, user: publicUser(u) });
});

router.post('/login/mfa', async (req, res) => {
  const email = clean(req.body?.email, 200).toLowerCase();
  const u = await adb.userByEmail(email);
  if (!u) return res.status(404).json({ ok: false, error: 'Account not found.' });
  const r = await checkOtp(email, 'mfa', req.body?.code);
  if (!r.ok) return res.status(400).json(r);
  await startSession(res, req, u.id);
  return res.json({ ok: true, user: publicUser(u) });
});

/* ── login: email OTP (passwordless) ──────────────────────────── */
router.post('/otp/request', async (req, res) => {
  const email = clean(req.body?.email, 200).toLowerCase();
  if (!isEmail(email)) return res.status(400).json({ ok: false, error: 'Please enter a valid email address.' });
  const u = await adb.userByEmail(email);
  let dev = {};
  if (u) {
    const sent = await issueOtp(email, 'login');
    if (!sent.ok) return res.status(429).json(sent);
    if (sent.devOtp) dev = { devOtp: sent.devOtp };
  }
  return res.json({ ok: true, message: 'If an account exists for this email, a sign-in code has been sent.', ...dev });
});

router.post('/otp/verify', async (req, res) => {
  const email = clean(req.body?.email, 200).toLowerCase();
  const u = await adb.userByEmail(email);
  if (!u) return res.status(400).json({ ok: false, error: 'Incorrect code.' });
  const r = await checkOtp(email, 'login', req.body?.code);
  if (!r.ok) return res.status(400).json(r);
  if (!u.email_verified_at) {
    await adb.verifyEmail(u.id);
    await adb.claimOrders(u.id, email);
    await adb.claimPayments(u.id, email);
    sendWelcome(u).catch(() => {});
  }
  await startSession(res, req, u.id);
  return res.json({ ok: true, user: publicUser(await adb.userById(u.id)) });
});

router.post('/logout', async (req, res) => { await endSession(res, req); res.json({ ok: true }); });

/* ── profile ──────────────────────────────────────────────────── */
router.get('/me', requireAuth, (req, res) => res.json({ ok: true, user: publicUser(req.user) }));

router.patch('/me', requireAuth, async (req, res) => {
  const b = req.body || {};
  const name = clean(b.name ?? req.user.name, 120);
  if (!name) return res.status(400).json({ ok: false, error: 'Name cannot be empty.' });
  await adb.updateProfile({
    id: req.user.id, name,
    phone: clean(b.phone ?? req.user.phone, 30) || null,
    company: clean(b.company ?? req.user.company, 200) || null,
    marketing_optin: (b.marketing ?? Boolean(req.user.marketing_optin)) === true ? 1 : 0,
  });
  return res.json({ ok: true, user: publicUser(await adb.userById(req.user.id)) });
});

router.post('/me/password', requireAuth, async (req, res) => {
  const { current, next } = req.body || {};
  if (!bcrypt.compareSync(String(current || ''), req.user.password_hash)) {
    return res.status(401).json({ ok: false, error: 'Current password is incorrect.' });
  }
  const pwErr = passwordProblem(next);
  if (pwErr) return res.status(400).json({ ok: false, error: pwErr });
  await adb.setPassword(bcrypt.hashSync(String(next), 11), req.user.id);
  await adb.revokeAll(req.user.id);            // sign out other sessions
  await startSession(res, req, req.user.id);   // keep the current device signed in
  return res.json({ ok: true });
});

/* ── MFA (email-OTP second factor) ────────────────────────────── */
router.post('/me/mfa/request', requireAuth, async (req, res) => {
  const sent = await issueOtp(req.user.email, 'mfa');
  if (!sent.ok) return res.status(429).json(sent);
  return res.json({ ok: true, ...(sent.devOtp ? { devOtp: sent.devOtp } : {}) });
});
router.post('/me/mfa', requireAuth, async (req, res) => {
  const enable = req.body?.enable === true;
  if (!enable && !bcrypt.compareSync(String(req.body?.password || ''), req.user.password_hash)) {
    return res.status(401).json({ ok: false, error: 'Enter your password to turn off two-step verification.' });
  }
  const r = await checkOtp(req.user.email, 'mfa', req.body?.code);
  if (!r.ok) return res.status(400).json(r);
  await adb.setMfa(enable ? 1 : 0, req.user.id);
  return res.json({ ok: true, mfaEnabled: enable });
});

/* ── orders · payments · enquiries · sessions ─────────────────── */
router.get('/me/orders', requireAuth, async (req, res) =>
  res.json({ ok: true, orders: await adb.ordersByUser(req.user.id, req.user.email) }));
router.get('/me/payments', requireAuth, async (req, res) =>
  res.json({ ok: true, payments: await adb.paymentsByUser(req.user.id, req.user.email) }));
router.get('/me/enquiries', requireAuth, async (req, res) =>
  res.json({ ok: true, enquiries: await adb.enquiriesByEmail(req.user.email) }));
router.get('/me/sessions', requireAuth, async (req, res) =>
  res.json({ ok: true, sessions: await adb.listSessions(req.user.id) }));
router.post('/me/sessions/revoke-others', requireAuth, async (req, res) => {
  await adb.revokeAll(req.user.id);
  await startSession(res, req, req.user.id);
  return res.json({ ok: true });
});

/* ── data export (right of access) ────────────────────────────── */
router.get('/me/export', requireAuth, async (req, res) => {
  const u = req.user;
  res.setHeader('Content-Disposition', 'attachment; filename="my-data-next-imaginations.json"');
  res.json({
    exportedAt: new Date().toISOString(),
    account: publicUser(u),
    orders: await adb.ordersByUser(u.id, u.email),
    payments: await adb.paymentsByUser(u.id, u.email),
    enquiries: await adb.enquiriesByEmail(u.email),
  });
});

/* ── account deletion (right to erasure) ──────────────────────── */
router.post('/me/delete/request', requireAuth, async (req, res) => {
  const sent = await issueOtp(req.user.email, 'delete');
  if (!sent.ok) return res.status(429).json(sent);
  return res.json({ ok: true, ...(sent.devOtp ? { devOtp: sent.devOtp } : {}) });
});
router.post('/me/delete', requireAuth, async (req, res) => {
  const u = req.user;
  if (!bcrypt.compareSync(String(req.body?.password || ''), u.password_hash)) {
    return res.status(401).json({ ok: false, error: 'Password is incorrect.' });
  }
  const r = await checkOtp(u.email, 'delete', req.body?.code);
  if (!r.ok) return res.status(400).json(r);
  await adb.anonOrders(u.id, u.email);
  await adb.anonPayments(u.id, u.email);
  await adb.anonEnquiries(u.email);
  await adb.purgeOtps(u.email);
  await adb.revokeAll(u.id);
  await adb.deleteUserCascade(u.id);
  await endSession(res, req);
  console.log(`[account] deleted user ${u.id} on request`);
  return res.json({ ok: true, message: 'Your account and personal data have been deleted.' });
});

/* ── referrals ────────────────────────────────────────────────── */
async function ensureRef(u) {
  if (u.ref_code) return u.ref_code;
  const code = 'NI' + randomBytes(4).toString('hex').toUpperCase();
  await adb.setRef(code, u.id);
  return code;
}
router.get('/me/referrals', requireAuth, async (req, res) => {
  const code = await ensureRef(req.user);
  const refs = (await adb.referrals(code)).map((r) => ({
    name: r.name.split(' ')[0],
    email: r.email.replace(/(.{2}).+(@.+)/, '$1•••$2'),
    joined: r.created_at,
  }));
  const credits = await adb.creditsByUser(req.user.id);
  const total = credits.reduce((a, b) => a + b.amount_inr, 0);
  res.json({ ok: true, code, link: `${SITE()}/account.html?ref=${code}`, referrals: refs, credits, totalCredit: total });
});

/* ── tickets ──────────────────────────────────────────────────── */
router.get('/me/tickets', requireAuth, async (req, res) => {
  const base = await adb.ticketsByUser(req.user.id);
  const list = [];
  for (const t of base) list.push({ ...t, replies: await adb.repliesFor(t.id) });
  res.json({ ok: true, tickets: list });
});
router.post('/me/tickets', requireAuth, async (req, res) => {
  const subject = clean(req.body?.subject, 200), body = clean(req.body?.body, 4000);
  if (!subject || !body) return res.status(400).json({ ok: false, error: 'Subject and message are required.' });
  const id = await adb.createTicket(req.user.id, subject);
  await adb.addReply(id, 'client', body);
  if (OWNER()) notify(OWNER(), `[Ticket ${id}] ${subject}`, `From ${req.user.name} <${req.user.email}>:\n\n${body}`);
  res.json({ ok: true, id });
});
router.post('/me/tickets/:id/reply', requireAuth, async (req, res) => {
  const t = await adb.ticketById(req.params.id, req.user.id);
  if (!t) return res.status(404).json({ ok: false, error: 'Ticket not found.' });
  const body = clean(req.body?.body, 4000);
  if (!body) return res.status(400).json({ ok: false, error: 'Message is required.' });
  await adb.addReply(t.id, 'client', body);
  await adb.touchTicket('open', t.id);
  if (OWNER()) notify(OWNER(), `[Ticket ${t.id}] client replied`, body);
  res.json({ ok: true });
});

/* ── admin: orders, payments, tickets, credits (Bearer ADMIN_TOKEN) ── */
function requireAdmin(req, res, next) {
  if (!adminAuthOk(req)) return res.status(401).json({ ok: false, error: 'Unauthorized' });
  next();
}
router.post('/admin/orders', requireAdmin, async (req, res) => {
  const b = req.body || {};
  const email = clean(b.email, 200).toLowerCase();
  const title = clean(b.title, 200);
  if (!title) return res.status(400).json({ ok: false, error: 'Order title is required.' });
  const amount = parseAmount(b.amount_inr);
  if (amount === null) return res.status(400).json({ ok: false, error: 'amount_inr must be a whole number ≥ 0.' });
  const status = clean(b.status, 30) || 'quoted';
  if (!ORDER_STATUSES.has(status)) return res.status(400).json({ ok: false, error: `status must be one of: ${[...ORDER_STATUSES].join(', ')}.` });
  const u = email ? await adb.userByEmail(email) : null;
  const id = await adb.createOrder({
    user_id: u ? u.id : null, email: email || null,
    title, service: clean(b.service, 120) || null,
    amount_inr: amount, status,
    notes: clean(b.notes, 2000) || null,
  });
  if (u) {
    sendBranded({
      to: u.email,
      subject: `Your project is confirmed — ${title}`,
      heading: 'Your project is confirmed',
      lines: [
        `Hi ${String(u.name).split(' ')[0]}, we've set up your project "${title}"${clean(b.service, 120) ? ` (${clean(b.service, 120)})` : ''}.`,
        amount > 0 ? `Agreed value: ₹${amount.toLocaleString('en-IN')} (exclusive of 18% GST). This is fixed and won't change.` : 'We\'ll confirm the value in your written quote.',
        'You can follow it through every stage — Discovery, Design, Build, Review, Live, Care — from your dashboard, and we\'ll email you as it progresses.',
      ],
      cta: { label: 'View your project', url: `${SITE()}/account.html#orders` },
    }).catch(() => {});
  }
  if (OWNER()) notify(OWNER(), `Order created — ${title} (₹${amount.toLocaleString('en-IN')})`, `For ${email || 'no account'}.`);
  res.json({ ok: true, id });
});
router.post('/admin/payments', requireAdmin, async (req, res) => {
  const b = req.body || {};
  const email = clean(b.email, 200).toLowerCase();
  const amount = parseAmount(b.amount_inr);
  if (amount === null) return res.status(400).json({ ok: false, error: 'amount_inr must be a whole number ≥ 0.' });
  const status = clean(b.status, 30) || 'received';
  if (!PAYMENT_STATUSES.has(status)) return res.status(400).json({ ok: false, error: `status must be one of: ${[...PAYMENT_STATUSES].join(', ')}.` });
  const method = clean(b.method, 30) || null;
  if (method && !PAYMENT_METHODS.has(method)) return res.status(400).json({ ok: false, error: `method must be one of: ${[...PAYMENT_METHODS].join(', ')}.` });
  const u = email ? await adb.userByEmail(email) : null;
  const id = await adb.createPayment({
    user_id: u ? u.id : null, order_id: clean(b.order_id, 40) || null, email: email || null,
    amount_inr: amount, method,
    reference: clean(b.reference, 120) || null, status,
    paid_at: clean(b.paid_at, 40) || adb.nowStr(),
  });
  if (u) {
    try {
      const p = await adb.paymentById(id, u.id, u.email);
      const o = p && p.order_id ? await adb.orderById(p.order_id) : null;
      const pdf = await buildInvoicePDF(p, u, o);
      const isReceipt = status === 'received';
      await sendBranded({
        to: u.email,
        subject: `${isReceipt ? 'Receipt' : 'Invoice'} ${invNo(id)} — Next Imaginations`,
        heading: isReceipt ? 'Payment received — thank you' : 'Your invoice is ready',
        lines: [
          `Hi ${String(u.name).split(' ')[0]}, ${isReceipt ? 'we\'ve received your payment' : 'here\'s your invoice'}${o ? ` for "${o.title}"` : ''}.`,
          `Amount: ₹${amount.toLocaleString('en-IN')} (exclusive of 18% GST).${isReceipt ? '' : ' Payment details are on the attached invoice.'}`,
          'The PDF is attached, and you can always find it in your dashboard under Payments.',
        ],
        cta: { label: 'View in dashboard', url: `${SITE()}/account.html#payments` },
        attachments: [{ filename: `${invNo(id)}.pdf`, content: pdf, contentType: 'application/pdf' }],
      });
    } catch (_) { /* email failure must not fail the API call */ }
  }
  if (OWNER()) notify(OWNER(), `Payment recorded — ₹${amount.toLocaleString('en-IN')}`, `For ${email || 'no account'} (${status}).`);
  res.json({ ok: true, id });
});
router.post('/admin/tickets/:id/reply', requireAdmin, async (req, res) => {
  const t = await adb.anyTicket(req.params.id);
  if (!t) return res.status(404).json({ ok: false, error: 'Not found' });
  const body = clean(req.body?.body, 4000);
  await adb.addReply(t.id, 'studio', body);
  await adb.touchTicket(clean(req.body?.status, 20) || 'answered', t.id);
  const u = await adb.userById(t.user_id);
  if (u) sendBranded({ to: u.email, subject: `Re: ${t.subject} — Next Imaginations support`,
    heading: 'A reply to your ticket', lines: [body, 'You can view the full thread and reply from your dashboard.'],
    cta: { label: 'Open support thread', url: `${SITE()}/account.html#support` } }).catch(() => {});
  res.json({ ok: true });
});

/* order milestone stage (admin) + client notifications */
const STAGES = ['Discovery', 'Design', 'Build', 'Review', 'Live', 'Care'];
router.post('/admin/orders/:id/stage', requireAdmin, async (req, res) => {
  const o = await adb.orderById(req.params.id);
  if (!o) return res.status(404).json({ ok: false, error: 'Not found' });
  const stage = Math.max(0, Math.min(5, Number(req.body?.stage) || 0));
  const status = clean(req.body?.status, 30) || o.status;
  await adb.setStage(stage, status, o.id);
  const u = o.user_id ? await adb.userById(o.user_id) : (o.email ? await adb.userByEmail(o.email) : null);
  if (u) notify(u.email, `Project update: ${o.title}`, `Your project "${o.title}" has moved to the ${STAGES[stage]} stage (status: ${status}).\n\nSee the full timeline in your dashboard → Orders.\n\n— Next Imaginations`);
  res.json({ ok: true, stage, status });
});

/* referral credit (admin) */
router.post('/admin/credits', requireAdmin, async (req, res) => {
  const email = clean(req.body?.email, 200).toLowerCase();
  const u = await adb.userByEmail(email);
  if (!u) return res.status(404).json({ ok: false, error: 'No account with that email.' });
  const amt = req.body?.amount_inr === undefined ? 5000 : parseAmount(req.body.amount_inr);
  if (amt === null || amt === 0) return res.status(400).json({ ok: false, error: 'amount_inr must be a whole number > 0.' });
  await adb.addCredit(u.id, amt, clean(req.body?.reason, 200) || 'Referral reward');
  sendBranded({ to: u.email, subject: `₹${amt.toLocaleString('en-IN')} credit added — Next Imaginations`,
    heading: 'Credit added to your account',
    lines: [`A credit of ₹${amt.toLocaleString('en-IN')} has been added to your account${req.body?.reason ? ` (${req.body.reason})` : ''}.`, 'It will be applied automatically to your next invoice.'],
    cta: { label: 'View your account', url: `${SITE()}/account.html` } }).catch(() => {});
  res.json({ ok: true });
});

/* ── branded PDF invoice for a payment ────────────────────────── */
const invNo = (id) => `NI-${String(id).slice(-6).toUpperCase()}`;
function buildInvoicePDF(p, user, o) {
  return new Promise((resolve, reject) => {
    const wine = '#2A0A12', gold = '#C6A052', ink = '#3A2A2E';
    const doc = new PDFDocument({ size: 'A4', margin: 56 });
    const chunks = [];
    doc.on('data', (c) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
    doc.rect(0, 0, doc.page.width, 118).fill(wine);
    doc.fillColor(gold).font('Times-Bold').fontSize(24).text('Next Imaginations', 56, 42);
    doc.font('Helvetica').fontSize(9).fillColor('#E8D9B0').text('Creative IT & Digital Studio · Chandigarh, India · nextimaginations.com', 56, 74);
    doc.fillColor(ink).font('Helvetica-Bold').fontSize(16).text(p.status === 'received' ? 'RECEIPT' : 'INVOICE', 56, 150);
    doc.font('Helvetica').fontSize(10).fillColor('#666');
    doc.text(`No. ${invNo(p.id)}`, 56, 174);
    doc.text(`Date: ${String(p.paid_at || p.created_at).slice(0, 10)}`, 56, 188);
    doc.text('Billed to', 340, 150);
    doc.fillColor(ink).font('Helvetica-Bold').text(user.name, 340, 164);
    doc.font('Helvetica').fillColor('#666').text(user.company || '', 340, 178).text(user.email, 340, user.company ? 192 : 178 + 14);
    let y = 240;
    doc.moveTo(56, y).lineTo(539, y).strokeColor(gold).lineWidth(1).stroke();
    y += 14;
    doc.fillColor('#999').fontSize(8).text('DESCRIPTION', 56, y).text('METHOD', 330, y).text('AMOUNT (INR)', 460, y, { align: 'right', width: 79 });
    y += 18;
    doc.fillColor(ink).fontSize(11).font('Helvetica')
      .text(o ? `${o.title}${o.service ? ' — ' + o.service : ''}` : 'Professional services', 56, y, { width: 260 })
      .text((p.method || '—').toUpperCase(), 330, y)
      .font('Helvetica-Bold').text(`₹ ${Number(p.amount_inr).toLocaleString('en-IN')}`, 400, y, { align: 'right', width: 139 });
    y += 40;
    if (p.reference) { doc.font('Helvetica').fontSize(9).fillColor('#666').text(`Reference: ${p.reference}`, 56, y); y += 16; }
    doc.moveTo(56, y).lineTo(539, y).strokeColor('#DDD').lineWidth(0.5).stroke();
    y += 12;
    doc.fillColor('#666').fontSize(9).text(`Status: ${p.status.toUpperCase()}`, 56, y);
    doc.fillColor(ink).font('Helvetica-Bold').fontSize(13).text(`Total  ₹ ${Number(p.amount_inr).toLocaleString('en-IN')}`, 340, y, { align: 'right', width: 199 });
    y += 44;
    doc.font('Helvetica').fontSize(8).fillColor('#999')
      .text('Amounts are exclusive of GST unless stated. This document is generated from your Next Imaginations client account.', 56, y, { width: 483 })
      .text('Questions? nextimaginations@gmail.com · +91 89300 06242', 56, y + 24);
    doc.end();
  });
}

router.get('/me/payments/:id/invoice.pdf', requireAuth, async (req, res) => {
  const p = await adb.paymentById(req.params.id, req.user.id, req.user.email);
  if (!p) return res.status(404).json({ ok: false, error: 'Payment not found.' });
  const o = p.order_id ? await adb.orderById(p.order_id) : null;
  const pdf = await buildInvoicePDF(p, req.user, o);
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `inline; filename="${invNo(p.id)}.pdf"`);
  res.send(pdf);
});

/* ── Razorpay — active only when keys are configured ──────────── */
const RZP_ID = process.env.RAZORPAY_KEY_ID, RZP_SECRET = process.env.RAZORPAY_KEY_SECRET;
router.post('/me/payments/:id/rzp-order', requireAuth, async (req, res) => {
  if (!RZP_ID || !RZP_SECRET) return res.status(400).json({ ok: false, error: 'Online payments are not enabled yet.' });
  const p = await adb.paymentById(req.params.id, req.user.id, req.user.email);
  if (!p || p.status !== 'pending') return res.status(400).json({ ok: false, error: 'No pending payment found.' });
  const r = await fetch('https://api.razorpay.com/v1/orders', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Basic ' + Buffer.from(`${RZP_ID}:${RZP_SECRET}`).toString('base64') },
    body: JSON.stringify({ amount: p.amount_inr * 100, currency: 'INR', receipt: invNo(p.id) }),
  });
  const data = await r.json();
  if (!r.ok) return res.status(502).json({ ok: false, error: 'Payment gateway error.' });
  res.json({ ok: true, orderId: data.id, keyId: RZP_ID, amount: p.amount_inr * 100, name: req.user.name, email: req.user.email });
});
router.post('/me/payments/:id/rzp-verify', requireAuth, async (req, res) => {
  if (!RZP_SECRET) return res.status(400).json({ ok: false, error: 'Not enabled.' });
  const p = await adb.paymentById(req.params.id, req.user.id, req.user.email);
  const { order_id, payment_id, signature } = req.body || {};
  if (!p || !order_id || !payment_id || !signature) return res.status(400).json({ ok: false, error: 'Invalid request.' });
  const expect = createHmac('sha256', RZP_SECRET).update(order_id + '|' + payment_id).digest('hex');
  if (!safeEq(expect, signature)) return res.status(400).json({ ok: false, error: 'Signature mismatch.' });
  await adb.markPaid('RZP:' + payment_id, p.id);
  if (OWNER()) notify(OWNER(), `Payment received — ₹${p.amount_inr.toLocaleString('en-IN')}`, `Client ${req.user.email} paid payment ${p.id} online (${payment_id}).`);
  res.json({ ok: true });
});

export default router;
