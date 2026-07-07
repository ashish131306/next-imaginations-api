// server.js — Next Imaginations enquiry API (Render + MongoDB Atlas build).
//
// API-only: the static site lives on Vercel. Endpoints:
//
//   GET   /api/health          — liveness probe (used by Render health checks)
//   POST  /api/enquiries       — record a contact-form or bundle-builder enquiry
//   GET   /api/enquiries       — list enquiries      (Bearer ADMIN_TOKEN)
//   PATCH /api/enquiries/:id   — update lead status  (Bearer ADMIN_TOKEN)
//
// Data lives in MongoDB (Atlas in production) — the service itself is
// stateless, so it needs no persistent disk and restarts are harmless.

import 'dotenv/config';
import express from 'express';
import { lookup } from 'node:dns/promises';
import { connectDb, createEnquiry, listEnquiries, countEnquiries, setStatus, closeDb } from './db.js';
import { recordPageview } from './db.js';
import { ensureAccountIndexes } from './account-db.js';
import authRouter, { adminAuthOk } from './auth.js';
import { verifyMail, mailConfigured } from './mailer.js';

const app = express();
const PORT = process.env.PORT || 3000;

// Render sits behind a proxy — this makes req.ip the real client IP,
// which the per-IP rate limiter below depends on.
app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use((req, res, next) => {
  if ((req.headers['x-forwarded-proto'] || '').includes('https')) {
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
  }
  next();
});

app.use(express.json({ limit: '64kb' }));

/* ---------------------------------------------------------------- CORS --- */

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS ||
  'https://nextimaginations.com,https://www.nextimaginations.com')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

function originAllowed(origin) {
  if (!origin) return false;
  if (ALLOWED_ORIGINS.includes(origin)) return true;
  // Allow Vercel preview deployments (e.g. next-imaginations-git-main-xyz.vercel.app)
  try {
    const { hostname, protocol } = new URL(origin);
    return protocol === 'https:' && hostname.endsWith('.vercel.app');
  } catch {
    return false;
  }
}

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && originAllowed(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Max-Age', '86400');
  }
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

/* -------------------------------------------------- Per-IP rate limiter --- */

const WINDOW_MS = 60_000; // 1 minute

function makeLimiter(maxHits, message = 'Too many requests. Please try again shortly.') {
  const hits = new Map();
  setInterval(() => {
    const cutoff = Date.now() - WINDOW_MS;
    for (const [ip, arr] of hits) {
      const fresh = arr.filter((t) => t > cutoff);
      if (fresh.length) hits.set(ip, fresh);
      else hits.delete(ip);
    }
  }, WINDOW_MS).unref();
  return function limiter(req, res, next) {
    const ip = req.ip || 'unknown';
    const now = Date.now();
    const arr = (hits.get(ip) || []).filter((t) => t > now - WINDOW_MS);
    arr.push(now);
    hits.set(ip, arr);
    if (arr.length > maxHits) {
      return res.status(429).json({ ok: false, error: message });
    }
    next();
  };
}
// The account dashboard fires ~9 API calls per page-load, so the general
// limit must comfortably allow a few loads per minute. Overridable via env.
const rateLimit = makeLimiter(Number(process.env.RATE_LIMIT_GENERAL || 60));
const authLimiter = makeLimiter(Number(process.env.RATE_LIMIT_AUTH || 10), 'Too many attempts. Please wait a minute.');

/* ----------------------------------------------------------- Admin auth --- */

function requireAdmin(req, res, next) {
  if (!adminAuthOk(req)) return res.status(401).json({ ok: false, error: 'Unauthorised.' });
  next();
}

/* ---------------------------------------------------------------- Routes --- */

app.get('/api/health', async (_req, res) => {
  try {
    res.json({ ok: true, service: 'next-imaginations-api', db: 'mongodb', enquiries: await countEnquiries() });
  } catch {
    res.status(503).json({ ok: false, error: 'Database unreachable.' });
  }
});

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

app.post('/api/enquiries', rateLimit, async (req, res) => {
  const b = req.body || {};

  // Honeypot: real users never fill the hidden "website" field.
  // Bots do — respond as if it worked, store nothing.
  if (typeof b.website === 'string' && b.website.trim() !== '') {
    return res.json({ ok: true });
  }

  const name = String(b.name || '').trim().slice(0, 120);
  const email = String(b.email || '').trim().slice(0, 200);
  const message = String(b.message || '').trim().slice(0, 5000);

  const errors = [];
  if (name.length < 2) errors.push('Please tell us your name.');
  if (!EMAIL_RE.test(email)) errors.push('That email address does not look valid.');
  if (message.length < 5) errors.push('Please include a short message.');
  if (errors.length) return res.status(400).json({ ok: false, errors });

  try {
    const id = await createEnquiry({
      name,
      email,
      company: b.company ? String(b.company).trim().slice(0, 200) : null,
      interest: b.interest ? String(b.interest).trim().slice(0, 200) : null,
      message,
      source: b.source ? String(b.source).trim().slice(0, 40) : 'contact',
      services: b.services,
      estimate: b.estimate,
      ip: req.ip || null,
      user_agent: String(req.headers['user-agent'] || '').slice(0, 300) || null,
    });

    // Notification hook placeholder — wire up email/WhatsApp alerts here later.
    // notifyNewEnquiry(id);

    res.status(201).json({ ok: true, id });
  } catch (err) {
    console.error('createEnquiry failed:', err.message);
    res.status(500).json({ ok: false, error: 'Could not save your enquiry. Please try again or call us directly.' });
  }
});

app.get('/api/enquiries', requireAdmin, async (_req, res) => {
  try {
    res.json({ ok: true, enquiries: await listEnquiries() });
  } catch (err) {
    console.error('listEnquiries failed:', err.message);
    res.status(500).json({ ok: false, error: 'Could not read enquiries.' });
  }
});

app.patch('/api/enquiries/:id', requireAdmin, async (req, res) => {
  const status = String(req.body?.status || '').trim();
  const allowed = ['new', 'contacted', 'in-progress', 'won', 'closed'];
  if (!allowed.includes(status)) {
    return res.status(400).json({ ok: false, error: `Status must be one of: ${allowed.join(', ')}` });
  }
  try {
    const found = await setStatus(req.params.id, status);
    if (!found) return res.status(404).json({ ok: false, error: 'No enquiry with that id.' });
    res.json({ ok: true });
  } catch {
    res.status(400).json({ ok: false, error: 'Invalid enquiry id.' });
  }
});


/* -------------------------------------------------------- Account API --- */

// Public runtime config for the account UI (Razorpay key when enabled).
app.get('/api/config', (_req, res) => res.json({ ok: true, rzpKey: process.env.RAZORPAY_KEY_ID || null }));

// CSRF defence for the cookie-authenticated account routes: a mutating
// request that carries a browser Origin must come from an allowed origin.
// (Bearer-token admin calls and non-browser clients send no Origin.)
app.use('/api/auth', (req, res, next) => {
  if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && !(req.headers.authorization || '').startsWith('Bearer ')) {
    const origin = req.headers.origin;
    if (origin && !originAllowed(origin)) {
      return res.status(403).json({ ok: false, error: 'Cross-site request refused.' });
    }
  }
  next();
});

// Tighter limiter on credential endpoints, general limiter elsewhere.
app.use('/api/auth', (req, res, next) => {
  if (/^\/(register|login(\/mfa)?|otp\/(request|verify)|verify-email)$/.test(req.path)) {
    return authLimiter(req, res, next);
  }
  return rateLimit(req, res, next);
});

app.use('/api/auth', authRouter);

/* ------------------------------------------------ Site support routes --- */
// Ported from the full v12 server so the static site keeps working:
// founding-spots counter, page-view beacon, and the site-check lead magnet.

app.get('/api/spots', (_req, res) => {
  const left = Number(process.env.SPOTS_LEFT ?? 25);
  res.json({ ok: true, left: Number.isFinite(left) ? left : 25 });
});

app.post('/api/pv', async (req, res) => {
  try {
    let path = String(req.body?.path || req.body?.p || '/').slice(0, 200);
    if (!path.startsWith('/')) path = '/';
    path = path.split('?')[0].split('#')[0];
    await recordPageview(path);
  } catch { /* analytics must never break anything */ }
  res.status(204).end();
});

// Free website health check (lead magnet). SSRF-guarded: DNS-resolves the
// target and refuses private/loopback ranges, standard ports only.
const PRIVATE = [/^10\./, /^127\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./, /^169\.254\./, /^0\./, /^::1$/, /^f[cd]/i];
app.post('/api/tools/site-check', rateLimit, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  let url = String(req.body?.url || '').trim();
  if (!EMAIL_RE.test(email)) return res.status(400).json({ ok: false, error: 'Please enter a valid email so we can send you the report.' });
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  let u; try { u = new URL(url); } catch { return res.status(400).json({ ok: false, error: 'That does not look like a valid URL.' }); }
  if (!['http:', 'https:'].includes(u.protocol) || (u.port && !['80', '443'].includes(u.port))) {
    return res.status(400).json({ ok: false, error: 'Only standard http/https URLs are supported.' });
  }
  try {
    const a = await lookup(u.hostname);
    if (PRIVATE.some((re) => re.test(a.address))) return res.status(400).json({ ok: false, error: 'That host cannot be scanned.' });
  } catch { return res.status(400).json({ ok: false, error: 'We could not resolve that domain.' }); }

  const t0 = Date.now();
  let resp, html = '';
  try {
    resp = await fetch(u.href, { redirect: 'follow', signal: AbortSignal.timeout(9000), headers: { 'User-Agent': 'NI-SiteCheck/1.0 (+https://nextimaginations.com)' } });
    html = (await resp.text()).slice(0, 400_000);
  } catch { return res.status(400).json({ ok: false, error: 'We could not reach that site (it may be down or blocking scanners).' }); }
  const ms = Date.now() - t0;
  const h = (n) => resp.headers.get(n) || '';
  const m = (re) => (html.match(re) || [])[1] || '';
  const imgs = html.match(/<img\b[^>]*>/gi) || [];
  const withAlt = imgs.filter((t) => /\balt\s*=\s*["'][^"']+["']/i.test(t)).length;
  const checks = [
    { k: 'HTTPS in use', ok: resp.url.startsWith('https://'), w: 3, tip: 'Serve the site over HTTPS with a valid certificate.' },
    { k: 'Response time under 1.5s', ok: ms < 1500, w: 3, tip: `First response took ${ms} ms — aim for under 1500 ms.` },
    { k: 'Title tag present (10\u201365 chars)', ok: (() => { const t = m(/<title[^>]*>([^<]*)<\/title>/i).trim(); return t.length >= 10 && t.length <= 65; })(), w: 2, tip: 'Write a unique 10\u201365 character title for search results.' },
    { k: 'Meta description present', ok: /<meta[^>]+name=["']description["'][^>]+content=["'][^"']{40,}/i.test(html), w: 2, tip: 'Add a 120\u2013160 character meta description.' },
    { k: 'Single H1 heading', ok: (html.match(/<h1[\s>]/gi) || []).length === 1, w: 1, tip: 'Use exactly one H1 per page.' },
    { k: 'Viewport meta (mobile-ready)', ok: /<meta[^>]+name=["']viewport["']/i.test(html), w: 2, tip: 'Add a responsive viewport meta tag.' },
    { k: 'Image alt coverage \u2265 80%', ok: imgs.length === 0 || withAlt / imgs.length >= 0.8, w: 1, tip: `Only ${withAlt}/${imgs.length} images have alt text.` },
    { k: 'Compression enabled', ok: /gzip|br|deflate/.test(h('content-encoding')), w: 2, tip: 'Enable gzip/brotli compression on the server.' },
    { k: 'HSTS header', ok: Boolean(h('strict-transport-security')), w: 2, tip: 'Add Strict-Transport-Security to enforce HTTPS.' },
    { k: 'X-Content-Type-Options', ok: h('x-content-type-options').toLowerCase() === 'nosniff', w: 1, tip: 'Add X-Content-Type-Options: nosniff.' },
    { k: 'Clickjacking protection', ok: Boolean(h('x-frame-options')) || /frame-ancestors/i.test(h('content-security-policy')), w: 1, tip: 'Add X-Frame-Options or a frame-ancestors CSP.' },
    { k: 'Caching configured', ok: Boolean(h('cache-control')), w: 1, tip: 'Set Cache-Control headers for static assets.' },
  ];
  const max = checks.reduce((a, c) => a + c.w, 0);
  const got = checks.reduce((a, c) => a + (c.ok ? c.w : 0), 0);
  const score = Math.round((got / max) * 100);
  try {
    await createEnquiry({ name: 'Site-check lead', email, company: null, interest: 'Website health check', message: `Scanned ${u.href} \u2014 score ${score}/100 (${ms} ms).`, source: 'tool', ip: req.ip, user_agent: String(req.headers['user-agent'] || '').slice(0, 300) });
  } catch { /* the scan result still goes back to the visitor */ }
  res.json({ ok: true, score, ms, url: resp.url, checks: checks.map(({ k, ok, tip }) => ({ k, ok, tip })) });
});

app.use((_req, res) => res.status(404).json({ ok: false, error: 'Not found.' }));

/* ------------------------------------------------------------------ Boot --- */

try {
  await connectDb();
  await ensureAccountIndexes();
  console.log('MongoDB connected.');
} catch (err) {
  console.error('FATAL: could not connect to MongoDB —', err.message);
  process.exit(1);
}

if (mailConfigured) {
  verifyMail().then((r) => console.log(r.ok ? 'SMTP verified.' : `SMTP PROBLEM: ${r.error || ''} ${r.response || ''}`));
} else {
  console.log('SMTP not configured — mail falls back to console logging.');
}

const server = app.listen(PORT, () => {
  console.log(`Next Imaginations API listening on :${PORT}`);
  console.log(`Allowed origins: ${ALLOWED_ORIGINS.join(', ')} (+ *.vercel.app previews)`);
});

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    server.close(async () => {
      await closeDb().catch(() => {});
      process.exit(0);
    });
  });
}
