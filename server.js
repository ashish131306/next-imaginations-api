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
import { verifyMail, mailConfigured, sendMail, sendBranded } from './mailer.js';

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
  // A JSON/PDF API never needs to run scripts, be framed, or be embedded
  // cross-origin — say so explicitly on every response.
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-site');
  next();
});

app.use(express.json({ limit: '64kb' }));

/* ------------------------------------------------ Email automation ----- */
// Where new-lead alerts go, and a nicely formatted brand contact block.
const OWNER_EMAIL = process.env.NOTIFY_EMAIL || process.env.SMTP_USER || 'nextimaginations@gmail.com';
const SITE_URL = process.env.PUBLIC_URL || 'https://www.nextimaginations.com';
const inr = (n) => '₹' + Number(n || 0).toLocaleString('en-IN');

// Fire-and-forget: e-mail must never delay or break the API response.
function notifyNewEnquiry(lead) {
  const first = String(lead.name || 'there').split(' ')[0];
  const src = lead.source || 'contact';

  // (a) Owner alert — full lead detail, one-tap reply.
  const detail = [
    `New ${src} enquiry from ${lead.name} <${lead.email}>.`,
    lead.company ? `Company: ${lead.company}` : null,
    lead.interest ? `Interest: ${lead.interest}` : null,
    Array.isArray(lead.services) && lead.services.length ? `Services: ${lead.services.join(', ')}` : null,
    lead.estimate && (lead.estimate.once || lead.estimate.monthly)
      ? `Estimate: ${lead.estimate.once ? inr(lead.estimate.once) + ' one-time' : ''}${lead.estimate.monthly ? ' + ' + inr(lead.estimate.monthly) + '/mo' : ''}` : null,
    '',
    'Message:',
    lead.message || '(none)',
  ].filter((x) => x !== null);
  sendBranded({
    to: OWNER_EMAIL,
    subject: `New ${src} enquiry — ${lead.name}`,
    heading: `New enquiry from ${lead.name}`,
    lines: detail,
    cta: { label: `Reply to ${first}`, url: `mailto:${lead.email}?subject=Re:%20your%20enquiry%20to%20Next%20Imaginations` },
  }).catch((e) => console.error('[mail] owner notify failed:', e.message));

  // (b) Auto-acknowledgment to the person who wrote in.
  const ackLines = [
    `Thanks for reaching out to Next Imaginations. This is a quick automatic note to confirm your message arrived safely — nothing more is needed from you right now.`,
    `A principal reads every enquiry personally and will reply within one business day. If it's urgent, call or WhatsApp us on +91 89300 06242.`,
  ];
  if (src === 'bundle') ackLines.push('We\'ll come back with a clear, fixed quote for the services you selected — no open meters, no surprises.');
  sendBranded({
    to: lead.email,
    subject: 'We received your message — Next Imaginations',
    heading: `Thanks, ${first} — we\'ve got it`,
    lines: ackLines,
    cta: { label: 'Explore our work', url: `${SITE_URL}/work` },
  }).catch((e) => console.error('[mail] ack failed:', e.message));
}

// Site-check tool: e-mail the actual scan report to the visitor + alert owner.
function notifySiteCheck({ email, url, score, ms, checks }) {
  const passed = checks.filter((c) => c.ok).length;
  const failing = checks.filter((c) => !c.ok);
  const first = (email.split('@')[0] || 'there');
  const reportLines = [
    `Here's your free website health check for ${url}.`,
    `Overall score: ${score}/100  (${passed} of ${checks.length} checks passed, first response ${ms} ms).`,
  ];
  if (failing.length) {
    reportLines.push('', 'Top things worth fixing:');
    failing.slice(0, 6).forEach((c) => reportLines.push(`• ${c.k} — ${c.tip}`));
  } else {
    reportLines.push('', 'Every check passed — your site is in great shape.');
  }
  reportLines.push('', 'Want us to fix these for you? Reply to this email or call +91 89300 06242. Your first project comes at founding-client rates.');
  sendBranded({
    to: email,
    subject: `Your website health check — ${score}/100`,
    heading: `Your site scored ${score}/100`,
    lines: reportLines,
    cta: { label: 'Talk to us about fixing these', url: `${SITE_URL}/contact` },
  }).catch((e) => console.error('[mail] site-check report failed:', e.message));

  sendMail({
    to: OWNER_EMAIL,
    subject: `Tool lead — ${email} scanned a site (${score}/100)`,
    text: `${email} ran the free site check on ${url} and scored ${score}/100. Follow up within a business day.`,
  }).catch((e) => console.error('[mail] site-check owner notify failed:', e.message));
}

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
    await countEnquiries(); // round-trips the database
    res.json({ ok: true, service: 'next-imaginations-api', db: 'ok' });
  } catch {
    res.status(503).json({ ok: false, error: 'Database unreachable.' });
  }
});

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Deep-copy a client-supplied object, dropping any key that starts with '$'
// or contains '.', so nothing operator-shaped is ever stored.
function sanitizeObj(v, depth = 0) {
  if (depth > 4 || v === null || typeof v !== 'object') return v;
  if (Array.isArray(v)) return v.slice(0, 24).map((x) => sanitizeObj(x, depth + 1));
  const out = {};
  for (const [k, val] of Object.entries(v)) {
    if (k.startsWith('$') || k.includes('.')) continue;
    out[k.slice(0, 64)] = sanitizeObj(val, depth + 1);
  }
  return out;
}

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
      services: Array.isArray(b.services) ? sanitizeObj(b.services) : null,
      estimate: b.estimate && typeof b.estimate === 'object' ? sanitizeObj(b.estimate) : null,
      ip: req.ip || null,
      user_agent: String(req.headers['user-agent'] || '').slice(0, 300) || null,
    });

    // Owner alert + auto-acknowledgment (async; never blocks the response).
    notifyNewEnquiry({ id, name, email,
      company: b.company ? String(b.company).trim().slice(0, 200) : null,
      interest: b.interest ? String(b.interest).trim().slice(0, 200) : null,
      message, source: b.source ? String(b.source).trim().slice(0, 40) : 'contact',
      services: Array.isArray(b.services) ? sanitizeObj(b.services) : null,
      estimate: b.estimate && typeof b.estimate === 'object' ? sanitizeObj(b.estimate) : null });

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
  if (/^\/(register|login(\/mfa)?|otp\/(request|verify)|verify-email(\/resend)?)$/.test(req.path)) {
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
    // Follow up to 3 redirects MANUALLY, re-validating each hop's hostname
    // against the private-range list, so a public URL can't bounce the
    // scanner into internal networks.
    let hop = u, redirects = 0;
    for (;;) {
      resp = await fetch(hop.href, { redirect: 'manual', signal: AbortSignal.timeout(9000), headers: { 'User-Agent': 'NI-SiteCheck/1.0 (+https://nextimaginations.com)' } });
      if (![301, 302, 303, 307, 308].includes(resp.status)) break;
      if (++redirects > 3) return res.status(400).json({ ok: false, error: 'That site redirects too many times.' });
      const loc = resp.headers.get('location');
      if (!loc) break;
      hop = new URL(loc, hop);
      if (!['http:', 'https:'].includes(hop.protocol) || (hop.port && !['80', '443'].includes(hop.port))) {
        return res.status(400).json({ ok: false, error: 'That site redirects somewhere we cannot scan.' });
      }
      const hopAddr = await lookup(hop.hostname).catch(() => null);
      if (!hopAddr || PRIVATE.some((re) => re.test(hopAddr.address))) {
        return res.status(400).json({ ok: false, error: 'That site redirects somewhere we cannot scan.' });
      }
    }
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
  const publicChecks = checks.map(({ k, ok, tip }) => ({ k, ok, tip }));
  notifySiteCheck({ email, url: resp.url, score, ms, checks: publicChecks });
  res.json({ ok: true, score, ms, url: resp.url, checks: publicChecks });
});

app.use((_req, res) => res.status(404).json({ ok: false, error: 'Not found.' }));

// Last-resort error handler: log with an id, never leak internals.
app.use((err, req, res, _next) => {
  const id = Math.random().toString(36).slice(2, 10);
  console.error(`[err ${id}] ${req.method} ${req.path} — ${err.status || 500} ${err.message}`);
  if (res.headersSent) return;
  const status = err.type === 'entity.too.large' ? 413 : (err.status && err.status < 500 ? err.status : 500);
  const msg = status === 413 ? 'Request too large.' : status < 500 ? 'Bad request.' : `Something went wrong on our side (ref ${id}).`;
  res.status(status).json({ ok: false, error: msg });
});

process.on('unhandledRejection', (e) => console.error('[unhandledRejection]', e?.message || e));
process.on('uncaughtException', (e) => { console.error('[uncaughtException]', e?.stack || e); });

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

// Keep-alive must outlive the platform load-balancer's idle window to avoid
// sporadic 502s; cap slow requests instead of leaving sockets open for ages.
server.keepAliveTimeout = 120_000;
server.headersTimeout = 125_000;
server.requestTimeout = 30_000;

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    server.close(async () => {
      await closeDb().catch(() => {});
      process.exit(0);
    });
  });
}
