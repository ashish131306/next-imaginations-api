// account-db.js — MongoDB data layer for accounts, sessions, OTPs, orders,
// payments, tickets and credits. Ported 1:1 from the SQLite q/q2 layer so
// auth.js behaves identically.
//
// Convention notes (kept deliberately SQLite-compatible for the frontend):
//   • All timestamps are STRINGS in "YYYY-MM-DD HH:MM:SS" (UTC). The account
//     dashboard parses/slices these, and the format sorts lexicographically,
//     so string comparison works for expiry checks too.
//   • Documents expose `id` (the ObjectId as a string); user_id/order_id etc.
//     store those same strings.
//   • Emails are stored lowercase; matching against enquiry/order emails is
//     case-insensitive.

import { ObjectId } from 'mongodb';
import { collections } from './db.js';
import { encrypt, decrypt } from './crypto-fields.js';

const c = collections; // { users, otps, sessions, orders, payments, tickets, ticketReplies, credits, enquiries }

export const nowStr = (offsetMs = 0) =>
  new Date(Date.now() + offsetMs).toISOString().slice(0, 19).replace('T', ' ');

const oid = (v) => { try { return new ObjectId(String(v)); } catch { return null; } };
const pub = (doc) => doc ? { ...doc, id: String(doc._id) } : null;
const ciEmail = (email) =>
  new RegExp(`^${String(email).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i');

export async function ensureAccountIndexes() {
  await c.users.createIndex({ email: 1 }, { unique: true, name: 'uniq_email' });
  await c.users.createIndex({ ref_code: 1 }, { name: 'idx_ref', sparse: true });
  await c.otps.createIndex({ email: 1, purpose: 1, consumed_at: 1 }, { name: 'idx_otp_lookup' });
  await c.sessions.createIndex({ token_hash: 1 }, { unique: true, name: 'uniq_token' });
  await c.sessions.createIndex({ user_id: 1 }, { name: 'idx_sess_user' });
  await c.orders.createIndex({ user_id: 1 }, { name: 'idx_orders_user' });
  await c.orders.createIndex({ email: 1 }, { name: 'idx_orders_email', sparse: true });
  await c.payments.createIndex({ user_id: 1 }, { name: 'idx_pay_user' });
  await c.payments.createIndex({ email: 1 }, { name: 'idx_pay_email', sparse: true });
  await c.tickets.createIndex({ user_id: 1 }, { name: 'idx_tickets_user' });
  await c.ticketReplies.createIndex({ ticket_id: 1 }, { name: 'idx_replies_ticket' });
  await c.credits.createIndex({ user_id: 1 }, { name: 'idx_credits_user' });
  // Self-cleaning collections: expired OTPs vanish after a day, session rows a
  // month after their own 30-day expiry, failed-login counters after an hour.
  await c.otps.createIndex({ created_dt: 1 }, { expireAfterSeconds: 86400, name: 'ttl_otps' });
  await c.sessions.createIndex({ created_dt: 1 }, { expireAfterSeconds: 35 * 86400, name: 'ttl_sessions' });
  await c.authFails.createIndex({ ts: 1 }, { expireAfterSeconds: 3600, name: 'ttl_fails' });
  await c.authFails.createIndex({ k: 1, ts: 1 }, { name: 'idx_fails_k' });
}

/* ── durable brute-force throttle (survives restarts) ──────────── */
export async function recordAuthFail(key) {
  await c.authFails.insertOne({ k: String(key).toLowerCase(), ts: new Date() });
}
export async function authFailCount(key, windowMs = 15 * 60 * 1000) {
  return c.authFails.countDocuments({ k: String(key).toLowerCase(), ts: { $gt: new Date(Date.now() - windowMs) } });
}
export async function clearAuthFails(key) {
  await c.authFails.deleteMany({ k: String(key).toLowerCase() });
}

/* ── users ─────────────────────────────────────────────────────── */
function decUser(u) {
  if (!u) return u;
  if (u.phone) u.phone = decrypt(u.phone);
  if (u.totp_secret) u.totp_secret = decrypt(u.totp_secret);
  return u;
}
export async function userByEmail(email) {
  return decUser(pub(await c.users.findOne({ email: String(email).toLowerCase() })));
}
export async function userById(id) {
  const _id = oid(id); if (!_id) return null;
  return decUser(pub(await c.users.findOne({ _id })));
}
export async function createUser(u) {
  const { insertedId } = await c.users.insertOne({
    name: u.name, email: u.email, phone: encrypt(u.phone), company: u.company,
    password_hash: u.password_hash,
    email_verified_at: null, mfa_enabled: 0,
    consent_version: u.consent_version, consent_at: nowStr(),
    marketing_optin: u.marketing_optin ? 1 : 0,
    ref_code: null, referred_by: null,
    created_at: nowStr(), updated_at: nowStr(),
  });
  return String(insertedId);
}
export async function verifyEmail(id) {
  await c.users.updateOne({ _id: oid(id) }, { $set: { email_verified_at: nowStr(), updated_at: nowStr() } });
}
export async function updateProfile(p) {
  await c.users.updateOne({ _id: oid(p.id) }, {
    $set: { name: p.name, phone: encrypt(p.phone), company: p.company, marketing_optin: p.marketing_optin ? 1 : 0, updated_at: nowStr() },
  });
}
export async function setPassword(hash, id) {
  await c.users.updateOne({ _id: oid(id) }, { $set: { password_hash: hash, updated_at: nowStr() } });
}
export async function setMfa(on, id) {
  await c.users.updateOne({ _id: oid(id) }, { $set: { mfa_enabled: on ? 1 : 0, updated_at: nowStr() } });
}
export async function setTotpSecret(id, secret) {
  await c.users.updateOne({ _id: oid(id) }, { $set: { totp_secret: encrypt(secret), totp_enabled: 0, updated_at: nowStr() } });
}
export async function enableTotp(id) {
  await c.users.updateOne({ _id: oid(id) }, { $set: { totp_enabled: 1, updated_at: nowStr() } });
}
export async function disableTotp(id) {
  await c.users.updateOne({ _id: oid(id) }, { $set: { totp_secret: null, totp_enabled: 0, updated_at: nowStr() } });
}
export async function setReferredBy(id, code) {
  await c.users.updateOne({ _id: oid(id) }, { $set: { referred_by: code } });
}
export async function userByRef(code) {
  return pub(await c.users.findOne({ ref_code: code }));
}
export async function setRef(code, id) {
  await c.users.updateOne({ _id: oid(id) }, { $set: { ref_code: code } });
}
export async function referrals(code) {
  return (await c.users.find({ referred_by: code })
    .project({ name: 1, email: 1, created_at: 1 }).toArray()).map(pub);
}
export async function deleteUserCascade(id) {
  const uid = String(id);
  const tix = await c.tickets.find({ user_id: uid }).project({ _id: 1 }).toArray();
  if (tix.length) await c.ticketReplies.deleteMany({ ticket_id: { $in: tix.map((t) => String(t._id)) } });
  await c.tickets.deleteMany({ user_id: uid });
  await c.credits.deleteMany({ user_id: uid });
  await c.sessions.deleteMany({ user_id: uid });
  await c.users.deleteOne({ _id: oid(id) });
}

/* ── OTPs ──────────────────────────────────────────────────────── */
export async function createOtp(email, purpose, codeHash) {
  await c.otps.insertOne({
    email: String(email).toLowerCase(), purpose, code_hash: codeHash,
    expires_at: nowStr(10 * 60 * 1000), attempts: 0, consumed_at: null, created_at: nowStr(),
    created_dt: new Date(),
  });
}
export async function freshOtp(email, purpose) {
  return pub(await c.otps.find({
    email: String(email).toLowerCase(), purpose, consumed_at: null, expires_at: { $gt: nowStr() },
  }).sort({ _id: -1 }).limit(1).next());
}
export async function bumpOtp(id) {
  await c.otps.updateOne({ _id: oid(id) }, { $inc: { attempts: 1 } });
}
export async function consumeOtp(id) {
  await c.otps.updateOne({ _id: oid(id) }, { $set: { consumed_at: nowStr() } });
}
export async function recentOtps(email) {
  return c.otps.countDocuments({ email: String(email).toLowerCase(), created_at: { $gt: nowStr(-3600 * 1000) } });
}
export async function purgeOtps(email) {
  await c.otps.deleteMany({ email: String(email).toLowerCase() });
}

/* ── sessions ──────────────────────────────────────────────────── */
export async function createSession(tokenHash, userId, ip, ua) {
  await c.sessions.insertOne({
    token_hash: tokenHash, user_id: String(userId),
    created_at: nowStr(), expires_at: nowStr(30 * 86400 * 1000),
    ip: ip || null, user_agent: ua || null, revoked_at: null, created_dt: new Date(),
  });
}
export async function sessionByHash(tokenHash) {
  return pub(await c.sessions.findOne({ token_hash: tokenHash, revoked_at: null, expires_at: { $gt: nowStr() } }));
}
export async function revokeSession(tokenHash) {
  await c.sessions.updateOne({ token_hash: tokenHash }, { $set: { revoked_at: nowStr() } });
}
export async function revokeAll(userId) {
  await c.sessions.updateMany({ user_id: String(userId) }, { $set: { revoked_at: nowStr() } });
}
export async function listSessions(userId) {
  return (await c.sessions.find({ user_id: String(userId), revoked_at: null, expires_at: { $gt: nowStr() } })
    .sort({ _id: -1 }).project({ token_hash: 0 }).toArray()).map(pub);
}

/* ── orders · payments · enquiries ─────────────────────────────── */
export async function ordersByUser(userId, email) {
  return (await c.orders.find({ $or: [{ user_id: String(userId) }, { email: ciEmail(email) }] })
    .sort({ _id: -1 }).toArray()).map(pub);
}
export async function paymentsByUser(userId, email) {
  return (await c.payments.find({ $or: [{ user_id: String(userId) }, { email: ciEmail(email) }] })
    .sort({ _id: -1 }).toArray()).map(pub);
}
export async function enquiriesByEmail(email) {
  return (await c.enquiries.find({ email: ciEmail(email) }).sort({ _id: -1 }).limit(100)
    .project({ interest: 1, message: 1, source: 1, status: 1, created_at: 1 }).toArray())
    .map((e) => ({ ...pub(e), message: decrypt(e.message), created_at: fmtDate(e.created_at) }));
}
// enquiries.created_at is a BSON Date (written by the enquiry API) — render it
// in the same string format the dashboard expects.
const fmtDate = (d) => d instanceof Date ? d.toISOString().slice(0, 19).replace('T', ' ') : d;

export async function createOrder(o) {
  const { insertedId } = await c.orders.insertOne({
    user_id: o.user_id ? String(o.user_id) : null, email: o.email,
    title: o.title, service: o.service, amount_inr: o.amount_inr,
    status: o.status, notes: o.notes, stage: 0,
    created_at: nowStr(), updated_at: nowStr(),
  });
  return String(insertedId);
}
export async function createPayment(p) {
  const { insertedId } = await c.payments.insertOne({
    user_id: p.user_id ? String(p.user_id) : null,
    order_id: p.order_id ? String(p.order_id) : null,
    email: p.email, amount_inr: p.amount_inr, method: p.method,
    reference: p.reference, status: p.status, paid_at: p.paid_at, created_at: nowStr(),
  });
  return String(insertedId);
}
export async function claimOrders(userId, email) {
  await c.orders.updateMany({ user_id: null, email: ciEmail(email) }, { $set: { user_id: String(userId) } });
}
export async function claimPayments(userId, email) {
  await c.payments.updateMany({ user_id: null, email: ciEmail(email) }, { $set: { user_id: String(userId) } });
}
export async function orderById(id) {
  const _id = oid(id); if (!_id) return null;
  return pub(await c.orders.findOne({ _id }));
}
export async function paymentById(id, userId, email) {
  const _id = oid(id); if (!_id) return null;
  return pub(await c.payments.findOne({ _id, $or: [{ user_id: String(userId) }, { email: ciEmail(email) }] }));
}
export async function setStage(stage, status, id) {
  await c.orders.updateOne({ _id: oid(id) }, { $set: { stage, status, updated_at: nowStr() } });
}
export async function markPaid(reference, id) {
  await c.payments.updateOne({ _id: oid(id) }, { $set: { status: 'received', reference, paid_at: nowStr() } });
}

/* ── erasure (right to be forgotten; ledgers anonymised) ───────── */
export async function anonOrders(userId, email) {
  await c.orders.updateMany({ $or: [{ user_id: String(userId) }, { email: ciEmail(email) }] },
    { $set: { user_id: null, email: null } });
}
export async function anonPayments(userId, email) {
  await c.payments.updateMany({ $or: [{ user_id: String(userId) }, { email: ciEmail(email) }] },
    { $set: { user_id: null, email: null } });
}
export async function anonEnquiries(email) {
  await c.enquiries.updateMany({ email: ciEmail(email) },
    { $set: { name: '[deleted user]', email: 'deleted@user.invalid', company: null, ip: null, user_agent: null } });
}

/* ── tickets ───────────────────────────────────────────────────── */
export async function createTicket(userId, subject) {
  const { insertedId } = await c.tickets.insertOne({
    user_id: String(userId), subject, status: 'open', created_at: nowStr(), updated_at: nowStr(),
  });
  return String(insertedId);
}
export async function ticketsByUser(userId) {
  return (await c.tickets.find({ user_id: String(userId) }).sort({ _id: -1 }).toArray()).map(pub);
}
export async function ticketById(id, userId) {
  const _id = oid(id); if (!_id) return null;
  return pub(await c.tickets.findOne({ _id, user_id: String(userId) }));
}
export async function anyTicket(id) {
  const _id = oid(id); if (!_id) return null;
  return pub(await c.tickets.findOne({ _id }));
}
export async function touchTicket(status, id) {
  await c.tickets.updateOne({ _id: oid(id) }, { $set: { status, updated_at: nowStr() } });
}
export async function addReply(ticketId, author, body) {
  await c.ticketReplies.insertOne({ ticket_id: String(ticketId), author, body, created_at: nowStr() });
}
export async function repliesFor(ticketId) {
  return (await c.ticketReplies.find({ ticket_id: String(ticketId) }).sort({ _id: 1 })
    .project({ author: 1, body: 1, created_at: 1, _id: 0 }).toArray());
}

/* ── credits ───────────────────────────────────────────────────── */
export async function creditsByUser(userId) {
  return (await c.credits.find({ user_id: String(userId) }).sort({ _id: -1 })
    .project({ amount_inr: 1, reason: 1, created_at: 1, _id: 0 }).toArray());
}
export async function addCredit(userId, amount, reason) {
  await c.credits.insertOne({ user_id: String(userId), amount_inr: amount, reason, created_at: nowStr() });
}

/* ── admin: sessions + read-all views for the owner dashboard ───── */
export async function createAdminSession(tokenHash, ip, ua) {
  await c.adminSessions.insertOne({
    token_hash: tokenHash, created_at: nowStr(), created_dt: new Date(),
    expires_at: nowStr(7 * 86400 * 1000), ip: ip || null, user_agent: ua || null,
  });
}
export async function adminSessionValid(tokenHash) {
  return Boolean(await c.adminSessions.findOne({ token_hash: tokenHash, expires_at: { $gt: nowStr() } }));
}
export async function revokeAdminSession(tokenHash) {
  await c.adminSessions.deleteOne({ token_hash: tokenHash });
}

export async function adminAllEnquiries(limit = 500) {
  return (await c.enquiries.find({}).sort({ created_at: -1, _id: -1 }).limit(limit).toArray())
    .map((e) => ({ ...pub(e), message: decrypt(e.message), created_at: fmtDate(e.created_at) }));
}
export async function setEnquiryStatus(id, status) {
  const _id = oid(id); if (!_id) return false;
  const r = await c.enquiries.updateOne({ _id }, { $set: { status: String(status).slice(0, 40) } });
  return r.matchedCount === 1;
}
export async function adminAllOrders() {
  return (await c.orders.find({}).sort({ _id: -1 }).limit(1000).toArray()).map(pub);
}
export async function adminAllPayments() {
  return (await c.payments.find({}).sort({ _id: -1 }).limit(1000).toArray()).map(pub);
}
export async function adminAllTickets() {
  const tix = (await c.tickets.find({}).sort({ _id: -1 }).limit(500).toArray()).map(pub);
  for (const t of tix) {
    t.replies = await c.ticketReplies.find({ ticket_id: String(t._id || t.id) }).sort({ _id: 1 }).project({ _id: 0 }).toArray();
    const u = await c.users.findOne({ _id: oid(t.user_id) }, { projection: { name: 1, email: 1 } });
    t.client = u ? { name: u.name, email: u.email } : null;
  }
  return tix;
}
export async function adminAllClients() {
  return (await c.users.find({}).sort({ _id: -1 }).limit(1000)
    .project({ password_hash: 0 }).toArray())
    .map((u) => ({ id: String(u._id), name: u.name, email: u.email, phone: decrypt(u.phone) || '', company: u.company || '',
      emailVerified: Boolean(u.email_verified_at), created_at: u.created_at }));
}
export async function adminStats() {
  const [leads, clients, orders, tickets] = await Promise.all([
    c.enquiries.countDocuments(), c.users.countDocuments(), c.orders.countDocuments(),
    c.tickets.countDocuments({ status: { $ne: 'closed' } }),
  ]);
  const newLeads = await c.enquiries.countDocuments({ status: 'new' });
  const paid = await c.payments.aggregate([
    { $match: { status: 'received' } }, { $group: { _id: null, sum: { $sum: '$amount_inr' } } },
  ]).toArray();
  const subs = await c.subscribers.countDocuments();
  return { leads, newLeads, clients, orders, openTickets: tickets, revenue: paid[0]?.sum || 0, subscribers: subs };
}

/* ── public payments: intents + coupon-aware settlement ────────── */
export async function createPendingPayment(p) {
  const { insertedId } = await c.payments.insertOne({
    user_id: null, order_id: null,
    email: p.email || null, payer_name: p.name || null,
    amount_inr: p.amount_inr, base_inr: p.base_inr ?? p.amount_inr,
    coupon: p.coupon || null, discount_inr: p.discount || 0,
    method: 'gateway', reference: null, status: 'pending',
    kind: p.kind || 'payment', rzp_order_id: p.rzp_order_id, note: p.note || null,
    paid_at: null, created_at: nowStr(),
  });
  return String(insertedId);
}
export async function setPaymentRzpOrder(id, rzpOrderId) {
  const _id = oid(id); if (!_id) return;
  await c.payments.updateOne({ _id }, { $set: { rzp_order_id: rzpOrderId } });
}
export async function markPaymentPaidByRzpOrder(rzpOrderId, reference) {
  const doc = await c.payments.findOne({ rzp_order_id: rzpOrderId });
  if (!doc) return { found: false };
  if (doc.status === 'received') return { found: true, alreadyPaid: true, payment: pub(doc) };
  await c.payments.updateOne({ _id: doc._id }, { $set: { status: 'received', reference, paid_at: nowStr() } });
  return { found: true, alreadyPaid: false, payment: pub({ ...doc, status: 'received', reference, paid_at: nowStr() }) };
}
