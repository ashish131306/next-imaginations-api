// db.js — MongoDB data layer (official driver, no ORM).
//
// The rest of the app only depends on the functions exported below, so the
// storage engine is fully swappable — this file replaced the earlier SQLite
// layer without touching the API routes' behaviour.
//
// Connection string comes from MONGODB_URI (a MongoDB Atlas SRV URI in
// production, e.g. mongodb+srv://user:pass@cluster0.xxxxx.mongodb.net).

import { MongoClient, ObjectId } from 'mongodb';

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017';
const DB_NAME = process.env.DB_NAME || 'next-imaginations';

const client = new MongoClient(MONGODB_URI, {
  maxPoolSize: 10,
  serverSelectionTimeoutMS: 8000,
});

let enquiries; // collection handle, set by connectDb()
let pageviews; // daily per-path counters

// Live collection handles for the account layer (populated by connectDb).
export const collections = {};

/** Connect once at startup. The server refuses to boot if this fails —
 *  better to crash loudly than to silently drop leads. */
export async function connectDb() {
  await client.connect();
  const db = client.db(DB_NAME);
  enquiries = db.collection('enquiries');
  pageviews = db.collection('pageviews');
  Object.assign(collections, {
    enquiries,
    users: db.collection('users'),
    otps: db.collection('otps'),
    sessions: db.collection('sessions'),
    orders: db.collection('orders'),
    payments: db.collection('payments'),
    tickets: db.collection('tickets'),
    ticketReplies: db.collection('ticket_replies'),
    credits: db.collection('credits'),
    authFails: db.collection('auth_fails'),
  });

  await enquiries.createIndexes([
    { key: { created_at: -1 }, name: 'idx_created_desc' },
    { key: { status: 1 }, name: 'idx_status' },
    { key: { email: 1 }, name: 'idx_email' },
  ]);

  await pageviews.createIndex({ day: 1, path: 1 }, { unique: true, name: 'idx_day_path' });

  // Round-trip ping so a bad URI/credentials fail at boot, not first request.
  await db.command({ ping: 1 });
  return db;
}

export async function createEnquiry(data) {
  const doc = {
    name: data.name,
    email: data.email,
    company: data.company || null,
    interest: data.interest || null,
    message: data.message,
    source: data.source || 'contact',
    services: Array.isArray(data.services) ? data.services.slice(0, 12) : null,
    estimate: data.estimate && typeof data.estimate === 'object' ? data.estimate : null,
    ip: data.ip || null,
    user_agent: data.user_agent || null,
    status: 'new',
    created_at: new Date(),
  };
  const { insertedId } = await enquiries.insertOne(doc);
  return insertedId.toString();
}

export async function listEnquiries(limit = 500) {
  return enquiries.find({}).sort({ created_at: -1 }).limit(limit).toArray();
}

export async function countEnquiries() {
  return enquiries.countDocuments();
}

export async function setStatus(id, status) {
  const { matchedCount } = await enquiries.updateOne(
    { _id: new ObjectId(id) },
    { $set: { status: String(status).slice(0, 40) } }
  );
  return matchedCount === 1;
}

/** Cheap daily page-view counter: one doc per (day, path). */
export async function recordPageview(path) {
  const day = new Date().toISOString().slice(0, 10);
  await pageviews.updateOne(
    { day, path },
    { $inc: { n: 1 }, $setOnInsert: { first_seen: new Date() } },
    { upsert: true }
  );
}

export async function closeDb() {
  await client.close();
}
