// crypto-fields.js — application-level field encryption (AES-256-GCM).
//
// Used for data that must be unreadable even to someone who gets a copy of the
// database: TOTP 2FA secrets and free-text lead PII. AES-256-GCM is
// authenticated encryption, so tampering is detected on decrypt.
//
// The key comes from ENCRYPTION_KEY (32 bytes, base64). Values are tagged with
// an "enc.v1." prefix so decrypt() can transparently pass through anything that
// isn't encrypted — existing plaintext rows keep working with no migration.

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const raw = process.env.ENCRYPTION_KEY || '';
let KEY = null;
try { const b = Buffer.from(raw, 'base64'); if (b.length === 32) KEY = b; } catch { /* ignore */ }
export const encryptionReady = Boolean(KEY);

export function encrypt(plaintext) {
  if (!KEY || plaintext == null || plaintext === '') return plaintext;
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', KEY, iv);
  const ct = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return 'enc.v1.' + Buffer.concat([iv, tag, ct]).toString('base64');
}

export function decrypt(value) {
  if (typeof value !== 'string' || !value.startsWith('enc.v1.')) return value; // plaintext / not ours
  if (!KEY) return value;
  try {
    const buf = Buffer.from(value.slice(7), 'base64');
    const iv = buf.subarray(0, 12), tag = buf.subarray(12, 28), ct = buf.subarray(28);
    const d = createDecipheriv('aes-256-gcm', KEY, iv);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
  } catch { return value; }
}
