// mailer.js — transactional mail via SMTP (Brevo-ready), with branded HTML.
// Point SMTP_* at Brevo (smtp-relay.brevo.com:587). Without SMTP configured,
// mail is logged to the console so every flow stays testable in dev.

import nodemailer from 'nodemailer';

const configured = Boolean(process.env.SMTP_HOST);

const transport = configured
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: String(process.env.SMTP_SECURE || '') === 'true', // 587 = false (STARTTLS)
      auth: process.env.SMTP_USER
        ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
        : undefined,
      connectionTimeout: 10000, // fail fast if the SMTP host is unreachable
      greetingTimeout: 8000,
      socketTimeout: 15000,
    })
  : null;

export const mailConfigured = configured;

// Defence-in-depth: strip CR/LF (and NULs) from any header built from user
// input, so nothing can inject extra SMTP headers via subject or recipient.
const oneLine = (s) => String(s ?? '').replace(/[\r\n\u0000]/g, ' ').trim();
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

const BRAND = {
  name: 'Next Imaginations',
  tagline: 'Build the new horizon.',
  site: 'https://www.nextimaginations.com',
  email: 'nextimaginations@gmail.com',
  phone: '+91 89300 06242',
  wine: '#2A0A12',
  wineDeep: '#1e0710',
  gold: '#C6A052',
  gold2: '#E6CD91',
  ink: '#F2E7D5',
  mute: '#B9A38F',
};

// Wrap body HTML in the branded shell. `cta` is optional {label, url}.
export function renderEmail({ heading, bodyHtml, cta }) {
  const btn = cta
    ? `<table role="presentation" cellpadding="0" cellspacing="0" style="margin:28px 0"><tr><td style="border-radius:8px;background:${BRAND.gold}">
         <a href="${esc(cta.url)}" style="display:inline-block;padding:13px 26px;font-family:Georgia,'Times New Roman',serif;font-size:15px;font-weight:bold;color:${BRAND.wine};text-decoration:none;border-radius:8px">${esc(cta.label)}</a>
       </td></tr></table>`
    : '';
  return `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:${BRAND.wineDeep};">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:${BRAND.wineDeep};padding:32px 16px">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:${BRAND.wine};border:1px solid rgba(198,160,82,.25);border-radius:14px;overflow:hidden">
        <tr><td style="padding:28px 32px 8px">
          <div style="font-family:Georgia,'Times New Roman',serif;font-size:22px;font-weight:bold;color:${BRAND.gold2};letter-spacing:.3px">${BRAND.name}</div>
          <div style="font-family:Arial,sans-serif;font-size:12px;color:${BRAND.mute};margin-top:2px">${BRAND.tagline}</div>
        </td></tr>
        <tr><td style="padding:0 32px"><div style="height:1px;background:rgba(198,160,82,.25);margin:16px 0"></div></td></tr>
        <tr><td style="padding:4px 32px 8px">
          <h1 style="font-family:Georgia,'Times New Roman',serif;font-size:21px;font-weight:normal;color:${BRAND.ink};margin:0 0 14px">${esc(heading)}</h1>
          <div style="font-family:Arial,sans-serif;font-size:15px;line-height:1.65;color:${BRAND.ink}">${bodyHtml}</div>
          ${btn}
        </td></tr>
        <tr><td style="padding:8px 32px 28px">
          <div style="height:1px;background:rgba(198,160,82,.18);margin:20px 0 16px"></div>
          <div style="font-family:Arial,sans-serif;font-size:12px;line-height:1.6;color:${BRAND.mute}">
            ${BRAND.name} · Creative IT &amp; Digital Studio · Chandigarh, India<br>
            <a href="mailto:${BRAND.email}" style="color:${BRAND.gold};text-decoration:none">${BRAND.email}</a> · ${BRAND.phone} · <a href="${BRAND.site}" style="color:${BRAND.gold};text-decoration:none">nextimaginations.com</a>
          </div>
        </td></tr>
      </table>
      <div style="font-family:Arial,sans-serif;font-size:11px;color:${BRAND.mute};margin-top:16px;opacity:.7">You received this because you have an account or enquiry with ${BRAND.name}.</div>
    </td></tr>
  </table>
</body></html>`;
}

// Core sender. Accepts optional `html` and `attachments` (nodemailer format).
export async function sendMail({ to, subject, text, html, attachments }) {
  to = oneLine(to);
  subject = oneLine(subject).slice(0, 250);
  if (!transport) {
    const att = attachments && attachments.length ? `\n  [+${attachments.length} attachment(s): ${attachments.map((a) => a.filename).join(', ')}]` : '';
    console.log(`\n  [mail — dev fallback] to: ${to}\n  subject: ${subject}\n  ${String(text || '(html only)').replace(/\n/g, '\n  ')}${att}\n`);
    return { dev: true };
  }
  try {
    const info = await transport.sendMail({
      from: process.env.MAIL_FROM || `Next Imaginations <no-reply@nextimaginations.com>`,
      to, subject,
      text: text || undefined,
      html: html || undefined,
      attachments: attachments || undefined,
    });
    return { dev: false, ok: true, id: info.messageId };
  } catch (e) {
    // Surface the real reason (Brevo rejection, auth failure, unverified sender,
    // network block) instead of failing silently.
    console.error(`\n  ⚠  EMAIL FAILED → ${to}  |  subject: ${subject}`);
    console.error(`     ${e.message}`);
    if (e.response) console.error(`     server said: ${String(e.response).slice(0, 200)}`);
    if (e.code) console.error(`     code: ${e.code}`);
    return { dev: false, ok: false, error: e.message };
  }
}

// One-shot SMTP verification, used at startup so misconfiguration is obvious.
export async function verifyMail() {
  if (!transport) return { configured: false };
  try { await transport.verify(); return { configured: true, ok: true }; }
  catch (e) { return { configured: true, ok: false, error: e.message, code: e.code, response: e.response }; }
}

// Convenience: build a branded HTML email AND a plain-text fallback from the
// same content, then send. `lines` is an array of paragraph strings (plain);
// they're escaped for HTML and joined with newlines for text.
export async function sendBranded({ to, subject, heading, lines, cta, attachments }) {
  const bodyHtml = lines.map((l) => `<p style="margin:0 0 12px">${esc(l)}</p>`).join('');
  const html = renderEmail({ heading, bodyHtml, cta });
  const text = `${heading}\n\n${lines.join('\n\n')}${cta ? `\n\n${cta.label}: ${cta.url}` : ''}\n\n— Next Imaginations · nextimaginations.com`;
  return sendMail({ to, subject, text, html, attachments });
}

export function otpMail(code, purpose) {
  const why = {
    verify: 'verify your email address',
    login: 'sign in to your account',
    mfa: 'complete your two-step sign-in',
    delete: 'confirm deletion of your account',
    password: 'reset your password',
  }[purpose] || 'continue';
  const bodyHtml =
    `<p style="margin:0 0 14px">Your one-time code to ${esc(why)} is:</p>
     <div style="font-family:'Courier New',monospace;font-size:32px;font-weight:bold;letter-spacing:8px;color:${BRAND.gold2};background:${BRAND.wineDeep};border:1px solid rgba(198,160,82,.3);border-radius:10px;padding:18px;text-align:center;margin:0 0 14px">${esc(code)}</div>
     <p style="margin:0;color:${BRAND.mute};font-size:13px">It expires in 10 minutes. If you didn't request this, you can safely ignore this email — nothing happens without the code.</p>`;
  return {
    subject: `${code} is your Next Imaginations code`,
    text: `Your one-time code to ${why} is:\n\n${code}\n\nIt expires in 10 minutes. If you didn't request this, ignore this email — no action is taken without the code.\n\n— Next Imaginations · nextimaginations.com`,
    html: renderEmail({ heading: 'Your verification code', bodyHtml }),
  };
}
