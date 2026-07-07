// scripts/list-enquiries.js — print stored leads in the terminal.
// Usage: npm run enquiries   (reads MONGODB_URI from .env)
import 'dotenv/config';
import { connectDb, listEnquiries, countEnquiries, closeDb } from '../db.js';

await connectDb();
const rows = await listEnquiries(200);
console.log(`\nNext Imaginations — ${await countEnquiries()} enquiries (showing latest ${rows.length})\n`);

for (const r of rows) {
  const when = r.created_at instanceof Date ? r.created_at.toISOString().replace('T', ' ').slice(0, 19) : r.created_at;
  console.log(`${r._id}  [${r.status}]  ${when}  —  ${r.source}`);
  console.log(`   ${r.name} <${r.email}>${r.company ? '  ·  ' + r.company : ''}`);
  if (r.interest) console.log(`   Interest: ${r.interest}`);
  if (r.services?.length) console.log(`   Services: ${r.services.join(', ')}`);
  if (r.estimate) console.log(`   Estimate: ${JSON.stringify(r.estimate)}`);
  console.log(`   ${String(r.message).replace(/\s+/g, ' ').slice(0, 160)}`);
  console.log('');
}
await closeDb();
