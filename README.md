# Next Imaginations — Enquiry API (Render + MongoDB Atlas build)

API-only backend for nextimaginations.com. The static site is deployed
separately on Vercel; this service records contact-form enquiries and
bundle-builder quotes in MongoDB. The service itself is stateless — all data
lives in Atlas, so no persistent disk is needed and restarts are harmless.

## API
| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/health` | — | Liveness probe (reports DB + enquiry count) |
| POST | `/api/enquiries` | — | Store an enquiry (validated, honeypot, 20 req/min/IP, 64 KB limit) |
| GET | `/api/enquiries` | `Bearer ADMIN_TOKEN` | List stored leads |
| PATCH | `/api/enquiries/:id` | `Bearer ADMIN_TOKEN` | Set lead status: new / contacted / in-progress / won / closed |

## Deploy
See `../DEPLOYMENT.md`. Short version: create a free MongoDB Atlas cluster,
then Render → New → Blueprint → this repo, and paste the Atlas URI when
prompted.

## Local
```bash
npm install
cp .env.example .env    # point MONGODB_URI at local mongod or your Atlas cluster
npm start               # http://localhost:3000/api/health
npm run enquiries       # print stored leads in the terminal
```

## Data layer
All MongoDB specifics are confined to `db.js` (indexes on created_at, status,
email). Swapping engines again later means replacing that one file.
