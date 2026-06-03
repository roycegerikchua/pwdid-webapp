# PWD ID Standalone Web App

Standalone Express + MSSQL replacement for the Node-RED PWD ID System flow.

## What it includes

- `GET /auth/login` — UBEPOS/VIP_HO barcode login
- `GET/POST /auth/select-branch` — branch selection on every VIP_HO login, synced from `posConfig.dbo.posConfig`
- `GET /` — authenticated mobile-friendly PWD ID checker UI
- `POST /pwdid/lookup` — authenticated central MSSQL lookup
- `POST /pwdid/save` — parameterized MERGE insert/update into `dbo.PWDID`, stamped with session user and selected branch
- `GET /pwdid/list` — authenticated searchable recent records
- `GET /pwdid/stats` — authenticated totals for dashboard stats
- `POST /pwd-ocr-upload` — authenticated Google Vision OCR extraction copied from the Node-RED function logic
- `POST /test-pwd/lookup` — authenticated proxy to the Puppeteer DOH lookup service
- `GET /health` — service health check

## Run locally

```bash
cd /opt/data/pwdid-webapp
npm install
npm start
```

Open:

```text
http://127.0.0.1:3015
```

## Run with Docker

```bash
cd /opt/data/pwdid-webapp
docker compose up -d --build
```

## Configuration

Copy `.env.example` to `.env` and set:

- `MSSQL_SERVER`, `MSSQL_PORT`, `MSSQL_DATABASE`, `MSSQL_USER`, `MSSQL_PASSWORD`
- `GOOGLE_VISION_API_KEY`
- `PUPPETEER_URL` — defaults to `http://192.168.111.112:3000/pwdid/doh-lookup`
- `SESSION_SECRET` — set to a long random value in production
- `PORT` — defaults to `3015`

The app creates the local auth support tables if missing:

- `dbo.Staff`
- `dbo.Branches`
- `dbo.PWDID_Audit`

It also adds these metadata columns to `dbo.PWDID` if missing: `encoded_by_user_id`, `encoded_by_username`, `encoded_by_full_name`, `branch_id`, `branch_code`, `branch_name`, `saved_from_app`.

The local `.env` in this folder is gitignored.

## Verification

With the app running:

```bash
npm test
```

The smoke test checks health and unauthenticated protection by default. To run the authenticated stats/lookup/list checks, provide a real login:

```bash
SMOKE_USERNAME=your_barcode SMOKE_PASSWORD=your_password npm test
```
