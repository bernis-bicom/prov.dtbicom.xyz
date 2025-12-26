# prov.dtbicom.xyz

Touchless provisioning server for Yealink devices with a simple admin UI.

## Features

- Admin UI at `/admin` with login + session cookies
- SQLite-backed storage for PBX servers and device credentials
- Dynamic Yealink config endpoint at `/yealink/{mac}.cfg`
- Dockerized with Caddy reverse proxy

## Quick start (Docker + Caddy)

1. Copy the env template and set credentials:

```bash
cp .env.example .env
```

2. Edit `.env` and set `ADMIN_PASS` to a strong password.

3. Start the stack:

```bash
docker compose up -d --build
```

4. Visit `https://prov.dtbicom.xyz/admin` and log in.

## Yealink RPS setup

- In Yealink RPS, set the provisioning URL to:
  `https://prov.dtbicom.xyz/yealink/`
- The phone will request `${MAC}.cfg` automatically.
- Example resolved URL:
  `https://prov.dtbicom.xyz/yealink/001122334455.cfg`

## Admin workflow

1. Add a PBX server (host, port, transport, optional outbound proxy).
2. Add a device with MAC + SIP auth credentials.
3. The device config is generated dynamically at `/yealink/{mac}.cfg`.

## Environment variables

- `ADMIN_USER`: admin username (default `admin`).
- `ADMIN_PASS`: admin password (required for production).
- `SESSION_TTL_HOURS`: session lifetime in hours (default `168`).
- `SESSION_COOKIE`: cookie name (default `prov_session`).
- `COOKIE_SECURE`: `1` to force secure cookies (default: production only).
- `DB_PATH`: SQLite database location (default `/data/provisioning.db`).
- `PORT`: internal app port (default `3000`).

## Data storage

SQLite database lives at `data/provisioning.db` when running locally or in the
Docker volume `prov-data` when running the compose stack.

## Local dev (no Docker)

```bash
npm install
npm run dev
```

App runs on `http://localhost:3000`.
# prov.dtbicom.xyz
