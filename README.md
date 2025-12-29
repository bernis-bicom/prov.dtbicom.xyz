# prov.dtbicom.xyz

Touchless provisioning server for Yealink devices with a simple admin UI.

## Features

- Admin UI at `/admin` with login + session cookies
- SQLite-backed storage for PBX servers and device credentials
- Dynamic Yealink config endpoint at `/yealink/{mac}.cfg`
- Dockerized with Caddy reverse proxy (HTTPS on port 6000)

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

4. Visit `https://prov.dtbicom.xyz:6000/admin` and log in.

Note: Caddy uses host networking to avoid Docker egress blocks. The app is
bound to `127.0.0.1:6001` on the host, while HTTPS listens on port 6000.

## HTTPS on port 6000 (acme-dns)

This stack ships with a custom Caddy build that includes the acme-dns module.
It issues certs via DNS-01, so you do not need ports 80/443 open.

### Step 1: Register with acme-dns

```bash
curl -X POST https://auth.acme-dns.io/register
```

Save the JSON response values: `username`, `password`, `subdomain`,
`fulldomain`, and `server_url`.

### Step 2: Add the required CNAME

Create this DNS record (replace the values with your response):

```
_acme-challenge.prov.dtbicom.xyz CNAME <fulldomain>.
```

Example:

```
_acme-challenge.prov.dtbicom.xyz CNAME 37c5...e2ab.auth.acme-dns.io.
```

### Step 3: Add credentials to .env

Set these in `.env`:

```
ACMEDNS_USERNAME=<username>
ACMEDNS_PASSWORD=<password>
ACMEDNS_SUBDOMAIN=<subdomain>
ACMEDNS_SERVER_URL=<server_url>
```

Then restart Caddy:

```bash
docker compose restart caddy
```

Note: because HTTPS is on port 6000, users must include the port in the URL.

## Yealink RPS setup

- In Yealink RPS, set the provisioning URL to:
  `https://prov.dtbicom.xyz:6000/yealink/`
- The phone will request `${MAC}.cfg` automatically.
- Example resolved URL:
  `https://prov.dtbicom.xyz:6000/yealink/001122334455.cfg`

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
- `PORT`: internal app port (default `3000`, set to `6001` in Docker).
- `ACMEDNS_USERNAME`: acme-dns username.
- `ACMEDNS_PASSWORD`: acme-dns password.
- `ACMEDNS_SUBDOMAIN`: acme-dns subdomain.
- `ACMEDNS_SERVER_URL`: acme-dns API URL.

## Data storage

SQLite database lives at `data/provisioning.db` when running locally or in the
Docker volume `prov-data` when running the compose stack.

## Local dev (no Docker)

```bash
npm install
npm run dev
```

App runs on `http://localhost:3000` by default; set `PORT=6001` if you want
to mirror the Docker setup.
