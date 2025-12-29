import express from "express";
import cookieParser from "cookie-parser";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import type { NextFunction, Request, Response } from "express";
import {
  formatMac,
  normalizeMac,
  normalizeTransport,
  parseInteger,
  renderYealinkConfig,
} from "./lib.js";

const currentDir = path.dirname(fileURLToPath(import.meta.url));
const isDistBuild = currentDir.split(path.sep).includes("dist");
const projectRoot = path.resolve(currentDir, isDistBuild ? "../.." : "..");

const PORT = Number.parseInt(process.env.PORT || "3000", 10);
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "change-me";
const SESSION_COOKIE = process.env.SESSION_COOKIE || "prov_session";
const SESSION_TTL_HOURS = Number.parseInt(
  process.env.SESSION_TTL_HOURS || "168",
  10
);
const COOKIE_SECURE = process.env.COOKIE_SECURE
  ? process.env.COOKIE_SECURE === "1"
  : process.env.NODE_ENV === "production";
const DB_PATH =
  process.env.DB_PATH || path.join(projectRoot, "data", "provisioning.db");

const dataDir = path.dirname(DB_PATH);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const db = new Database(DB_PATH);
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS pbx_servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 5060,
    transport TEXT NOT NULL DEFAULT 'udp',
    outbound_proxy_host TEXT,
    outbound_proxy_port INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL UNIQUE,
    label TEXT,
    extension TEXT NOT NULL,
    auth_user TEXT NOT NULL,
    auth_pass TEXT NOT NULL,
    display_name TEXT,
    pbx_server_id INTEGER NOT NULL,
    line_number INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (pbx_server_id) REFERENCES pbx_servers(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
  );
`);

type PbxServer = {
  id: number;
  name: string;
  host: string;
  port: number;
  transport: string;
  outbound_proxy_host: string | null;
  outbound_proxy_port: number | null;
  created_at: string;
  updated_at: string;
};

type Device = {
  id: number;
  mac: string;
  label: string | null;
  extension: string;
  auth_user: string;
  auth_pass: string;
  display_name: string | null;
  pbx_server_id: number;
  line_number: number;
  created_at: string;
  updated_at: string;
};

type DeviceWithPbx = Device & {
  pbx_name: string;
  pbx_host: string;
  pbx_port: number;
  pbx_transport: string;
  pbx_proxy_host: string | null;
  pbx_proxy_port: number | null;
};

type SessionRow = {
  id: number;
  token: string;
  created_at: string;
  expires_at: string;
};

type NoticeMessage = {
  type: "success" | "error";
  text: string;
};

type RequestWithSession = Request & { session?: SessionRow };

const statements = {
  listPbx: db.prepare(
    "SELECT * FROM pbx_servers ORDER BY name COLLATE NOCASE"
  ),
  getPbx: db.prepare("SELECT * FROM pbx_servers WHERE id = ?"),
  insertPbx: db.prepare(`
    INSERT INTO pbx_servers
      (name, host, port, transport, outbound_proxy_host, outbound_proxy_port, created_at, updated_at)
    VALUES
      (?, ?, ?, ?, ?, ?, ?, ?)
  `),
  updatePbx: db.prepare(`
    UPDATE pbx_servers
    SET name = ?, host = ?, port = ?, transport = ?, outbound_proxy_host = ?, outbound_proxy_port = ?, updated_at = ?
    WHERE id = ?
  `),
  deletePbx: db.prepare("DELETE FROM pbx_servers WHERE id = ?"),
  listDevices: db.prepare(`
    SELECT devices.*, pbx_servers.name AS pbx_name, pbx_servers.host AS pbx_host,
           pbx_servers.port AS pbx_port, pbx_servers.transport AS pbx_transport,
           pbx_servers.outbound_proxy_host AS pbx_proxy_host,
           pbx_servers.outbound_proxy_port AS pbx_proxy_port
    FROM devices
    JOIN pbx_servers ON pbx_servers.id = devices.pbx_server_id
    ORDER BY devices.label COLLATE NOCASE, devices.extension
  `),
  getDevice: db.prepare(`
    SELECT devices.*, pbx_servers.name AS pbx_name, pbx_servers.host AS pbx_host,
           pbx_servers.port AS pbx_port, pbx_servers.transport AS pbx_transport,
           pbx_servers.outbound_proxy_host AS pbx_proxy_host,
           pbx_servers.outbound_proxy_port AS pbx_proxy_port
    FROM devices
    JOIN pbx_servers ON pbx_servers.id = devices.pbx_server_id
    WHERE devices.id = ?
  `),
  getDeviceByMac: db.prepare(`
    SELECT devices.*, pbx_servers.name AS pbx_name, pbx_servers.host AS pbx_host,
           pbx_servers.port AS pbx_port, pbx_servers.transport AS pbx_transport,
           pbx_servers.outbound_proxy_host AS pbx_proxy_host,
           pbx_servers.outbound_proxy_port AS pbx_proxy_port
    FROM devices
    JOIN pbx_servers ON pbx_servers.id = devices.pbx_server_id
    WHERE devices.mac = ?
  `),
  insertDevice: db.prepare(`
    INSERT INTO devices
      (mac, label, extension, auth_user, auth_pass, display_name, pbx_server_id, line_number, created_at, updated_at)
    VALUES
      (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `),
  updateDevice: db.prepare(`
    UPDATE devices
    SET mac = ?, label = ?, extension = ?, auth_user = ?, auth_pass = ?, display_name = ?, pbx_server_id = ?, line_number = ?, updated_at = ?
    WHERE id = ?
  `),
  deleteDevice: db.prepare("DELETE FROM devices WHERE id = ?"),
  insertSession: db.prepare(
    "INSERT INTO sessions (token, created_at, expires_at) VALUES (?, ?, ?)"
  ),
  getSession: db.prepare("SELECT * FROM sessions WHERE token = ?"),
  deleteSession: db.prepare("DELETE FROM sessions WHERE token = ?"),
  deleteExpiredSessions: db.prepare(
    "DELETE FROM sessions WHERE expires_at <= ?"
  ),
};

const app = express();
app.set("trust proxy", true);
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use("/assets", express.static(path.join(projectRoot, "public")));

if (ADMIN_PASS === "change-me") {
  console.warn("ADMIN_PASS is set to the default; update it before production use.");
}

function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function buildNoticeUrl(
  baseUrl: string,
  kind: "error" | "notice",
  message: string
): string {
  const url = new URL(baseUrl, "http://localhost");
  url.searchParams.set(kind, message);
  return url.pathname + url.search;
}

function createSession(): { token: string; expiresAt: Date } {
  const token = crypto.randomBytes(24).toString("hex");
  const now = new Date();
  const expiresAt = new Date(
    now.getTime() + SESSION_TTL_HOURS * 60 * 60 * 1000
  );
  statements.insertSession.run(
    token,
    now.toISOString(),
    expiresAt.toISOString()
  );
  return { token, expiresAt };
}

function getSession(request: Request): SessionRow | null {
  const cookies = request.cookies as Record<string, string> | undefined;
  const token = cookies?.[SESSION_COOKIE];
  if (!token) return null;
  const session = statements.getSession.get(token) as SessionRow | undefined;
  if (!session) return null;
  if (new Date(session.expires_at) <= new Date()) {
    statements.deleteSession.run(token);
    return null;
  }
  return session;
}

function requireAuth(
  request: Request,
  response: Response,
  next: NextFunction
): void {
  const session = getSession(request);
  if (session) {
    (request as RequestWithSession).session = session;
    next();
    return;
  }
  response.redirect("/admin");
}

function renderLayout({
  title,
  bodyClass,
  content,
  message,
}: {
  title: string;
  bodyClass: string;
  content: string;
  message: NoticeMessage | null;
}): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(title)}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Spline+Sans+Mono:wght@400;600&display=swap"
      rel="stylesheet"
    />
    <link rel="stylesheet" href="/assets/styles.css" />
  </head>
  <body class="${escapeHtml(bodyClass)}">
    <div class="backdrop"></div>
    ${message ? `<div class="notice notice--${message.type}">${escapeHtml(message.text)}</div>` : ""}
    ${content}
  </body>
</html>`;
}

function renderLoginPage({
  message,
}: {
  message: NoticeMessage | null;
}): string {
  const content = `
    <main class="shell login-shell">
      <section class="card login-card reveal">
        <div class="card-header">
          <p class="eyebrow">Provisioning</p>
          <h1>Sign in</h1>
          <p class="subhead">Manage PBX servers and device configs.</p>
        </div>
        <form method="post" action="/admin/login" class="form-grid">
          <label class="field">
            <span>Username</span>
            <input name="username" type="text" autocomplete="username" required />
          </label>
          <label class="field">
            <span>Password</span>
            <input name="password" type="password" autocomplete="current-password" required />
          </label>
          <button class="button" type="submit">Log in</button>
        </form>
      </section>
    </main>
  `;

  return renderLayout({
    title: "Provisioning Admin",
    bodyClass: "login",
    content,
    message,
  });
}

function renderAdminPage({
  request,
  pbxServers,
  devices,
  message,
}: {
  request: Request;
  pbxServers: PbxServer[];
  devices: DeviceWithPbx[];
  message: NoticeMessage | null;
}): string {
  const host = request.get("host") ?? "localhost";
  const baseUrl = `${request.protocol}://${host}`;
  const provisionPattern = `${baseUrl}/yealink/{mac}.cfg`;
  const pbxOptions = pbxServers
    .map(
      (server) =>
        `<option value="${server.id}">${escapeHtml(
          `${server.name} (${server.host})`
        )}</option>`
    )
    .join("");

  const pbxRows = pbxServers
    .map((server, index) => {
      const delay = 120 + index * 40;
      return `
      <article class="item reveal" style="--delay:${delay}ms">
        <form method="post" action="/admin/pbx-servers/${server.id}" class="form-grid form-grid--tight">
          <label class="field">
            <span>Name</span>
            <input name="name" type="text" value="${escapeHtml(server.name)}" required />
          </label>
          <label class="field">
            <span>Host</span>
            <input name="host" type="text" value="${escapeHtml(server.host)}" required />
          </label>
          <label class="field">
            <span>Port</span>
            <input name="port" type="number" min="1" max="65535" value="${escapeHtml(
              server.port
            )}" required />
          </label>
          <label class="field">
            <span>Transport</span>
            <select name="transport" required>
              <option value="udp"${server.transport === "udp" ? " selected" : ""}>UDP</option>
              <option value="tcp"${server.transport === "tcp" ? " selected" : ""}>TCP</option>
              <option value="tls"${server.transport === "tls" ? " selected" : ""}>TLS</option>
            </select>
          </label>
          <label class="field">
            <span>Proxy host</span>
            <input name="outbound_proxy_host" type="text" value="${escapeHtml(
              server.outbound_proxy_host || ""
            )}" placeholder="Optional" />
          </label>
          <label class="field">
            <span>Proxy port</span>
            <input name="outbound_proxy_port" type="number" min="1" max="65535" value="${escapeHtml(
              server.outbound_proxy_port || ""
            )}" placeholder="Optional" />
          </label>
          <div class="form-actions">
            <button class="button" type="submit">Save</button>
          </div>
        </form>
        <form method="post" action="/admin/pbx-servers/${server.id}/delete" class="inline-form">
          <button class="button button--ghost" type="submit">Delete</button>
        </form>
      </article>
      `;
    })
    .join("");

  const deviceRows = devices
    .map((device, index) => {
      const delay = 140 + index * 40;
      return `
      <article class="item reveal" style="--delay:${delay}ms">
        <form method="post" action="/admin/devices/${device.id}" class="form-grid form-grid--tight">
          <label class="field">
            <span>Label</span>
            <input name="label" type="text" value="${escapeHtml(device.label || "")}" placeholder="Desk phone" />
          </label>
          <label class="field">
            <span>MAC</span>
            <input name="mac" type="text" value="${escapeHtml(formatMac(device.mac))}" required />
          </label>
          <label class="field">
            <span>Extension</span>
            <input name="extension" type="text" value="${escapeHtml(device.extension)}" required />
          </label>
          <label class="field">
            <span>Auth user</span>
            <input name="auth_user" type="text" value="${escapeHtml(device.auth_user)}" required />
          </label>
          <label class="field">
            <span>Auth pass</span>
            <input name="auth_pass" type="password" value="${escapeHtml(device.auth_pass)}" required />
          </label>
          <label class="field">
            <span>Display name</span>
            <input name="display_name" type="text" value="${escapeHtml(device.display_name || "")}" placeholder="Optional" />
          </label>
          <label class="field">
            <span>PBX server</span>
            <select name="pbx_server_id" required>
              ${pbxServers
                .map(
                  (server) =>
                    `<option value="${server.id}"${
                      device.pbx_server_id === server.id ? " selected" : ""
                    }>${escapeHtml(server.name)} (${escapeHtml(
                      server.host
                    )})</option>`
                )
                .join("")}
            </select>
          </label>
          <label class="field">
            <span>Line</span>
            <input name="line_number" type="number" min="1" max="16" value="${escapeHtml(
              device.line_number
            )}" />
          </label>
          <div class="form-actions">
            <button class="button" type="submit">Save</button>
          </div>
        </form>
        <div class="item-footer">
          <span class="tag">${escapeHtml(device.pbx_name)}</span>
          <span class="tag mono">${escapeHtml(
            `${baseUrl}/yealink/${formatMac(device.mac)}.cfg`
          )}</span>
        </div>
        <form method="post" action="/admin/devices/${device.id}/delete" class="inline-form">
          <button class="button button--ghost" type="submit">Delete</button>
        </form>
      </article>
      `;
    })
    .join("");

  const content = `
    <header class="hero reveal" style="--delay:60ms">
      <div class="hero-main">
        <div class="brand">
          <div class="logo">P</div>
          <div>
            <p class="eyebrow">Provisioning</p>
            <h1>Touchless config control</h1>
            <p class="subhead">Manage PBX servers and push Yealink configs instantly.</p>
          </div>
        </div>
        <div class="hero-meta">
          <div class="metric">
            <span>${pbxServers.length}</span>
            <span class="label">PBX servers</span>
          </div>
          <div class="metric">
            <span>${devices.length}</span>
            <span class="label">Devices</span>
          </div>
        </div>
      </div>
      <div class="hero-secondary">
        <div class="pattern">
          <p>Provisioning URL pattern</p>
          <code>${escapeHtml(provisionPattern)}</code>
        </div>
        <form method="post" action="/admin/logout" class="inline-form">
          <button class="button button--ghost" type="submit">Log out</button>
        </form>
      </div>
    </header>

    <main class="shell">
      <section class="card reveal" style="--delay:120ms">
        <div class="card-header">
          <h2>PBX servers</h2>
          <p class="subhead">Store connection details and transport for each PBX.</p>
        </div>
        <form method="post" action="/admin/pbx-servers" class="form-grid">
          <label class="field">
            <span>Name</span>
            <input name="name" type="text" placeholder="PBXware DC1" required />
          </label>
          <label class="field">
            <span>Host</span>
            <input name="host" type="text" placeholder="pbx.dtbicom.xyz" required />
          </label>
          <label class="field">
            <span>Port</span>
            <input name="port" type="number" min="1" max="65535" value="5060" required />
          </label>
          <label class="field">
            <span>Transport</span>
            <select name="transport" required>
              <option value="udp" selected>UDP</option>
              <option value="tcp">TCP</option>
              <option value="tls">TLS</option>
            </select>
          </label>
          <label class="field">
            <span>Proxy host</span>
            <input name="outbound_proxy_host" type="text" placeholder="Optional" />
          </label>
          <label class="field">
            <span>Proxy port</span>
            <input name="outbound_proxy_port" type="number" min="1" max="65535" placeholder="Optional" />
          </label>
          <div class="form-actions">
            <button class="button" type="submit">Add server</button>
          </div>
        </form>
        <div class="list">
          ${pbxRows || "<p class=\"empty\">No PBX servers yet.</p>"}
        </div>
      </section>

      <section class="card reveal" style="--delay:160ms">
        <div class="card-header">
          <h2>Devices</h2>
          <p class="subhead">Pair a MAC address with SIP credentials and a PBX.</p>
        </div>
        <form method="post" action="/admin/devices" class="form-grid">
          <label class="field">
            <span>Label</span>
            <input name="label" type="text" placeholder="Front desk" />
          </label>
          <label class="field">
            <span>MAC</span>
            <input name="mac" type="text" placeholder="00:11:22:33:44:55" required />
          </label>
          <label class="field">
            <span>Extension</span>
            <input name="extension" type="text" placeholder="1001" required />
          </label>
          <label class="field">
            <span>Auth user</span>
            <input name="auth_user" type="text" placeholder="1001" required />
          </label>
          <label class="field">
            <span>Auth pass</span>
            <input name="auth_pass" type="password" placeholder="Secret" required />
          </label>
          <label class="field">
            <span>Display name</span>
            <input name="display_name" type="text" placeholder="Optional" />
          </label>
          <label class="field">
            <span>PBX server</span>
            <select name="pbx_server_id" required>
              ${pbxOptions || "<option value=\"\">Add a PBX first</option>"}
            </select>
          </label>
          <label class="field">
            <span>Line</span>
            <input name="line_number" type="number" min="1" max="16" value="1" />
          </label>
          <div class="form-actions">
            <button class="button" type="submit" ${pbxServers.length ? "" : "disabled"}>Add device</button>
          </div>
        </form>
        <div class="list">
          ${deviceRows || "<p class=\"empty\">No devices yet.</p>"}
        </div>
      </section>
    </main>
  `;

  return renderLayout({
    title: "Provisioning Admin",
    bodyClass: "admin",
    content,
    message,
  });
}

function cleanupSessions() {
  statements.deleteExpiredSessions.run(new Date().toISOString());
}

setInterval(cleanupSessions, 60 * 60 * 1000).unref();

app.get("/health", (_request, response) => {
  response.json({ status: "ok" });
});

app.get("/", (_request, response) => {
  response.redirect("/admin");
});

app.get("/admin", (request, response) => {
  const session = getSession(request);
  const errorParam =
    typeof request.query.error === "string" ? request.query.error : null;
  const noticeParam =
    typeof request.query.notice === "string" ? request.query.notice : null;
  const message = errorParam
    ? { type: "error", text: errorParam }
    : noticeParam
      ? { type: "success", text: noticeParam }
      : null;

  if (!session) {
    response.send(renderLoginPage({ message }));
    return;
  }

  const pbxServers = statements.listPbx.all() as PbxServer[];
  const devices = statements.listDevices.all() as DeviceWithPbx[];
  response.send(
    renderAdminPage({ request, pbxServers, devices, message })
  );
});

app.post("/admin/login", (request, response) => {
  const username = String(request.body.username || "").trim();
  const password = String(request.body.password || "");

  if (username !== ADMIN_USER || password !== ADMIN_PASS) {
    response.redirect(buildNoticeUrl("/admin", "error", "Invalid login."));
    return;
  }

  const session = createSession();
  response.cookie(SESSION_COOKIE, session.token, {
    httpOnly: true,
    sameSite: "lax",
    secure: COOKIE_SECURE,
    expires: session.expiresAt,
  });
  response.redirect(buildNoticeUrl("/admin", "notice", "Welcome back."));
});

app.post("/admin/logout", requireAuth, (request, response) => {
  const cookies = request.cookies as Record<string, string> | undefined;
  const token = cookies?.[SESSION_COOKIE];
  if (token) {
    statements.deleteSession.run(token);
  }
  response.clearCookie(SESSION_COOKIE);
  response.redirect(buildNoticeUrl("/admin", "notice", "Logged out."));
});

app.post("/admin/pbx-servers", requireAuth, (request, response) => {
  const name = String(request.body.name || "").trim();
  const host = String(request.body.host || "").trim();
  const port = parseInteger(request.body.port, 5060);
  const transport = normalizeTransport(request.body.transport);
  const proxyHost = String(request.body.outbound_proxy_host || "").trim();
  const proxyPort = request.body.outbound_proxy_port
    ? parseInteger(request.body.outbound_proxy_port, 0)
    : null;

  if (!name || !host || !transport || port < 1 || port > 65535) {
    response.redirect(
      buildNoticeUrl("/admin", "error", "Invalid PBX server data.")
    );
    return;
  }

  const now = new Date().toISOString();
  statements.insertPbx.run(
    name,
    host,
    port,
    transport,
    proxyHost || null,
    proxyPort || null,
    now,
    now
  );

  response.redirect(buildNoticeUrl("/admin", "notice", "PBX added."));
});

app.post("/admin/pbx-servers/:id", requireAuth, (request, response) => {
  const id = Number.parseInt(request.params.id, 10);
  const existing = statements.getPbx.get(id) as PbxServer | undefined;
  if (!existing) {
    response.redirect(buildNoticeUrl("/admin", "error", "PBX not found."));
    return;
  }

  const name = String(request.body.name || "").trim();
  const host = String(request.body.host || "").trim();
  const port = parseInteger(request.body.port, 5060);
  const transport = normalizeTransport(request.body.transport);
  const proxyHost = String(request.body.outbound_proxy_host || "").trim();
  const proxyPort = request.body.outbound_proxy_port
    ? parseInteger(request.body.outbound_proxy_port, 0)
    : null;

  if (!name || !host || !transport || port < 1 || port > 65535) {
    response.redirect(
      buildNoticeUrl("/admin", "error", "Invalid PBX server data.")
    );
    return;
  }

  const now = new Date().toISOString();
  statements.updatePbx.run(
    name,
    host,
    port,
    transport,
    proxyHost || null,
    proxyPort || null,
    now,
    id
  );

  response.redirect(buildNoticeUrl("/admin", "notice", "PBX updated."));
});

app.post(
  "/admin/pbx-servers/:id/delete",
  requireAuth,
  (request, response) => {
    const id = Number.parseInt(request.params.id, 10);
    statements.deletePbx.run(id);
    response.redirect(buildNoticeUrl("/admin", "notice", "PBX removed."));
  }
);

app.post("/admin/devices", requireAuth, (request, response) => {
  const mac = normalizeMac(request.body.mac);
  const label = String(request.body.label || "").trim();
  const extension = String(request.body.extension || "").trim();
  const authUser = String(request.body.auth_user || "").trim();
  const authPass = String(request.body.auth_pass || "");
  const displayName = String(request.body.display_name || "").trim();
  const pbxServerId = parseInteger(request.body.pbx_server_id, 0);
  const lineNumber = parseInteger(request.body.line_number, 1);

  if (
    !mac ||
    !extension ||
    !authUser ||
    !authPass ||
    !pbxServerId ||
    lineNumber < 1 ||
    lineNumber > 16
  ) {
    response.redirect(
      buildNoticeUrl("/admin", "error", "Invalid device data.")
    );
    return;
  }

  const pbx = statements.getPbx.get(pbxServerId) as PbxServer | undefined;
  if (!pbx) {
    response.redirect(
      buildNoticeUrl("/admin", "error", "PBX server not found.")
    );
    return;
  }

  const now = new Date().toISOString();
  try {
    statements.insertDevice.run(
      mac,
      label || null,
      extension,
      authUser,
      authPass,
      displayName || null,
      pbxServerId,
      lineNumber,
      now,
      now
    );
  } catch (error) {
    response.redirect(
      buildNoticeUrl("/admin", "error", "Device MAC already exists.")
    );
    return;
  }

  response.redirect(buildNoticeUrl("/admin", "notice", "Device added."));
});

app.post("/admin/devices/:id", requireAuth, (request, response) => {
  const id = Number.parseInt(request.params.id, 10);
  const existing = statements.getDevice.get(id) as DeviceWithPbx | undefined;
  if (!existing) {
    response.redirect(buildNoticeUrl("/admin", "error", "Device not found."));
    return;
  }

  const mac = normalizeMac(request.body.mac);
  const label = String(request.body.label || "").trim();
  const extension = String(request.body.extension || "").trim();
  const authUser = String(request.body.auth_user || "").trim();
  const authPass = String(request.body.auth_pass || "");
  const displayName = String(request.body.display_name || "").trim();
  const pbxServerId = parseInteger(request.body.pbx_server_id, 0);
  const lineNumber = parseInteger(request.body.line_number, 1);

  if (
    !mac ||
    !extension ||
    !authUser ||
    !authPass ||
    !pbxServerId ||
    lineNumber < 1 ||
    lineNumber > 16
  ) {
    response.redirect(
      buildNoticeUrl("/admin", "error", "Invalid device data.")
    );
    return;
  }

  const pbx = statements.getPbx.get(pbxServerId) as PbxServer | undefined;
  if (!pbx) {
    response.redirect(
      buildNoticeUrl("/admin", "error", "PBX server not found.")
    );
    return;
  }

  const now = new Date().toISOString();
  try {
    statements.updateDevice.run(
      mac,
      label || null,
      extension,
      authUser,
      authPass,
      displayName || null,
      pbxServerId,
      lineNumber,
      now,
      id
    );
  } catch (error) {
    response.redirect(
      buildNoticeUrl("/admin", "error", "Device MAC already exists.")
    );
    return;
  }

  response.redirect(buildNoticeUrl("/admin", "notice", "Device updated."));
});

app.post(
  "/admin/devices/:id/delete",
  requireAuth,
  (request, response) => {
    const id = Number.parseInt(request.params.id, 10);
    statements.deleteDevice.run(id);
    response.redirect(buildNoticeUrl("/admin", "notice", "Device removed."));
  }
);

app.get("/yealink/:mac.cfg", (request, response) => {
  const normalized = normalizeMac(request.params.mac);
  if (!normalized) {
    response.status(404).send("Not Found");
    return;
  }

  const device = statements.getDeviceByMac.get(normalized) as
    | DeviceWithPbx
    | undefined;
  if (!device) {
    response.status(404).send("Not Found");
    return;
  }

  const config = renderYealinkConfig(device);
  response.setHeader("Content-Type", "text/plain; charset=utf-8");
  response.setHeader("Cache-Control", "no-store");
  response.send(config);
});

app.listen(PORT, () => {
  console.log(`Provisioning server listening on :${PORT}`);
});
