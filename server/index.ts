import express from "express";
import cookieParser from "cookie-parser";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import tls from "node:tls";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import type { NextFunction, Request, Response as ExpressResponse } from "express";
import {
  formatMac,
  normalizeMac,
  normalizeTransport,
  parseInteger,
  parseBasicAuthHeader,
  applyFirmwareUrl,
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
const UPSTREAM_TIMEOUT_MS = Number.parseInt(
  process.env.UPSTREAM_TIMEOUT_MS || "4000",
  10
);
const AMI_TIMEOUT_MS = Number.parseInt(
  process.env.AMI_TIMEOUT_MS || "4000",
  10
);
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
    prov_username TEXT,
    prov_password TEXT,
    upstream_base_url TEXT,
    upstream_username TEXT,
    upstream_password TEXT,
    upstream_mac_case TEXT,
    ami_host TEXT,
    ami_port INTEGER,
    ami_username TEXT,
    ami_password TEXT,
    ami_tls INTEGER NOT NULL DEFAULT 0,
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
    model TEXT,
    pjsip_endpoint TEXT,
    firmware_id INTEGER,
    firmware_url_override TEXT,
    firmware_pending INTEGER NOT NULL DEFAULT 0,
    firmware_requested_at TEXT,
    firmware_sent_at TEXT,
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

  CREATE TABLE IF NOT EXISTS firmware_catalog (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor TEXT NOT NULL,
    model TEXT NOT NULL,
    version TEXT NOT NULL,
    url TEXT NOT NULL,
    source TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
`);

function ensureColumns(
  table: string,
  columns: Array<{ name: string; type: string }>
): void {
  const existing = db
    .prepare(`PRAGMA table_info(${table})`)
    .all() as Array<{ name: string }>;
  const names = new Set(existing.map((column) => column.name));
  for (const column of columns) {
    if (!names.has(column.name)) {
      db.exec(`ALTER TABLE ${table} ADD COLUMN ${column.name} ${column.type}`);
    }
  }
}

ensureColumns("pbx_servers", [
  { name: "prov_username", type: "TEXT" },
  { name: "prov_password", type: "TEXT" },
  { name: "upstream_base_url", type: "TEXT" },
  { name: "upstream_username", type: "TEXT" },
  { name: "upstream_password", type: "TEXT" },
  { name: "upstream_mac_case", type: "TEXT" },
  { name: "ami_host", type: "TEXT" },
  { name: "ami_port", type: "INTEGER" },
  { name: "ami_username", type: "TEXT" },
  { name: "ami_password", type: "TEXT" },
  { name: "ami_tls", type: "INTEGER" },
]);

ensureColumns("devices", [
  { name: "model", type: "TEXT" },
  { name: "pjsip_endpoint", type: "TEXT" },
  { name: "firmware_id", type: "INTEGER" },
  { name: "firmware_url_override", type: "TEXT" },
  { name: "firmware_pending", type: "INTEGER" },
  { name: "firmware_requested_at", type: "TEXT" },
  { name: "firmware_sent_at", type: "TEXT" },
]);

function migrateFirmwareCatalogSchema(): void {
  const indexes = db
    .prepare("PRAGMA index_list(firmware_catalog)")
    .all() as Array<{ name: string; unique: number }>;
  const urlUniqueIndex = indexes.find((index) => {
    if (!index.unique) return false;
    const columns = db
      .prepare(`PRAGMA index_info(${index.name})`)
      .all() as Array<{ name: string }>;
    return columns.length === 1 && columns[0]?.name === "url";
  });
  if (urlUniqueIndex) {
    db.transaction(() => {
      db.exec(`
        CREATE TABLE firmware_catalog_new (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          vendor TEXT NOT NULL,
          model TEXT NOT NULL,
          version TEXT NOT NULL,
          url TEXT NOT NULL,
          source TEXT NOT NULL,
          fetched_at TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        INSERT INTO firmware_catalog_new
          (vendor, model, version, url, source, fetched_at, created_at, updated_at)
        SELECT vendor, model, version, url, source, fetched_at, created_at, updated_at
        FROM firmware_catalog;
        DROP TABLE firmware_catalog;
        ALTER TABLE firmware_catalog_new RENAME TO firmware_catalog;
      `);
    })();
  }
  db.exec(
    "CREATE UNIQUE INDEX IF NOT EXISTS firmware_catalog_unique ON firmware_catalog(model, version, url, source)"
  );
}

migrateFirmwareCatalogSchema();

type PbxServer = {
  id: number;
  name: string;
  host: string;
  port: number;
  transport: string;
  outbound_proxy_host: string | null;
  outbound_proxy_port: number | null;
  prov_username: string | null;
  prov_password: string | null;
  upstream_base_url: string | null;
  upstream_username: string | null;
  upstream_password: string | null;
  upstream_mac_case: string | null;
  ami_host: string | null;
  ami_port: number | null;
  ami_username: string | null;
  ami_password: string | null;
  ami_tls: number | null;
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
  model: string | null;
  pjsip_endpoint: string | null;
  firmware_id: number | null;
  firmware_url_override: string | null;
  firmware_pending: number | null;
  firmware_requested_at: string | null;
  firmware_sent_at: string | null;
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
  pbx_prov_username: string | null;
  pbx_prov_password: string | null;
  pbx_upstream_base_url: string | null;
  pbx_upstream_username: string | null;
  pbx_upstream_password: string | null;
  pbx_upstream_mac_case: string | null;
  pbx_ami_host: string | null;
  pbx_ami_port: number | null;
  pbx_ami_username: string | null;
  pbx_ami_password: string | null;
  pbx_ami_tls: number | null;
  firmware_vendor: string | null;
  firmware_model: string | null;
  firmware_version: string | null;
  firmware_url: string | null;
};

type SessionRow = {
  id: number;
  token: string;
  created_at: string;
  expires_at: string;
};

type FirmwareCatalogEntry = {
  id: number;
  vendor: string;
  model: string;
  version: string;
  url: string;
  source: string;
  fetched_at: string;
  created_at: string;
  updated_at: string;
};

type FirmwareCatalogInput = {
  vendor: string;
  model: string;
  version: string;
  url: string;
  source: string;
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
      (name, host, port, transport, outbound_proxy_host, outbound_proxy_port, prov_username, prov_password, upstream_base_url, upstream_username, upstream_password, upstream_mac_case, ami_host, ami_port, ami_username, ami_password, ami_tls, created_at, updated_at)
    VALUES
      (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `),
  updatePbx: db.prepare(`
    UPDATE pbx_servers
    SET name = ?, host = ?, port = ?, transport = ?, outbound_proxy_host = ?, outbound_proxy_port = ?, prov_username = ?, prov_password = ?, upstream_base_url = ?, upstream_username = ?, upstream_password = ?, upstream_mac_case = ?, ami_host = ?, ami_port = ?, ami_username = ?, ami_password = ?, ami_tls = ?, updated_at = ?
    WHERE id = ?
  `),
  deletePbx: db.prepare("DELETE FROM pbx_servers WHERE id = ?"),
  listDevices: db.prepare(`
    SELECT devices.*, pbx_servers.name AS pbx_name, pbx_servers.host AS pbx_host,
           pbx_servers.port AS pbx_port, pbx_servers.transport AS pbx_transport,
           pbx_servers.outbound_proxy_host AS pbx_proxy_host,
           pbx_servers.outbound_proxy_port AS pbx_proxy_port,
           pbx_servers.prov_username AS pbx_prov_username,
           pbx_servers.prov_password AS pbx_prov_password,
           pbx_servers.upstream_base_url AS pbx_upstream_base_url,
           pbx_servers.upstream_username AS pbx_upstream_username,
           pbx_servers.upstream_password AS pbx_upstream_password,
           pbx_servers.upstream_mac_case AS pbx_upstream_mac_case,
           pbx_servers.ami_host AS pbx_ami_host,
           pbx_servers.ami_port AS pbx_ami_port,
           pbx_servers.ami_username AS pbx_ami_username,
           pbx_servers.ami_password AS pbx_ami_password,
           pbx_servers.ami_tls AS pbx_ami_tls,
           firmware_catalog.vendor AS firmware_vendor,
           firmware_catalog.model AS firmware_model,
           firmware_catalog.version AS firmware_version,
           firmware_catalog.url AS firmware_url
    FROM devices
    JOIN pbx_servers ON pbx_servers.id = devices.pbx_server_id
    LEFT JOIN firmware_catalog ON firmware_catalog.id = devices.firmware_id
    ORDER BY devices.label COLLATE NOCASE, devices.extension
  `),
  getDevice: db.prepare(`
    SELECT devices.*, pbx_servers.name AS pbx_name, pbx_servers.host AS pbx_host,
           pbx_servers.port AS pbx_port, pbx_servers.transport AS pbx_transport,
           pbx_servers.outbound_proxy_host AS pbx_proxy_host,
           pbx_servers.outbound_proxy_port AS pbx_proxy_port,
           pbx_servers.prov_username AS pbx_prov_username,
           pbx_servers.prov_password AS pbx_prov_password,
           pbx_servers.upstream_base_url AS pbx_upstream_base_url,
           pbx_servers.upstream_username AS pbx_upstream_username,
           pbx_servers.upstream_password AS pbx_upstream_password,
           pbx_servers.upstream_mac_case AS pbx_upstream_mac_case,
           pbx_servers.ami_host AS pbx_ami_host,
           pbx_servers.ami_port AS pbx_ami_port,
           pbx_servers.ami_username AS pbx_ami_username,
           pbx_servers.ami_password AS pbx_ami_password,
           pbx_servers.ami_tls AS pbx_ami_tls,
           firmware_catalog.vendor AS firmware_vendor,
           firmware_catalog.model AS firmware_model,
           firmware_catalog.version AS firmware_version,
           firmware_catalog.url AS firmware_url
    FROM devices
    JOIN pbx_servers ON pbx_servers.id = devices.pbx_server_id
    LEFT JOIN firmware_catalog ON firmware_catalog.id = devices.firmware_id
    WHERE devices.id = ?
  `),
  getDeviceByMac: db.prepare(`
    SELECT devices.*, pbx_servers.name AS pbx_name, pbx_servers.host AS pbx_host,
           pbx_servers.port AS pbx_port, pbx_servers.transport AS pbx_transport,
           pbx_servers.outbound_proxy_host AS pbx_proxy_host,
           pbx_servers.outbound_proxy_port AS pbx_proxy_port,
           pbx_servers.prov_username AS pbx_prov_username,
           pbx_servers.prov_password AS pbx_prov_password,
           pbx_servers.upstream_base_url AS pbx_upstream_base_url,
           pbx_servers.upstream_username AS pbx_upstream_username,
           pbx_servers.upstream_password AS pbx_upstream_password,
           pbx_servers.upstream_mac_case AS pbx_upstream_mac_case,
           pbx_servers.ami_host AS pbx_ami_host,
           pbx_servers.ami_port AS pbx_ami_port,
           pbx_servers.ami_username AS pbx_ami_username,
           pbx_servers.ami_password AS pbx_ami_password,
           pbx_servers.ami_tls AS pbx_ami_tls,
           firmware_catalog.vendor AS firmware_vendor,
           firmware_catalog.model AS firmware_model,
           firmware_catalog.version AS firmware_version,
           firmware_catalog.url AS firmware_url
    FROM devices
    JOIN pbx_servers ON pbx_servers.id = devices.pbx_server_id
    LEFT JOIN firmware_catalog ON firmware_catalog.id = devices.firmware_id
    WHERE devices.mac = ?
  `),
  insertDevice: db.prepare(`
    INSERT INTO devices
      (mac, label, extension, auth_user, auth_pass, display_name, pbx_server_id, line_number, model, pjsip_endpoint, firmware_id, firmware_url_override, firmware_pending, firmware_requested_at, firmware_sent_at, created_at, updated_at)
    VALUES
      (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `),
  updateDevice: db.prepare(`
    UPDATE devices
    SET mac = ?, label = ?, extension = ?, auth_user = ?, auth_pass = ?, display_name = ?, pbx_server_id = ?, line_number = ?, model = ?, pjsip_endpoint = ?, firmware_id = ?, firmware_url_override = ?, updated_at = ?
    WHERE id = ?
  `),
  deleteDevice: db.prepare("DELETE FROM devices WHERE id = ?"),
  listFirmware: db.prepare(
    "SELECT * FROM firmware_catalog ORDER BY vendor COLLATE NOCASE, model COLLATE NOCASE, version COLLATE NOCASE"
  ),
  getFirmwareStats: db.prepare(
    "SELECT COUNT(*) AS count, MAX(fetched_at) AS last_fetched_at FROM firmware_catalog"
  ),
  getFirmware: db.prepare("SELECT * FROM firmware_catalog WHERE id = ?"),
  upsertFirmware: db.prepare(`
    INSERT INTO firmware_catalog
      (vendor, model, version, url, source, fetched_at, created_at, updated_at)
    VALUES
      (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(model, version, url, source) DO UPDATE SET
      vendor = excluded.vendor,
      model = excluded.model,
      version = excluded.version,
      source = excluded.source,
      fetched_at = excluded.fetched_at,
      updated_at = excluded.updated_at
  `),
  triggerFirmware: db.prepare(`
    UPDATE devices
    SET firmware_pending = 1, firmware_requested_at = ?, updated_at = ?
    WHERE id = ?
  `),
  markFirmwareSent: db.prepare(`
    UPDATE devices
    SET firmware_pending = 0, firmware_sent_at = ?, updated_at = ?
    WHERE id = ?
  `),
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

function normalizeBaseUrl(value: string): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    if (!url.pathname.endsWith("/")) {
      url.pathname += "/";
    }
    return url.toString();
  } catch (error) {
    return null;
  }
}

function normalizeUrl(value: string): string | null {
  if (!value) return null;
  try {
    return new URL(value).toString();
  } catch (error) {
    return null;
  }
}

function decodeHtml(value: string): string {
  return value
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, "\"")
    .replace(/&#39;/g, "'");
}

function cleanHtmlText(value: string): string {
  return decodeHtml(value.replace(/<[^>]+>/g, ""))
    .replace(/\s+/g, " ")
    .trim();
}

function parse3cxFirmwareCatalog(
  html: string,
  source: string
): FirmwareCatalogInput[] {
  const tableMatch = html.match(
    /<table class="firmwares"[^>]*>([\s\S]*?)<\/table>/i
  );
  if (!tableMatch) return [];
  const tableHtml = tableMatch[1];
  const rowRegex =
    /<tr[^>]*>\s*<td[^>]*>([\s\S]*?)<\/td>\s*<td[^>]*>([\s\S]*?)<\/td>\s*<td[^>]*>[\s\S]*?<\/td>\s*<td[^>]*>\s*<a[^>]*href="([^"]+)"[^>]*>/gi;
  const entries: FirmwareCatalogInput[] = [];
  let match: RegExpExecArray | null = null;
  while ((match = rowRegex.exec(tableHtml)) !== null) {
    const model = cleanHtmlText(match[1] ?? "");
    const version = cleanHtmlText(match[2] ?? "");
    const urlRaw = (match[3] ?? "").trim();
    if (!model || !version || !urlRaw) continue;
    let url: string;
    try {
      url = new URL(urlRaw, "https://www.3cx.com").toString();
    } catch (error) {
      continue;
    }
    const vendor = model.split(" ")[0] || "Unknown";
    entries.push({
      vendor,
      model,
      version,
      url,
      source,
    });
  }
  return entries;
}

function resolveDeviceFirmwareUrl(device: DeviceWithPbx): string | null {
  const override = String(device.firmware_url_override || "").trim();
  if (override) return override;
  if (device.firmware_url) return device.firmware_url;
  return null;
}

function md5(value: string): string {
  return crypto.createHash("md5").update(value).digest("hex");
}

function parseDigestChallenge(header: string): Record<string, string> | null {
  const match = header.match(/Digest\s+(.+)/i);
  if (!match) return null;
  const params = match[1];
  const result: Record<string, string> = {};
  const regex = /(\w+)=(".*?"|[^,]+)(?:,\s*|$)/g;
  let part: RegExpExecArray | null = null;
  while ((part = regex.exec(params)) !== null) {
    const key = part[1];
    const raw = part[2] ?? "";
    const value = raw.replace(/^"|"$/g, "");
    result[key] = value;
  }
  return result;
}

function buildDigestAuthHeader(options: {
  method: string;
  url: URL;
  username: string;
  password: string;
  challenge: Record<string, string>;
}): string | null {
  const { method, url, username, password, challenge } = options;
  const realm = challenge.realm;
  const nonce = challenge.nonce;
  if (!realm || !nonce) return null;
  const uri = url.pathname + url.search;
  const qop = challenge.qop ? challenge.qop.split(",")[0]?.trim() : null;
  const cnonce = crypto.randomBytes(8).toString("hex");
  const nc = "00000001";
  const ha1 = md5(`${username}:${realm}:${password}`);
  const ha2 = md5(`${method}:${uri}`);
  const response = qop
    ? md5(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`)
    : md5(`${ha1}:${nonce}:${ha2}`);

  const parts = [
    `username="${username}"`,
    `realm="${realm}"`,
    `nonce="${nonce}"`,
    `uri="${uri}"`,
    `response="${response}"`,
  ];
  if (challenge.opaque) {
    parts.push(`opaque="${challenge.opaque}"`);
  }
  if (qop) {
    parts.push(`qop=${qop}`, `nc=${nc}`, `cnonce="${cnonce}"`);
  }
  return `Digest ${parts.join(", ")}`;
}

async function fetchWithTimeout(
  url: URL,
  options: RequestInit = {}
): Promise<globalThis.Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timeoutId);
  }
}

type AmiMessage = Record<string, string>;

function sanitizeAmiValue(value: string): string {
  return value.replace(/[\r\n]/g, " ").trim();
}

function parseAmiMessage(block: string): AmiMessage {
  const message: AmiMessage = {};
  for (const line of block.split(/\r\n/)) {
    const separator = line.indexOf(":");
    if (separator <= 0) continue;
    const key = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    if (key) {
      message[key] = value;
    }
  }
  return message;
}

function formatAmiAction(fields: AmiMessage): string {
  const lines = Object.entries(fields).map(
    ([key, value]) => `${key}: ${sanitizeAmiValue(value)}`
  );
  return `${lines.join("\r\n")}\r\n\r\n`;
}

function createAmiActionId(): string {
  return crypto.randomUUID
    ? crypto.randomUUID()
    : crypto.randomBytes(12).toString("hex");
}

async function createAmiClient(options: {
  host: string;
  port: number;
  useTls: boolean;
}): Promise<{
  sendAction: (fields: AmiMessage) => Promise<AmiMessage>;
  close: () => void;
}> {
  const { host, port, useTls } = options;
  return new Promise((resolve, reject) => {
    const socket = useTls
      ? tls.connect({ host, port, rejectUnauthorized: false })
      : net.createConnection({ host, port });
    let buffer = "";
    let connected = false;
    const pending = new Map<
      string,
      { resolve: (msg: AmiMessage) => void; reject: (err: Error) => void; timer: NodeJS.Timeout }
    >();

    const flushPending = (error: Error) => {
      for (const entry of pending.values()) {
        clearTimeout(entry.timer);
        entry.reject(error);
      }
      pending.clear();
    };

    socket.setTimeout(AMI_TIMEOUT_MS);
    socket.on("timeout", () => {
      socket.destroy(new Error("AMI connection timed out."));
    });
    socket.on("error", (error) => {
      if (!connected) {
        reject(error);
      }
      flushPending(error instanceof Error ? error : new Error(String(error)));
    });
    socket.on("close", () => {
      flushPending(new Error("AMI connection closed."));
    });
    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      let boundary = buffer.indexOf("\r\n\r\n");
      while (boundary !== -1) {
        const raw = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 4);
        boundary = buffer.indexOf("\r\n\r\n");
        if (!raw.trim()) continue;
        const message = parseAmiMessage(raw);
        const actionId = message.ActionID;
        if (actionId && pending.has(actionId)) {
          const entry = pending.get(actionId);
          if (entry) {
            clearTimeout(entry.timer);
            pending.delete(actionId);
            entry.resolve(message);
          }
        }
      }
    });
    socket.on("connect", () => {
      connected = true;
      socket.setTimeout(0);
      resolve({
        sendAction: (fields: AmiMessage) => {
          return new Promise((sendResolve, sendReject) => {
            const actionId = createAmiActionId();
            const payload = { ...fields, ActionID: actionId };
            const timer = setTimeout(() => {
              pending.delete(actionId);
              sendReject(new Error("AMI response timeout."));
            }, AMI_TIMEOUT_MS);
            pending.set(actionId, {
              resolve: sendResolve,
              reject: sendReject,
              timer,
            });
            socket.write(formatAmiAction(payload));
          });
        },
        close: () => {
          socket.end();
        },
      });
    });
  });
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
  response: ExpressResponse,
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

function logProvisioningAccess(entry: {
  mac: string;
  ip: string;
  userAgent: string;
  status: "ok" | "unauthorized" | "not_found" | "error";
  reason?: string;
  pbx?: string;
}): void {
  console.info(
    JSON.stringify({
      ts: new Date().toISOString(),
      event: "provision_request",
      ...entry,
    })
  );
}

function getUpstreamAuthHeader(device: DeviceWithPbx): string | null {
  if (!device.pbx_upstream_username || !device.pbx_upstream_password) {
    return null;
  }
  const token = Buffer.from(
    `${device.pbx_upstream_username}:${device.pbx_upstream_password}`
  ).toString("base64");
  return `Basic ${token}`;
}

function getUpstreamCredentials(
  device: DeviceWithPbx
): { username: string; password: string } | null {
  if (!device.pbx_upstream_username || !device.pbx_upstream_password) {
    return null;
  }
  return {
    username: device.pbx_upstream_username,
    password: device.pbx_upstream_password,
  };
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

function buildFirmwareOptions(
  entries: FirmwareCatalogEntry[],
  selectedId: number | null,
  modelFilter?: string | null
): string {
  const normalizedFilter = String(modelFilter || "").trim().toLowerCase();
  let filtered = entries;
  if (normalizedFilter) {
    filtered = entries.filter((entry) =>
      entry.model.toLowerCase().includes(normalizedFilter)
    );
    if (!filtered.length) {
      filtered = entries;
    }
  }
  const options = filtered
    .map((entry) => {
      const label = `${entry.model} (${entry.version})`;
      const selected =
        selectedId && entry.id === selectedId ? " selected" : "";
      return `<option value="${entry.id}"${selected}>${escapeHtml(
        label
      )}</option>`;
    })
    .join("");
  return `<option value="">None</option>${options}`;
}

function formatTimestamp(value: string | null): string {
  if (!value) return "Never";
  return value.replace("T", " ").replace("Z", "");
}

function renderAdminPage({
  request,
  pbxServers,
  devices,
  firmwareCatalog,
  firmwareStats,
  message,
}: {
  request: Request;
  pbxServers: PbxServer[];
  devices: DeviceWithPbx[];
  firmwareCatalog: FirmwareCatalogEntry[];
  firmwareStats: { count: number; last_fetched_at: string | null };
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
  const firmwareOptionsAll = buildFirmwareOptions(
    firmwareCatalog,
    null,
    null
  );
  const firmwareCount = firmwareStats.count || 0;
  const firmwareLastSync = firmwareStats.last_fetched_at
    ? formatTimestamp(firmwareStats.last_fetched_at)
    : "Never";

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
          <label class="field">
            <span>Prov user</span>
            <input name="prov_username" type="text" value="${escapeHtml(
              server.prov_username || ""
            )}" placeholder="Optional" />
          </label>
          <label class="field">
            <span>Prov pass</span>
            <input name="prov_password" type="password" value="${escapeHtml(
              server.prov_password || ""
            )}" placeholder="Optional" />
          </label>
          <label class="field">
            <span>Upstream base URL</span>
            <input name="upstream_base_url" type="url" value="${escapeHtml(
              server.upstream_base_url || ""
            )}" placeholder="https://pbx.example.com/prov/yealink/" />
          </label>
          <label class="field">
            <span>Upstream user</span>
            <input name="upstream_username" type="text" value="${escapeHtml(
              server.upstream_username || ""
            )}" placeholder="Optional" />
          </label>
          <label class="field">
            <span>Upstream pass</span>
            <input name="upstream_password" type="password" value="${escapeHtml(
              server.upstream_password || ""
            )}" placeholder="Optional" />
          </label>
          <label class="field">
            <span>Upstream MAC case</span>
            <select name="upstream_mac_case">
              <option value="lower"${
                !server.upstream_mac_case || server.upstream_mac_case === "lower"
                  ? " selected"
                  : ""
              }>lowercase</option>
              <option value="upper"${
                server.upstream_mac_case === "upper" ? " selected" : ""
              }>UPPERCASE</option>
            </select>
          </label>
          <label class="field">
            <span>AMI host</span>
            <input name="ami_host" type="text" value="${escapeHtml(
              server.ami_host || ""
            )}" placeholder="pbx.dtbicom.xyz" />
          </label>
          <label class="field">
            <span>AMI port</span>
            <input name="ami_port" type="number" min="1" max="65535" value="${escapeHtml(
              server.ami_port || 5038
            )}" />
          </label>
          <label class="field">
            <span>AMI user</span>
            <input name="ami_username" type="text" value="${escapeHtml(
              server.ami_username || ""
            )}" placeholder="Optional" />
          </label>
          <label class="field">
            <span>AMI pass</span>
            <input name="ami_password" type="password" value="${escapeHtml(
              server.ami_password || ""
            )}" placeholder="Optional" />
          </label>
          <label class="field">
            <span>AMI TLS</span>
            <select name="ami_tls">
              <option value="0"${
                !server.ami_tls ? " selected" : ""
              }>Disabled</option>
              <option value="1"${
                server.ami_tls ? " selected" : ""
              }>Enabled</option>
            </select>
          </label>
          <div class="form-actions">
            <button class="button" type="submit">Save</button>
          </div>
        </form>
        <form method="post" action="/admin/pbx-servers/${server.id}/test-ami" class="inline-form">
          <button class="button button--ghost" type="submit">Test AMI</button>
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
      const firmwareOptions = buildFirmwareOptions(
        firmwareCatalog,
        device.firmware_id,
        device.model
      );
      const firmwareUrl = resolveDeviceFirmwareUrl(device);
      const firmwareLabel = device.firmware_url_override
        ? "Firmware override URL"
        : device.firmware_model
          ? `${device.firmware_model} (${device.firmware_version || "unknown"})`
          : null;
      const notifyEndpoint = String(
        device.pjsip_endpoint || device.auth_user || ""
      ).trim();
      const notifyReady = Boolean(
        device.pbx_ami_host &&
          device.pbx_ami_username &&
          device.pbx_ami_password &&
          notifyEndpoint
      );
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
            <span>Model</span>
            <input name="model" type="text" value="${escapeHtml(device.model || "")}" placeholder="Yealink T43U" />
          </label>
          <label class="field">
            <span>PJSIP endpoint</span>
            <input name="pjsip_endpoint" type="text" value="${escapeHtml(
              device.pjsip_endpoint || ""
            )}" placeholder="200100" />
          </label>
          <label class="field">
            <span>Firmware</span>
            <select name="firmware_id">
              ${firmwareOptions}
            </select>
          </label>
          <label class="field">
            <span>Firmware override URL</span>
            <input name="firmware_url_override" type="url" value="${escapeHtml(
              device.firmware_url_override || ""
            )}" placeholder="https://example.com/fw.rom" />
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
          ${
            firmwareLabel
              ? `<span class="tag">${escapeHtml(firmwareLabel)}</span>`
              : ""
          }
          ${
            device.firmware_pending
              ? `<span class="tag tag--pending">Firmware pending</span>`
              : ""
          }
          <span class="tag">Last sent: ${escapeHtml(
            formatTimestamp(device.firmware_sent_at)
          )}</span>
        </div>
        <form method="post" action="/admin/devices/${device.id}/firmware/trigger" class="inline-form">
          <button class="button button--ghost" type="submit"${
            firmwareUrl ? "" : " disabled"
          }>Trigger firmware update</button>
        </form>
        <form method="post" action="/admin/devices/${device.id}/notify" class="inline-form">
          <button class="button button--ghost" type="submit"${
            notifyReady ? "" : " disabled"
          }>Trigger check-sync</button>
        </form>
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
            <h1>Yealink Auto Provisioning Switchboard</h1>
            <p class="subhead">Manage PBX servers and push Yealink configs instantly.</p>
            <p class="helper">Yealink server URL: ${escapeHtml(
              `${baseUrl}/yealink/`
            )} (phone appends its MAC + .cfg)</p>
            <p class="attribution">Built by Bernis@Bicom</p>
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
      <section class="card reveal" style="--delay:100ms">
        <div class="card-header">
          <h2>Firmware catalog</h2>
          <p class="subhead">Sync firmware URLs from 3CX (V20 + V18) and target one-shot updates per device.</p>
          <p class="helper">Entries: ${escapeHtml(
            firmwareCount
          )} &bull; Last sync: ${escapeHtml(firmwareLastSync)}</p>
        </div>
        <form method="post" action="/admin/firmware/sync" class="form-grid form-grid--tight">
          <button class="button" type="submit">Sync from 3CX</button>
        </form>
      </section>

      <section class="card reveal" style="--delay:120ms">
        <div class="card-header">
          <h2>PBX servers</h2>
          <p class="subhead">Store connection details and transport for each PBX.</p>
          <p class="helper">Use upstream settings if PBXware already hosts full Yealink configs (BLFs, keys, etc.). Base URL should point to the folder containing MAC.cfg; choose MAC case + upstream auth if needed.</p>
          <p class="helper">AMI settings enable check-sync notifications (PJSIPNotify) for instant reprovisioning.</p>
          <p class="helper">Use "Test AMI" after saving to verify the credentials before triggering check-sync.</p>
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
          <label class="field">
            <span>Prov user</span>
            <input name="prov_username" type="text" placeholder="Optional" />
          </label>
          <label class="field">
            <span>Prov pass</span>
            <input name="prov_password" type="password" placeholder="Optional" />
          </label>
          <label class="field">
            <span>Upstream base URL</span>
            <input name="upstream_base_url" type="url" placeholder="https://pbx.example.com/prov/yealink/" />
          </label>
          <label class="field">
            <span>Upstream user</span>
            <input name="upstream_username" type="text" placeholder="Optional" />
          </label>
          <label class="field">
            <span>Upstream pass</span>
            <input name="upstream_password" type="password" placeholder="Optional" />
          </label>
          <label class="field">
            <span>Upstream MAC case</span>
            <select name="upstream_mac_case">
              <option value="lower" selected>lowercase</option>
              <option value="upper">UPPERCASE</option>
            </select>
          </label>
          <label class="field">
            <span>AMI host</span>
            <input name="ami_host" type="text" placeholder="pbx.dtbicom.xyz" />
          </label>
          <label class="field">
            <span>AMI port</span>
            <input name="ami_port" type="number" min="1" max="65535" value="5038" />
          </label>
          <label class="field">
            <span>AMI user</span>
            <input name="ami_username" type="text" placeholder="Optional" />
          </label>
          <label class="field">
            <span>AMI pass</span>
            <input name="ami_password" type="password" placeholder="Optional" />
          </label>
          <label class="field">
            <span>AMI TLS</span>
            <select name="ami_tls">
              <option value="0" selected>Disabled</option>
              <option value="1">Enabled</option>
            </select>
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
          <p class="helper">Firmware updates are one-shot and apply on the next provisioning request.</p>
          <p class="helper">Check-sync notifications require AMI credentials on the PBX and a PJSIP endpoint.</p>
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
            <span>Model</span>
            <input name="model" type="text" placeholder="Yealink T43U" />
          </label>
          <label class="field">
            <span>PJSIP endpoint</span>
            <input name="pjsip_endpoint" type="text" placeholder="200100" />
          </label>
          <label class="field">
            <span>Firmware</span>
            <select name="firmware_id">
              ${firmwareOptionsAll}
            </select>
          </label>
          <label class="field">
            <span>Firmware override URL</span>
            <input name="firmware_url_override" type="url" placeholder="https://example.com/fw.rom" />
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
  const message: NoticeMessage | null = errorParam
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
  const firmwareCatalog = statements.listFirmware.all() as FirmwareCatalogEntry[];
  const firmwareStatsRow = statements.getFirmwareStats.get() as
    | { count: number; last_fetched_at: string | null }
    | undefined;
  const firmwareStats = {
    count: firmwareStatsRow?.count ?? 0,
    last_fetched_at: firmwareStatsRow?.last_fetched_at ?? null,
  };
  response.send(
    renderAdminPage({
      request,
      pbxServers,
      devices,
      firmwareCatalog,
      firmwareStats,
      message,
    })
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
  const provUser = String(request.body.prov_username || "").trim();
  const provPass = String(request.body.prov_password || "");
  const upstreamBaseInput = String(request.body.upstream_base_url || "").trim();
  const upstreamBaseUrl = normalizeBaseUrl(upstreamBaseInput);
  const upstreamUser = String(request.body.upstream_username || "").trim();
  const upstreamPass = String(request.body.upstream_password || "");
  const upstreamMacCaseInput = String(
    request.body.upstream_mac_case || "lower"
  ).toLowerCase();
  const upstreamMacCase =
    upstreamMacCaseInput === "upper" ? "upper" : "lower";
  const amiHostInput = String(request.body.ami_host || "").trim();
  const amiPortInput = parseInteger(request.body.ami_port, 5038);
  const amiUser = String(request.body.ami_username || "").trim();
  const amiPass = String(request.body.ami_password || "");
  const amiTls = String(request.body.ami_tls || "0") === "1" ? 1 : 0;

  if (!name || !host || !transport || port < 1 || port > 65535) {
    response.redirect(
      buildNoticeUrl("/admin", "error", "Invalid PBX server data.")
    );
    return;
  }
  if ((provUser && !provPass) || (!provUser && provPass)) {
    response.redirect(
      buildNoticeUrl(
        "/admin",
        "error",
        "Provisioning username and password must both be set."
      )
    );
    return;
  }
  if (upstreamBaseInput && !upstreamBaseUrl) {
    response.redirect(
      buildNoticeUrl("/admin", "error", "Upstream URL is invalid.")
    );
    return;
  }
  if ((upstreamUser && !upstreamPass) || (!upstreamUser && upstreamPass)) {
    response.redirect(
      buildNoticeUrl(
        "/admin",
        "error",
        "Upstream username and password must both be set."
      )
    );
    return;
  }
  if (amiHostInput && (amiPortInput < 1 || amiPortInput > 65535)) {
    response.redirect(
      buildNoticeUrl("/admin", "error", "AMI port is invalid.")
    );
    return;
  }
  if ((amiHostInput || amiUser || amiPass) && (!amiHostInput || !amiUser || !amiPass)) {
    response.redirect(
      buildNoticeUrl(
        "/admin",
        "error",
        "AMI host, username, and password must all be set."
      )
    );
    return;
  }
  const amiHost = amiHostInput || null;
  const amiPort = amiHost ? amiPortInput : null;
  const amiUsername = amiHost ? amiUser : null;
  const amiPassword = amiHost ? amiPass : null;
  const amiTlsValue = amiHost ? amiTls : 0;

  const now = new Date().toISOString();
  statements.insertPbx.run(
    name,
    host,
    port,
    transport,
    proxyHost || null,
    proxyPort || null,
    provUser || null,
    provPass || null,
    upstreamBaseUrl || null,
    upstreamUser || null,
    upstreamPass || null,
    upstreamMacCase,
    amiHost,
    amiPort,
    amiUsername,
    amiPassword,
    amiTlsValue,
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
  const provUser = String(request.body.prov_username || "").trim();
  const provPass = String(request.body.prov_password || "");
  const upstreamBaseInput = String(request.body.upstream_base_url || "").trim();
  const upstreamBaseUrl = normalizeBaseUrl(upstreamBaseInput);
  const upstreamUser = String(request.body.upstream_username || "").trim();
  const upstreamPass = String(request.body.upstream_password || "");
  const upstreamMacCaseInput = String(
    request.body.upstream_mac_case || "lower"
  ).toLowerCase();
  const upstreamMacCase =
    upstreamMacCaseInput === "upper" ? "upper" : "lower";
  const amiHostInput = String(request.body.ami_host || "").trim();
  const amiPortInput = parseInteger(request.body.ami_port, 5038);
  const amiUser = String(request.body.ami_username || "").trim();
  const amiPass = String(request.body.ami_password || "");
  const amiTls = String(request.body.ami_tls || "0") === "1" ? 1 : 0;

  if (!name || !host || !transport || port < 1 || port > 65535) {
    response.redirect(
      buildNoticeUrl("/admin", "error", "Invalid PBX server data.")
    );
    return;
  }
  if ((provUser && !provPass) || (!provUser && provPass)) {
    response.redirect(
      buildNoticeUrl(
        "/admin",
        "error",
        "Provisioning username and password must both be set."
      )
    );
    return;
  }
  if (upstreamBaseInput && !upstreamBaseUrl) {
    response.redirect(
      buildNoticeUrl("/admin", "error", "Upstream URL is invalid.")
    );
    return;
  }
  if ((upstreamUser && !upstreamPass) || (!upstreamUser && upstreamPass)) {
    response.redirect(
      buildNoticeUrl(
        "/admin",
        "error",
        "Upstream username and password must both be set."
      )
    );
    return;
  }
  if (amiHostInput && (amiPortInput < 1 || amiPortInput > 65535)) {
    response.redirect(
      buildNoticeUrl("/admin", "error", "AMI port is invalid.")
    );
    return;
  }
  if ((amiHostInput || amiUser || amiPass) && (!amiHostInput || !amiUser || !amiPass)) {
    response.redirect(
      buildNoticeUrl(
        "/admin",
        "error",
        "AMI host, username, and password must all be set."
      )
    );
    return;
  }
  const amiHost = amiHostInput || null;
  const amiPort = amiHost ? amiPortInput : null;
  const amiUsername = amiHost ? amiUser : null;
  const amiPassword = amiHost ? amiPass : null;
  const amiTlsValue = amiHost ? amiTls : 0;

  const now = new Date().toISOString();
  statements.updatePbx.run(
    name,
    host,
    port,
    transport,
    proxyHost || null,
    proxyPort || null,
    provUser || null,
    provPass || null,
    upstreamBaseUrl || null,
    upstreamUser || null,
    upstreamPass || null,
    upstreamMacCase,
    amiHost,
    amiPort,
    amiUsername,
    amiPassword,
    amiTlsValue,
    now,
    id
  );

  response.redirect(buildNoticeUrl("/admin", "notice", "PBX updated."));
});

app.post(
  "/admin/pbx-servers/:id/test-ami",
  requireAuth,
  async (request, response) => {
    const id = Number.parseInt(request.params.id, 10);
    const pbx = statements.getPbx.get(id) as PbxServer | undefined;
    if (!pbx) {
      response.redirect(buildNoticeUrl("/admin", "error", "PBX not found."));
      return;
    }
    if (!pbx.ami_host || !pbx.ami_username || !pbx.ami_password) {
      response.redirect(
        buildNoticeUrl(
          "/admin",
          "error",
          "PBX AMI settings are incomplete."
        )
      );
      return;
    }

    let client: Awaited<ReturnType<typeof createAmiClient>> | null = null;
    try {
      client = await createAmiClient({
        host: pbx.ami_host,
        port: pbx.ami_port || 5038,
        useTls: pbx.ami_tls === 1,
      });
      const login = await client.sendAction({
        Action: "Login",
        Username: pbx.ami_username,
        Secret: pbx.ami_password,
        Events: "off",
      });
      if (login.Response !== "Success") {
        throw new Error(login.Message || "AMI login failed.");
      }
      await client.sendAction({ Action: "Logoff" }).catch(() => undefined);
      response.redirect(
        buildNoticeUrl("/admin", "notice", "AMI connection successful.")
      );
    } catch (error) {
      const message =
        error instanceof Error && error.message
          ? error.message
          : "AMI connection failed.";
      response.redirect(buildNoticeUrl("/admin", "error", message));
    } finally {
      if (client) {
        client.close();
      }
    }
  }
);

app.post(
  "/admin/pbx-servers/:id/delete",
  requireAuth,
  (request, response) => {
    const id = Number.parseInt(request.params.id, 10);
    statements.deletePbx.run(id);
    response.redirect(buildNoticeUrl("/admin", "notice", "PBX removed."));
  }
);

app.post("/admin/firmware/sync", requireAuth, async (_request, response) => {
  try {
    const fetchOptions = {
      headers: { "user-agent": "prov-dtbicom-xyz firmware sync" },
    };
    const [v20Response, v18Response] = await Promise.all([
      fetch("https://www.3cx.com/docs/phone-firmwares/", fetchOptions),
      fetch("https://www.3cx.com/docs/phone-firmware-v18/", fetchOptions),
    ]);
    if (!v20Response.ok || !v18Response.ok) {
      const status = !v20Response.ok
        ? v20Response.status
        : v18Response.status;
      response.redirect(
        buildNoticeUrl(
          "/admin",
          "error",
          `Firmware sync failed (${status}).`
        )
      );
      return;
    }
    const [v20Html, v18Html] = await Promise.all([
      v20Response.text(),
      v18Response.text(),
    ]);
    const parsed = [
      ...parse3cxFirmwareCatalog(v20Html, "3cx-v20"),
      ...parse3cxFirmwareCatalog(v18Html, "3cx-v18"),
    ];
    if (!parsed.length) {
      response.redirect(
        buildNoticeUrl("/admin", "error", "No firmware entries found.")
      );
      return;
    }
    const unique = new Map<string, FirmwareCatalogInput>();
    for (const entry of parsed) {
      const key = `${entry.model}||${entry.version}||${entry.url}||${entry.source}`;
      if (!unique.has(key)) {
        unique.set(key, entry);
      }
    }
    const entries = Array.from(unique.values());
    const now = new Date().toISOString();
    const insertEntries = db.transaction((rows: FirmwareCatalogInput[]) => {
      for (const row of rows) {
        statements.upsertFirmware.run(
          row.vendor,
          row.model,
          row.version,
          row.url,
          row.source,
          now,
          now,
          now
        );
      }
    });
    insertEntries(entries);
    response.redirect(
      buildNoticeUrl(
        "/admin",
        "notice",
        `Firmware sync complete (${entries.length} entries).`
      )
    );
  } catch (error) {
    response.redirect(
      buildNoticeUrl("/admin", "error", "Firmware sync failed.")
    );
  }
});

app.post("/admin/devices", requireAuth, (request, response) => {
  const mac = normalizeMac(request.body.mac);
  const label = String(request.body.label || "").trim();
  const extension = String(request.body.extension || "").trim();
  const authUser = String(request.body.auth_user || "").trim();
  const authPass = String(request.body.auth_pass || "");
  const displayName = String(request.body.display_name || "").trim();
  const model = String(request.body.model || "").trim();
  const pjsipEndpoint = String(request.body.pjsip_endpoint || "").trim();
  const firmwareIdInput = parseInteger(request.body.firmware_id, 0);
  const firmwareUrlOverrideInput = String(
    request.body.firmware_url_override || ""
  ).trim();
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

  const firmwareUrlOverride = firmwareUrlOverrideInput
    ? normalizeUrl(firmwareUrlOverrideInput)
    : null;
  if (firmwareUrlOverrideInput && !firmwareUrlOverride) {
    response.redirect(
      buildNoticeUrl("/admin", "error", "Firmware override URL is invalid.")
    );
    return;
  }

  let firmwareId: number | null = null;
  if (firmwareIdInput > 0) {
    const firmware = statements.getFirmware.get(
      firmwareIdInput
    ) as FirmwareCatalogEntry | undefined;
    if (firmware) {
      firmwareId = firmwareIdInput;
    }
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
      model || null,
      pjsipEndpoint || null,
      firmwareId,
      firmwareUrlOverride,
      0,
      null,
      null,
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
  const model = String(request.body.model || "").trim();
  const pjsipEndpoint = String(request.body.pjsip_endpoint || "").trim();
  const firmwareIdInput = parseInteger(request.body.firmware_id, 0);
  const firmwareUrlOverrideInput = String(
    request.body.firmware_url_override || ""
  ).trim();
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

  const firmwareUrlOverride = firmwareUrlOverrideInput
    ? normalizeUrl(firmwareUrlOverrideInput)
    : null;
  if (firmwareUrlOverrideInput && !firmwareUrlOverride) {
    response.redirect(
      buildNoticeUrl("/admin", "error", "Firmware override URL is invalid.")
    );
    return;
  }

  let firmwareId: number | null = null;
  if (firmwareIdInput > 0) {
    const firmware = statements.getFirmware.get(
      firmwareIdInput
    ) as FirmwareCatalogEntry | undefined;
    if (firmware) {
      firmwareId = firmwareIdInput;
    }
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
      model || null,
      pjsipEndpoint || null,
      firmwareId,
      firmwareUrlOverride,
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
  "/admin/devices/:id/firmware/trigger",
  requireAuth,
  (request, response) => {
    const id = Number.parseInt(request.params.id, 10);
    const device = statements.getDevice.get(id) as DeviceWithPbx | undefined;
    if (!device) {
      response.redirect(buildNoticeUrl("/admin", "error", "Device not found."));
      return;
    }
    const firmwareUrl = resolveDeviceFirmwareUrl(device);
    if (!firmwareUrl) {
      response.redirect(
        buildNoticeUrl(
          "/admin",
          "error",
          "Select firmware or set an override URL first."
        )
      );
      return;
    }
    const now = new Date().toISOString();
    statements.triggerFirmware.run(now, now, id);
    response.redirect(
      buildNoticeUrl(
        "/admin",
        "notice",
        "Firmware update queued for next provision."
      )
    );
  }
);

app.post(
  "/admin/devices/:id/notify",
  requireAuth,
  async (request, response) => {
    const id = Number.parseInt(request.params.id, 10);
    const device = statements.getDevice.get(id) as DeviceWithPbx | undefined;
    if (!device) {
      response.redirect(buildNoticeUrl("/admin", "error", "Device not found."));
      return;
    }
    const endpoint = String(
      device.pjsip_endpoint || device.auth_user || ""
    ).trim();
    if (!endpoint) {
      response.redirect(
        buildNoticeUrl(
          "/admin",
          "error",
          "PJSIP endpoint is required to send check-sync."
        )
      );
      return;
    }
    if (!device.pbx_ami_host || !device.pbx_ami_username || !device.pbx_ami_password) {
      response.redirect(
        buildNoticeUrl(
          "/admin",
          "error",
          "PBX AMI settings are incomplete."
        )
      );
      return;
    }

    let client: Awaited<ReturnType<typeof createAmiClient>> | null = null;
    try {
      client = await createAmiClient({
        host: device.pbx_ami_host,
        port: device.pbx_ami_port || 5038,
        useTls: device.pbx_ami_tls === 1,
      });
      const login = await client.sendAction({
        Action: "Login",
        Username: device.pbx_ami_username,
        Secret: device.pbx_ami_password,
        Events: "off",
      });
      if (login.Response !== "Success") {
        throw new Error(login.Message || "AMI login failed.");
      }
      const notify = await client.sendAction({
        Action: "PJSIPNotify",
        Endpoint: endpoint,
        Event: "check-sync",
      });
      if (notify.Response !== "Success") {
        throw new Error(notify.Message || "AMI notify failed.");
      }
      await client.sendAction({ Action: "Logoff" }).catch(() => undefined);
      response.redirect(
        buildNoticeUrl("/admin", "notice", "Check-sync sent via AMI.")
      );
    } catch (error) {
      const message =
        error instanceof Error && error.message
          ? error.message
          : "AMI notify failed.";
      response.redirect(buildNoticeUrl("/admin", "error", message));
    } finally {
      if (client) {
        client.close();
      }
    }
  }
);

app.post(
  "/admin/devices/:id/delete",
  requireAuth,
  (request, response) => {
    const id = Number.parseInt(request.params.id, 10);
    statements.deleteDevice.run(id);
    response.redirect(buildNoticeUrl("/admin", "notice", "Device removed."));
  }
);

app.get("/yealink/:mac.cfg", async (request, response) => {
  const normalized = normalizeMac(request.params.mac);
  if (!normalized) {
    logProvisioningAccess({
      mac: String(request.params.mac || ""),
      ip: request.ip || "unknown",
      userAgent: request.get("user-agent") || "unknown",
      status: "not_found",
      reason: "invalid_mac",
    });
    response.status(404).send("Not Found");
    return;
  }

  const device = statements.getDeviceByMac.get(normalized) as
    | DeviceWithPbx
    | undefined;
  if (!device) {
    logProvisioningAccess({
      mac: normalized,
      ip: request.ip || "unknown",
      userAgent: request.get("user-agent") || "unknown",
      status: "not_found",
      reason: "unknown_mac",
    });
    response.status(404).send("Not Found");
    return;
  }

  const provUser = device.pbx_prov_username;
  const provPass = device.pbx_prov_password;
  if (provUser || provPass) {
    if (!provUser || !provPass) {
      logProvisioningAccess({
        mac: normalized,
        ip: request.ip || "unknown",
        userAgent: request.get("user-agent") || "unknown",
        status: "error",
        reason: "prov_credentials_misconfigured",
        pbx: device.pbx_name,
      });
      response.status(500).send("Provisioning credentials are misconfigured.");
      return;
    }
    const credentials = parseBasicAuthHeader(request.headers.authorization);
    if (
      !credentials ||
      credentials.username !== provUser ||
      credentials.password !== provPass
    ) {
      logProvisioningAccess({
        mac: normalized,
        ip: request.ip || "unknown",
        userAgent: request.get("user-agent") || "unknown",
        status: "unauthorized",
        reason: credentials ? "invalid_credentials" : "missing_credentials",
        pbx: device.pbx_name,
      });
      response.setHeader("WWW-Authenticate", "Basic realm=\"Provisioning\"");
      response.status(401).send("Unauthorized");
      return;
    }
  }

  const firmwareUrl = resolveDeviceFirmwareUrl(device);
  const firmwarePending = Boolean(device.firmware_pending);
  const shouldInjectFirmware = firmwarePending && Boolean(firmwareUrl);

  if (device.pbx_upstream_base_url) {
    const upstreamMac =
      device.pbx_upstream_mac_case === "upper"
        ? normalized.toUpperCase()
        : normalized;
    const upstreamUrl = new URL(
      `${upstreamMac}.cfg`,
      device.pbx_upstream_base_url
    );
    const forwardedUserAgent = request.get("user-agent") || "Yealink";
    const proxyHost = request.get("host") || "prov.dtbicom.xyz";
    const baseHeaders: Record<string, string> = {
      "user-agent": `${forwardedUserAgent} (via ${proxyHost})`,
    };
    const credentials = getUpstreamCredentials(device);
    let upstreamResponse: globalThis.Response | null = null;
    try {
      upstreamResponse = await fetchWithTimeout(upstreamUrl, {
        headers: baseHeaders,
      });
      if (upstreamResponse.status === 401 && credentials) {
        const authHeader = upstreamResponse.headers.get("www-authenticate");
        if (authHeader) {
          const challenge = parseDigestChallenge(authHeader);
          if (challenge) {
            const digestHeader = buildDigestAuthHeader({
              method: "GET",
              url: upstreamUrl,
              username: credentials.username,
              password: credentials.password,
              challenge,
            });
            if (digestHeader) {
              upstreamResponse = await fetchWithTimeout(upstreamUrl, {
                headers: { ...baseHeaders, authorization: digestHeader },
              });
            }
          } else if (authHeader.toLowerCase().includes("basic")) {
            const basicHeader = getUpstreamAuthHeader(device);
            if (basicHeader) {
              upstreamResponse = await fetchWithTimeout(upstreamUrl, {
                headers: { ...baseHeaders, authorization: basicHeader },
              });
            }
          }
        }
      }
      const contentType =
        upstreamResponse.headers.get("content-type") ||
        "text/plain; charset=utf-8";
      const body = await upstreamResponse.text();
      const shouldApplyFirmware = upstreamResponse.ok && shouldInjectFirmware;
      const responseBody = shouldApplyFirmware
        ? applyFirmwareUrl(body, firmwareUrl as string)
        : body;
      if (shouldApplyFirmware) {
        const now = new Date().toISOString();
        statements.markFirmwareSent.run(now, now, device.id);
      }
      logProvisioningAccess({
        mac: normalized,
        ip: request.ip || "unknown",
        userAgent: request.get("user-agent") || "unknown",
        status: upstreamResponse.ok ? "ok" : "error",
        reason: upstreamResponse.ok
          ? "upstream_ok"
          : `upstream_${upstreamResponse.status}`,
        pbx: device.pbx_name,
      });
      response.status(upstreamResponse.status);
      response.setHeader("Content-Type", contentType);
      response.setHeader("Cache-Control", "no-store");
      response.send(responseBody || "Upstream provisioning failed.");
      return;
    } catch (error) {
      logProvisioningAccess({
        mac: normalized,
        ip: request.ip || "unknown",
        userAgent: request.get("user-agent") || "unknown",
        status: "error",
        reason: "upstream_error",
        pbx: device.pbx_name,
      });
      response.status(502).send("Upstream provisioning failed.");
      return;
    }
  }

  let config = renderYealinkConfig(device);
  if (shouldInjectFirmware) {
    config = applyFirmwareUrl(config, firmwareUrl as string);
    const now = new Date().toISOString();
    statements.markFirmwareSent.run(now, now, device.id);
  }
  logProvisioningAccess({
    mac: normalized,
    ip: request.ip || "unknown",
    userAgent: request.get("user-agent") || "unknown",
    status: "ok",
    reason: provUser ? "auth_ok" : "no_auth",
    pbx: device.pbx_name,
  });
  response.setHeader("Content-Type", "text/plain; charset=utf-8");
  response.setHeader("Cache-Control", "no-store");
  response.send(config);
});

app.listen(PORT, () => {
  console.log(`Provisioning server listening on :${PORT}`);
});
