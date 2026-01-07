import express from "express";
import cookieParser from "cookie-parser";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import tls from "node:tls";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import multer from "multer";
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
const LOG_PAGE_LIMIT = Number.parseInt(
  process.env.LOG_PAGE_LIMIT || "500",
  10
);
const DB_PATH =
  process.env.DB_PATH || path.join(projectRoot, "data", "provisioning.db");
const FIRMWARE_DIR =
  process.env.FIRMWARE_DIR ||
  path.join(path.dirname(DB_PATH), "firmware");
const FIRMWARE_BASE_URL = process.env.FIRMWARE_BASE_URL || "";
const FIRMWARE_IMPORT_ENABLED =
  process.env.FIRMWARE_IMPORT_ENABLED !== "0";
const FIRMWARE_IMPORT_URLS = (process.env.FIRMWARE_IMPORT_URLS || "")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);

const dataDir = path.dirname(DB_PATH);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}
if (!fs.existsSync(FIRMWARE_DIR)) {
  fs.mkdirSync(FIRMWARE_DIR, { recursive: true });
}
const firmwareTmpDir = path.join(FIRMWARE_DIR, ".tmp");
if (!fs.existsSync(firmwareTmpDir)) {
  fs.mkdirSync(firmwareTmpDir, { recursive: true });
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
    ami_notify_type TEXT,
    ami_reboot_type TEXT,
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

  CREATE TABLE IF NOT EXISTS provisioning_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    mac TEXT NOT NULL,
    ip TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT,
    pbx TEXT
  );

  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
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
  { name: "ami_notify_type", type: "TEXT" },
  { name: "ami_reboot_type", type: "TEXT" },
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
  ami_notify_type: string | null;
  ami_reboot_type: string | null;
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
  pbx_ami_notify_type: string | null;
  pbx_ami_reboot_type: string | null;
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
};

type ProvisionLogRow = {
  id: number;
  created_at: string;
  mac: string;
  ip: string;
  user_agent: string;
  status: string;
  reason: string | null;
  pbx: string | null;
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
      (name, host, port, transport, outbound_proxy_host, outbound_proxy_port, prov_username, prov_password, upstream_base_url, upstream_username, upstream_password, upstream_mac_case, ami_host, ami_port, ami_username, ami_password, ami_tls, ami_notify_type, ami_reboot_type, created_at, updated_at)
    VALUES
      (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `),
  updatePbx: db.prepare(`
    UPDATE pbx_servers
    SET name = ?, host = ?, port = ?, transport = ?, outbound_proxy_host = ?, outbound_proxy_port = ?, prov_username = ?, prov_password = ?, upstream_base_url = ?, upstream_username = ?, upstream_password = ?, upstream_mac_case = ?, ami_host = ?, ami_port = ?, ami_username = ?, ami_password = ?, ami_tls = ?, ami_notify_type = ?, ami_reboot_type = ?, updated_at = ?
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
           pbx_servers.ami_notify_type AS pbx_ami_notify_type,
           pbx_servers.ami_reboot_type AS pbx_ami_reboot_type,
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
           pbx_servers.ami_notify_type AS pbx_ami_notify_type,
           pbx_servers.ami_reboot_type AS pbx_ami_reboot_type,
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
           pbx_servers.ami_notify_type AS pbx_ami_notify_type,
           pbx_servers.ami_reboot_type AS pbx_ami_reboot_type,
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
  insertProvisionLog: db.prepare(`
    INSERT INTO provisioning_logs
      (created_at, mac, ip, user_agent, status, reason, pbx)
    VALUES
      (?, ?, ?, ?, ?, ?, ?)
  `),
  listProvisionLogs: db.prepare(`
    SELECT * FROM provisioning_logs
    ORDER BY created_at DESC
    LIMIT ?
  `),
  listProvisionLogsFiltered: db.prepare(`
    SELECT * FROM provisioning_logs
    WHERE mac LIKE ? COLLATE NOCASE
       OR ip LIKE ? COLLATE NOCASE
       OR user_agent LIKE ? COLLATE NOCASE
       OR status LIKE ? COLLATE NOCASE
       OR reason LIKE ? COLLATE NOCASE
       OR pbx LIKE ? COLLATE NOCASE
    ORDER BY created_at DESC
    LIMIT ?
  `),
  getProvisionLogStats: db.prepare(
    "SELECT COUNT(*) AS count FROM provisioning_logs"
  ),
  getProvisionLogCountFiltered: db.prepare(`
    SELECT COUNT(*) AS count FROM provisioning_logs
    WHERE mac LIKE ? COLLATE NOCASE
       OR ip LIKE ? COLLATE NOCASE
       OR user_agent LIKE ? COLLATE NOCASE
       OR status LIKE ? COLLATE NOCASE
       OR reason LIKE ? COLLATE NOCASE
       OR pbx LIKE ? COLLATE NOCASE
  `),
  listFirmware: db.prepare(
    "SELECT * FROM firmware_catalog ORDER BY vendor COLLATE NOCASE, model COLLATE NOCASE, version COLLATE NOCASE"
  ),
  getFirmwareStats: db.prepare(
    "SELECT COUNT(*) AS count, MAX(fetched_at) AS last_fetched_at FROM firmware_catalog"
  ),
  getFirmware: db.prepare("SELECT * FROM firmware_catalog WHERE id = ?"),
  getFirmwareByKey: db.prepare(
    "SELECT * FROM firmware_catalog WHERE vendor = ? AND model = ? AND version = ?"
  ),
  deleteFirmwareByKey: db.prepare(
    "DELETE FROM firmware_catalog WHERE vendor = ? AND model = ? AND version = ?"
  ),
  clearFirmwareCatalog: db.prepare("DELETE FROM firmware_catalog"),
  insertFirmware: db.prepare(`
    INSERT INTO firmware_catalog
      (vendor, model, version, url, source, fetched_at, created_at, updated_at)
    VALUES
      (?, ?, ?, ?, ?, ?, ?, ?)
  `),
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
  clearFirmwareAssignments: db.prepare(`
    UPDATE devices
    SET firmware_id = NULL,
        firmware_pending = 0,
        firmware_requested_at = NULL,
        firmware_sent_at = NULL,
        updated_at = ?
  `),
  insertSession: db.prepare(
    "INSERT INTO sessions (token, created_at, expires_at) VALUES (?, ?, ?)"
  ),
  getSession: db.prepare("SELECT * FROM sessions WHERE token = ?"),
  deleteSession: db.prepare("DELETE FROM sessions WHERE token = ?"),
  deleteExpiredSessions: db.prepare(
    "DELETE FROM sessions WHERE expires_at <= ?"
  ),
  getSetting: db.prepare("SELECT value FROM settings WHERE key = ?"),
  deleteSetting: db.prepare("DELETE FROM settings WHERE key = ?"),
  setSetting: db.prepare(`
    INSERT INTO settings (key, value)
    VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `),
};

const app = express();
app.set("trust proxy", true);
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use("/assets", express.static(path.join(projectRoot, "public")));
app.use(
  "/firmware",
  express.static(FIRMWARE_DIR, { dotfiles: "ignore" })
);

if (ADMIN_PASS === "change-me") {
  console.warn("ADMIN_PASS is set to the default; update it before production use.");
}

const FIRMWARE_SOURCE = "local";
const firmwareUpload = multer({ dest: firmwareTmpDir });

async function clearFirmwareFiles(): Promise<void> {
  await fs.promises.mkdir(FIRMWARE_DIR, { recursive: true });
  const entries = await fs.promises.readdir(FIRMWARE_DIR, {
    withFileTypes: true,
  });
  await Promise.all(
    entries.map(async (entry) => {
      const fullPath = path.join(FIRMWARE_DIR, entry.name);
      if (entry.name === ".tmp") {
        await fs.promises.rm(fullPath, { recursive: true, force: true });
        await fs.promises.mkdir(fullPath, { recursive: true });
        return;
      }
      await fs.promises.rm(fullPath, { recursive: true, force: true });
    })
  );
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

function sanitizeFileComponent(value: string): string {
  const cleaned = value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return cleaned || "firmware";
}

function sanitizeExtension(value: string): string {
  const cleaned = value.toLowerCase().replace(/[^a-z0-9.]/g, "");
  if (!cleaned) return ".bin";
  return cleaned.startsWith(".") ? cleaned : `.${cleaned}`;
}

function buildFirmwareFileName(params: {
  vendor: string;
  model: string;
  version: string;
  extension: string;
}): string {
  const vendor = sanitizeFileComponent(params.vendor);
  const model = sanitizeFileComponent(params.model);
  const version = sanitizeFileComponent(params.version);
  const extension = sanitizeExtension(params.extension);
  return `${vendor}_${model}_${version}${extension}`;
}

function getFirmwareBaseUrl(request: Request): string {
  if (FIRMWARE_BASE_URL) {
    return FIRMWARE_BASE_URL.replace(/\/+$/, "");
  }
  const host = request.get("host") ?? "localhost";
  return `${request.protocol}://${host}/firmware`;
}

async function downloadToFile(url: string, filePath: string): Promise<void> {
  const response = await fetch(url, {
    headers: { "user-agent": "AutoProv Switchboard firmware import" },
  });
  if (!response.ok || !response.body) {
    throw new Error(`Download failed (${response.status})`);
  }
  const tempPath = `${filePath}.tmp-${crypto.randomUUID()}`;
  try {
    await pipeline(
      Readable.fromWeb(response.body as any),
      fs.createWriteStream(tempPath)
    );
    await fs.promises.rename(tempPath, filePath);
  } catch (error) {
    await fs.promises.rm(tempPath, { force: true });
    throw error;
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

function parseFirmwareCatalog(html: string, baseUrl: string): FirmwareCatalogInput[] {
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
      url = new URL(urlRaw, baseUrl).toString();
    } catch (error) {
      continue;
    }
    const vendor = model.split(" ")[0] || "Unknown";
    entries.push({
      vendor,
      model,
      version,
      url,
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
  const timestamp = new Date().toISOString();
  const payload = {
    ts: timestamp,
    event: "provision_request",
    ...entry,
  };
  console.info(JSON.stringify(payload));
  try {
    statements.insertProvisionLog.run(
      timestamp,
      entry.mac,
      entry.ip,
      entry.userAgent,
      entry.status,
      entry.reason || null,
      entry.pbx || null
    );
  } catch (error) {
    console.warn("Failed to persist provisioning log.", error);
  }
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
      href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Sora:wght@400;500;600;700&display=swap"
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
    title: "AutoProv Switchboard",
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

function formatParisTimestamp(value: string | null): string {
  if (!value) return "Never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Europe/Paris",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).formatToParts(date);
  const lookup = Object.fromEntries(
    parts
      .filter((part) => part.type !== "literal")
      .map((part) => [part.type, part.value])
  );
  return `${lookup.year}-${lookup.month}-${lookup.day} ${lookup.hour}:${lookup.minute}:${lookup.second}`;
}
type AdminNavKey = "overview" | "pbx" | "devices" | "firmware" | "logs" | "about";

function getNoticeMessage(request: Request): NoticeMessage | null {
  const errorParam =
    typeof request.query.error === "string" ? request.query.error : null;
  const noticeParam =
    typeof request.query.notice === "string" ? request.query.notice : null;
  return errorParam
    ? { type: "error", text: errorParam }
    : noticeParam
      ? { type: "success", text: noticeParam }
      : null;
}

function renderAdminShell({
  request,
  title,
  activeNav,
  header,
  content,
  message,
}: {
  request: Request;
  title: string;
  activeNav: AdminNavKey;
  header: string;
  content: string;
  message: NoticeMessage | null;
}): string {
  const navItems: { key: AdminNavKey; label: string; href: string }[] = [
    { key: "overview", label: "Overview", href: "/admin/overview" },
    { key: "pbx", label: "PBX servers", href: "/admin/pbx" },
    { key: "devices", label: "Devices", href: "/admin/devices" },
    { key: "firmware", label: "Firmware", href: "/admin/firmware" },
    { key: "logs", label: "Logs", href: "/admin/logs" },
    { key: "about", label: "About", href: "/admin/about" },
  ];
  const navLinks = navItems
    .map(
      (item) =>
        `<a class="nav-link${
          item.key === activeNav ? " nav-link--active" : ""
        }" href="${item.href}">${escapeHtml(item.label)}</a>`
    )
    .join("");
  const shell = `
    <div class="app-shell">
      <aside class="sidebar">
        <div class="sidebar-brand">
          <div class="logo">P</div>
          <div>
            <p class="eyebrow">Provisioning</p>
            <p class="brand-title">AutoProv Switchboard</p>
          </div>
        </div>
        <nav class="nav">
          ${navLinks}
        </nav>
        <div class="sidebar-footer">
          <p class="attribution">Built by Bernis@Bicom</p>
          <form method="post" action="/admin/logout" class="inline-form">
            <button class="button button--ghost" type="submit">Log out</button>
          </form>
        </div>
      </aside>
      <div class="content">
        <header class="page-header">
          ${header}
        </header>
        <main class="page-main">
          ${content}
        </main>
      </div>
    </div>
  `;
  return renderLayout({
    title,
    bodyClass: "admin",
    content: shell,
    message,
  });
}

function buildPbxRows(pbxServers: PbxServer[]): string {
  return pbxServers
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
          <label class="field">
            <span>AMI notify type</span>
            <input name="ami_notify_type" type="text" value="${escapeHtml(
              server.ami_notify_type || "yealink-notify"
            )}" placeholder="yealink-notify" />
          </label>
          <label class="field">
            <span>AMI reboot type</span>
            <input name="ami_reboot_type" type="text" value="${escapeHtml(
              server.ami_reboot_type || "yealink-reboot"
            )}" placeholder="yealink-reboot" />
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
}

function buildDeviceRows({
  devices,
  pbxServers,
  firmwareCatalog,
  baseUrl,
}: {
  devices: DeviceWithPbx[];
  pbxServers: PbxServer[];
  firmwareCatalog: FirmwareCatalogEntry[];
  baseUrl: string;
}): string {
  return devices
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
        <form method="post" action="/admin/devices/${device.id}/reboot" class="inline-form">
          <button class="button button--ghost" type="submit"${
            notifyReady ? "" : " disabled"
          }>Trigger reboot</button>
        </form>
        <form method="post" action="/admin/devices/${device.id}/delete" class="inline-form">
          <button class="button button--ghost" type="submit">Delete</button>
        </form>
      </article>
      `;
    })
    .join("");
}

function renderOverviewPage({
  request,
  pbxServers,
  devices,
  firmwareStats,
  message,
}: {
  request: Request;
  pbxServers: PbxServer[];
  devices: DeviceWithPbx[];
  firmwareStats: { count: number; last_fetched_at: string | null };
  message: NoticeMessage | null;
}): string {
  const host = request.get("host") ?? "localhost";
  const baseUrl = `${request.protocol}://${host}`;
  const provisionPattern = `${baseUrl}/yealink/{mac}.cfg`;
  const serverUrl = `${baseUrl}/yealink/`;
  const firmwareCount = firmwareStats.count || 0;
  const firmwareLastSync = firmwareStats.last_fetched_at
    ? formatTimestamp(firmwareStats.last_fetched_at)
    : "Never";
  const header = `
    <div>
      <p class="eyebrow">Provisioning</p>
      <h1 class="page-title">Overview</h1>
      <p class="subhead">Track your provisioning status and jump into setup.</p>
    </div>
  `;
  const content = `
    <section class="summary-grid">
      <div class="summary-card">
        <p class="summary-label">PBX servers</p>
        <p class="summary-value">${pbxServers.length}</p>
        <p class="summary-meta">Configured systems</p>
      </div>
      <div class="summary-card">
        <p class="summary-label">Devices</p>
        <p class="summary-value">${devices.length}</p>
        <p class="summary-meta">Active endpoints</p>
      </div>
      <div class="summary-card">
        <p class="summary-label">Yealink firmware</p>
        <p class="summary-value">${firmwareCount}</p>
        <p class="summary-meta">Last update: ${escapeHtml(firmwareLastSync)}</p>
      </div>
    </section>

    <section class="card">
      <div class="card-header">
        <h2>Provisioning URL</h2>
        <p class="subhead">Paste the server URL into Yealink Auto Provisioning.</p>
      </div>
      <div class="provisioning-grid">
        <div class="provisioning-block">
          <span class="helper">Server URL</span>
          <code class="mono code-block">${escapeHtml(serverUrl)}</code>
        </div>
        <div class="provisioning-block">
          <span class="helper">Phone pattern</span>
          <code class="mono code-block">${escapeHtml(provisionPattern)}</code>
        </div>
      </div>
      <div class="steps">
        <div class="step">1. Add your PBX server details.</div>
        <div class="step">2. Add devices and SIP credentials.</div>
        <div class="step">3. Point the phone to the server URL.</div>
      </div>
    </section>

    <section class="card">
      <div class="card-header">
        <h2>Quick actions</h2>
        <p class="subhead">Jump straight to the tasks you do most.</p>
      </div>
      <div class="quick-links">
        <a class="link-card" href="/admin/pbx">
          <strong>PBX servers</strong>
          <span>Add or update PBX connections.</span>
        </a>
        <a class="link-card" href="/admin/devices">
          <strong>Devices</strong>
          <span>Pair MACs and push check-sync.</span>
        </a>
        <a class="link-card" href="/admin/firmware">
          <strong>Firmware</strong>
          <span>Manage firmware files and trigger updates.</span>
        </a>
        <a class="link-card" href="/admin/logs">
          <strong>Logs</strong>
          <span>Review provisioning requests and outcomes.</span>
        </a>
      </div>
    </section>
  `;
  return renderAdminShell({
    request,
    title: "Provisioning Overview",
    activeNav: "overview",
    header,
    content,
    message,
  });
}

function renderPbxPage({
  request,
  pbxServers,
  message,
}: {
  request: Request;
  pbxServers: PbxServer[];
  message: NoticeMessage | null;
}): string {
  const pbxRows = buildPbxRows(pbxServers);
  const header = `
    <div>
      <p class="eyebrow">Provisioning</p>
      <h1 class="page-title">PBX servers</h1>
      <p class="subhead">Store connection details, upstream configs, and AMI credentials.</p>
    </div>
  `;
  const content = `
    <section class="card">
      <div class="card-header">
        <h2>Add PBX server</h2>
        <p class="subhead">Define SIP and provisioning details for each PBX.</p>
        <p class="helper">Use upstream settings if PBXware already hosts full Yealink configs (BLFs, keys, etc.).</p>
        <p class="helper">AMI settings enable check-sync notifications (PJSIPNotify) for instant reprovisioning.</p>
        <p class="helper">Use "Test AMI" after saving to verify credentials before triggering check-sync or reboot.</p>
        <p class="helper">PBXware defaults: notify type "yealink-notify" and reboot type "yealink-reboot".</p>
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
        <label class="field">
          <span>AMI notify type</span>
          <input name="ami_notify_type" type="text" value="yealink-notify" />
        </label>
        <label class="field">
          <span>AMI reboot type</span>
          <input name="ami_reboot_type" type="text" value="yealink-reboot" />
        </label>
        <div class="form-actions">
          <button class="button" type="submit">Add server</button>
        </div>
      </form>
    </section>

    <section class="card">
      <div class="card-header">
        <h2>Existing servers</h2>
        <p class="subhead">Edit, test AMI, or remove a PBX server.</p>
      </div>
      <div class="list">
        ${pbxRows || "<p class=\"empty\">No PBX servers yet.</p>"}
      </div>
    </section>
  `;
  return renderAdminShell({
    request,
    title: "PBX servers",
    activeNav: "pbx",
    header,
    content,
    message,
  });
}

function renderDevicesPage({
  request,
  pbxServers,
  devices,
  firmwareCatalog,
  message,
}: {
  request: Request;
  pbxServers: PbxServer[];
  devices: DeviceWithPbx[];
  firmwareCatalog: FirmwareCatalogEntry[];
  message: NoticeMessage | null;
}): string {
  const host = request.get("host") ?? "localhost";
  const baseUrl = `${request.protocol}://${host}`;
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
  const deviceRows = buildDeviceRows({
    devices,
    pbxServers,
    firmwareCatalog,
    baseUrl,
  });
  const header = `
    <div>
      <p class="eyebrow">Provisioning</p>
      <h1 class="page-title">Devices</h1>
      <p class="subhead">Pair MAC addresses with SIP credentials and a PBX.</p>
    </div>
  `;
  const content = `
    <section class="card">
      <div class="card-header">
        <h2>Add device</h2>
        <p class="subhead">Firmware updates are one-shot and apply on the next provisioning request.</p>
        <p class="helper">Check-sync and reboot notifications require AMI credentials on the PBX and a PJSIP endpoint.</p>
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
    </section>

    <section class="card">
      <div class="card-header">
        <h2>Registered devices</h2>
        <p class="subhead">Update credentials, trigger check-sync, or queue firmware updates.</p>
      </div>
      <div class="list">
        ${deviceRows || "<p class=\"empty\">No devices yet.</p>"}
      </div>
    </section>
  `;
  return renderAdminShell({
    request,
    title: "Devices",
    activeNav: "devices",
    header,
    content,
    message,
  });
}

function renderFirmwarePage({
  request,
  firmwareCatalog,
  firmwareStats,
  firmwareImportedAt,
  message,
}: {
  request: Request;
  firmwareCatalog: FirmwareCatalogEntry[];
  firmwareStats: { count: number; last_fetched_at: string | null };
  firmwareImportedAt: string | null;
  message: NoticeMessage | null;
}): string {
  const firmwareCount = firmwareStats.count || 0;
  const firmwareLastSync = firmwareStats.last_fetched_at
    ? formatTimestamp(firmwareStats.last_fetched_at)
    : "Never";
  const filterInput =
    typeof request.query.q === "string" ? request.query.q.trim() : "";
  const normalizedFilter = filterInput.toLowerCase();
  const filtered = normalizedFilter
    ? firmwareCatalog.filter((entry) => {
        const haystack = `${entry.vendor} ${entry.model} ${entry.version} ${entry.url}`.toLowerCase();
        return haystack.includes(normalizedFilter);
      })
    : firmwareCatalog;
  const firmwareRows = filtered
    .map(
      (entry) => `
        <div class="table-row">
          <span>${escapeHtml(entry.vendor)}</span>
          <span>${escapeHtml(entry.model)}</span>
          <span>${escapeHtml(entry.version)}</span>
          <span class="mono table-url">${escapeHtml(entry.url)}</span>
        </div>
      `
    )
    .join("");
  const header = `
    <div>
      <p class="eyebrow">Provisioning</p>
      <h1 class="page-title">Firmware</h1>
      <p class="subhead">Manage firmware URLs for one-shot updates.</p>
    </div>
  `;
  const importReady = FIRMWARE_IMPORT_ENABLED && !firmwareImportedAt;
  const content = `
    <section class="card">
      <div class="card-header">
        <h2>Yealink firmware catalog</h2>
        <p class="subhead">Manage Yealink firmware files hosted on this server.</p>
        <p class="helper">Entries: ${escapeHtml(
          firmwareCount
        )} &bull; Last change: ${escapeHtml(firmwareLastSync)}</p>
        ${
          firmwareImportedAt
            ? `<p class="helper">Import completed: ${escapeHtml(
                formatTimestamp(firmwareImportedAt)
              )}</p>`
            : ""
        }
      </div>
      <div class="card-actions">
        <form method="post" action="/admin/firmware/import" class="form-grid form-grid--tight">
          <button class="button" type="submit"${
            importReady ? "" : " disabled"
          }>Import Yealink firmware catalog</button>
        </form>
        <p class="helper">One-time import downloads Yealink firmware into local storage from the configured catalog URLs. Leave this page open while it runs.</p>
        <form method="post" action="/admin/firmware/clear" class="form-grid form-grid--tight" onsubmit="return confirm('Clear the firmware catalog and delete stored files?');">
          <button class="button button--ghost" type="submit">Clear firmware catalog</button>
        </form>
        <p class="helper">Clearing removes all catalog entries and deletes stored firmware files.</p>
      </div>
    </section>

    <section class="card">
      <div class="card-header">
        <h2>Add firmware</h2>
        <p class="subhead">Upload a firmware file and map it to a model + version.</p>
        <p class="helper">Uploading the same vendor/model/version replaces the existing entry.</p>
      </div>
      <form method="post" action="/admin/firmware/upload" enctype="multipart/form-data" class="form-grid">
        <label class="field">
          <span>Vendor</span>
          <input name="vendor" type="text" placeholder="Yealink" required />
        </label>
        <label class="field">
          <span>Model</span>
          <input name="model" type="text" placeholder="T43U" required />
        </label>
        <label class="field">
          <span>Version</span>
          <input name="version" type="text" placeholder="108.86.0.93" required />
        </label>
        <label class="field">
          <span>Firmware file</span>
          <input name="file" type="file" required />
        </label>
        <div class="form-actions">
          <button class="button" type="submit">Upload firmware</button>
        </div>
      </form>
    </section>

    <section class="card">
      <div class="card-header">
        <h2>Firmware entries</h2>
        <p class="subhead">Showing ${escapeHtml(
          filtered.length
        )} of ${escapeHtml(firmwareCount)} firmware entries.</p>
      </div>
      <form method="get" action="/admin/firmware" class="form-grid form-grid--tight">
        <label class="field">
          <span>Filter</span>
          <input name="q" type="text" value="${escapeHtml(filterInput)}" placeholder="Search vendor, model, version, URL" />
        </label>
        <div class="form-actions">
          <button class="button button--ghost" type="submit">Apply filter</button>
        </div>
      </form>
      <div class="table table--firmware">
        <div class="table-head">
          <span>Vendor</span>
          <span>Model</span>
          <span>Version</span>
          <span>URL</span>
        </div>
        ${
          firmwareRows ||
          `<p class="empty">${
            filterInput
              ? "No firmware entries match that filter."
              : "No firmware entries yet."
          }</p>`
        }
      </div>
    </section>
  `;
  return renderAdminShell({
    request,
    title: "Firmware",
    activeNav: "firmware",
    header,
    content,
    message,
  });
}

function renderLogsPage({
  request,
  logs,
  totalCount,
  filteredCount,
  filterInput,
  message,
}: {
  request: Request;
  logs: ProvisionLogRow[];
  totalCount: number;
  filteredCount: number;
  filterInput: string;
  message: NoticeMessage | null;
}): string {
  const rows = logs
    .map((entry) => {
      const formattedMac = formatMac(entry.mac) || entry.mac;
      const statusClass =
        entry.status === "ok"
          ? "tag tag--ok"
          : entry.status === "unauthorized"
            ? "tag tag--warn"
            : entry.status === "not_found"
              ? "tag tag--neutral"
              : "tag tag--error";
      return `
        <div class="table-row">
          <span>${escapeHtml(formatParisTimestamp(entry.created_at))}</span>
          <span class="mono">${escapeHtml(formattedMac)}</span>
          <span class="${statusClass}">${escapeHtml(entry.status)}</span>
          <span>${escapeHtml(entry.pbx || "—")}</span>
          <span class="mono">${escapeHtml(entry.ip)}</span>
          <span class="table-url">${escapeHtml(entry.reason || "—")}</span>
          <span class="table-url">${escapeHtml(entry.user_agent)}</span>
        </div>
      `;
    })
    .join("");
  const header = `
    <div>
      <p class="eyebrow">Provisioning</p>
      <h1 class="page-title">Logs</h1>
      <p class="subhead">Review provisioning requests and their outcomes.</p>
    </div>
  `;
  const content = `
    <section class="card">
      <div class="card-header">
        <h2>Provisioning logs</h2>
        <p class="subhead">Showing ${escapeHtml(
          String(filteredCount)
        )} of ${escapeHtml(String(totalCount))} entries (latest ${escapeHtml(
          String(LOG_PAGE_LIMIT)
        )}).</p>
      </div>
      <form method="get" action="/admin/logs" class="form-grid form-grid--tight">
        <label class="field">
          <span>Filter</span>
          <input name="q" type="text" value="${escapeHtml(
            filterInput
          )}" placeholder="Search MAC, status, PBX, IP, user agent" />
        </label>
        <div class="form-actions">
          <button class="button button--ghost" type="submit">Apply filter</button>
        </div>
      </form>
      <div class="table-scroll">
        <div class="table table--logs">
          <div class="table-head">
            <span>Time</span>
            <span>MAC</span>
            <span>Status</span>
            <span>PBX</span>
            <span>IP</span>
            <span>Reason</span>
            <span>User Agent</span>
          </div>
          ${
            rows ||
            `<p class="empty">${
              filterInput
                ? "No log entries match that filter."
                : "No provisioning logs yet."
            }</p>`
          }
        </div>
      </div>
    </section>
  `;
  return renderAdminShell({
    request,
    title: "Logs",
    activeNav: "logs",
    header,
    content,
    message,
  });
}

function renderAboutPage({
  request,
  message,
}: {
  request: Request;
  message: NoticeMessage | null;
}): string {
  const host = request.get("host") ?? "localhost";
  const baseUrl = `${request.protocol}://${host}`;
  const serverUrl = `${baseUrl}/yealink/`;
  const header = `
    <div>
      <p class="eyebrow">Provisioning</p>
      <h1 class="page-title">About</h1>
      <p class="subhead">How the AutoProv Switchboard works.</p>
    </div>
  `;
  const content = `
    <section class="card">
      <div class="card-header">
        <h2>What this panel does</h2>
        <p class="subhead">Centralizes provisioning data and delivers Yealink configs on demand.</p>
      </div>
      <div class="about-grid">
        <div class="about-card">
          <h3>Provisioning URL</h3>
          <p>Phones fetch configs from <code class="mono code-block">${escapeHtml(
            serverUrl
          )}</code>. The phone appends its MAC plus <code>.cfg</code>.</p>
        </div>
        <div class="about-card">
          <h3>PBX servers</h3>
          <p>Store SIP transport, proxy, and provisioning credentials per PBX. Optional upstream proxying lets you reuse existing PBXware config bundles.</p>
        </div>
        <div class="about-card">
          <h3>Devices</h3>
          <p>Each device maps a MAC to SIP credentials, line number, and PBX server. The config is generated dynamically at request time.</p>
        </div>
        <div class="about-card">
          <h3>AMI check-sync</h3>
          <p>When AMI credentials are set, you can trigger <code>PJSIPNotify</code> to make phones pull new configs or reboot on demand.</p>
        </div>
        <div class="about-card">
          <h3>Firmware updates</h3>
          <p>Upload firmware files, map them to models, and trigger one-shot updates. The firmware URL is merged into the config on the next provision.</p>
        </div>
        <div class="about-card">
          <h3>Access & logs</h3>
          <p>Admin access is protected by session cookies. Provisioning requests are logged with MAC, IP, and result.</p>
        </div>
      </div>
    </section>
  `;
  return renderAdminShell({
    request,
    title: "About",
    activeNav: "about",
    header,
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
  const message = getNoticeMessage(request);

  if (!session) {
    response.send(renderLoginPage({ message }));
    return;
  }
  if (message) {
    response.redirect(
      buildNoticeUrl(
        "/admin/overview",
        message.type === "error" ? "error" : "notice",
        message.text
      )
    );
    return;
  }
  response.redirect("/admin/overview");
});

app.get("/admin/overview", requireAuth, (request, response) => {
  const message = getNoticeMessage(request);
  const pbxServers = statements.listPbx.all() as PbxServer[];
  const devices = statements.listDevices.all() as DeviceWithPbx[];
  const firmwareStatsRow = statements.getFirmwareStats.get() as
    | { count: number; last_fetched_at: string | null }
    | undefined;
  const firmwareStats = {
    count: firmwareStatsRow?.count ?? 0,
    last_fetched_at: firmwareStatsRow?.last_fetched_at ?? null,
  };
  response.send(
    renderOverviewPage({
      request,
      pbxServers,
      devices,
      firmwareStats,
      message,
    })
  );
});

app.get("/admin/pbx", requireAuth, (request, response) => {
  const message = getNoticeMessage(request);
  const pbxServers = statements.listPbx.all() as PbxServer[];
  response.send(
    renderPbxPage({
      request,
      pbxServers,
      message,
    })
  );
});

app.get("/admin/devices", requireAuth, (request, response) => {
  const message = getNoticeMessage(request);
  const pbxServers = statements.listPbx.all() as PbxServer[];
  const devices = statements.listDevices.all() as DeviceWithPbx[];
  const firmwareCatalog = statements.listFirmware.all() as FirmwareCatalogEntry[];
  response.send(
    renderDevicesPage({
      request,
      pbxServers,
      devices,
      firmwareCatalog,
      message,
    })
  );
});

app.get("/admin/firmware", requireAuth, (request, response) => {
  const message = getNoticeMessage(request);
  const firmwareCatalog = statements.listFirmware.all() as FirmwareCatalogEntry[];
  const firmwareStatsRow = statements.getFirmwareStats.get() as
    | { count: number; last_fetched_at: string | null }
    | undefined;
  const importedRow = statements.getSetting.get(
    "firmware_imported_at"
  ) as { value: string } | undefined;
  const firmwareImportedAt = importedRow?.value ?? null;
  const firmwareStats = {
    count: firmwareStatsRow?.count ?? 0,
    last_fetched_at: firmwareStatsRow?.last_fetched_at ?? null,
  };
  response.send(
    renderFirmwarePage({
      request,
      firmwareCatalog,
      firmwareStats,
      firmwareImportedAt,
      message,
    })
  );
});

app.get("/admin/logs", requireAuth, (request, response) => {
  const message = getNoticeMessage(request);
  const filterInput =
    typeof request.query.q === "string" ? request.query.q.trim() : "";
  const totalRow = statements.getProvisionLogStats.get() as
    | { count: number }
    | undefined;
  const totalCount = totalRow?.count ?? 0;
  if (filterInput) {
    const query = `%${filterInput}%`;
    const logs = statements.listProvisionLogsFiltered.all(
      query,
      query,
      query,
      query,
      query,
      query,
      LOG_PAGE_LIMIT
    ) as ProvisionLogRow[];
    const filteredRow = statements.getProvisionLogCountFiltered.get(
      query,
      query,
      query,
      query,
      query,
      query
    ) as { count: number } | undefined;
    const filteredCount = filteredRow?.count ?? 0;
    response.send(
      renderLogsPage({
        request,
        logs,
        totalCount,
        filteredCount,
        filterInput,
        message,
      })
    );
    return;
  }
  const logs = statements.listProvisionLogs.all(
    LOG_PAGE_LIMIT
  ) as ProvisionLogRow[];
  response.send(
    renderLogsPage({
      request,
      logs,
      totalCount,
      filteredCount: totalCount,
      filterInput,
      message,
    })
  );
});

app.get("/admin/about", requireAuth, (request, response) => {
  const message = getNoticeMessage(request);
  response.send(renderAboutPage({ request, message }));
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
  response.redirect(buildNoticeUrl("/admin/overview", "notice", "Welcome back."));
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
  const amiNotifyTypeInput = String(
    request.body.ami_notify_type || ""
  ).trim();
  const amiRebootTypeInput = String(
    request.body.ami_reboot_type || ""
  ).trim();

  if (!name || !host || !transport || port < 1 || port > 65535) {
    response.redirect(
      buildNoticeUrl("/admin/pbx", "error", "Invalid PBX server data.")
    );
    return;
  }
  if ((provUser && !provPass) || (!provUser && provPass)) {
    response.redirect(
      buildNoticeUrl(
        "/admin/pbx",
        "error",
        "Provisioning username and password must both be set."
      )
    );
    return;
  }
  if (upstreamBaseInput && !upstreamBaseUrl) {
    response.redirect(
      buildNoticeUrl("/admin/pbx", "error", "Upstream URL is invalid.")
    );
    return;
  }
  if ((upstreamUser && !upstreamPass) || (!upstreamUser && upstreamPass)) {
    response.redirect(
      buildNoticeUrl(
        "/admin/pbx",
        "error",
        "Upstream username and password must both be set."
      )
    );
    return;
  }
  if (amiHostInput && (amiPortInput < 1 || amiPortInput > 65535)) {
    response.redirect(
      buildNoticeUrl("/admin/pbx", "error", "AMI port is invalid.")
    );
    return;
  }
  if ((amiHostInput || amiUser || amiPass) && (!amiHostInput || !amiUser || !amiPass)) {
    response.redirect(
      buildNoticeUrl(
        "/admin/pbx",
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
  const amiNotifyType = amiNotifyTypeInput || null;
  const amiRebootType = amiRebootTypeInput || null;

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
    amiNotifyType,
    amiRebootType,
    now,
    now
  );

  response.redirect(buildNoticeUrl("/admin/pbx", "notice", "PBX added."));
});

app.post("/admin/pbx-servers/:id", requireAuth, (request, response) => {
  const id = Number.parseInt(request.params.id, 10);
  const existing = statements.getPbx.get(id) as PbxServer | undefined;
  if (!existing) {
    response.redirect(buildNoticeUrl("/admin/pbx", "error", "PBX not found."));
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
  const amiNotifyTypeInput = String(
    request.body.ami_notify_type || ""
  ).trim();
  const amiRebootTypeInput = String(
    request.body.ami_reboot_type || ""
  ).trim();

  if (!name || !host || !transport || port < 1 || port > 65535) {
    response.redirect(
      buildNoticeUrl("/admin/pbx", "error", "Invalid PBX server data.")
    );
    return;
  }
  if ((provUser && !provPass) || (!provUser && provPass)) {
    response.redirect(
      buildNoticeUrl(
        "/admin/pbx",
        "error",
        "Provisioning username and password must both be set."
      )
    );
    return;
  }
  if (upstreamBaseInput && !upstreamBaseUrl) {
    response.redirect(
      buildNoticeUrl("/admin/pbx", "error", "Upstream URL is invalid.")
    );
    return;
  }
  if ((upstreamUser && !upstreamPass) || (!upstreamUser && upstreamPass)) {
    response.redirect(
      buildNoticeUrl(
        "/admin/pbx",
        "error",
        "Upstream username and password must both be set."
      )
    );
    return;
  }
  if (amiHostInput && (amiPortInput < 1 || amiPortInput > 65535)) {
    response.redirect(
      buildNoticeUrl("/admin/pbx", "error", "AMI port is invalid.")
    );
    return;
  }
  if ((amiHostInput || amiUser || amiPass) && (!amiHostInput || !amiUser || !amiPass)) {
    response.redirect(
      buildNoticeUrl(
        "/admin/pbx",
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
  const amiNotifyType = amiNotifyTypeInput || null;
  const amiRebootType = amiRebootTypeInput || null;

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
    amiNotifyType,
    amiRebootType,
    now,
    id
  );

  response.redirect(buildNoticeUrl("/admin/pbx", "notice", "PBX updated."));
});

app.post(
  "/admin/pbx-servers/:id/test-ami",
  requireAuth,
  async (request, response) => {
    const id = Number.parseInt(request.params.id, 10);
    const pbx = statements.getPbx.get(id) as PbxServer | undefined;
    if (!pbx) {
      response.redirect(buildNoticeUrl("/admin/pbx", "error", "PBX not found."));
      return;
    }
    if (!pbx.ami_host || !pbx.ami_username || !pbx.ami_password) {
      response.redirect(
        buildNoticeUrl(
          "/admin/pbx",
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
        buildNoticeUrl("/admin/pbx", "notice", "AMI connection successful.")
      );
    } catch (error) {
      const message =
        error instanceof Error && error.message
          ? error.message
          : "AMI connection failed.";
      response.redirect(buildNoticeUrl("/admin/pbx", "error", message));
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
    response.redirect(buildNoticeUrl("/admin/pbx", "notice", "PBX removed."));
  }
);

app.post("/admin/firmware/import", requireAuth, async (request, response) => {
  if (!FIRMWARE_IMPORT_ENABLED) {
    response.redirect(
      buildNoticeUrl("/admin/firmware", "error", "Firmware import is disabled.")
    );
    return;
  }
  try {
    const seedUrls = FIRMWARE_IMPORT_URLS;
    if (!seedUrls.length) {
      response.redirect(
        buildNoticeUrl(
          "/admin/firmware",
          "error",
          "Firmware import URLs are not configured."
        )
      );
      return;
    }
    const fetchOptions = {
      headers: { "user-agent": "AutoProv Switchboard firmware import" },
    };
    const responses = await Promise.all(
      seedUrls.map((url) => fetch(url, fetchOptions))
    );
    const failedResponse = responses.find((res) => !res.ok);
    if (failedResponse) {
      response.redirect(
        buildNoticeUrl(
          "/admin/firmware",
          "error",
          `Firmware import failed (${failedResponse.status}).`
        )
      );
      return;
    }
    const htmlPages = await Promise.all(responses.map((res) => res.text()));
    const parsed = htmlPages.flatMap((html, index) =>
      parseFirmwareCatalog(html, seedUrls[index] || "")
    );
    const yealinkEntries = parsed.filter(
      (entry) => entry.vendor.toLowerCase() === "yealink"
    );
    if (!yealinkEntries.length) {
      response.redirect(
        buildNoticeUrl(
          "/admin/firmware",
          "error",
          "No Yealink firmware entries found."
        )
      );
      return;
    }
    const unique = new Map<string, FirmwareCatalogInput>();
    for (const entry of yealinkEntries) {
      const key = `${entry.vendor}||${entry.model}||${entry.version}`;
      if (!unique.has(key)) {
        unique.set(key, entry);
      }
    }
    const entries = Array.from(unique.values());
    const baseUrl = getFirmwareBaseUrl(request);
    const now = new Date().toISOString();
    let successCount = 0;
    let failureCount = 0;
    const concurrency = 4;
    const queue = entries.slice();

    const workers = Array.from({ length: concurrency }, async () => {
      while (queue.length) {
        const entry = queue.shift();
        if (!entry) break;
        try {
          const extension = sanitizeExtension(
            path.extname(new URL(entry.url).pathname || "")
          );
          const fileName = buildFirmwareFileName({
            vendor: entry.vendor,
            model: entry.model,
            version: entry.version,
            extension,
          });
          const filePath = path.join(FIRMWARE_DIR, fileName);
          await downloadToFile(entry.url, filePath);
          const localUrl = `${baseUrl}/${encodeURIComponent(fileName)}`;
          const transaction = db.transaction(() => {
            statements.deleteFirmwareByKey.run(
              entry.vendor,
              entry.model,
              entry.version
            );
            statements.insertFirmware.run(
              entry.vendor,
              entry.model,
              entry.version,
              localUrl,
              FIRMWARE_SOURCE,
              now,
              now,
              now
            );
          });
          transaction();
          successCount += 1;
        } catch (error) {
          failureCount += 1;
        }
      }
    });

    await Promise.all(workers);
    if (successCount === 0) {
      response.redirect(
        buildNoticeUrl(
          "/admin/firmware",
          "error",
          "Firmware import failed (no files downloaded)."
        )
      );
      return;
    }
    statements.setSetting.run("firmware_imported_at", now);
    response.redirect(
      buildNoticeUrl(
        "/admin/firmware",
        "notice",
        `Yealink firmware import complete (${successCount} ok, ${failureCount} failed).`
      )
    );
  } catch (error) {
    response.redirect(
      buildNoticeUrl("/admin/firmware", "error", "Firmware import failed.")
    );
  }
});

app.post("/admin/firmware/clear", requireAuth, async (request, response) => {
  try {
    await clearFirmwareFiles();
    const now = new Date().toISOString();
    const transaction = db.transaction(() => {
      statements.clearFirmwareCatalog.run();
      statements.clearFirmwareAssignments.run(now);
      statements.deleteSetting.run("firmware_imported_at");
    });
    transaction();
    response.redirect(
      buildNoticeUrl("/admin/firmware", "notice", "Firmware catalog cleared.")
    );
  } catch (error) {
    response.redirect(
      buildNoticeUrl("/admin/firmware", "error", "Failed to clear firmware.")
    );
  }
});

app.post(
  "/admin/firmware/upload",
  requireAuth,
  firmwareUpload.single("file"),
  async (request, response) => {
    const vendor = String(request.body.vendor || "").trim();
    const model = String(request.body.model || "").trim();
    const version = String(request.body.version || "").trim();
    const file = request.file;
    if (!vendor || !model || !version || !file) {
      if (file?.path) {
        fs.promises.unlink(file.path).catch(() => undefined);
      }
      response.redirect(
        buildNoticeUrl("/admin/firmware", "error", "Invalid firmware data.")
      );
      return;
    }
    const extension = sanitizeExtension(path.extname(file.originalname || ""));
    const fileName = buildFirmwareFileName({
      vendor,
      model,
      version,
      extension,
    });
    const filePath = path.join(FIRMWARE_DIR, fileName);
    try {
      await fs.promises.rm(filePath, { force: true });
      await fs.promises.rename(file.path, filePath);
    } catch (error) {
      await fs.promises
        .copyFile(file.path, filePath)
        .then(() => fs.promises.unlink(file.path))
        .catch(() => undefined);
    }
    const baseUrl = getFirmwareBaseUrl(request);
    const localUrl = `${baseUrl}/${encodeURIComponent(fileName)}`;
    const now = new Date().toISOString();
    const transaction = db.transaction(() => {
      statements.deleteFirmwareByKey.run(vendor, model, version);
      statements.insertFirmware.run(
        vendor,
        model,
        version,
        localUrl,
        FIRMWARE_SOURCE,
        now,
        now,
        now
      );
    });
    transaction();
    response.redirect(
      buildNoticeUrl("/admin/firmware", "notice", "Firmware uploaded.")
    );
  }
);

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
      buildNoticeUrl("/admin/devices", "error", "Invalid device data.")
    );
    return;
  }

  const firmwareUrlOverride = firmwareUrlOverrideInput
    ? normalizeUrl(firmwareUrlOverrideInput)
    : null;
  if (firmwareUrlOverrideInput && !firmwareUrlOverride) {
    response.redirect(
      buildNoticeUrl(
        "/admin/devices",
        "error",
        "Firmware override URL is invalid."
      )
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
      buildNoticeUrl("/admin/devices", "error", "PBX server not found.")
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
      buildNoticeUrl("/admin/devices", "error", "Device MAC already exists.")
    );
    return;
  }

  response.redirect(
    buildNoticeUrl("/admin/devices", "notice", "Device added.")
  );
});

app.post("/admin/devices/:id", requireAuth, (request, response) => {
  const id = Number.parseInt(request.params.id, 10);
  const existing = statements.getDevice.get(id) as DeviceWithPbx | undefined;
  if (!existing) {
    response.redirect(
      buildNoticeUrl("/admin/devices", "error", "Device not found.")
    );
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
      buildNoticeUrl("/admin/devices", "error", "Invalid device data.")
    );
    return;
  }

  const firmwareUrlOverride = firmwareUrlOverrideInput
    ? normalizeUrl(firmwareUrlOverrideInput)
    : null;
  if (firmwareUrlOverrideInput && !firmwareUrlOverride) {
    response.redirect(
      buildNoticeUrl(
        "/admin/devices",
        "error",
        "Firmware override URL is invalid."
      )
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
      buildNoticeUrl("/admin/devices", "error", "PBX server not found.")
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
      buildNoticeUrl("/admin/devices", "error", "Device MAC already exists.")
    );
    return;
  }

  response.redirect(
    buildNoticeUrl("/admin/devices", "notice", "Device updated.")
  );
});

app.post(
  "/admin/devices/:id/firmware/trigger",
  requireAuth,
  (request, response) => {
    const id = Number.parseInt(request.params.id, 10);
    const device = statements.getDevice.get(id) as DeviceWithPbx | undefined;
    if (!device) {
      response.redirect(
        buildNoticeUrl("/admin/devices", "error", "Device not found.")
      );
      return;
    }
    const firmwareUrl = resolveDeviceFirmwareUrl(device);
    if (!firmwareUrl) {
      response.redirect(
        buildNoticeUrl(
          "/admin/devices",
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
        "/admin/devices",
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
      response.redirect(
        buildNoticeUrl("/admin/devices", "error", "Device not found.")
      );
      return;
    }
    const endpoint = String(
      device.pjsip_endpoint || device.auth_user || ""
    ).trim();
    if (!endpoint) {
      response.redirect(
        buildNoticeUrl(
          "/admin/devices",
          "error",
          "PJSIP endpoint is required to send check-sync."
        )
      );
      return;
    }
    if (!device.pbx_ami_host || !device.pbx_ami_username || !device.pbx_ami_password) {
      response.redirect(
        buildNoticeUrl(
          "/admin/devices",
          "error",
          "PBX AMI settings are incomplete."
        )
      );
      return;
    }
    const notifyType =
      (device.pbx_ami_notify_type || "yealink-notify").trim() ||
      "yealink-notify";

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
        Option: notifyType,
      });
      if (notify.Response !== "Success") {
        throw new Error(notify.Message || "AMI notify failed.");
      }
      await client.sendAction({ Action: "Logoff" }).catch(() => undefined);
      response.redirect(
        buildNoticeUrl("/admin/devices", "notice", "Check-sync sent via AMI.")
      );
    } catch (error) {
      const message =
        error instanceof Error && error.message
          ? error.message
          : "AMI notify failed.";
      response.redirect(buildNoticeUrl("/admin/devices", "error", message));
    } finally {
      if (client) {
        client.close();
      }
    }
  }
);

app.post(
  "/admin/devices/:id/reboot",
  requireAuth,
  async (request, response) => {
    const id = Number.parseInt(request.params.id, 10);
    const device = statements.getDevice.get(id) as DeviceWithPbx | undefined;
    if (!device) {
      response.redirect(
        buildNoticeUrl("/admin/devices", "error", "Device not found.")
      );
      return;
    }
    const endpoint = String(
      device.pjsip_endpoint || device.auth_user || ""
    ).trim();
    if (!endpoint) {
      response.redirect(
        buildNoticeUrl(
          "/admin/devices",
          "error",
          "PJSIP endpoint is required to send reboot."
        )
      );
      return;
    }
    if (!device.pbx_ami_host || !device.pbx_ami_username || !device.pbx_ami_password) {
      response.redirect(
        buildNoticeUrl(
          "/admin/devices",
          "error",
          "PBX AMI settings are incomplete."
        )
      );
      return;
    }
    const rebootType =
      (device.pbx_ami_reboot_type || "yealink-reboot").trim() ||
      "yealink-reboot";

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
        Option: rebootType,
      });
      if (notify.Response !== "Success") {
        throw new Error(notify.Message || "AMI notify failed.");
      }
      await client.sendAction({ Action: "Logoff" }).catch(() => undefined);
      response.redirect(
        buildNoticeUrl("/admin/devices", "notice", "Reboot sent via AMI.")
      );
    } catch (error) {
      const message =
        error instanceof Error && error.message
          ? error.message
          : "AMI notify failed.";
      response.redirect(buildNoticeUrl("/admin/devices", "error", message));
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
    response.redirect(
      buildNoticeUrl("/admin/devices", "notice", "Device removed.")
    );
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
