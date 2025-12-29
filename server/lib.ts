export type TransportKey = "udp" | "tcp" | "tls";

export const transports = new Map<TransportKey, number>([
  ["udp", 0],
  ["tcp", 1],
  ["tls", 2],
]);

export interface DeviceConfig {
  line_number?: number | null;
  label?: string | null;
  display_name?: string | null;
  extension: string;
  auth_user: string;
  auth_pass: string;
  pbx_host: string;
  pbx_port?: number | null;
  pbx_transport?: string | null;
  pbx_proxy_host?: string | null;
  pbx_proxy_port?: number | null;
}

export function normalizeMac(input: unknown): string | null {
  const cleaned = String(input || "")
    .toLowerCase()
    .replace(/[^a-f0-9]/g, "");
  if (cleaned.length !== 12) return null;
  return cleaned;
}

export function formatMac(mac: unknown): string {
  const normalized = normalizeMac(mac);
  if (!normalized) return "";
  const chunks = normalized.match(/.{2}/g);
  return chunks ? chunks.join(":") : "";
}

export function sanitizeConfigValue(value: unknown): string {
  return String(value ?? "").replace(/[\r\n]/g, " ").trim();
}

export function parseInteger(value: unknown, fallback: number): number {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isNaN(parsed) ? fallback : parsed;
}

export function normalizeTransport(value: unknown): TransportKey | null {
  const key = String(value || "udp").toLowerCase();
  return transports.has(key as TransportKey) ? (key as TransportKey) : null;
}

export function renderYealinkConfig(device: DeviceConfig): string {
  const line = parseInteger(device.line_number, 1);
  const label = sanitizeConfigValue(device.label || device.extension);
  const displayName = sanitizeConfigValue(
    device.display_name || device.label || device.extension
  );
  const userName = sanitizeConfigValue(device.extension);
  const authName = sanitizeConfigValue(device.auth_user);
  const password = sanitizeConfigValue(device.auth_pass);
  const serverHost = sanitizeConfigValue(device.pbx_host);
  const serverPort = parseInteger(device.pbx_port, 5060);
  const transportKey = normalizeTransport(device.pbx_transport) || "udp";
  const transportValue = transports.get(transportKey) ?? 0;

  const lines = [
    "#!version:1.0.0.1",
    `account.${line}.enable = 1`,
    `account.${line}.label = ${label}`,
    `account.${line}.display_name = ${displayName}`,
    `account.${line}.user_name = ${userName}`,
    `account.${line}.auth_name = ${authName}`,
    `account.${line}.password = ${password}`,
    `account.${line}.sip_server.1.address = ${serverHost}`,
    `account.${line}.sip_server.1.port = ${serverPort}`,
    `account.${line}.transport = ${transportValue}`,
  ];

  if (device.pbx_proxy_host) {
    lines.push(`account.${line}.outbound_proxy_enable = 1`);
    lines.push(
      `account.${line}.outbound_proxy.1.address = ${sanitizeConfigValue(
        device.pbx_proxy_host
      )}`
    );
    if (device.pbx_proxy_port) {
      lines.push(
        `account.${line}.outbound_proxy.1.port = ${parseInteger(
          device.pbx_proxy_port,
          5060
        )}`
      );
    }
  }

  return lines.join("\n") + "\n";
}
