import { describe, expect, it } from "vitest";
import {
  formatMac,
  normalizeMac,
  parseBasicAuthHeader,
  applyFirmwareUrl,
  renderYealinkConfig,
} from "../server/lib.js";

describe("mac helpers", () => {
  it("normalizes MACs by stripping separators", () => {
    expect(normalizeMac("00:11:22:33:44:55")).toBe("001122334455");
    expect(normalizeMac("00-11-22-33-44-55")).toBe("001122334455");
    expect(normalizeMac("001122334455")).toBe("001122334455");
  });

  it("rejects invalid MACs", () => {
    expect(normalizeMac("not-a-mac")).toBeNull();
    expect(formatMac("not-a-mac")).toBe("");
  });

  it("formats MACs with colons", () => {
    expect(formatMac("001122334455")).toBe("00:11:22:33:44:55");
  });
});

describe("renderYealinkConfig", () => {
  it("renders core SIP fields", () => {
    const config = renderYealinkConfig({
      line_number: 2,
      label: "Front desk",
      display_name: "Front desk",
      extension: "1001",
      auth_user: "1001",
      auth_pass: "secret",
      pbx_host: "pbx.example.com",
      pbx_port: 5061,
      pbx_transport: "tcp",
    });

    expect(config).toContain("account.2.enable = 1");
    expect(config).toContain("account.2.user_name = 1001");
    expect(config).toContain("account.2.auth_name = 1001");
    expect(config).toContain("account.2.sip_server.1.address = pbx.example.com");
    expect(config).toContain("account.2.sip_server.1.port = 5061");
    expect(config).toContain("account.2.transport = 1");
    expect(config).toContain("account.2.sip_server_host = pbx.example.com");
    expect(config).toContain("account.2.sip_server_port = 5061");
    expect(config).toContain("account.2.sip_server.1.transport_type = 1");
  });

  it("includes outbound proxy when configured", () => {
    const config = renderYealinkConfig({
      extension: "2002",
      auth_user: "2002",
      auth_pass: "secret",
      pbx_host: "pbx.example.com",
      pbx_proxy_host: "proxy.example.com",
      pbx_proxy_port: 5080,
    });

    expect(config).toContain("outbound_proxy_enable = 1");
    expect(config).toContain(
      "outbound_proxy.1.address = proxy.example.com"
    );
    expect(config).toContain("outbound_proxy.1.port = 5080");
  });
});

describe("parseBasicAuthHeader", () => {
  it("parses valid basic auth headers", () => {
    const header = `Basic ${Buffer.from("user:pass").toString("base64")}`;
    expect(parseBasicAuthHeader(header)).toEqual({
      username: "user",
      password: "pass",
    });
  });

  it("rejects invalid headers", () => {
    expect(parseBasicAuthHeader("Bearer token")).toBeNull();
    expect(parseBasicAuthHeader("Basic")).toBeNull();
  });
});

describe("applyFirmwareUrl", () => {
  it("appends firmware.url when missing", () => {
    const config = "#!version:1.0.0.1\naccount.1.enable = 1\n";
    const output = applyFirmwareUrl(config, "https://example.com/fw.rom");
    expect(output).toContain("firmware.url = https://example.com/fw.rom");
  });

  it("replaces existing firmware.url entries", () => {
    const config =
      "#!version:1.0.0.1\nfirmware.url = http://old/fw.rom\naccount.1.enable = 1\n";
    const output = applyFirmwareUrl(config, "https://example.com/fw.rom");
    expect(output).not.toContain("firmware.url = http://old/fw.rom");
    expect(output).toContain("firmware.url = https://example.com/fw.rom");
  });
});
