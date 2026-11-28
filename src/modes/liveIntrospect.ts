import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { AuditReport, Finding } from "../types.js";
import { checkToolPermissions } from "../checks/permissionCheck.js";
import { checkPromptInjection } from "../checks/injectionCheck.js";

export interface LiveTarget {
  command?: string;
  args?: string[];
  url?: string;
}

/**
 * Connect to an MCP server — either by launching it over stdio, or by
 * dialing an HTTP(S) URL with no credentials — and introspect its declared
 * tools. For a URL target, whether the connection succeeds at all *is* the
 * auth check: a server that hands back a tool list with zero credentials
 * offered has no authentication enforced on this endpoint.
 */
export async function auditLive(target: LiveTarget): Promise<AuditReport> {
  if (!target.url && !target.command) {
    throw new Error("auditLive requires either a url or a command");
  }

  const transport = target.url
    ? new StreamableHTTPClientTransport(new URL(target.url))
    : new StdioClientTransport({ command: target.command!, args: target.args ?? [] });

  const client = new Client({ name: "mcp-audit", version: "0.1.0" });
  const findings: Finding[] = [];
  let connected = false;

  try {
    await client.connect(transport);
    connected = true;

    if (target.url) {
      findings.push({
        id: "live.http-no-auth",
        severity: "high",
        title: "Server accepted connection with no credentials",
        detail:
          "mcp-audit connected and listed tools from this URL without sending any Authorization header or API key. This only tells you no credential is required from wherever this check was run — if the URL is loopback-only, exposure is limited to local processes; if it's reachable over a network, this is an open door to anyone who finds the URL.",
      });
    }

    const { tools } = await client.listTools();

    findings.push({
      id: "live.tools-discovered",
      severity: "info",
      title: `Discovered ${tools.length} tool(s)`,
      detail: tools.map((t) => t.name).join(", ") || "(none)",
    });

    for (const tool of tools) {
      findings.push({
        id: `live.tool.${tool.name}`,
        severity: "info",
        title: `Tool: ${tool.name}`,
        detail: tool.description?.slice(0, 200) ?? "(no description)",
      });
    }

    findings.push(...checkToolPermissions(tools));
    findings.push(...checkPromptInjection(tools));
  } catch (err) {
    if (target.url) {
      findings.push({
        id: "live.http-auth-enforced",
        severity: "info",
        title: "Connection rejected without credentials",
        detail: `Good sign: the server refused an unauthenticated request. (${String(err).slice(0, 200)})`,
      });
    } else {
      findings.push({
        id: "live.connect-failed",
        severity: "info",
        title: "Could not connect to target",
        detail: String(err).slice(0, 300),
      });
    }
  } finally {
    if (connected) await client.close().catch(() => {});
  }

  return {
    target: target.url ?? `${target.command} ${(target.args ?? []).join(" ")}`.trim(),
    mode: "live",
    findings,
  };
}
