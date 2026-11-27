import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { AuditReport, Finding } from "../types.js";

export interface LiveTarget {
  command: string;
  args: string[];
}

/**
 * Phase 0: connect to a locally-launchable MCP server over stdio and list its
 * tools. No real security checks yet — this just proves the introspection
 * plumbing works. Checks land in Phase 1+.
 */
export async function auditLive(target: LiveTarget): Promise<AuditReport> {
  const transport = new StdioClientTransport({
    command: target.command,
    args: target.args,
  });

  const client = new Client({ name: "mcp-audit", version: "0.1.0" });

  const findings: Finding[] = [];

  try {
    await client.connect(transport);
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
  } finally {
    await client.close().catch(() => {});
  }

  return {
    target: `${target.command} ${target.args.join(" ")}`.trim(),
    mode: "live",
    findings,
  };
}
