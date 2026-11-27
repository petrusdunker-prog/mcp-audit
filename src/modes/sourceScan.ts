import type { AuditReport } from "../types.js";

/**
 * Mode A: static scan of a local MCP server repo (auth checks, dependency
 * CVEs, secret leakage, permission over-reach). Not implemented until
 * Phase 1 — this stub exists so the CLI surface is stable now.
 */
export async function auditSource(path: string): Promise<AuditReport> {
  return {
    target: path,
    mode: "source",
    findings: [
      {
        id: "source.not-implemented",
        severity: "info",
        title: "Source scan not implemented yet",
        detail: "Static checks (auth, dependency CVEs, secrets, permission scope) land in Phase 1.",
      },
    ],
  };
}
