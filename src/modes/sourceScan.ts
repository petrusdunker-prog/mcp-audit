import type { AuditReport } from "../types.js";
import { checkAuth } from "../checks/authCheck.js";

/**
 * Mode A: static scan of a local MCP server repo.
 * Phase 1: auth check only. Dependency CVEs, secret leakage, and permission
 * over-reach checks land in later phases.
 */
export async function auditSource(path: string): Promise<AuditReport> {
  const findings = await checkAuth(path);

  return {
    target: path,
    mode: "source",
    findings,
  };
}
