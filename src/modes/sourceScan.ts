import type { AuditReport } from "../types.js";
import { checkAuth } from "../checks/authCheck.js";
import { checkDependencies } from "../checks/depCheck.js";

/**
 * Mode A: static scan of a local MCP server repo.
 * Phase 1: auth check. Phase 2: npm dependency vulnerability check.
 * Secret leakage and permission over-reach checks land in later phases.
 */
export async function auditSource(path: string): Promise<AuditReport> {
  const [authFindings, depFindings] = await Promise.all([checkAuth(path), checkDependencies(path)]);

  return {
    target: path,
    mode: "source",
    findings: [...authFindings, ...depFindings],
  };
}
