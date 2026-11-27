import type { AuditReport } from "../types.js";
import { checkAuth } from "../checks/authCheck.js";
import { checkDependencies } from "../checks/depCheck.js";
import { checkSecrets } from "../checks/secretCheck.js";

/**
 * Mode A: static scan of a local MCP server repo.
 * Phase 1: auth check. Phase 2: npm dependency vulnerability check.
 * Phase 3: secret leakage check. Permission over-reach lands on Mode B
 * (live tool introspection), where we have structured tool metadata.
 */
export async function auditSource(path: string): Promise<AuditReport> {
  const [authFindings, depFindings, secretFindings] = await Promise.all([
    checkAuth(path),
    checkDependencies(path),
    checkSecrets(path),
  ]);

  return {
    target: path,
    mode: "source",
    findings: [...authFindings, ...depFindings, ...secretFindings],
  };
}
