import type { AuditReport, Severity } from "./types.js";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

export function worseSeverity(a: Severity, b: Severity): Severity {
  return severityRank(a) <= severityRank(b) ? a : b;
}

/** True if any finding is at least as severe as `threshold` (e.g. threshold
 *  "high" matches "high" and "critical" findings). Used for CI exit codes. */
export function hasFindingAtOrAbove(report: AuditReport, threshold: Severity): boolean {
  return report.findings.some((f) => severityRank(f.severity) <= severityRank(threshold));
}
