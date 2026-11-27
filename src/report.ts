import type { AuditReport, Severity } from "./types.js";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "[CRITICAL]",
  high: "[HIGH]",
  medium: "[MEDIUM]",
  low: "[LOW]",
  info: "[INFO]",
};

export function printReport(report: AuditReport): void {
  console.log(`\nmcp-audit report — target: ${report.target} (mode: ${report.mode})\n`);

  if (report.findings.length === 0) {
    console.log("No findings.");
    return;
  }

  const sorted = [...report.findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  for (const finding of sorted) {
    console.log(`${SEVERITY_LABEL[finding.severity]} ${finding.title}`);
    console.log(`  ${finding.detail}`);
  }

  console.log(`\n${sorted.length} finding(s).`);
}

export function toJson(report: AuditReport): string {
  return JSON.stringify(report, null, 2);
}
