import type { AuditReport } from "./types.js";
import { severityRank, SEVERITY_LABEL } from "./severity.js";

export function printReport(report: AuditReport): void {
  console.log(`\nmcp-audit report — target: ${report.target} (mode: ${report.mode})\n`);

  if (report.findings.length === 0) {
    console.log("No findings.");
    return;
  }

  const sorted = [...report.findings].sort(
    (a, b) => severityRank(a.severity) - severityRank(b.severity)
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
