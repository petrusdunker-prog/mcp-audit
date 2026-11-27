export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
}

export interface AuditReport {
  target: string;
  mode: "source" | "live";
  findings: Finding[];
}
