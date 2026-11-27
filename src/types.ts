export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  /** Repo-relative path this finding points to, when it has one (not every
   *  check is file-specific — e.g. live/permission findings aren't). Always
   *  forward-slash, even on Windows, since this feeds SARIF artifact URIs. */
  location?: { file: string };
}

export interface AuditReport {
  target: string;
  mode: "source" | "live";
  findings: Finding[];
}
