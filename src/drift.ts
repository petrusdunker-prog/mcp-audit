import type { AuditReport, Finding, Severity } from "./types.js";
import { severityRank, SEVERITY_LABEL } from "./severity.js";

export type DriftStatus = "new" | "resolved";

export interface DriftEntry {
  status: DriftStatus;
  /** For "new": the finding as it is now. For "resolved": the finding as it
   *  was in the baseline (it no longer exists to describe "as it is now"). */
  finding: Finding;
}

export interface DriftSummary {
  newCount: number;
  resolvedCount: number;
  /** The single number a human should look at first: the worst severity
   *  among *new* findings, or null if nothing new appeared. A resolved
   *  CRITICAL is good news; a new LOW is still the thing to check first. */
  highestNewSeverity: Severity | null;
}

export interface DriftReport {
  /** What was scanned this time. */
  target: string;
  mode: "source" | "live";
  /** What the baseline was originally scanned against — surfaced so a
   *  mismatch (diffing against a baseline from a different target) is at
   *  least visible, not silently misleading. */
  baselineTarget: string;
  summary: DriftSummary;
  /** new + resolved only — unchanged findings are deliberately excluded,
   *  that's the whole point of a drift report. Sorted worst-first. */
  entries: DriftEntry[];
}

/**
 * Diffs two scans of (nominally) the same target by finding id. A finding's
 * id is the identity key: present in current but not baseline = "new",
 * present in baseline but not current = "resolved", present in both =
 * unchanged (and excluded from the result).
 *
 * This does NOT try to pair up "the same check got worse" (e.g. an
 * auth-pattern-found finding disappearing while a no-auth-pattern finding
 * appears for the same underlying transport) into a single "escalated"
 * entry — that shows up correctly anyway as a resolved low/info entry plus
 * a new high-severity entry, which is loud enough on its own. Pairing them
 * is a possible later refinement, not required for this to be useful.
 */
export function diffReports(baseline: AuditReport, current: AuditReport): DriftReport {
  const baselineIds = new Set(baseline.findings.map((f) => f.id));
  const currentIds = new Set(current.findings.map((f) => f.id));

  const entries: DriftEntry[] = [];

  for (const finding of current.findings) {
    if (!baselineIds.has(finding.id)) {
      entries.push({ status: "new", finding });
    }
  }
  for (const finding of baseline.findings) {
    if (!currentIds.has(finding.id)) {
      entries.push({ status: "resolved", finding });
    }
  }

  entries.sort((a, b) => severityRank(a.finding.severity) - severityRank(b.finding.severity));

  const newEntries = entries.filter((e) => e.status === "new");
  const summary: DriftSummary = {
    newCount: newEntries.length,
    resolvedCount: entries.length - newEntries.length,
    highestNewSeverity: newEntries[0]?.finding.severity ?? null,
  };

  return {
    target: current.target,
    mode: current.mode,
    baselineTarget: baseline.target,
    summary,
    entries,
  };
}

const STATUS_LABEL: Record<DriftStatus, string> = {
  new: "NEW",
  resolved: "RESOLVED",
};

export function printDrift(drift: DriftReport): void {
  console.log(`\nmcp-audit drift — target: ${drift.target} (baseline: ${drift.baselineTarget})\n`);

  if (drift.target !== drift.baselineTarget) {
    console.log(
      `Note: baseline was scanned from a different target path ("${drift.baselineTarget}") than this run ("${drift.target}") — comparing anyway, but verify this baseline is actually the right one.\n`
    );
  }

  if (drift.entries.length === 0) {
    console.log("No drift — nothing new, nothing resolved since the baseline.");
    return;
  }

  for (const entry of drift.entries) {
    console.log(`${STATUS_LABEL[entry.status]} ${SEVERITY_LABEL[entry.finding.severity]} ${entry.finding.title}`);
    console.log(`  ${entry.finding.detail}`);
  }

  console.log(
    `\n${drift.summary.newCount} new, ${drift.summary.resolvedCount} resolved.` +
      (drift.summary.highestNewSeverity ? ` Highest new severity: ${drift.summary.highestNewSeverity}.` : "")
  );
}

export function driftToJson(drift: DriftReport): string {
  return JSON.stringify(drift, null, 2);
}
