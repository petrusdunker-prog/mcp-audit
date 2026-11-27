import type { Finding } from "../types.js";

export interface ToolSummary {
  name: string;
  description?: string;
}

// A name that reads as a getter/reader.
const NARROW_NAME_PATTERN = /^(get|read|list|fetch|lookup|describe|view|check|query)[_-]/i;

// Verbs that imply a mutating or dangerous action. Deliberately narrow and
// specific (not "all"/"every"/"admin") — those showed up constantly in
// legitimate, benign descriptions (e.g. "returns all environment
// variables") during real-world testing and would have made this check
// noisy to the point of being ignored.
const MUTATING_ACTION_PATTERN =
  /\b(delete|deletes|deleting|remove|removes|removing|write|writes|writing|overwrite|modify|modifies|modifying|update|updates|updating|create|creates|creating|exec(ute)?|executes|drop|sudo|\brm\b)\b/i;

/**
 * Heuristic: does a tool's name read as a narrow getter/reader while its
 * description admits a mutating or destructive action? This only catches
 * one obvious category of scope mismatch (a misleading name), not
 * over-broad permissions in general — a tool can be dangerous while being
 * honestly named, and this check says nothing about that case.
 */
export function checkToolPermissions(tools: ToolSummary[]): Finding[] {
  const findings: Finding[] = [];

  for (const tool of tools) {
    const nameLooksNarrow = NARROW_NAME_PATTERN.test(tool.name);
    const descriptionAdmitsMutation = tool.description ? MUTATING_ACTION_PATTERN.test(tool.description) : false;

    if (nameLooksNarrow && descriptionAdmitsMutation) {
      findings.push({
        id: `perm.scope-mismatch.${tool.name}`,
        severity: "medium",
        title: `Tool "${tool.name}" reads as read-only but its description admits a mutating action`,
        detail: `The name looks like a getter (get/read/list/...), but the description contains a mutating verb (delete/write/modify/create/exec/...). An agent or user skimming the name alone would reasonably expect this to be side-effect-free. Description: "${tool.description?.slice(0, 200)}"`,
      });
    }
  }

  findings.push({
    id: "perm.summary",
    severity: "info",
    title: `Checked ${tools.length} tool(s) for a narrow-name/mutating-description mismatch`,
    detail:
      findings.length === 0
        ? "No mismatches found. This heuristic only catches one specific pattern (misleading name), not over-broad permissions in general."
        : `${findings.length} mismatch(es) found — see above.`,
  });

  return findings;
}
