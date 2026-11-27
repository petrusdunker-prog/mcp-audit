import type { AuditReport, Finding, Severity } from "./types.js";

interface RuleInfo {
  id: string;
  name: string;
  shortDescription: string;
}

// SARIF wants one stable rule per *category* of check, with many results
// sharing it — not a fresh rule per finding instance (our Finding.id is
// per-instance, e.g. "secret.known.aws-access-key-id.config.ts"). Bucket by
// id prefix into the handful of checks this tool actually runs.
const RULE_CATALOG: { prefix: string; rule: RuleInfo }[] = [
  {
    prefix: "auth.",
    rule: { id: "mcp-audit/auth", name: "Authentication posture", shortDescription: "Missing or weak authentication on an MCP server's network transport" },
  },
  {
    prefix: "deps.",
    rule: { id: "mcp-audit/dependency-vulnerability", name: "Dependency vulnerability", shortDescription: "A dependency with a known vulnerability (OSV.dev)" },
  },
  {
    prefix: "secret.known.",
    rule: { id: "mcp-audit/secret-known-format", name: "Known-format secret", shortDescription: "A string matching a known credential format (AWS/GitHub/Slack/etc.)" },
  },
  {
    prefix: "secret.generic.",
    rule: { id: "mcp-audit/secret-generic", name: "Possible hardcoded credential", shortDescription: "A credential-sounding name assigned a literal string" },
  },
  {
    prefix: "perm.",
    rule: { id: "mcp-audit/permission-scope-mismatch", name: "Tool permission scope mismatch", shortDescription: "A tool's name reads as read-only but its description admits a mutating action" },
  },
  {
    prefix: "live.",
    rule: { id: "mcp-audit/live-introspection", name: "Live introspection", shortDescription: "A finding from connecting to a running MCP server" },
  },
];

const FALLBACK_RULE: RuleInfo = {
  id: "mcp-audit/other",
  name: "Other",
  shortDescription: "Uncategorized mcp-audit finding",
};

function ruleFor(finding: Finding): RuleInfo {
  return RULE_CATALOG.find((r) => finding.id.startsWith(r.prefix))?.rule ?? FALLBACK_RULE;
}

function sarifLevel(severity: Severity): "error" | "warning" | "note" {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    default:
      return "note";
  }
}

/**
 * SARIF 2.1.0 output for GitHub code scanning. Only non-"info" findings
 * become SARIF results — the "info" ones are bookkeeping/summary lines
 * ("scanned N files", "not applicable", ...), not actionable alerts, and
 * would just be noise in GitHub's alert triage UI.
 */
export function toSarif(report: AuditReport): string {
  const actionable = report.findings.filter((f) => f.severity !== "info");
  const rulesUsed = new Map<string, RuleInfo>();

  const results = actionable.map((finding) => {
    const rule = ruleFor(finding);
    rulesUsed.set(rule.id, rule);

    // report.target is whatever path/command/URL the user passed on the
    // command line — it can be absolute, or not a filesystem path at all
    // (a live-mode shell command or URL). Neither is a valid repo-relative
    // SARIF artifact URI, so only emit a location when a check actually
    // attributed the finding to a specific file; otherwise omit it rather
    // than invent one GitHub would reject or mishandle.
    const uri = finding.location?.file;

    return {
      ruleId: rule.id,
      level: sarifLevel(finding.severity),
      message: { text: `${finding.title} — ${finding.detail}` },
      ...(uri ? { locations: [{ physicalLocation: { artifactLocation: { uri } } }] } : {}),
    };
  });

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "mcp-audit",
            informationUri: "https://github.com/petrusdunker-prog/mcp-audit",
            version: "0.1.0",
            rules: [...rulesUsed.values()].map((rule) => ({
              id: rule.id,
              name: rule.name,
              shortDescription: { text: rule.shortDescription },
            })),
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
