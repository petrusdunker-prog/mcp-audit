import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import type { Finding } from "../types.js";
import { toRelPosix } from "../relPath.js";

const SCAN_EXTENSIONS = new Set([
  ".ts",
  ".js",
  ".mjs",
  ".cjs",
  ".tsx",
  ".jsx",
  ".json",
  ".yml",
  ".yaml",
  ".toml",
  ".ini",
  ".env",
]);
const IGNORED_DIRS = new Set(["node_modules", "dist", "build", ".git", "coverage"]);
const IGNORED_FILES = new Set(["package-lock.json", "pnpm-lock.yaml", "yarn.lock"]);

interface KnownPattern {
  id: string;
  label: string;
  regex: RegExp;
}

// Specific, low-false-positive formats: if one of these matches, it's very
// likely a real credential shape (as opposed to the generic heuristic below,
// which is much noisier).
const KNOWN_FORMAT_PATTERNS: KnownPattern[] = [
  { id: "aws-access-key-id", label: "AWS Access Key ID", regex: /AKIA[0-9A-Z]{16}/ },
  { id: "github-token", label: "GitHub token", regex: /gh[pousr]_[A-Za-z0-9]{36,}/ },
  { id: "github-pat-fine-grained", label: "GitHub fine-grained PAT", regex: /github_pat_[A-Za-z0-9_]{70,}/ },
  { id: "slack-token", label: "Slack token", regex: /xox[baprs]-[A-Za-z0-9-]{10,48}/ },
  { id: "stripe-live-key", label: "Stripe live secret key", regex: /sk_live_[0-9a-zA-Z]{20,}/ },
  { id: "google-api-key", label: "Google API key", regex: /AIza[0-9A-Za-z\-_]{35}/ },
  {
    id: "private-key-block",
    label: "Private key block",
    regex: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
  },
];

// Generic signal: a string literal assigned to a credential-sounding name.
// Much noisier than the known-format patterns — flagged at lower severity
// and filtered against obvious placeholders.
const GENERIC_ASSIGNMENT_PATTERN =
  /\b(api[_-]?key|apikey|secret|token|password|passwd|client[_-]?secret)\s*[:=]\s*["'`]([^"'`\n]{12,})["'`]/gi;

const PLACEHOLDER_PATTERN =
  /^(your|my|xxx+|placeholder|change[_-]?me|example|dummy|test|fake|insert|replace|\.\.\.|null|undefined)/i;

async function walk(dir: string, files: string[] = []): Promise<string[]> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return files;
  }
  for (const entry of entries) {
    if (IGNORED_DIRS.has(entry.name) || IGNORED_FILES.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      await walk(full, files);
    } else if (SCAN_EXTENSIONS.has(path.extname(entry.name)) || entry.name.startsWith(".env")) {
      files.push(full);
    }
  }
  return files;
}

/**
 * Scans source/config files for hardcoded secrets: a small set of specific,
 * low-false-positive known credential formats (CRITICAL), plus a much
 * noisier generic "credential-sounding name assigned a literal string"
 * heuristic (MEDIUM), filtered against obvious placeholder values. Neither
 * is a guarantee — this cannot tell a real leaked secret from a
 * convincing-looking test fixture.
 */
export async function checkSecrets(repoPath: string): Promise<Finding[]> {
  const files = await walk(repoPath);
  const findings: Finding[] = [];
  let knownHits = 0;
  let genericHits = 0;

  for (const file of files) {
    let content: string;
    try {
      content = await readFile(file, "utf-8");
    } catch {
      continue;
    }
    const rel = toRelPosix(repoPath, file);

    for (const pattern of KNOWN_FORMAT_PATTERNS) {
      if (pattern.regex.test(content)) {
        knownHits++;
        findings.push({
          id: `secret.known.${pattern.id}.${rel}`,
          severity: "critical",
          title: `Likely ${pattern.label} found in ${rel}`,
          detail: `Matched the known shape of a ${pattern.label}. If this is real, rotate the credential and scrub it from git history, not just this file.`,
          location: { file: rel },
        });
      }
    }

    const genericRegex = new RegExp(GENERIC_ASSIGNMENT_PATTERN);
    let match: RegExpExecArray | null;
    while ((match = genericRegex.exec(content))) {
      const value = match[2];
      if (PLACEHOLDER_PATTERN.test(value)) continue;
      genericHits++;
      findings.push({
        id: `secret.generic.${rel}.${match.index}`,
        severity: "medium",
        title: `Possible hardcoded credential in ${rel}`,
        detail: `Found a string literal assigned to a credential-sounding name: "${match[0].slice(0, 80)}". Could be real, or a test/example value — this heuristic can't tell the difference, verify manually.`,
        location: { file: rel },
      });
    }
  }

  findings.push({
    id: "secret.summary",
    severity: "info",
    title: `Scanned ${files.length} file(s) for leaked secrets`,
    detail: `${knownHits} known-format match(es), ${genericHits} generic suspicious-assignment match(es).`,
  });

  return findings;
}
