import { readdir, readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
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
// which is much noisier). Two of these are tightened beyond the obvious
// prefix match, based on real false positives found scanning a public
// repo (AgentValet/AgentValet) that itself handles/validates/documents
// private keys and tokens:
//  - private-key-block: the original matched just the header text, so any
//    code *constructing* that header (e.g. a template literal wrapping a
//    runtime value) matched with no real key material present. Real key
//    material is a long base64 blob between the markers — require it.
//  - slack-token: the original matched any xox[baprs]- prefix with enough
//    trailing characters, so "xoxb-real-token-here" (a placeholder in a
//    doc comment) matched. Real Slack tokens have a specific
//    digit-digit-random shape; require it. (This exact fix mirrors one
//    AgentValet's own secret-scanner script had already made, with a
//    comment explaining the same false positive.)
const KNOWN_FORMAT_PATTERNS: KnownPattern[] = [
  { id: "aws-access-key-id", label: "AWS Access Key ID", regex: /AKIA[0-9A-Z]{16}/g },
  { id: "github-token", label: "GitHub token", regex: /gh[pousr]_[A-Za-z0-9]{36,}/g },
  { id: "github-pat-fine-grained", label: "GitHub fine-grained PAT", regex: /github_pat_[A-Za-z0-9_]{70,}/g },
  { id: "slack-token", label: "Slack token", regex: /\bxox[baprs]-\d{9,}-\d{9,}-[A-Za-z0-9]{20,}/g },
  { id: "stripe-live-key", label: "Stripe live secret key", regex: /sk_live_[0-9a-zA-Z]{20,}/g },
  { id: "google-api-key", label: "Google API key", regex: /AIza[0-9A-Za-z\-_]{35}/g },
  {
    id: "private-key-block",
    label: "Private key block",
    regex: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\r\n]+[A-Za-z0-9+/=\s]{100,}/g,
  },
];

// Applied to the full matched text of a known-format hit — unlike
// PLACEHOLDER_PATTERN below (which only checks the generic heuristic's
// captured value, anchored at the start), this searches anywhere in the
// match, since a placeholder word can appear after a real-looking prefix
// ("ghp_EXAMPLEonlyNotARealToken...", or AWS's own canonical
// "AKIAIOSFODNN7EXAMPLE" — literally AWS's documented example key). Safe to
// check broadly here: a real high-entropy credential matching one of these
// tight formats essentially never coincidentally spells an English word.
const KNOWN_FORMAT_PLACEHOLDER_PATTERN =
  /example|placeholder|dummy|fake|changeme|change[_-]me|insert|replace|notreal|not[_-]a[_-]real|\byour\b/i;

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
      const regex = new RegExp(pattern.regex);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(content))) {
        if (KNOWN_FORMAT_PLACEHOLDER_PATTERN.test(match[0])) continue;
        knownHits++;
        // Hash of the matched text, not position — same reasoning as the
        // generic check's id below: stable across unrelated edits, and
        // lets two different real matches of the same pattern in one file
        // show up as distinct findings instead of colliding.
        const matchHash = createHash("sha1").update(match[0]).digest("hex").slice(0, 10);
        findings.push({
          id: `secret.known.${pattern.id}.${rel}.${matchHash}`,
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
      // Identity is the matched keyword+value, not the character offset —
      // an unrelated edit earlier in the file shifts every later offset,
      // which would otherwise make drift detection (Phase 7) see the same
      // literal match as "resolved" and "new" on the next run for no real
      // reason. Hash just keeps the id short and filename-safe.
      const matchHash = createHash("sha1").update(`${match[1]}:${value}`).digest("hex").slice(0, 10);
      findings.push({
        id: `secret.generic.${rel}.${matchHash}`,
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
