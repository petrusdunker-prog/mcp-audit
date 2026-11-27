import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import type { Finding } from "../types.js";

const SOURCE_EXTENSIONS = new Set([".ts", ".js", ".mjs", ".cjs", ".tsx", ".jsx"]);
const IGNORED_DIRS = new Set(["node_modules", "dist", "build", ".git", "coverage"]);

const HTTP_TRANSPORT_PATTERNS = [
  /StreamableHTTPServerTransport/,
  /SSEServerTransport/,
  /express\s*\(/,
  /fastify/i,
  /http\.createServer/,
  /createServer\s*\(/,
];

const STDIO_TRANSPORT_PATTERN = /StdioServerTransport/;

const AUTH_PATTERNS = [
  /authorization/i,
  /bearer\s+token/i,
  /req\.headers\[['"]authorization['"]\]/i,
  /x-api-key/i,
  /api[_-]?key/i,
  /jsonwebtoken/i,
  /passport/i,
  /oauth/i,
  /verifyToken/i,
  /basicAuth/i,
];

// A server that binds loopback-only and validates the request Origin isn't
// credential-authenticated, but it's a legitimate, widely-used mitigation
// for a local dev tool (it's the pattern the official MCP reference servers
// all use). Treat it as a weaker, second-tier signal rather than nothing.
const NETWORK_RESTRICTION_PATTERNS = [
  /localhostOriginValidation/,
  /127\.0\.0\.1/,
  /\bloopback\b/i,
  /allowOrigin/i,
  /validateOrigin/i,
];

async function walk(dir: string, files: string[] = []): Promise<string[]> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return files;
  }
  for (const entry of entries) {
    if (IGNORED_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      await walk(full, files);
    } else if (SOURCE_EXTENSIONS.has(path.extname(entry.name))) {
      files.push(full);
    }
  }
  return files;
}

/**
 * Heuristic, static check: does this MCP server use a network transport
 * (HTTP/SSE), and if so, is there any auth-related code anywhere in the
 * source? This is intentionally conservative — it flags the *absence* of a
 * recognizable auth pattern, not a confirmed vulnerability. stdio-only
 * servers are marked not-applicable: their trust boundary is the local
 * process invocation, not a network credential.
 */
export async function checkAuth(repoPath: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  const files = await walk(repoPath);
  if (files.length === 0) {
    return [
      {
        id: "auth.no-js-ts-source",
        severity: "info",
        title: "No JS/TS source files found — not a clean result",
        detail: `No .ts/.js files found under ${repoPath}. This server may be written in another language (e.g. Python) that this scanner doesn't analyze yet — this is a scope gap, not a finding that the server is safe.`,
      },
    ];
  }

  let usesHttpTransport = false;
  let usesStdioTransport = false;
  const matchedAuthFiles: string[] = [];
  const matchedRestrictionFiles: string[] = [];

  for (const file of files) {
    let content: string;
    try {
      content = await readFile(file, "utf-8");
    } catch {
      continue;
    }

    if (HTTP_TRANSPORT_PATTERNS.some((p) => p.test(content))) usesHttpTransport = true;
    if (STDIO_TRANSPORT_PATTERN.test(content)) usesStdioTransport = true;
    if (AUTH_PATTERNS.some((p) => p.test(content))) {
      matchedAuthFiles.push(path.relative(repoPath, file));
    }
    if (NETWORK_RESTRICTION_PATTERNS.some((p) => p.test(content))) {
      matchedRestrictionFiles.push(path.relative(repoPath, file));
    }
  }

  if (!usesHttpTransport && usesStdioTransport) {
    findings.push({
      id: "auth.stdio-only",
      severity: "info",
      title: "stdio-only transport — auth check not applicable",
      detail:
        "Only a stdio transport (StdioServerTransport) was found. There's no network listener here, so the trust boundary is who can spawn the process, not a network credential.",
    });
    return findings;
  }

  if (!usesHttpTransport && !usesStdioTransport) {
    findings.push({
      id: "auth.transport-unknown",
      severity: "info",
      title: "Could not determine transport type",
      detail:
        "No recognizable MCP transport setup (stdio or HTTP/SSE) was found in source. Either this scanner doesn't understand this server's structure yet, or this isn't an MCP server entrypoint.",
    });
    return findings;
  }

  if (matchedAuthFiles.length > 0) {
    findings.push({
      id: "auth.http-auth-pattern-found",
      severity: "info",
      title: "Auth-related code detected",
      detail: `Found auth-related patterns in: ${matchedAuthFiles.slice(0, 5).join(", ")}${
        matchedAuthFiles.length > 5 ? ", ..." : ""
      }. Presence of this code doesn't guarantee it's correctly enforced on every request path — manual review is still recommended.`,
    });
  } else if (matchedRestrictionFiles.length > 0) {
    findings.push({
      id: "auth.http-network-restriction-only",
      severity: "medium",
      title: "Network transport restricted (loopback/origin), but no credential required",
      detail: `Found loopback-bind or Origin-validation code in: ${matchedRestrictionFiles.slice(0, 5).join(", ")}. This is a legitimate pattern for a local-only dev tool, but there's no token/API-key/OAuth check backing it up — if this server's host binding is ever widened beyond loopback (e.g. a HOST env var), it would become reachable with zero authentication. Confirm the bind address is actually restricted in deployment.`,
    });
  } else {
    findings.push({
      id: "auth.http-no-auth-pattern",
      severity: "high",
      title: "Network transport detected with no authentication or restriction pattern found",
      detail:
        "This server sets up an HTTP/SSE listener, but no auth-related code (Authorization header, API key, OAuth, JWT, etc.) and no loopback/Origin restriction was found anywhere in the source. This is a heuristic, not a guarantee — verify manually before treating it as confirmed.",
    });
  }

  return findings;
}
