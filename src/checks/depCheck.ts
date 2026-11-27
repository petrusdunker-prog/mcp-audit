import { readFile } from "node:fs/promises";
import path from "node:path";
import type { Finding, Severity } from "../types.js";
import { worseSeverity } from "../severity.js";

interface DependencyRef {
  name: string;
  version: string;
  /** "lockfile" = exact resolved version (trustworthy); "declared" = parsed
   *  from package.json's semver range, which may not match what's actually
   *  installed. */
  source: "lockfile" | "declared";
}

interface OsvVuln {
  id: string;
  summary?: string;
  aliases?: string[];
  database_specific?: { severity?: string };
}

const OSV_ENDPOINT = "https://api.osv.dev/v1/query";
const CONCURRENCY = 5;

async function readJson(filePath: string): Promise<any | null> {
  try {
    return JSON.parse(await readFile(filePath, "utf-8"));
  } catch {
    return null;
  }
}

/**
 * Resolve declared npm dependencies to a best-available version: an exact
 * resolved version from package-lock.json when present, otherwise a
 * best-effort strip of the semver range operator from package.json (noted
 * as less reliable in the finding).
 */
async function resolveDependencies(repoPath: string): Promise<DependencyRef[]> {
  const pkg = await readJson(path.join(repoPath, "package.json"));
  if (!pkg) return [];

  const declared: Record<string, string> = {
    ...(pkg.dependencies ?? {}),
    ...(pkg.devDependencies ?? {}),
  };

  const lockVersions: Record<string, string> = {};
  const lock = await readJson(path.join(repoPath, "package-lock.json"));
  if (lock?.packages) {
    // npm lockfile v2/v3: keys are "node_modules/<name>" (top-level only, for v1 simplicity)
    for (const [key, value] of Object.entries<any>(lock.packages)) {
      if (!key.startsWith("node_modules/")) continue;
      const name = key.slice("node_modules/".length);
      if (name.includes("/node_modules/")) continue;
      if (value?.version) lockVersions[name] = value.version;
    }
  } else if (lock?.dependencies) {
    // npm lockfile v1
    for (const [name, value] of Object.entries<any>(lock.dependencies)) {
      if (value?.version) lockVersions[name] = value.version;
    }
  }

  const refs: DependencyRef[] = [];
  for (const [name, range] of Object.entries(declared)) {
    const exact = lockVersions[name];
    if (exact) {
      refs.push({ name, version: exact, source: "lockfile" });
      continue;
    }
    const guess = String(range).replace(/^[\^~>=<\s]+/, "").trim();
    if (/^\d+\.\d+\.\d+/.test(guess)) {
      refs.push({ name, version: guess, source: "declared" });
    }
    // else: unresolvable range ("workspace:*", "latest", a git URL, ...) — skip, OSV needs a concrete version.
  }
  return refs;
}

async function queryOsv(name: string, version: string): Promise<OsvVuln[]> {
  try {
    const res = await fetch(OSV_ENDPOINT, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ package: { name, ecosystem: "npm" }, version }),
    });
    if (!res.ok) return [];
    const data = (await res.json()) as { vulns?: OsvVuln[] };
    return data.vulns ?? [];
  } catch {
    return [];
  }
}

async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<R>
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  async function worker(): Promise<void> {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

function mapOsvSeverity(vuln: OsvVuln): Severity {
  switch (vuln.database_specific?.severity?.toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MODERATE":
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      // OSV doesn't always carry a severity rating — default to medium
      // rather than silently treating "unrated" as "low risk".
      return "medium";
  }
}

/**
 * Checks npm dependencies (package.json + package-lock.json when present)
 * against OSV.dev for known vulnerabilities. Other ecosystems (pip, etc.)
 * are not covered yet.
 */
export async function checkDependencies(repoPath: string): Promise<Finding[]> {
  const deps = await resolveDependencies(repoPath);
  if (deps.length === 0) {
    return [
      {
        id: "deps.no-package-json",
        severity: "info",
        title: "No npm dependencies found to check",
        detail: `No readable package.json with dependencies under ${repoPath}. This check only covers npm for now.`,
      },
    ];
  }

  let results: { dep: DependencyRef; vulns: OsvVuln[] }[];
  try {
    results = await mapWithConcurrency(deps, CONCURRENCY, async (dep) => ({
      dep,
      vulns: await queryOsv(dep.name, dep.version),
    }));
  } catch (err) {
    return [
      {
        id: "deps.query-failed",
        severity: "info",
        title: "Could not reach OSV.dev",
        detail: `Dependency vulnerability check skipped: ${String(err).slice(0, 200)}`,
      },
    ];
  }

  const findings: Finding[] = [];
  let vulnerableCount = 0;
  let inferredVersionCount = 0;

  for (const { dep, vulns } of results) {
    if (dep.source === "declared") inferredVersionCount++;
    if (vulns.length === 0) continue;
    vulnerableCount++;

    const worst = vulns.reduce<Severity>((acc, v) => worseSeverity(acc, mapOsvSeverity(v)), "info");
    const examples = vulns
      .slice(0, 3)
      .map((v) => `${v.aliases?.[0] ?? v.id}${v.summary ? `: ${v.summary}` : ""}`)
      .join(" | ");

    findings.push({
      id: `deps.vuln.${dep.name}`,
      severity: worst,
      title: `${dep.name}@${dep.version} — ${vulns.length} known vulnerabilit${vulns.length === 1 ? "y" : "ies"}`,
      detail:
        examples +
        (dep.source === "declared"
          ? " [version inferred from package.json's range, not a lockfile — verify the actually-installed version]"
          : ""),
      location: { file: "package.json" },
    });
  }

  findings.push({
    id: "deps.summary",
    severity: "info",
    title: `Checked ${deps.length} npm dependenc${deps.length === 1 ? "y" : "ies"} against OSV.dev`,
    detail: `${vulnerableCount} had known vulnerabilities.${
      inferredVersionCount > 0
        ? ` ${inferredVersionCount} version(s) were inferred from package.json (no lockfile match) — less reliable.`
        : ""
    }`,
  });

  return findings;
}
