// CLI-level regression tests for the --baseline/--write-baseline workflow
// (step 4 of the drift-detection phase). drift.test.mjs already covers the
// pure diffReports() classification logic directly; this covers the actual
// commander wiring, exit codes, and error handling a real invocation hits —
// everything manually verified by hand while building step 3, now made
// permanent.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "dist", "cli.js");
const fixture = (name) => path.join(ROOT, "test-fixtures", name);

function run(args) {
  try {
    const stdout = execFileSync("node", [CLI, ...args], { encoding: "utf-8", cwd: ROOT });
    return { stdout, status: 0 };
  } catch (err) {
    return { stdout: err.stdout ?? "", stderr: err.stderr ?? "", status: err.status };
  }
}

test("a new finding appearing against a different baseline is reported NEW and exits 0 without --fail-on", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "mcp-audit-baseline-"));
  try {
    const baseline = path.join(dir, "baseline.json");
    run(["scan", fixture("clean-deps"), "--write-baseline", baseline]);
    const result = run(["scan", fixture("vulnerable-deps"), "--baseline", baseline]);
    assert.equal(result.status, 0);
    assert.match(result.stdout, /NEW \[HIGH\]/);
    assert.match(result.stdout, /lodash/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scanning the same target twice reports no drift", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "mcp-audit-baseline-"));
  try {
    const baseline = path.join(dir, "baseline.json");
    run(["scan", fixture("secret-known"), "--write-baseline", baseline]);
    const result = run(["scan", fixture("secret-known"), "--baseline", baseline]);
    assert.equal(result.status, 0);
    assert.match(result.stdout, /No drift/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("--fail-on only considers new findings, not unchanged baseline findings", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "mcp-audit-baseline-"));
  try {
    const baseline = path.join(dir, "baseline.json");
    // secret-known always has CRITICAL findings; diffing it against itself
    // means those findings are unchanged, not new.
    run(["scan", fixture("secret-known"), "--write-baseline", baseline]);
    const result = run(["scan", fixture("secret-known"), "--baseline", baseline, "--fail-on", "critical"]);
    assert.equal(result.status, 0, "should not fail on a critical finding that already existed in the baseline");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a resolved finding (present in baseline, gone now) is reported RESOLVED", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "mcp-audit-baseline-"));
  try {
    const baseline = path.join(dir, "baseline.json");
    run(["scan", fixture("vulnerable-deps"), "--write-baseline", baseline]);
    const result = run(["scan", fixture("clean-deps"), "--baseline", baseline]);
    assert.equal(result.status, 0);
    assert.match(result.stdout, /RESOLVED \[HIGH\]/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a missing baseline file fails cleanly, not with a stack trace", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "mcp-audit-baseline-"));
  try {
    const missing = path.join(dir, "does-not-exist.json");
    const result = run(["scan", fixture("secret-known"), "--baseline", missing]);
    assert.equal(result.status, 1);
    assert.doesNotMatch(result.stdout + result.stderr, /at Object\.readFileSync|at async/, "should not leak a stack trace");
    assert.match(result.stdout + result.stderr, /Could not read baseline file/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("--baseline with --format sarif is rejected with a clear error, not silently wrong output", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "mcp-audit-baseline-"));
  try {
    const baseline = path.join(dir, "baseline.json");
    run(["scan", fixture("secret-known"), "--write-baseline", baseline]);
    const result = run(["scan", fixture("secret-known"), "--baseline", baseline, "--format", "sarif"]);
    assert.equal(result.status, 1);
    assert.match(result.stdout + result.stderr, /sarif.*isn't supported/i);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("--baseline X --write-baseline X diffs against the old state, then accepts the new one", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "mcp-audit-baseline-"));
  try {
    const file = path.join(dir, "combo.json");
    run(["scan", fixture("secret-generic"), "--write-baseline", file]);
    const result = run(["scan", fixture("secret-known"), "--baseline", file, "--write-baseline", file]);
    assert.equal(result.status, 0);
    assert.match(result.stdout, /NEW \[CRITICAL\]/);

    const after = run(["scan", fixture("secret-known"), "--baseline", file]);
    assert.match(after.stdout, /No drift/, "baseline file should now reflect the secret-known scan");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
