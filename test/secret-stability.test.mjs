// Regression test for step 2 of the drift-detection phase: a generic
// secret finding's id must not depend on where in the file the match sits,
// or an unrelated edit earlier in the file would make drift detection
// (Phase 7) see the same literal match as "resolved" + "new" for no real
// reason.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { checkSecrets } from "../dist/checks/secretCheck.js";

const MATCH_LINE = `export const token = "abcdef1234567890";\n`;

async function scanWithContent(content) {
  const dir = await mkdtemp(path.join(tmpdir(), "mcp-audit-secret-stability-"));
  try {
    await writeFile(path.join(dir, "config.ts"), content, "utf-8");
    return await checkSecrets(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test("a generic secret finding's id is stable when unrelated content shifts its offset", async () => {
  const before = await scanWithContent(MATCH_LINE);
  const after = await scanWithContent("// a comment that didn't exist before\n".repeat(20) + MATCH_LINE);

  const beforeId = before.find((f) => f.id.startsWith("secret.generic."))?.id;
  const afterId = after.find((f) => f.id.startsWith("secret.generic."))?.id;

  assert.ok(beforeId, "expected a generic secret finding before the shift");
  assert.ok(afterId, "expected a generic secret finding after the shift");
  assert.equal(beforeId, afterId, "id should not depend on character offset");
});

test("two different credential-sounding literals in the same file get different ids", async () => {
  const findings = await scanWithContent('const token = "abcdef1234567890";\nconst apiKey = "zzzzzzzzzzzzzzzz";\n');
  const ids = findings.filter((f) => f.id.startsWith("secret.generic.")).map((f) => f.id);
  assert.equal(ids.length, 2);
  assert.notEqual(ids[0], ids[1]);
});
