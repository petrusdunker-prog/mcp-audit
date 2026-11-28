# mcp-audit

A security auditor for MCP (Model Context Protocol) servers. Checks for missing
authentication, vulnerable dependencies, leaked secrets, and overly broad tool
permissions — the kind of issues that show up repeatedly across public MCP
servers today.

## Status: Phase 8 (prompt-injection heuristics for Mode B)

Two scan modes:

- **Mode A — source scan** (`mcp-audit scan <path>`): static analysis of a
  cloned MCP server's code and config.
  - Auth check. Detects whether the server uses a network transport
    (HTTP/SSE) at all; if so, looks for credential-based auth (Authorization
    header, API key, OAuth, JWT) or, failing that, a loopback-bind/Origin-
    validation restriction (the pattern the official MCP reference servers
    use). stdio-only servers are marked not-applicable.
  - npm dependency vulnerability check. Resolves each dependency's exact
    version from `package-lock.json` when present (otherwise falls back to
    the semver range in `package.json`, flagged as less reliable), then
    queries [OSV.dev](https://osv.dev) for known CVEs. Other ecosystems
    (pip, etc.) aren't covered yet.
  - Secret leakage check. A small set of specific, low-false-positive known
    credential formats (AWS/GitHub/Slack/Stripe/Google keys, private key
    blocks) at CRITICAL, plus a noisier generic "credential-sounding name
    assigned a literal string" heuristic at MEDIUM, filtered against obvious
    placeholders.
- **Mode B — live introspection** (`mcp-audit live <command> [args...]` or
  `mcp-audit live --url <url>`): connects to a running MCP server and lists
  its declared tools.
  - With `--url`, the connection attempt itself *is* the auth check — if it
    succeeds with zero credentials offered, that's flagged.
  - Permission-scope-mismatch check: flags a tool whose name reads as a
    narrow getter (`get_`/`read_`/`list_`/...) but whose description admits
    a mutating action (delete/write/modify/create/exec/...). Only catches
    this one specific pattern, not over-broad permissions in general.
  - Prompt-injection check: scans every tool's full metadata (name,
    description, and declared input schema — a parameter's own description
    can carry an injection as easily as the tool's) for three documented,
    narrow techniques: a fake system/role marker (`SYSTEM:`, `[INST]`,
    `<|im_start|>`, ...), language aimed at overriding the calling model's
    behavior rather than describing the tool ("ignore previous
    instructions", "without telling the user", ...), and hidden/invisible
    Unicode characters (zero-width spaces, Unicode Tag characters, bidi
    overrides — the "ASCII smuggling" technique). Not a general "sounds
    suspicious" filter — three specific, documented patterns, nothing else.

This is a heuristic tool, not a guarantee. It's intentionally conservative —
each check so far has been tuned against real false positives found by
testing against the official `modelcontextprotocol/servers` reference repo,
not just synthetic fixtures:
- **Auth check**: the loopback+Origin-validation pattern used by every
  server there is its own weaker "restricted but uncredentialed" tier
  (MEDIUM), not lumped in with no protection at all (HIGH).
- **Dependency check**: caught a real, currently-open memory-exhaustion DoS
  in the `zod` version the filesystem server depends on.
- **Permission check**: an early wordlist (`all`/`every`/`admin`) would have
  flagged the reference server's own `get-env` debug tool ("Returns all
  environment variables...") as a false positive; the wordlist was narrowed
  to specific mutating verbs before shipping.
- **Secret check**: scanning a real security-conscious project
  (`AgentValet/AgentValet`) turned up 12 false positives from code that
  itself handles/validates secrets rather than leaking one — see
  `VALIDATION.md` and the Known Limitations section below.
- **Prompt-injection check**: validated against 53 tools across 5 real
  servers (the official reference server, two more official servers, and
  two popular community servers) with zero false positives so far — see
  `VALIDATION.md` for the real text-extraction bug this testing caught
  before it shipped.

## Usage

```bash
npm install
npm run build

# Mode A — static scan of a cloned repo
node dist/cli.js scan ./path/to/cloned-mcp-server

# Mode B — stdio target
node dist/cli.js live npx -y @modelcontextprotocol/server-everything

# Mode B — HTTP target (no credentials sent)
node dist/cli.js live --url http://127.0.0.1:3001/mcp

# Output formats: text (default), json, sarif
node dist/cli.js scan ./path --format json
node dist/cli.js scan ./path --format sarif > results.sarif
node dist/cli.js live --format json npx -y @modelcontextprotocol/server-everything  # flags must come BEFORE the stdio command

# Exit 1 if any finding is at least this severe — for CI
node dist/cli.js scan ./path --fail-on high
```

### Drift detection (baselining)

A scan is a snapshot. `--baseline`/`--write-baseline` give it memory between
runs, so you can ask "what changed" instead of re-reading the same report
every time:

```bash
# First time: accept the current state as the baseline
node dist/cli.js scan ./path --write-baseline .mcp-audit-baseline.json

# Later: diff against it — only NEW and RESOLVED findings are shown,
# unchanged ones (already-accepted state) are silent
node dist/cli.js scan ./path --baseline .mcp-audit-baseline.json

# --fail-on in baseline mode only looks at NEW findings
node dist/cli.js scan ./path --baseline .mcp-audit-baseline.json --fail-on critical

# Diff against the old baseline, then accept the new state in one command
node dist/cli.js scan ./path --baseline .mcp-audit-baseline.json --write-baseline .mcp-audit-baseline.json
```

The baseline file is meant to be committed to the repo, like a lockfile —
update it the same way you'd accept an updated snapshot test, after
reviewing what changed. `--baseline` doesn't support `--format sarif` (SARIF
results aren't naturally "new vs. resolved" — see the GitHub Action section
for how the two combine instead). Mode B (live) baselining isn't supported
yet — only `scan`.

The diff works by comparing finding ids between two reports, not by hashing
files — every finding already has a stable id (`deps.vuln.lodash`,
`perm.scope-mismatch.get_user_profile`), so a baseline is just a saved
report and diffing means set-comparing two id lists. That only works if an
id doesn't drift for reasons that have nothing to do with the underlying
issue — the generic secret check originally keyed a finding on the matched
text's character offset in the file, which shifts whenever unrelated
content earlier in the file changes, and would have produced false
new+resolved pairs for the exact same literal match on every unrelated
edit. It's now keyed on a hash of the matched content instead. Worth
knowing if you're reading raw JSON reports or building on top of this:
finding ids are designed to be stable across unrelated changes, not just
stable within one run.

### GitHub Action

Published at [petrusdunker-prog/mcp-audit](https://github.com/petrusdunker-prog/mcp-audit).
`action.yml` at its root makes it usable as a composite action from any other
repo:

```yaml
- uses: petrusdunker-prog/mcp-audit@main
  with:
    path: .                                   # repo to scan, default "."
    fail-on: high                             # optional; omit to never fail the job on findings
    baseline-file: .mcp-audit-baseline.json    # optional; see below
permissions:
  security-events: write  # required for the SARIF upload step
```

Without `baseline-file`: it builds the tool, runs `scan --format sarif`,
uploads the result via `github/codeql-action/upload-sarif` (alerts show up
in the repo's Security tab), and — if `fail-on` is set — fails the job
afterward without needing a second scan.

With `baseline-file` set to a committed baseline (see "Drift detection"
above — create and commit this yourself first; the Action never writes one
for you, since the whole point is a human reviewing what's being accepted):
the SARIF pass still runs and uploads the full current state regardless, but
`fail-on` is evaluated by a separate diff-against-baseline pass instead, so
it only fails the job on findings that are NEW since the baseline — not the
whole scan. That pass's output also lands in the run's job summary. This is
genuinely two scans in that mode (SARIF can't represent "new vs. resolved"
the way a diff can), both still run after the point where alerts have
already been uploaded.

See `.github/workflows/ci.yml` for this repo's own CI, including a
self-scan job that dogfoods the action — with a real baseline
(`.mcp-audit-baseline.json`, committed in this repo) and `fail-on: critical`
against it, so it only fails on something genuinely new, not the
intentional findings in `test-fixtures/`.

## Test fixtures

`test-fixtures/` holds minimal fixtures used to deterministically validate
each check without depending on the real OSV.dev database state flipping
underneath a future test run (the vulnerable one is pinned to a package
version with a long-settled historical CVE, so it won't age out):

- `stdio-only/`, `http-no-auth/`, `http-with-auth/` — auth-check branches.
- `vulnerable-deps/`, `clean-deps/` — dependency-check branches (`lodash@4.17.15`
  has several known CVEs; `commander@13.1.0` doesn't).
- `secret-known/`, `secret-generic/`, `secret-clean/` — secret-check branches
  (fake-but-correctly-shaped AWS/GitHub/private-key credentials, low-entropy
  so they don't trip a real scanner the way an earlier draft did on push; a
  generic credential-sounding assignment; env-var-only, no literals).
- `secret-known-placeholder/` — the exact real-world false positives found
  scanning AgentValet/AgentValet (AWS's own canonical example key, a
  GitHub-token-shaped placeholder, etc.) — should produce zero findings.
- `live-permission-mismatch/` — a tiny **runnable** stdio server (unlike the
  non-`live-*` fixtures above) with one tool whose name/description
  deliberately mismatch, used to validate the Mode B permission check
  end-to-end:
  `node dist/cli.js live --format json npx tsx test-fixtures/live-permission-mismatch/server.ts`
- `live-prompt-injection/` — another runnable stdio server, with one benign
  tool and three carrying a different injection technique each (fake role
  marker, override language, hidden Unicode), used to validate the
  prompt-injection check end-to-end.

Everything else is read as text only, never executed. (The committed Slack
token test is the exception that proves this isn't just a formality — it's
tested at runtime instead, in `test/secret-stability.test.mjs`, specifically
*because* a committed one trips GitHub's own push protection.)

`npm test` runs all of the above as a real regression suite
(`test/fixtures.test.mjs`, via Node's built-in test runner) instead of the
one-off manual checks used while building each phase — this is what CI runs.

## Known limitations

- **Auth and secret checks pool findings across the whole scanned tree.**
  Point them at one server's own directory, not a monorepo root containing
  several unrelated servers — a sibling subfolder with real auth code will
  mask a finding that a different subfolder genuinely has none. (Running
  `scan .` on this very repo demonstrates it: the auth check sees the
  `http-with-auth` fixture's auth code and the `http-no-auth` fixture's
  missing auth together, and reports the former rather than flagging the
  latter.) Scan each server's directory individually.
- **Dependency check only resolves top-level `package-lock.json` entries**,
  not nested/hoisted workspace members — in an npm-workspaces monorepo,
  scan each workspace member's own directory (where its `package.json` is),
  not just the root.
- **The generic secret heuristic is noisy on real codebases** — validated
  against 17 real public MCP servers (see `VALIDATION.md`), its two biggest
  false-positive sources are test/e2e fixture values and documentation prose
  that merely mentions `token=`/`secret:` syntax inside a comment. This is
  why it sits at MEDIUM with "verify manually" wording rather than CRITICAL —
  but don't read a MEDIUM hit as "probably a real leak" without checking.
- **Known-format patterns can still false-positive on code that *handles*
  secrets rather than leaking one** — found by scanning a real security-
  conscious project (`AgentValet/AgentValet`) that itself parses/validates
  private keys and tokens. Fixed what was reproducible: the private-key and
  Slack-token patterns now require real key material/token structure (not
  just the header/prefix), and every known-format match is checked against
  an obvious-placeholder filter (catches AWS's own canonical
  `AKIAIOSFODNN7EXAMPLE`, `ghp_EXAMPLE...`, etc.). What's *not* fully
  fixed: a pattern can still match inside code whose job is literally to
  detect or compare against that exact shape (a string-comparison check
  against an API's own regex, for instance) — there's no general way to
  tell "this is a stored value" from "this is a shape being checked for"
  without deeper code analysis than this tool does.
- Every check here is a heuristic, not a guarantee — see the specific
  caveats in each check's own section above.

## Roadmap

1. ~~Scaffolding~~
2. ~~Auth check (source + live)~~
3. ~~Dependency vulnerability check (OSV.dev)~~
4. ~~Secret leakage + permission over-reach checks~~
5. ~~Reporting polish (SARIF) + GitHub Action~~
6. ~~Validation run against public servers + publish findings~~ (see `VALIDATION.md`)
7. ~~Drift/integrity detection~~ — diffs two scans by finding id (a baseline
   is just a saved report) rather than hashing raw files; `scan` gets
   `--baseline`/`--write-baseline`; validated against real history (two
   snapshots of the official filesystem server 12 weeks apart — see
   `VALIDATION.md`); wired into the Action via `baseline-file`, dogfooded on
   this repo's own CI with a real committed baseline. Mode B (live)
   baselining and pairing "same category got worse" into one escalation
   entry are still out of scope — plain new/resolved already does the job.
8. ~~Prompt-injection heuristics~~ — three narrow, documented techniques
   (fake role marker, override language, hidden Unicode) scanned across a
   tool's full metadata including its input schema, on Mode B only.
   Validated against 53 tools across 5 real servers, zero false positives
   so far — see `VALIDATION.md`, including a real text-extraction bug this
   testing caught (`JSON.stringify` escapes a real newline to a literal
   `\n`, which glues a word character in front of whatever follows and can
   silently defeat a `\b` boundary check right where a fake role marker
   realistically sits — on its own line). Mode A (static) coverage and
   output-content scanning (vs. just declared metadata) are both out of
   scope — this tool only ever introspects a tool list, it never calls one.
9. **Dynamic/live probing (planned, not started).** Behavioral checks beyond
   "did it accept zero credentials" — input validation, rate-limiting.
   Ethically narrower in scope than the static checks: only ever run against
   servers you control yourself, never third-party infrastructure without
   permission.

**Explicitly out of scope for this roadmap:** watching actual tool-call
traffic in real time to catch a tool doing something beyond what it was
asked for a given invocation. That's a fundamentally different product (a
proxy/interceptor sitting between the agent and the server, not a scanner)
and isn't planned as an extension of this tool.
