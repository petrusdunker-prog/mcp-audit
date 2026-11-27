# mcp-audit

A security auditor for MCP (Model Context Protocol) servers. Checks for missing
authentication, vulnerable dependencies, leaked secrets, and overly broad tool
permissions — the kind of issues that show up repeatedly across public MCP
servers today.

## Status: Phase 5 (validated against 17 real public servers — see `VALIDATION.md`)

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

### GitHub Action

Once this is published as its own repository, `action.yml` at its root makes
it usable as a composite action from any other repo:

```yaml
- uses: your-org/mcp-audit@main
  with:
    path: .            # repo to scan, default "."
    fail-on: high      # optional; omit to never fail the job on findings
permissions:
  security-events: write  # required for the SARIF upload step
```

It builds the tool, runs `scan --format sarif`, uploads the result via
`github/codeql-action/upload-sarif` (alerts show up in the repo's Security
tab), and — if `fail-on` is set — fails the job afterward without needing a
second scan. See `.github/workflows/ci.yml` for this repo's own CI, including
a self-scan job that dogfoods the action against its own source.

## Test fixtures

`test-fixtures/` holds minimal fixtures used to deterministically validate
each check without depending on the real OSV.dev database state flipping
underneath a future test run (the vulnerable one is pinned to a package
version with a long-settled historical CVE, so it won't age out):

- `stdio-only/`, `http-no-auth/`, `http-with-auth/` — auth-check branches.
- `vulnerable-deps/`, `clean-deps/` — dependency-check branches (`lodash@4.17.15`
  has several known CVEs; `commander@13.1.0` doesn't).
- `secret-known/`, `secret-generic/`, `secret-clean/` — secret-check branches
  (fake-but-correctly-shaped AWS/GitHub credentials; a generic credential-
  sounding assignment; env-var-only, no literals).
- `live-permission-mismatch/` — a tiny **runnable** stdio server (unlike the
  others) with one tool whose name/description deliberately mismatch, used
  to validate the Mode B permission check end-to-end:
  `node dist/cli.js live --format json npx tsx test-fixtures/live-permission-mismatch/server.ts`

Everything else is read as text only, never executed.

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
- Every check here is a heuristic, not a guarantee — see the specific
  caveats in each check's own section above.

## Roadmap

1. ~~Scaffolding~~
2. ~~Auth check (source + live)~~
3. ~~Dependency vulnerability check (OSV.dev)~~
4. ~~Secret leakage + permission over-reach checks~~
5. ~~Reporting polish (SARIF) + GitHub Action~~
6. ~~Validation run against public servers + publish findings~~ (this phase — see `VALIDATION.md`)
7. (later) Claude Skill wrapper, prompt-injection heuristics, dynamic probing
