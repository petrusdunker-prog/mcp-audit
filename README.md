# mcp-audit

A security auditor for MCP (Model Context Protocol) servers. Checks for missing
authentication, vulnerable dependencies, leaked secrets, and overly broad tool
permissions — the kind of issues that show up repeatedly across public MCP
servers today.

## Status: Phase 2 (dependency vulnerability check)

Two scan modes:

- **Mode A — source scan** (`mcp-audit scan <path>`): static analysis of a
  cloned MCP server's code and config.
  - Implemented: auth check. Detects whether the server uses a network
    transport (HTTP/SSE) at all; if so, looks for credential-based auth
    (Authorization header, API key, OAuth, JWT) or, failing that, a
    loopback-bind/Origin-validation restriction (the pattern the official MCP
    reference servers use). stdio-only servers are marked not-applicable.
  - Implemented: npm dependency vulnerability check. Resolves each
    dependency's exact version from `package-lock.json` when present
    (otherwise falls back to the semver range in `package.json`, flagged as
    less reliable), then queries [OSV.dev](https://osv.dev) for known CVEs.
    Other ecosystems (pip, etc.) aren't covered yet.
  - Not yet implemented: secret leakage, permission over-reach (land in
    later phases).
- **Mode B — live introspection** (`mcp-audit live <command> [args...]` or
  `mcp-audit live --url <url>`): connects to a running MCP server and lists
  its declared tools. With `--url`, the connection attempt itself *is* the
  auth check — if it succeeds with zero credentials offered, that's flagged.

This is a heuristic tool, not a guarantee. It's intentionally conservative:
tested against the official `modelcontextprotocol/servers` reference repo,
the loopback+Origin-validation pattern used by every server there is called
out as a weaker "restricted but uncredentialed" signal (MEDIUM), not treated
the same as no protection at all (HIGH) — see `src/checks/authCheck.ts`. The
dependency check caught a real, currently-open vulnerability in that same
repo (a memory-exhaustion DoS in the `zod` version the filesystem server
depends on) during testing — see `src/checks/depCheck.ts`.

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

# JSON output (either mode)
node dist/cli.js scan ./path --json
```

## Test fixtures

`test-fixtures/` holds minimal fixtures used to deterministically validate
each check without depending on the real OSV.dev database state flipping
underneath a future test run (the vulnerable one is pinned to a package
version with a long-settled historical CVE, so it won't age out):

- `stdio-only/`, `http-no-auth/`, `http-with-auth/` — auth-check branches.
- `vulnerable-deps/`, `clean-deps/` — dependency-check branches (`lodash@4.17.15`
  has several known CVEs; `commander@13.1.0` doesn't).

None of these are meant to run — the scanner only reads their source/manifest text.

## Roadmap

1. ~~Scaffolding~~
2. ~~Auth check (source + live)~~
3. ~~Dependency vulnerability check (OSV.dev)~~ (this phase)
4. Secret leakage + permission over-reach checks
5. Reporting polish (SARIF) + GitHub Action
6. Validation run against public servers + publish findings
7. (later) Claude Skill wrapper, prompt-injection heuristics, dynamic probing
