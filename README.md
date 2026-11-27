# mcp-audit

A security auditor for MCP (Model Context Protocol) servers. Checks for missing
authentication, vulnerable dependencies, leaked secrets, and overly broad tool
permissions — the kind of issues that show up repeatedly across public MCP
servers today.

## Status: Phase 1 (auth check)

Two scan modes:

- **Mode A — source scan** (`mcp-audit scan <path>`): static analysis of a
  cloned MCP server's code and config.
  - Implemented: auth check. Detects whether the server uses a network
    transport (HTTP/SSE) at all; if so, looks for credential-based auth
    (Authorization header, API key, OAuth, JWT) or, failing that, a
    loopback-bind/Origin-validation restriction (the pattern the official MCP
    reference servers use). stdio-only servers are marked not-applicable.
  - Not yet implemented: dependency CVEs, secret leakage, permission
    over-reach (land in later phases).
- **Mode B — live introspection** (`mcp-audit live <command> [args...]` or
  `mcp-audit live --url <url>`): connects to a running MCP server and lists
  its declared tools. With `--url`, the connection attempt itself *is* the
  auth check — if it succeeds with zero credentials offered, that's flagged.

This is a heuristic tool, not a guarantee. It's intentionally conservative:
tested against the official `modelcontextprotocol/servers` reference repo,
the loopback+Origin-validation pattern used by every server there is called
out as a weaker "restricted but uncredentialed" signal (MEDIUM), not treated
the same as no protection at all (HIGH) — see `src/checks/authCheck.ts`.

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

`test-fixtures/` holds three minimal synthetic servers used to deterministically
validate each auth-check branch (stdio-only / HTTP-no-auth / HTTP-with-auth).
They're not meant to run — the scanner only reads their source text.

## Roadmap

1. ~~Scaffolding~~
2. ~~Auth check (source + live)~~ (this phase)
3. Dependency vulnerability check (OSV.dev)
4. Secret leakage + permission over-reach checks
5. Reporting polish (SARIF) + GitHub Action
6. Validation run against public servers + publish findings
7. (later) Claude Skill wrapper, prompt-injection heuristics, dynamic probing
