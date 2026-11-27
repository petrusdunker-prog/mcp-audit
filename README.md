# mcp-audit

A security auditor for MCP (Model Context Protocol) servers. Checks for missing
authentication, vulnerable dependencies, leaked secrets, and overly broad tool
permissions — the kind of issues that show up repeatedly across public MCP
servers today.

## Status: Phase 0 (scaffolding)

Two scan modes are planned:

- **Mode A — source scan** (`mcp-audit scan <path>`): static analysis of a
  cloned MCP server's code and config. Not implemented yet — lands in Phase 1+.
- **Mode B — live introspection** (`mcp-audit live <command> [args...]`):
  launches an MCP server over stdio and inspects its declared tools. Currently
  just lists discovered tools as a plumbing sanity check; real checks (auth,
  permission scope) land in later phases.

## Usage

```bash
npm install
npm run build

# Mode B sanity check against a public reference server
node dist/cli.js live npx -y @modelcontextprotocol/server-everything
```

## Roadmap

1. ~~Scaffolding~~ (this phase)
2. Auth check (source + live)
3. Dependency vulnerability check (OSV.dev)
4. Secret leakage + permission over-reach checks
5. Reporting polish (SARIF) + GitHub Action
6. Validation run against public servers + publish findings
7. (later) Claude Skill wrapper, prompt-injection heuristics, dynamic probing
