# Validation run: scanning 17 real public MCP servers

Phase 5 of mcp-audit's build: run the finished tool against real, independently
written MCP servers pulled from the wild — not just the official reference
repo (already used throughout phases 1-4 for tuning) — to see whether it holds
up outside its own test corpus, and to get real numbers instead of guesses.

## Methodology

- Source list: [punkpeye/awesome-mcp-servers](https://github.com/punkpeye/awesome-mcp-servers),
  a large community-maintained directory (~5,000 unique GitHub links at time
  of writing).
- Sampling: extracted all unique `github.com/<org>/<repo>` links, excluded the
  official `modelcontextprotocol` org and the list-aggregator repos themselves,
  sorted, then took every ~280th entry — a systematic spread across the whole
  alphabetized list rather than hand-picking, to avoid cherry-picking either
  easy wins or easy failures.
- 18 repos selected, 17 cloned successfully (1 no longer exists/was made
  private).
- Each run through `mcp-audit scan <path>` as-is, no flags, no manual setup.

This is a small, non-random sample — not a claim about the whole ecosystem.
Treat the percentages below as "what we saw in 17 repos," not an industry
statistic.

## Aggregate results (n=17)

| Category | Count | Note |
|---|---|---|
| HTTP transport with no auth and no restriction pattern (HIGH) | 0/17 | none in this sample |
| HTTP transport, loopback/Origin-restricted but no credential (MEDIUM) | 1/17 | the official-reference pattern also showed up in the wild |
| At least one dependency with a known CVE | 7/17 (41%) | 15 vulnerable-dependency findings total |
| Known-format secret (CRITICAL — AWS/GitHub/Slack/etc. shape) | 0/17 | none found |
| Generic credential-sounding literal (MEDIUM heuristic) | 6/17 (35%) | see "noise" below — manually verified, zero were real secrets |
| Not JS/TS — scanner has no coverage | 3/17 | Python/other-language servers, scope gap not a clean bill of health |
| No `package.json` found | 7/17 | no npm dependency surface to check |

## What held up

- **Zero false "HIGH" auth alarms.** Nothing in this sample tripped the
  no-auth-at-all tier, and the one MEDIUM hit was a legitimate loopback+Origin
  server (the same pattern validated against the official reference repo in
  Phase 1) — the auth check's severity tiering continues to hold outside its
  original tuning corpus.
- **Real, systemic dependency finding.** Several sampled servers pin an older
  `@modelcontextprotocol/sdk` version that has multiple publicly disclosed
  CVEs (e.g. `google-mcp` on `1.17.4`, `mcp-keycloak-admin` on `1.30.0` — both
  already public information via OSV.dev, not a novel disclosure). This is a
  genuinely useful, actionable, ecosystem-level takeaway: the SDK itself has
  had vulnerabilities, and bumping it is a real fix, not theoretical.
- **Zero real secrets.** Every generic-heuristic hit was manually checked
  against the source; all 6 affected repos' hits were test fixtures, mock
  tokens, or documentation prose — not real leaked credentials. Good: no
  responsible-disclosure situation arose from this run, and worth saying
  plainly rather than quietly skipping.

## What didn't: new noise pattern found

The generic secret heuristic's false-positive rate in real code is higher
than the earlier single-repo test suggested. Two new noise sources showed up
repeatedly across this sample that weren't visible when only the official
reference repo was tested:

1. **End-to-end/test fixture values** (`PASSWORD = 'e2e-throwaway-password'`,
   `password: 'correct horse battery'`) — expected, and already the reason
   this check sits at MEDIUM rather than CRITICAL, but it was the single
   largest source of hits by far (one repo alone: 37).
2. **Documentation prose that happens to contain `token=` or `secret:`
   syntax** inside a comment or JSDoc block explaining the code, not an
   actual assignment. The regex has no way to distinguish "here's example
   code in a comment" from real code — a concrete limitation worth fixing
   before this check could reasonably move to a stricter default.

Neither is a correctness bug — MEDIUM severity and the "verify manually"
wording were specifically chosen to survive exactly this kind of noise, and
nothing here produced a false CRITICAL. But it's a real signal that the
generic check needs either comment-stripping or a confidence-score mode
before it's quiet enough to lead a published "X servers had hardcoded
secrets" headline — this run doesn't support a hardcoded-secrets claim at
all, and shouldn't be used to imply one.

## Methodology footnote

One sampled entry (`childrentime/reactuse`) is primarily a React hooks
library, not a dedicated MCP server — it carries an MCP mode as a secondary
feature. Included as sampled since the source list lists it as an MCP
server; worth knowing the curated list's entries aren't all "dedicated server
projects" in the way the other 16 are.

## Bottom line

In a real, systematically-sampled slice of the ecosystem, the auth and
dependency checks produced correct, non-alarmist, actionable results with no
false highs. The secret check's generic heuristic is noisier on test-heavy
real codebases than the single-repo tuning pass suggested — documented above
and in the main README's Known Limitations, not quietly dropped.
