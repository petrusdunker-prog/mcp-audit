// Fixture: the exact real-world false-positive patterns found scanning
// AgentValet/AgentValet during a real run of this tool (2026-11-28). None
// of these should be flagged — they're placeholders/examples/pattern
// definitions, not real credentials, and this is the regression test for
// the fix.
export const AWS_EXAMPLE = "AKIAIOSFODNN7EXAMPLE"; // AWS's own documented example key
export const GITHUB_EXAMPLE = "ghp_EXAMPLEonlyNotARealToken0123456789ab";
export const SLACK_PLACEHOLDER_DOC = "Authorization: Bearer xoxb-real-token"; // doc-comment example, no real digit structure
export const SLACK_PLACEHOLDER_GENERIC = "xoxb-your-token-here";

// A template literal that *constructs* the PEM wrapper around a runtime
// value, the way AgentValet's env.ts does — there's no actual key material
// in the source, just the header text and an interpolated variable.
export function wrapKey(body: string): string {
  return `-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----`;
}

// A key-material placeholder in a config schema's description, the way
// AgentValet's smithery.yaml does — the "<...>" breaks the required
// base64-like payload run immediately after the header.
export const SCHEMA_DOC_EXAMPLE = "-----BEGIN PRIVATE KEY-----\n<your PKCS#8 key here>\n-----END PRIVATE KEY-----";
