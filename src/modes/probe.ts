import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { AuditReport, Finding } from "../types.js";
import { NARROW_NAME_PATTERN } from "../checks/permissionCheck.js";
import { generateMalformedArgSets, findingForOutcome, type ProbeOutcome } from "../checks/dynamicCheck.js";

export interface ProbeTarget {
  command: string;
  args?: string[];
}

const CALL_TIMEOUT_MS = 5000;
const RATE_LIMIT_CALL_COUNT = 10;

async function callAndClassify(
  client: Client,
  toolName: string,
  args: Record<string, unknown>
): Promise<ProbeOutcome> {
  try {
    const result = await client.callTool({ name: toolName, arguments: args }, undefined, {
      timeout: CALL_TIMEOUT_MS,
    });
    if (result.isError) {
      return { kind: "rejected", detail: "Tool returned isError: true." };
    }
    return { kind: "accepted", detail: "Tool returned a success result." };
  } catch (err) {
    const message = String(err instanceof Error ? err.message : err);
    // A protocol/validation-level error (the SDK or server rejected the
    // call outright, e.g. a schema mismatch caught before the handler
    // even ran) is the server doing its job — not a crash.
    if (/invalid|validation|required|expected|schema/i.test(message)) {
      return { kind: "rejected", detail: `Rejected with: ${message.slice(0, 150)}` };
    }
    return { kind: "crashed", detail: `Did not complete cleanly: ${message.slice(0, 150)}` };
  }
}

/**
 * Dynamic probing (Phase 9) — the only mode in this tool that actually
 * calls a tool rather than just reading metadata about it, so it carries
 * real blast-radius: a call can have a real side effect, not just report
 * on one. Three rails keep that bounded:
 *  - stdio only. No --url support here at all — a stdio target is
 *    something you are, by definition, launching yourself locally; a URL
 *    could be anyone's remote infrastructure, which this tool will not
 *    dynamically probe.
 *  - only auto-calls tools whose name already passes the read-only-name
 *    heuristic (get_/read_/list_/...) shared with the permission check —
 *    anything else is skipped, never called.
 *  - every argument sent is deliberately malformed, derived from the
 *    tool's own declared schema, never real-looking data — the point is
 *    testing input validation, not using the tool for its real purpose.
 */
export async function auditProbe(target: ProbeTarget): Promise<AuditReport> {
  const transport = new StdioClientTransport({ command: target.command, args: target.args ?? [] });
  const client = new Client({ name: "mcp-audit", version: "0.1.0" });
  const findings: Finding[] = [];
  let connected = false;

  try {
    await client.connect(transport);
    connected = true;

    const { tools } = await client.listTools();
    const probeable = tools.filter((t) => NARROW_NAME_PATTERN.test(t.name));

    findings.push({
      id: "probe.scope",
      severity: "info",
      title: `Probing ${probeable.length} of ${tools.length} tool(s) (read-only-named only)`,
      detail:
        probeable.length === 0
          ? "No tool names matched the read-only heuristic (get_/read_/list_/fetch_/...) — nothing was called."
          : `Only tools whose name already looks read-only are called automatically: ${probeable.map((t) => t.name).join(", ")}.`,
    });

    let callCount = 0;

    for (const tool of probeable) {
      const argSets = generateMalformedArgSets(tool.inputSchema as { required?: string[]; properties?: Record<string, { type?: string }> } | undefined);

      if (argSets.length === 0) {
        findings.push({
          id: `probe.no-required-fields.${tool.name}`,
          severity: "info",
          title: `Tool "${tool.name}" declares no required fields — skipped`,
          detail: "Nothing to violate: this tool's schema has no required properties, so there's no malformed-input case to construct.",
        });
        continue;
      }

      for (const argSet of argSets) {
        callCount++;
        const outcome = await callAndClassify(client, tool.name, argSet.args);
        const finding = findingForOutcome(tool.name, argSet, outcome);
        if (finding) findings.push(finding);
      }
    }

    // Rate-limit check: a small, capped burst against the first
    // read-only-named tool (if any) — never an unbounded flood, and this
    // deliberately re-triggers whatever validation outcome that tool
    // already showed above; it isn't re-counted as a new finding, only
    // scanned for an explicit rate-limit signal in the responses.
    if (probeable.length > 0) {
      const target = probeable[0];
      let sawRateLimitSignal = false;
      let errors = 0;
      const start = Date.now();

      for (let i = 0; i < RATE_LIMIT_CALL_COUNT; i++) {
        try {
          const result = await client.callTool({ name: target.name, arguments: {} }, undefined, {
            timeout: CALL_TIMEOUT_MS,
          });
          const text = JSON.stringify(result);
          if (/rate.?limit|429|too many requests|throttle/i.test(text)) sawRateLimitSignal = true;
        } catch (err) {
          errors++;
          const message = String(err instanceof Error ? err.message : err);
          if (/rate.?limit|429|too many requests|throttle/i.test(message)) sawRateLimitSignal = true;
        }
      }

      const elapsedMs = Date.now() - start;
      findings.push({
        id: "probe.rate-limit",
        severity: sawRateLimitSignal ? "info" : "low",
        title: sawRateLimitSignal
          ? `Rate-limiting observed within ${RATE_LIMIT_CALL_COUNT} rapid calls`
          : `No rate-limiting observed within ${RATE_LIMIT_CALL_COUNT} rapid calls`,
        detail: `Called "${target.name}" ${RATE_LIMIT_CALL_COUNT} times back-to-back in ${elapsedMs}ms (${errors} error response(s)). ${
          sawRateLimitSignal
            ? "At least one response mentioned rate-limiting/throttling explicitly."
            : "No response mentioned rate-limiting/throttling — doesn't mean none exists (it may trigger at a higher volume than this capped check sends), but nothing showed up at this small scale."
        }`,
      });
    }

    findings.push({
      id: "probe.summary",
      severity: "info",
      title: `Made ${callCount} probe call(s) across ${probeable.length} tool(s)`,
      detail: "Only deliberately malformed input was sent, to read-only-named tools only. See README for exactly what this does and does not cover.",
    });
  } finally {
    if (connected) await client.close().catch(() => {});
  }

  return {
    target: `${target.command} ${(target.args ?? []).join(" ")}`.trim(),
    mode: "live",
    findings,
  };
}
