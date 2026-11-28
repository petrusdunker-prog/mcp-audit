import type { Finding } from "../types.js";

export interface MalformedArgSet {
  label: string;
  args: Record<string, unknown>;
}

interface JsonSchemaProperty {
  type?: string;
  minimum?: number;
  maximum?: number;
  exclusiveMinimum?: number;
  exclusiveMaximum?: number;
  [key: string]: unknown;
}

interface JsonSchema {
  type?: string;
  properties?: Record<string, JsonSchemaProperty>;
  required?: string[];
}

const OVERSIZED_STRING_LENGTH = 50_000;

function wrongTypeValue(declaredType: string | undefined): unknown {
  switch (declaredType) {
    case "string":
      return 12345;
    case "number":
    case "integer":
      return "not-a-number";
    case "boolean":
      return "yes";
    case "array":
      return "not-an-array";
    case "object":
      return "not-an-object";
    default:
      return null;
  }
}

/**
 * A value that's genuinely out-of-bounds for this property, where
 * "out-of-bounds" can actually be justified against what the schema
 * declares — not just an arbitrary large/negative number. A plain
 * `{type: "number"}` with no min/max has no out-of-bounds value at all:
 * a huge negative number is still a perfectly valid number, and a tool
 * that accepts it (e.g. a sum function) isn't exhibiting a validation
 * gap, it's doing arithmetic correctly. Found via real-world testing —
 * an early version flagged exactly this as a false positive against the
 * official reference server's get-sum tool.
 */
function extremeValue(prop: JsonSchemaProperty | undefined): { value: unknown; justified: boolean } {
  switch (prop?.type) {
    case "string":
      // Empty is a reasonable universal probe for a required string even
      // without a declared minLength — a required-but-blank value is
      // usually nonsensical regardless.
      return { value: "", justified: true };
    case "number":
    case "integer": {
      const min =
        typeof prop.minimum === "number" ? prop.minimum : typeof prop.exclusiveMinimum === "number" ? prop.exclusiveMinimum : undefined;
      const max =
        typeof prop.maximum === "number" ? prop.maximum : typeof prop.exclusiveMaximum === "number" ? prop.exclusiveMaximum : undefined;
      if (min !== undefined) return { value: min - 1, justified: true };
      if (max !== undefined) return { value: max + 1, justified: true };
      return { value: 0, justified: false };
    }
    case "boolean":
      return { value: false, justified: false };
    case "array":
      return { value: [], justified: false };
    case "object":
      return { value: {}, justified: false };
    default:
      return { value: null, justified: false };
  }
}

/**
 * Builds a small, capped set of deliberately malformed argument sets from
 * a tool's own declared input schema — only for its required properties
 * (testing whether the server enforces what it itself declared), never
 * real-looking data, since the point is testing validation, not using the
 * tool for its real purpose. Returns an empty array if the tool declares
 * no required properties — there's nothing to send that would actually
 * violate its own schema, calling it with empty args is just a normal
 * valid call for that tool.
 */
export function generateMalformedArgSets(schema: JsonSchema | undefined): MalformedArgSet[] {
  const required = schema?.required ?? [];
  if (required.length === 0) return [];

  const properties = schema?.properties ?? {};
  const sets: MalformedArgSet[] = [{ label: "missing all required fields", args: {} }];

  const wrongTypeArgs: Record<string, unknown> = {};
  const extremeArgs: Record<string, unknown> = {};
  let hasStringField = false;
  let hasJustifiedExtreme = false;

  for (const name of required) {
    const prop = properties[name];
    wrongTypeArgs[name] = wrongTypeValue(prop?.type);
    const extreme = extremeValue(prop);
    extremeArgs[name] = extreme.value;
    if (extreme.justified) hasJustifiedExtreme = true;
    if (prop?.type === "string") hasStringField = true;
  }

  sets.push({ label: "wrong type for each required field", args: wrongTypeArgs });

  // Only claim "extreme" if at least one field actually has a value that's
  // out of bounds against what the schema declares — otherwise this would
  // just be sending ordinary valid values and calling it malformed.
  if (hasJustifiedExtreme) {
    sets.push({ label: "empty/extreme value for each required field", args: extremeArgs });
  }

  if (hasStringField) {
    const oversizedArgs: Record<string, unknown> = { ...extremeArgs };
    for (const name of required) {
      if (properties[name]?.type === "string") {
        oversizedArgs[name] = "A".repeat(OVERSIZED_STRING_LENGTH);
      }
    }
    sets.push({ label: "oversized string for each required string field", args: oversizedArgs });
  }

  return sets;
}

export type ProbeOutcome =
  | { kind: "rejected"; detail: string }
  | { kind: "accepted"; detail: string }
  | { kind: "crashed"; detail: string };

/**
 * One finding per malformed call that wasn't cleanly rejected. A server
 * that throws a protocol-level error or returns isError:true handled the
 * bad input correctly — nothing to report. One that "succeeds" anyway is a
 * weaker, MEDIUM signal (impact varies — some tools are legitimately
 * lenient). One that never returns cleanly (times out, connection drops)
 * is a stronger, HIGH signal: an uncaught crash triggered by malformed
 * input is a real fragility/DoS indicator, not just a lenient validator.
 */
export function findingForOutcome(toolName: string, argSet: MalformedArgSet, outcome: ProbeOutcome): Finding | null {
  if (outcome.kind === "rejected") return null;

  if (outcome.kind === "accepted") {
    return {
      id: `probe.input-validation.${toolName}.${argSet.label.replace(/\s+/g, "-")}`,
      severity: "medium",
      title: `Tool "${toolName}" accepted malformed input (${argSet.label}) without rejecting it`,
      detail: `Called with input that either violates this tool's declared schema or pushes a declared field to an unreasonable extreme (${argSet.label}), and it returned success rather than an error. Could be intentional leniency, or missing input validation — impact depends on what the tool does with the value. ${outcome.detail}`,
    };
  }

  return {
    id: `probe.crash.${toolName}.${argSet.label.replace(/\s+/g, "-")}`,
    severity: "high",
    title: `Tool "${toolName}" did not return cleanly for malformed input (${argSet.label})`,
    detail: `Called with deliberately invalid input (${argSet.label}) and the call did not complete normally (timed out or the connection dropped) rather than returning a clean error. That's a stronger signal than mere leniency — an uncaught crash triggered by bad input is a real fragility/DoS indicator. ${outcome.detail}`,
  };
}
