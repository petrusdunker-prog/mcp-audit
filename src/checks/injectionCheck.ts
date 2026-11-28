import type { Finding } from "../types.js";

export interface InspectableTool {
  name: string;
  description?: string;
  [key: string]: unknown;
}

// Markers that essentially never appear in a legitimate human-readable
// tool description — a server using one is almost certainly trying to put
// words in the calling model's mouth, not describe what the tool does.
const FAKE_ROLE_MARKER_PATTERN =
  /\b(SYSTEM|ADMIN OVERRIDE|ASSISTANT)\s*:|\[\/?(SYSTEM|INST)\]|<\|im_(start|end)\|>|###\s*(Instruction|System)\b/;

// Imperative language aimed at the calling model's behavior rather than
// describing the tool. Deliberately narrow — these are specific, commonly
// documented injection phrasings (see e.g. the Invariant Labs "tool
// poisoning" writeups), not generic words, following the same false-
// positive lesson the permission check already learned the hard way.
const OVERRIDE_LANGUAGE_PATTERN =
  /\bignore (all |any |the )?(previous|prior|above|system) instructions\b|\bdisregard (the )?(system prompt|previous instructions)\b|\b(do not|don'?t) (tell|inform|mention (this |it )?to) the user\b|\bwithout (telling|informing|notifying) the user\b|\byou must now\b|\bbefore (calling|using|responding)[, ]+(first |secretly )?(read|send|exfiltrate)\b/i;

// Zero-width spaces/joiners, Unicode Tag characters (the "ASCII smuggling"
// steganographic-injection technique), and bidi override controls.
// Legitimate tool metadata has no reason to contain any of these.
const HIDDEN_UNICODE_PATTERN = /[​-‏‪-‮⁠-⁤﻿\u{E0000}-\u{E007F}]/u;

/**
 * Collects every string value in a tool's metadata (name, description,
 * and anywhere in its input schema — a parameter's own description can
 * carry an injection just as easily as the tool's) into one block of real
 * text, joined with real newlines. Deliberately not JSON.stringify: that
 * escapes a real newline to the two literal characters "\" + "n", which
 * glues a word character directly in front of whatever follows and
 * silently defeats a \b boundary check right at the start of a line —
 * exactly where a fake role marker like "SYSTEM:" realistically sits,
 * on its own line after genuine description text.
 */
function extractText(tool: InspectableTool): string {
  const parts: string[] = [];
  const collect = (value: unknown): void => {
    if (typeof value === "string") parts.push(value);
    else if (Array.isArray(value)) value.forEach(collect);
    else if (value && typeof value === "object") Object.values(value).forEach(collect);
  };
  collect(tool);
  return parts.join("\n");
}

/**
 * Heuristic: does a tool's metadata (name, description, and declared input
 * schema) contain language or characters aimed at manipulating the calling
 * model rather than describing the tool? Three narrow, specific
 * sub-checks, not a general "sounds suspicious" filter — each chosen for
 * being a real, documented injection technique with low expected
 * false-positive risk, same discipline every other check here was held to
 * before being trusted. Unvalidated against real servers yet, so
 * severities start conservative (HIGH, not CRITICAL) pending that.
 */
export function checkPromptInjection(tools: InspectableTool[]): Finding[] {
  const findings: Finding[] = [];

  for (const tool of tools) {
    const text = extractText(tool);

    if (FAKE_ROLE_MARKER_PATTERN.test(text)) {
      findings.push({
        id: `injection.role-marker.${tool.name}`,
        severity: "high",
        title: `Tool "${tool.name}" metadata contains a fake system/role marker`,
        detail:
          "Found something that reads like a system-prompt or chat-turn marker (e.g. \"SYSTEM:\", \"[INST]\", \"<|im_start|>\") inside this tool's own metadata. A legitimate tool description has no reason to contain one — this is a documented technique for trying to make an LLM treat untrusted tool content as a higher-authority instruction.",
      });
    }

    if (OVERRIDE_LANGUAGE_PATTERN.test(text)) {
      findings.push({
        id: `injection.override-language.${tool.name}`,
        severity: "medium",
        title: `Tool "${tool.name}" metadata contains language aimed at overriding model behavior`,
        detail:
          "Found phrasing that reads as an instruction to the calling model (e.g. \"ignore previous instructions\", \"without telling the user\") rather than a description of what the tool does. Could be a real attempt at manipulating an agent, or a false positive from an unusual but innocent description — this heuristic is new and not yet validated against real servers, verify manually.",
      });
    }

    if (HIDDEN_UNICODE_PATTERN.test(text)) {
      findings.push({
        id: `injection.hidden-unicode.${tool.name}`,
        severity: "high",
        title: `Tool "${tool.name}" metadata contains hidden/invisible Unicode characters`,
        detail:
          "Found zero-width, Unicode Tag, or bidi-override characters in this tool's metadata — invisible to a human skimming it, but readable by the model. This is a known steganographic technique for hiding injected instructions in plain sight (\"ASCII smuggling\"). Legitimate tool metadata has no reason to contain these.",
      });
    }
  }

  findings.push({
    id: "injection.summary",
    severity: "info",
    title: `Checked ${tools.length} tool(s) for prompt-injection patterns in their metadata`,
    detail:
      findings.length === 0
        ? "No fake role markers, override-language phrasing, or hidden Unicode found. This heuristic only catches these three specific, documented techniques, not manipulation in general."
        : `${findings.length} finding(s) — see above.`,
  });

  return findings;
}
