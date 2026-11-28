#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { Command } from "commander";
import { auditSource } from "./modes/sourceScan.js";
import { auditLive } from "./modes/liveIntrospect.js";
import { printReport, toJson } from "./report.js";
import { toSarif } from "./sarif.js";
import { hasFindingAtOrAbove } from "./severity.js";
import { diffReports, printDrift, driftToJson } from "./drift.js";
import type { AuditReport, Severity } from "./types.js";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

interface OutputOpts {
  format?: "text" | "json" | "sarif";
  failOn?: Severity;
}

function emitReport(report: AuditReport, opts: OutputOpts): void {
  switch (opts.format) {
    case "sarif":
      console.log(toSarif(report));
      break;
    case "json":
      console.log(toJson(report));
      break;
    default:
      printReport(report);
  }

  if (opts.failOn && hasFindingAtOrAbove(report, opts.failOn)) {
    process.exitCode = 1;
  }
}

async function readBaseline(file: string): Promise<AuditReport> {
  let raw: string;
  try {
    raw = await readFile(file, "utf-8");
  } catch (err) {
    throw new Error(
      `Could not read baseline file "${file}": ${String(err instanceof Error ? err.message : err)}. ` +
        `Create one first with --write-baseline ${file}.`
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`Baseline file "${file}" is not valid JSON.`);
  }
  if (!parsed || typeof parsed !== "object" || !Array.isArray((parsed as AuditReport).findings)) {
    throw new Error(`Baseline file "${file}" doesn't look like an mcp-audit report (missing a findings array).`);
  }
  return parsed as AuditReport;
}

/** Baseline mode: diff instead of reporting the full point-in-time state.
 *  --fail-on applies only to *new* findings — the baseline is, by
 *  definition, already-accepted state, not something to fail the job over
 *  every single run. */
async function emitDrift(report: AuditReport, baselineFile: string, opts: OutputOpts): Promise<void> {
  const baseline = await readBaseline(baselineFile);
  const drift = diffReports(baseline, report);

  switch (opts.format) {
    case "sarif":
      throw new Error("--baseline with --format sarif isn't supported yet — use text or json.");
    case "json":
      console.log(driftToJson(drift));
      break;
    default:
      printDrift(drift);
  }

  if (opts.failOn) {
    const newOnly: AuditReport = { ...report, findings: drift.entries.filter((e) => e.status === "new").map((e) => e.finding) };
    if (hasFindingAtOrAbove(newOnly, opts.failOn)) {
      process.exitCode = 1;
    }
  }
}

const program = new Command();

program
  .name("mcp-audit")
  .description("Security auditor for MCP servers")
  .enablePositionalOptions()
  .version("0.1.0");

program
  .command("scan <path>")
  .description("Static scan of a local MCP server repo (Mode A)")
  .option("--format <format>", "text, json, or sarif", "text")
  .option("--fail-on <severity>", `exit 1 if any finding is at least this severe (${SEVERITIES.join("|")})`)
  .option("--baseline <file>", "diff against a previously saved report instead of printing the full state")
  .option("--write-baseline <file>", "save this scan's report for a future --baseline comparison")
  .action(
    async (
      path: string,
      opts: { format: string; failOn?: string; baseline?: string; writeBaseline?: string }
    ) => {
      const report = await auditSource(path);
      const outputOpts = { format: opts.format as OutputOpts["format"], failOn: opts.failOn as Severity | undefined };

      // Diff against the pre-existing baseline before possibly overwriting
      // it below — so `--baseline x --write-baseline x` means "compare
      // against what's there now, then accept the new state as the
      // baseline going forward" in one command.
      if (opts.baseline) {
        try {
          await emitDrift(report, opts.baseline, outputOpts);
        } catch (err) {
          console.error(err instanceof Error ? err.message : String(err));
          process.exitCode = 1;
          return;
        }
      } else {
        emitReport(report, outputOpts);
      }

      if (opts.writeBaseline) {
        await writeFile(opts.writeBaseline, toJson(report), "utf-8");
      }
    }
  );

program
  .command("live [command] [args...]")
  .description(
    "Introspect an MCP server's declared tools (Mode B) — launch over stdio, or dial --url with no credentials"
  )
  .passThroughOptions()
  .enablePositionalOptions()
  .option("-u, --url <url>", "HTTP(S) URL to connect to instead of spawning a stdio command")
  .option("--format <format>", "text, json, or sarif", "text")
  .option("--fail-on <severity>", `exit 1 if any finding is at least this severe (${SEVERITIES.join("|")})`)
  .action(
    async (
      command: string | undefined,
      args: string[],
      opts: { url?: string; format: string; failOn?: string }
    ) => {
      if (!opts.url && !command) {
        console.error("Provide either a stdio <command> or --url <url>");
        process.exitCode = 1;
        return;
      }
      const report = await auditLive({ command, args, url: opts.url });
      emitReport(report, { format: opts.format as OutputOpts["format"], failOn: opts.failOn as Severity | undefined });
    }
  );

program.parseAsync(process.argv);
