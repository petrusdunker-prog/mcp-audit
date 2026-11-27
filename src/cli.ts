#!/usr/bin/env node
import { Command } from "commander";
import { auditSource } from "./modes/sourceScan.js";
import { auditLive } from "./modes/liveIntrospect.js";
import { printReport, toJson } from "./report.js";
import { toSarif } from "./sarif.js";
import { hasFindingAtOrAbove } from "./severity.js";
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
  .action(async (path: string, opts: { format: string; failOn?: string }) => {
    const report = await auditSource(path);
    emitReport(report, { format: opts.format as OutputOpts["format"], failOn: opts.failOn as Severity | undefined });
  });

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
