#!/usr/bin/env node
import { Command } from "commander";
import { auditSource } from "./modes/sourceScan.js";
import { auditLive } from "./modes/liveIntrospect.js";
import { printReport, toJson } from "./report.js";

const program = new Command();

program
  .name("mcp-audit")
  .description("Security auditor for MCP servers")
  .enablePositionalOptions()
  .version("0.1.0");

program
  .command("scan <path>")
  .description("Static scan of a local MCP server repo (Mode A)")
  .option("--json", "output JSON instead of human-readable text")
  .action(async (path: string, opts: { json?: boolean }) => {
    const report = await auditSource(path);
    opts.json ? console.log(toJson(report)) : printReport(report);
  });

program
  .command("live [command] [args...]")
  .description(
    "Introspect an MCP server's declared tools (Mode B) — launch over stdio, or dial --url with no credentials"
  )
  .passThroughOptions()
  .enablePositionalOptions()
  .option("-u, --url <url>", "HTTP(S) URL to connect to instead of spawning a stdio command")
  .option("--json", "output JSON instead of human-readable text")
  .action(async (command: string | undefined, args: string[], opts: { url?: string; json?: boolean }) => {
    if (!opts.url && !command) {
      console.error("Provide either a stdio <command> or --url <url>");
      process.exitCode = 1;
      return;
    }
    const report = await auditLive({ command, args, url: opts.url });
    opts.json ? console.log(toJson(report)) : printReport(report);
  });

program.parseAsync(process.argv);
