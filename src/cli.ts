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
  .command("live <command> [args...]")
  .description("Launch an MCP server over stdio and introspect its declared tools (Mode B)")
  .passThroughOptions()
  .enablePositionalOptions()
  .option("--json", "output JSON instead of human-readable text")
  .action(async (command: string, args: string[], opts: { json?: boolean }) => {
    const report = await auditLive({ command, args });
    opts.json ? console.log(toJson(report)) : printReport(report);
  });

program.parseAsync(process.argv);
