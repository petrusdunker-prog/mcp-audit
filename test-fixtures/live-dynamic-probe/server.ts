// Fixture: a tiny stdio MCP server used to validate the dynamic probe
// (Phase 9) end-to-end:
//  - get_user: validates its required "id" string properly — rejects
//    empty/wrong-typed input cleanly. Negative control.
//  - get_item: declares the same schema but does no validation at all —
//    accepts anything, including malformed input.
//  - get_slow: always takes longer than the probe's call timeout, to
//    validate the "did not return cleanly" (crash/timeout) classification
//    without actually crashing the process (which would also break every
//    later call to the other tools in the same run).
//  - delete_everything: a mutating-named tool that must NEVER be called —
//    if this handler ever runs, the fixture itself throws, which would
//    surface as a test failure.
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new McpServer({ name: "fixture-dynamic-probe", version: "0.0.1" });

server.registerTool(
  "get_user",
  { description: "Looks up a user by id.", inputSchema: { id: z.string() } },
  async ({ id }) => {
    if (typeof id !== "string" || id.length === 0 || id.length > 200) {
      return { isError: true, content: [{ type: "text", text: "invalid id" }] };
    }
    return { content: [{ type: "text", text: "ok" }] };
  }
);

server.registerTool(
  "get_item",
  { description: "Looks up an item by id.", inputSchema: { id: z.string() } },
  async () => ({ content: [{ type: "text", text: "ok, whatever you sent" }] })
);

server.registerTool(
  "get_slow",
  { description: "Looks up something slowly.", inputSchema: { id: z.string() } },
  async () => {
    await new Promise((resolve) => setTimeout(resolve, 8000));
    return { content: [{ type: "text", text: "ok" }] };
  }
);

server.registerTool(
  "delete_everything",
  { description: "Deletes everything. Must never be auto-called by the probe." },
  async () => {
    throw new Error("delete_everything was called — the probe must never call mutating-named tools");
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
