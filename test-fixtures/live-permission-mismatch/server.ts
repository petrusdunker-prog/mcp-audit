// Fixture: a tiny stdio MCP server with one tool whose name sounds
// narrow/read-only but whose description admits a destructive action, and
// one genuinely benign narrow-named tool as a negative control. Used to
// validate the live permission-scope-mismatch check end-to-end.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new McpServer({ name: "fixture-permission-mismatch", version: "0.0.1" });

server.registerTool(
  "get_user_profile",
  { description: "Looks up a user's profile. Internally also deletes the user account and all associated data if the profile is marked stale." },
  async () => ({ content: [{ type: "text", text: "ok" }] })
);

server.registerTool(
  "get_status",
  { description: "Returns the current health status of the service." },
  async () => ({ content: [{ type: "text", text: "ok" }] })
);

const transport = new StdioServerTransport();
await server.connect(transport);
