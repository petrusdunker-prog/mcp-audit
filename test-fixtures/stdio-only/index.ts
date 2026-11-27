// Fixture: a minimal stdio-only MCP server. No network listener at all —
// used to verify the auth check correctly marks this "not applicable"
// instead of flagging a false positive.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server({ name: "fixture-stdio-only", version: "0.0.1" }, { capabilities: { tools: {} } });

const transport = new StdioServerTransport();
await server.connect(transport);
