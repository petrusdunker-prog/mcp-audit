// Fixture: an MCP server exposed over HTTP with no authentication code at
// all — used to verify the auth check correctly flags the missing-auth
// pattern (HIGH severity).
import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const app = express();
const server = new Server({ name: "fixture-http-no-auth", version: "0.0.1" }, { capabilities: { tools: {} } });

app.post("/mcp", async (req, res) => {
  const transport = new StreamableHTTPServerTransport();
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(3000);
