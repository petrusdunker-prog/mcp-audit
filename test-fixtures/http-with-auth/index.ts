// Fixture: an MCP server exposed over HTTP that checks a bearer token
// before handling any request — used to verify the auth check correctly
// detects the auth pattern and does not flag it (INFO severity, not HIGH).
import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const app = express();
const server = new Server({ name: "fixture-http-with-auth", version: "0.0.1" }, { capabilities: { tools: {} } });

function requireAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
  const header = req.headers["authorization"];
  if (!header || !header.startsWith("Bearer ")) {
    res.status(401).json({ error: "missing bearer token" });
    return;
  }
  const token = header.slice("Bearer ".length);
  if (token !== process.env.MCP_API_KEY) {
    res.status(403).json({ error: "invalid api key" });
    return;
  }
  next();
}

app.post("/mcp", requireAuth, async (req, res) => {
  const transport = new StreamableHTTPServerTransport();
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(3000);
