import "node:process";
import http from "node:http";
import { timingSafeEqual } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const HOST = "127.0.0.1";
const PORT = Number(process.env.MCP_BRIDGE_PORT || 8765);
const BRIDGE_TOKEN = process.env.MCP_BRIDGE_TOKEN || "";
const REPLICATE_TOKEN = process.env.REPLICATE_API_TOKEN || "";
const MAX_BODY = 1024 * 1024;

let mcpClient = null;
let connectPromise = null;

function loopbackOnly(req) {
  const address = req.socket.remoteAddress || "";
  const host = (req.headers.host || "").toLowerCase();
  const allowedHost = host === `127.0.0.1:${PORT}` || host === `localhost:${PORT}` ||
    host === "127.0.0.1" || host === "localhost";
  const allowedAddress = address === "127.0.0.1" || address === "::1" ||
    address === "::ffff:127.0.0.1";
  return allowedHost && allowedAddress;
}

function authorized(req) {
  if (!BRIDGE_TOKEN) return false;
  const header = req.headers.authorization || "";
  const supplied = header.startsWith("Bearer ") ? header.slice(7) : "";
  const a = Buffer.from(supplied);
  const b = Buffer.from(BRIDGE_TOKEN);
  return a.length === b.length && timingSafeEqual(a, b);
}

function send(res, status, payload) {
  const data = Buffer.from(JSON.stringify(payload));
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": data.length,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });
  res.end(data);
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw new Error("Request body is too large.");
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : {};
}

async function getMcpClient() {
  if (!REPLICATE_TOKEN) throw new Error("REPLICATE_API_TOKEN is not configured in the Termux environment.");
  if (mcpClient) return mcpClient;
  if (!connectPromise) {
    connectPromise = (async () => {
      const env = {
        PATH: process.env.PATH || "",
        HOME: process.env.HOME || "",
        TMPDIR: process.env.TMPDIR || "",
        PREFIX: process.env.PREFIX || "",
        REPLICATE_API_TOKEN: REPLICATE_TOKEN
      };
      const transport = new StdioClientTransport({
        command: "npx",
        args: ["--yes", "replicate-mcp@0.9.0"],
        env,
        stderr: "inherit"
      });
      const client = new Client(
        { name: "yasser-security-lab-android-bridge", version: "1.0.0" },
        { capabilities: {} }
      );
      await client.connect(transport);
      mcpClient = client;
      return client;
    })().catch((error) => {
      connectPromise = null;
      mcpClient = null;
      throw error;
    });
  }
  return connectPromise;
}

async function handle(req, res) {
  if (!loopbackOnly(req)) return send(res, 403, { error: "Loopback access only." });

  const url = new URL(req.url || "/", `http://127.0.0.1:${PORT}`);
  if (req.method === "GET" && url.pathname === "/health") {
    return send(res, 200, {
      status: "ok",
      service: "ysl-replicate-mcp-bridge",
      replicate_token_configured: Boolean(REPLICATE_TOKEN),
      bridge_auth_configured: Boolean(BRIDGE_TOKEN),
      connected: Boolean(mcpClient)
    });
  }

  if (!url.pathname.startsWith("/v1/mcp/")) return send(res, 404, { error: "Not found." });
  if (!authorized(req)) return send(res, 401, { error: "A valid local bridge token is required." });

  if (req.method === "GET" && url.pathname === "/v1/mcp/tools") {
    try {
      const client = await getMcpClient();
      const response = await client.listTools();
      const tools = (response.tools || []).map((tool) => ({
        name: tool.name,
        description: tool.description || "",
        inputSchema: tool.inputSchema || { type: "object", properties: {} }
      }));
      return send(res, 200, { tools, count: tools.length, server: "Replicate MCP" });
    } catch (error) {
      return send(res, 503, { error: error.message || "MCP tool discovery failed." });
    }
  }

  if (req.method === "POST" && url.pathname === "/v1/mcp/call") {
    let body;
    try {
      body = await readJson(req);
    } catch {
      return send(res, 400, { error: "Invalid JSON request body." });
    }
    if (body.user_approved !== true) {
      return send(res, 403, {
        status: "approval_required",
        message: "Confirm the tool name and arguments in the Android app before execution."
      });
    }
    if (typeof body.name !== "string" || !/^[a-zA-Z0-9_.-]{1,120}$/.test(body.name)) {
      return send(res, 400, { error: "A valid MCP tool name is required." });
    }
    if (!body.arguments || typeof body.arguments !== "object" || Array.isArray(body.arguments)) {
      return send(res, 400, { error: "Tool arguments must be a JSON object." });
    }
    try {
      const client = await getMcpClient();
      const listed = await client.listTools();
      if (!(listed.tools || []).some((tool) => tool.name === body.name)) {
        return send(res, 404, { error: "The requested tool is not exposed by the connected MCP server." });
      }
      const result = await client.callTool({ name: body.name, arguments: body.arguments });
      process.stdout.write(JSON.stringify({
        event: "approved_tool_call",
        tool: body.name,
        at: new Date().toISOString()
      }) + "\n");
      return send(res, 200, { status: "completed", tool: body.name, result });
    } catch (error) {
      return send(res, 502, { error: error.message || "MCP tool call failed." });
    }
  }

  return send(res, 404, { error: "Unknown MCP route." });
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((error) => send(res, 500, { error: error.message || "Internal bridge error." }));
});

server.listen(PORT, HOST, () => {
  process.stdout.write(`YSL Replicate MCP bridge listening on http://${HOST}:${PORT}\n`);
  process.stdout.write(`Replicate token configured: ${Boolean(REPLICATE_TOKEN)}\n`);
  process.stdout.write(`Local bridge token configured: ${Boolean(BRIDGE_TOKEN)}\n`);
});

async function shutdown() {
  server.close();
  if (mcpClient) {
    try { await mcpClient.close(); } catch {}
  }
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
