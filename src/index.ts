#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { createNeo4jDriver, createNeo4jDriverWithBasic, getAccessToken, OAuthConfig, verifyToken } from "./auth.js";
import * as dotenv from "dotenv";
import express from "express";
import cors from "cors";

dotenv.config();

const NEO4J_URI = process.env.NEO4J_URI || "bolt://localhost:7687";
const NEO4J_USER = process.env.NEO4J_USER;
const NEO4J_PASSWORD = process.env.NEO4J_PASSWORD;
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID;
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET;
const OAUTH_ISSUER_URL = process.env.OAUTH_ISSUER_URL;
const OAUTH_SCOPE = process.env.OAUTH_SCOPE;
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

const isOAuthEnabled = !!(OAUTH_CLIENT_ID && OAUTH_CLIENT_SECRET && OAUTH_ISSUER_URL);
const isBasicAuthEnabled = !!(NEO4J_USER && NEO4J_PASSWORD);

if (!isBasicAuthEnabled) {
  console.error("Missing configuration: NEO4J_USER and NEO4J_PASSWORD must be provided for Community Edition.");
  process.exit(1);
}

const oauthConfig: OAuthConfig = {
  clientId: OAUTH_CLIENT_ID || "",
  clientSecret: OAUTH_CLIENT_SECRET || "",
  issuerUrl: OAUTH_ISSUER_URL || "",
  scope: OAUTH_SCOPE,
};

async function main() {
  let driver: any;
  let accessToken: string | null = null;

  console.error("Connecting to Neo4j Community Edition via Basic Auth...");
  driver = createNeo4jDriverWithBasic(NEO4J_URI, NEO4J_USER!, NEO4J_PASSWORD!);

  const server = new Server(
    {
      name: "neo4j-mcp-server",
      version: "1.0.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  const tools = [
    {
      name: "execute_cypher",
      description: "Execute a Cypher query on the Neo4j database (Read/Write)",
      inputSchema: {
        type: "object",
        properties: {
          query: {
            type: "string",
            description: "The Cypher query to execute",
          },
          parameters: {
            type: "object",
            description: "Parameters for the Cypher query",
          },
        },
        required: ["query"],
      },
    },
    {
      name: "read_neo4j_cypher",
      description: "Execute a read-only Cypher query on the Neo4j database",
      inputSchema: {
        type: "object",
        properties: {
          query: {
            type: "string",
            description: "The read-only Cypher query to execute",
          },
          parameters: {
            type: "object",
            description: "Parameters for the Cypher query",
          },
        },
        required: ["query"],
      },
    },
    {
      name: "write_neo4j_cypher",
      description: "Execute a write Cypher query on the Neo4j database",
      inputSchema: {
        type: "object",
        properties: {
          query: {
            type: "string",
            description: "The write Cypher query to execute",
          },
          parameters: {
            type: "object",
            description: "Parameters for the Cypher query",
          },
        },
        required: ["query"],
      },
    },
    {
      name: "get_neo4j_schema",
      description: "Get the schema of the Neo4j database (labels, relationship types, and properties)",
      inputSchema: {
        type: "object",
        properties: {},
      },
    },
  ];

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: tools,
    };
  });

  const handleExecuteCypher = async (args: any, accessMode: string = 'WRITE') => {
    const query = args?.query as string;
    const parameters = (args?.parameters as Record<string, any>) || {};

    const session = driver.session({ defaultAccessMode: accessMode });
    try {
      const result = await session.run(query, parameters);
      const records = result.records.map((record: any) => record.toObject());
      return {
        content: [{ type: "text", text: JSON.stringify(records, null, 2) }],
      };
    } catch (error: any) {
      return {
        content: [{ type: "text", text: `Error executing Cypher (${accessMode}): ${error.message}` }],
        isError: true,
      };
    } finally {
      await session.close();
    }
  };

  const handleGetSchema = async () => {
    const session = driver.session({ defaultAccessMode: 'READ' });
    try {
      // Fetch labels and their properties
      const labelsResult = await session.run(`
        CALL db.labels() YIELD label
        CALL apoc.meta.data() YIELD label as l, property, type, kind
        WHERE l = label AND kind = 'node'
        RETURN label, collect({property: property, type: type}) as properties
      `).catch(async () => {
        // Fallback if APOC is not available
        return await session.run(`
          CALL db.labels() YIELD label
          RETURN label, [] as properties
        `);
      });

      // Fetch relationship types and their properties
      const relsResult = await session.run(`
        CALL db.relationshipTypes() YIELD relationshipType
        CALL apoc.meta.data() YIELD label as type, property, type as dataType, kind
        WHERE type = relationshipType AND kind = 'relationship'
        RETURN relationshipType, collect({property: property, type: dataType}) as properties
      `).catch(async () => {
        // Fallback if APOC is not available
        return await session.run(`
          CALL db.relationshipTypes() YIELD relationshipType
          RETURN relationshipType, [] as properties
        `);
      });

      const schema = {
        labels: labelsResult.records.map((r: any) => r.toObject()),
        relationshipTypes: relsResult.records.map((r: any) => r.toObject()),
      };

      return {
        content: [{ type: "text", text: JSON.stringify(schema, null, 2) }],
      };
    } catch (error: any) {
      return {
        content: [{ type: "text", text: `Error fetching schema: ${error.message}` }],
        isError: true,
      };
    } finally {
      await session.close();
    }
  };

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    switch (request.params.name) {
      case "execute_cypher":
        return await handleExecuteCypher(request.params.arguments, 'WRITE');
      case "read_neo4j_cypher":
        return await handleExecuteCypher(request.params.arguments, 'READ');
      case "write_neo4j_cypher":
        return await handleExecuteCypher(request.params.arguments, 'WRITE');
      case "get_neo4j_schema":
        return await handleGetSchema();
      default:
        throw new Error(`Tool not found: ${request.params.name}`);
    }
  });

  const app = express();
  app.use(cors());
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Speicher für Agent-Redirects (Zustandserhaltung über den OAuth-Flow hinweg)
  const pendingRedirects = new Map<string, string>();

  // Error Handler für malformed JSON
  app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (err instanceof SyntaxError && 'status' in err && err.status === 400) {
      console.error(`Malformed JSON received: ${err.message}`);
      return res.status(400).json({
        jsonrpc: "2.0",
        id: null,
        error: { code: -32700, message: "Parse error" }
      });
    }
    next();
  });

  // OIDC Discovery Proxy (hilft Agenten, die Auth-Konfiguration zu finden)
  app.get("/.well-known/openid-configuration", async (req, res) => {
    if (!isOAuthEnabled) return res.status(404).send();
    try {
      const configUrl = OAUTH_ISSUER_URL!.endsWith('/') 
        ? `${OAUTH_ISSUER_URL}.well-known/openid-configuration`
        : `${OAUTH_ISSUER_URL}/.well-known/openid-configuration`;
      
      console.error(`Fetching metadata from ${configUrl}...`);
      const response = await fetch(configUrl);
      if (!response.ok) throw new Error(`Provider returned ${response.status}`);
      const data = await response.json();
      
      // IMPORTANT: We use the actual request host to define the issuer.
      // If the client calls http://localhost:3000, the issuer MUST be http://localhost:3000.
      const protocol = req.headers['x-forwarded-proto'] || req.protocol;
      const host = req.headers['x-forwarded-host'] || req.get('host');
      const currentServerUrl = `${protocol}://${host}`;
      
      console.error(`Detected Server URL for OIDC: ${currentServerUrl}`);

      const proxiedConfig = {
        ...data,
        issuer: currentServerUrl,
        authorization_endpoint: `${currentServerUrl}/mcp/auth`,
        token_endpoint: `${currentServerUrl}/mcp/token`,
        jwks_uri: `${currentServerUrl}/mcp/jwks`,
        registration_endpoint: `${currentServerUrl}/mcp/register`,
      };

      if (!proxiedConfig.token_endpoint_auth_methods_supported) {
        proxiedConfig.token_endpoint_auth_methods_supported = ["client_secret_post", "client_secret_basic", "bearer"];
      } else if (!proxiedConfig.token_endpoint_auth_methods_supported.includes("bearer")) {
        proxiedConfig.token_endpoint_auth_methods_supported.push("bearer");
      }
      
      console.error(`Serving proxied OIDC metadata. New Issuer: ${proxiedConfig.issuer}`);
      res.json(proxiedConfig);
    } catch (error: any) {
      console.error(`Discovery Proxy Error: ${error.message}`);
      res.status(500).json({ error: error.message });
    }
  });

  app.get("/mcp/jwks", async (req, res) => {
    try {
      const configUrl = OAUTH_ISSUER_URL!.endsWith('/') 
        ? `${OAUTH_ISSUER_URL}.well-known/openid-configuration`
        : `${OAUTH_ISSUER_URL}/.well-known/openid-configuration`;
      const configRes = await fetch(configUrl);
      const config = await configRes.json();
      
      const response = await fetch(config.jwks_uri);
      const data = await response.json();
      res.json(data);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  // Proxy für den Authorization-Endpunkt (leitet zum echten Browser-Login bei OneLogin weiter)
  app.get("/mcp/auth", async (req, res) => {
    try {
      const configUrl = OAUTH_ISSUER_URL!.endsWith('/') 
        ? `${OAUTH_ISSUER_URL}.well-known/openid-configuration`
        : `${OAUTH_ISSUER_URL}/.well-known/openid-configuration`;
      const configRes = await fetch(configUrl);
      const config = await configRes.json();
      
      const authUrl = new URL(config.authorization_endpoint);
      
      // Wir speichern die ursprüngliche redirect_uri vom Agenten, 
      // um den Benutzer später dorthin zurückschicken zu können.
      const agentRedirectUri = req.query.redirect_uri as string;
      const state = req.query.state as string;
      
      if (agentRedirectUri && state) {
        pendingRedirects.set(state, agentRedirectUri);
      }
      
      // Wir leiten den Benutzer zum echten OneLogin-Login weiter,
      // verwenden aber UNSERE statische URL als redirect_uri bei OneLogin.
      // Wir entfernen auch hier 'resource' und 'audience', um OneLogin nicht zu verwirren.
      Object.keys(req.query).forEach(key => {
        const lowerKey = key.toLowerCase();
        if (key !== 'redirect_uri' && lowerKey !== 'resource' && lowerKey !== 'audience') {
          authUrl.searchParams.append(key, req.query[key] as string);
        }
      });
      
      const staticRedirectUri = `${BASE_URL}/mcp/callback`;
      authUrl.searchParams.append("redirect_uri", staticRedirectUri);
      
      if (!authUrl.searchParams.has("client_id")) {
        authUrl.searchParams.append("client_id", OAUTH_CLIENT_ID!);
      }
      
      // Wir müssen uns merken, wohin wir am Ende wirklich zurückleiten müssen.
      // In einer einfachen Implementierung nutzen wir den 'state' Parameter dafür
      // oder eine Session (hier zur Vereinfachung im State kodiert, falls möglich, 
      // oder wir setzen voraus, dass der Agent den State beibehält).
      
      console.error(`Redirecting user to OneLogin. Static Callback: ${staticRedirectUri}`);
      res.redirect(authUrl.toString());
    } catch (error: any) {
      res.status(500).send(`Auth Redirect Error: ${error.message}`);
    }
  });

  // Der statische Callback-Endpunkt, den Sie bei OneLogin hinterlegen
  app.get("/mcp/callback", (req, res) => {
    const code = req.query.code as string;
    const state = req.query.state as string;
    
    // Prüfen, ob wir einen Redirect für diesen State gespeichert haben
    const agentRedirectUri = state ? pendingRedirects.get(state) : null;
    
    if (agentRedirectUri) {
      pendingRedirects.delete(state); // Aufräumen
      
      const finalUrl = new URL(agentRedirectUri);
      if (code) finalUrl.searchParams.append("code", code);
      if (state) finalUrl.searchParams.append("state", state);
      
      console.error(`OAUTH FLOW COMPLETE. Redirecting user back to Agent: ${agentRedirectUri}`);
      return res.redirect(finalUrl.toString());
    }
    
    res.send(`
      <html>
        <head>
          <title>Login erfolgreich</title>
          <style>
            body { font-family: sans-serif; text-align: center; padding-top: 50px; }
            .success { color: green; font-size: 24px; }
          </style>
        </head>
        <body>
          <div class="success">✓ Login erfolgreich!</div>
          <p>Die Authentifizierung am Neo4j MCP Server war erfolgreich.</p>
          <p>Sie können dieses Fenster jetzt schließen. Ihr Agent sollte die Verbindung automatisch herstellen.</p>
          
          <script>
            // Falls der Agent auf einen lokalen Callback wartet, versuchen wir diesen zu bedienen.
            // Oft nutzen Agents den State oder ein bekanntes Callback-Muster.
            console.log("Login Code erhalten. Der Server validiert diesen nun beim nächsten Request.");
          </script>
        </body>
      </html>
    `);
  });

  // Proxy für Dynamic Client Registration (gibt einfach die statischen Credentials zurück)
  app.post("/mcp/register", (req, res) => {
    console.error("Agent requested dynamic registration. Providing static credentials...");
    res.status(201).json({
      client_id: OAUTH_CLIENT_ID,
      client_secret: OAUTH_CLIENT_SECRET,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      issuer: `${req.protocol}://${req.get('host')}`
    });
  });

  // Proxy für den Token-Endpunkt
  app.post("/mcp/token", async (req, res) => {
    console.error(`Proxying token request to OneLogin. Body: ${JSON.stringify(req.body)}`);
    try {
      const tokenUrl = await (async () => {
        const configUrl = OAUTH_ISSUER_URL!.endsWith('/') 
          ? `${OAUTH_ISSUER_URL}.well-known/openid-configuration`
          : `${OAUTH_ISSUER_URL}/.well-known/openid-configuration`;
        const response = await fetch(configUrl);
        const config = await response.json();
        return config.token_endpoint;
      })();

      // Leite die Anfrage (Authorization Code oder Client Credentials) an OneLogin weiter
      const body = new URLSearchParams();
      
      // Wir übernehmen selektiv Felder vom Agenten. 
      // Wir lassen 'resource' und 'audience' weg, da diese bei OneLogin oft zu 'invalid_target' führen.
      const forbiddenParams = ['resource', 'audience'];
      
      const sourceData = { ...req.query, ...req.body };
      
      Object.keys(sourceData).forEach(key => {
        const lowerKey = key.toLowerCase();
        if (forbiddenParams.includes(lowerKey)) {
          console.error(`Explicitly stripping problematic parameter: ${key}=${sourceData[key]}`);
          return;
        }
        body.append(key, sourceData[key]);
      });
      
      // Falls der Agent unsere Proxy-Redirect-URI genutzt hat, müssen wir diese auch beim Token-Tausch mitschicken
      if (body.get("redirect_uri")) {
        body.set("redirect_uri", `${BASE_URL}/mcp/callback`);
      }

      // Client Credentials hinzufügen
      if (!body.has("client_id") && OAUTH_CLIENT_ID) {
        body.append("client_id", OAUTH_CLIENT_ID);
      }
      if (!body.has("client_secret") && OAUTH_CLIENT_SECRET) {
        body.append("client_secret", OAUTH_CLIENT_SECRET);
      }

      // WICHTIG: OneLogin erwartet oft Basic Auth für den Token-Endpunkt.
      // Wir bauen den Authorization Header manuell zusammen, falls ID und Secret vorhanden sind.
      const headers: Record<string, string> = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      };
      
      // Falls der Agent bereits einen Authorization Header sendet (z.B. Basic), nutzen wir diesen.
      // Andernfalls fügen wir unsere konfigurierten Credentials hinzu.
      if (req.headers.authorization) {
        headers['Authorization'] = req.headers.authorization;
        console.error("Forwarding existing Authorization header from agent");
      } else if (OAUTH_CLIENT_ID && OAUTH_CLIENT_SECRET) {
        const credentials = Buffer.from(`${OAUTH_CLIENT_ID}:${OAUTH_CLIENT_SECRET}`).toString('base64');
        headers['Authorization'] = `Basic ${credentials}`;
        console.error("Using Basic Auth for OneLogin token exchange");
      }

      // Wir entfernen client_id/client_secret aus dem Body, wenn wir Basic Auth nutzen,
      // um den Fehler "client authentication must only be provided using one mechanism" zu vermeiden.
      if (headers['Authorization']) {
        body.delete("client_id");
        body.delete("client_secret");
      }

      const response = await fetch(tokenUrl, {
        method: 'POST',
        body: body,
        headers: headers,
      });

      const responseText = await response.text();
      console.error(`OneLogin Token Response (${response.status}): ${responseText}`);

      let data;
      try {
        data = JSON.parse(responseText);
      } catch (e) {
        data = { error: "invalid_json", error_description: responseText };
      }
      
      // Speichere das Token intern für die Validierung der MCP-Requests
      if (data.access_token) {
        accessToken = data.access_token;
        console.error("Access Token captured from login flow");
      }

      res.status(response.status).json(data);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  // Endpunkt für direkte MCP JSON-RPC Anfragen (ohne SSE)
  app.post("/mcp", async (req, res) => {
    console.error(`Received request: ${JSON.stringify(req.body)}`);
    
    if (!req.body) {
        return res.status(400).json({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32700, message: "Parse error: Empty request body" }
        });
    }

    // Falls OAuth aktiviert ist, prüfen wir den Bearer-Token
    if (isOAuthEnabled) {
      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        // WICHTIG: WWW-Authenticate Header hinzufügen, um dem Client mitzuteilen, dass Bearer Auth erwartet wird
        res.setHeader("WWW-Authenticate", 'Bearer realm="mcp"');
        return res.status(401).json({
          jsonrpc: "2.0",
          id: req.body.id || null,
          error: { code: -32001, message: "Unauthorized: Missing or invalid Bearer token" }
        });
      }
      
      const token = authHeader.split(" ")[1];
      
      try {
        // SCHNELLER PFAD: Falls das Token exakt dem entspricht, was wir gerade 
        // über unseren Proxy von OneLogin erhalten haben, vertrauen wir ihm.
        if (accessToken && token === accessToken) {
          console.error("Token verified via Fast Path (matches last proxied token).");
        } else {
          // Validierung des Tokens direkt beim Provider via Introspektion.
          const isValid = await verifyToken(oauthConfig, token);
          
          if (!isValid) {
            res.setHeader("WWW-Authenticate", 'Bearer realm="mcp", error="invalid_token"');
            return res.status(403).json({
              jsonrpc: "2.0",
              id: req.body.id || null,
              error: { code: -32001, message: "Forbidden: Token is invalid or expired" }
            });
          }
          // Wir merken uns dieses Token als gültig
          accessToken = token;
        }
      } catch (authError: any) {
        return res.status(500).json({
          jsonrpc: "2.0",
          id: req.body.id || null,
          error: { code: -32001, message: `OAuth2 Token Verification failed: ${authError.message}` }
        });
      }
    }

    const { method, params, id } = req.body;

    try {
      if (method === "initialize") {
        return res.json({
          jsonrpc: "2.0",
          id,
          result: {
            protocolVersion: "2024-11-05",
            capabilities: {
              tools: {}
            },
            serverInfo: {
              name: "neo4j-mcp-server",
              version: "1.0.0"
            }
          }
        });
      }

      if (method === "notifications/initialized") {
        console.error("Agent signalized initialization complete.");
        return res.status(200).send();
      }

      // Generischer Handler für Benachrichtigungen (haben kein 'id')
      if (id === undefined || id === null) {
        console.error(`Received notification: ${method}`);
        return res.status(200).send();
      }

      if (method === "list_tools" || (method === "tools/list")) {
        return res.json({ jsonrpc: "2.0", id, result: { tools } });
      }

      if (method === "call_tool" || (method === "tools/call")) {
        let result;
        switch (params.name) {
          case "execute_cypher":
            result = await handleExecuteCypher(params.arguments, 'WRITE');
            break;
          case "read_neo4j_cypher":
            result = await handleExecuteCypher(params.arguments, 'READ');
            break;
          case "write_neo4j_cypher":
            result = await handleExecuteCypher(params.arguments, 'WRITE');
            break;
          case "get_neo4j_schema":
            result = await handleGetSchema();
            break;
          default:
            return res.status(404).json({
              jsonrpc: "2.0",
              id,
              error: { code: -32601, message: `Tool not found: ${params.name}` }
            });
        }
        return res.json({ jsonrpc: "2.0", id, result });
      }

      res.status(404).json({
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: `Method not found: ${method}` }
      });
    } catch (error: any) {
      res.status(500).json({
        jsonrpc: "2.0",
        id,
        error: { code: -32603, message: error.message }
      });
    }
  });

  app.listen(PORT, () => {
    console.error(`Neo4j MCP Server (HTTP REST) running on port ${PORT}`);
    console.error(`MCP Endpoint: http://localhost:${PORT}/mcp`);
  });
}

main().catch((error) => {
  console.error("Fatal error in main():", error);
  process.exit(1);
});
