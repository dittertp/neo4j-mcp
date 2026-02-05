# Neo4j MCP Server

Dieser Model Context Protocol (MCP) Server ermöglicht es, Cypher-Abfragen auf einer Neo4j-Datenbank auszuführen. Er unterstützt die Authentifizierung via OAuth2 (Client Credentials Flow) oder klassisch per Benutzername und Passwort.

## Features

- **execute_cypher**: Führt eine Cypher-Abfrage aus und gibt die Ergebnisse im JSON-Format zurück.
- **Authentifizierung**:
  - **OAuth2 Support**: Verwendet Bearer-Token zur Authentifizierung gegenüber Neo4j.
  - **Basic Auth Support**: Verwendet Benutzername und Passwort zur Authentifizierung.

## Installation

1. Repository klonen
2. Abhängigkeiten installieren:
   ```bash
   npm install
   ```
3. TypeScript kompilieren:
   ```bash
   npm run build
   ```

## Konfiguration

Der Server verwendet ein hybrides Authentifizierungsmodell:
1.  **OAuth2 (Agent-Level)**: Der MCP-Server autorisiert sich beim Start gegenüber einem Identity Provider. Dies dient als Sicherheitslayer für den Zugriff der Agenten auf den Server.
2.  **Basic Auth (Datenbank-Level)**: Die eigentliche Verbindung zur **Neo4j Community Edition** erfolgt über Benutzername und Passwort.

### Umgebungsvariablen (`.env`)

```env
# Neo4j Verbindung (Basic Auth für Community Edition)
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=ihr-passwort

# Agenten-Autorisierung (OAuth2 Client Credentials via OIDC Discovery)
OAUTH_ISSUER_URL=https://deine-subdomain.onelogin.com/oidc/2
OAUTH_CLIENT_ID=ihr-client-id
OAUTH_CLIENT_SECRET=ihr-client-secret
OAUTH_SCOPE=neo4j
```

### OIDC Discovery

Der Server nutzt nun **OpenID Connect Discovery**. Sie müssen nur noch die `OAUTH_ISSUER_URL` angeben. Der Server findet den Token-Endpunkt automatisch unter `{OAUTH_ISSUER_URL}/.well-known/openid-configuration`.

Beispiele für `OAUTH_ISSUER_URL`:
- **OneLogin:** `https://deine-subdomain.onelogin.com/oidc/2`
- **Auth0:** `https://deine-domain.auth0.com/`
- **Azure AD:** `https://login.microsoftonline.com/{tenant}/v2.0`

## Remote-Nutzung (HTTP REST)

Der Server läuft nun als Remote-Dienst über eine standardmäßige HTTP-Schnittstelle (JSON-RPC über POST). SSE wurde entfernt.

### Starten des Servers

1.  Build erstellen: `npm run build`
2.  Server starten: `node build/index.js`

Der Server lauscht standardmäßig auf Port `3000` (konfigurierbar über die Umgebungsvariable `PORT`).

### API Endpunkt

Der MCP-kompatible Endpunkt ist: `http://localhost:3000/mcp`

### OIDC Discovery Support

Der Server stellt nun automatisch einen Discovery-Endpunkt unter `http://localhost:3000/.well-known/openid-configuration` bereit. Dieser spiegelt die Konfiguration Ihres Identity Providers (OneLogin) wider. Dies hilft modernen Agenten, die Authentifizierungsanforderungen des Servers automatisch zu erkennen.

Beispiel für einen Tool-Aufruf via `curl` (inkl. Bearer Token):

```bash
# Holen Sie sich zuerst ein Token (Beispiel via curl vom IdP)
# TOKEN=$(curl -X POST OAUTH_TOKEN_URL -d "grant_type=client_credentials&client_id=...&client_secret=..." | jq -r .access_token)

curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer DEIN_ACCESS_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "call_tool",
    "params": {
      "name": "execute_cypher",
      "arguments": {
        "query": "MATCH (n) RETURN count(n) as count"
      }
    }
  }'
```

## Tools

### `get_neo4j_schema`
Gibt die Struktur der Datenbank zurück (Knoten-Labels, Beziehungstypen und deren Eigenschaften). Dies hilft dem Agenten, die Datenbank besser zu verstehen.

### `execute_cypher`
Führt eine beliebige Cypher-Abfrage aus (Lesen und Schreiben).

### `read_neo4j_cypher`
Führt eine schreibgeschützte Cypher-Abfrage aus.

### `write_neo4j_cypher`
Führt eine schreibende Cypher-Abfrage aus.

### Parameter für Cypher-Tools:
- `query` (string, erforderlich): Die auszuführende Cypher-Abfrage.
- `parameters` (object, optional): Parameter für die Abfrage.

## GitHub Actions

Das Projekt enthält einen GitHub Workflow, der bei jedem Push auf den `main`-Branch automatisch ein neues Docker-Image baut und in die GitHub Container Registry (GHCR) hochlädt.

### Image Name
Das Image ist unter folgendem Namen verfügbar:
`ghcr.io/<DEIN_GITHUB_USERNAME>/neo4j-mcp:latest`

## Docker

Sie können den MCP-Server auch als Docker-Container betreiben.

### 1. Image bauen

```bash
docker build -t neo4j-mcp-server .
```

### 2. Container starten

Da der Server Umgebungsvariablen benötigt, sollten Sie diese beim Start übergeben oder eine `.env`-Datei verwenden.

**Mit einer `.env`-Datei:**

```bash
docker run -p 3000:3000 --env-file .env neo4j-mcp-server
```

**Direkt über die Kommandozeile:**

```bash
docker run -p 3000:3000 \
  -e NEO4J_URI=bolt://host.docker.internal:7687 \
  -e NEO4J_USER=neo4j \
  -e NEO4J_PASSWORD=ihr-passwort \
  -e OAUTH_ISSUER_URL=https://deine-subdomain.onelogin.com/oidc/2 \
  -e OAUTH_CLIENT_ID=ihr-client-id \
  -e OAUTH_CLIENT_SECRET=ihr-client-secret \
  neo4j-mcp-server
```

### 3. Mit Docker Compose (Empfohlen)

Am einfachsten lässt sich der Server mit Docker Compose starten, da hierbei die `.env`-Datei automatisch geladen wird.

```bash
docker-compose up -d
```

Dies baut das Image (falls noch nicht geschehen) und startet den Container im Hintergrund. Der Port wird automatisch aus der `.env` (Variable `PORT`) übernommen oder nutzt standardmäßig `3000`.

*Hinweis: Wenn Neo4j lokal auf Ihrem Host läuft, verwenden Sie `host.docker.internal` anstelle von `localhost` in der `.env`, um die Datenbank aus dem Container heraus zu erreichen.*
