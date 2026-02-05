import neo4j from 'neo4j-driver';

export interface OAuthConfig {
  clientId: string;
  clientSecret: string;
  issuerUrl: string;
  scope?: string;
}

async function discoverTokenUrl(issuerUrl: string): Promise<string> {
  const configUrl = issuerUrl.endsWith('/') 
    ? `${issuerUrl}.well-known/openid-configuration`
    : `${issuerUrl}/.well-known/openid-configuration`;
  
  const response = await fetch(configUrl);
  if (!response.ok) {
    throw new Error(`Failed to discover OpenID configuration from ${configUrl}: ${response.statusText}`);
  }
  
  const config = await response.json() as { token_endpoint: string };
  if (!config.token_endpoint) {
    throw new Error(`No token_endpoint found in OpenID configuration at ${configUrl}`);
  }
  
  return config.token_endpoint;
}

export async function getAccessToken(config: OAuthConfig): Promise<string> {
  const tokenUrl = await discoverTokenUrl(config.issuerUrl);
  
  const params = new URLSearchParams();
  params.append('grant_type', 'client_credentials');
  params.append('client_id', config.clientId);
  params.append('client_secret', config.clientSecret);
  if (config.scope) {
    params.append('scope', config.scope);
  }

  const response = await fetch(tokenUrl, {
    method: 'POST',
    body: params,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to fetch access token: ${response.statusText} - ${errorText}`);
  }

  const data = await response.json() as { access_token: string };
  return data.access_token;
}

export async function verifyToken(config: OAuthConfig, token: string): Promise<boolean> {
  const tokenUrl = await discoverTokenUrl(config.issuerUrl);
  // Introspection Endpunkt ist oft tokenUrl + /introspection oder in der config.
  // Da wir OIDC Discovery nutzen, könnten wir ihn dort suchen.
  // Viele Provider (wie OneLogin) nutzen den Token-Endpunkt mit speziellen Parametern oder einen separaten Endpunkt.
  // Wir versuchen hier die Standard-Introspektion.
  const configUrl = config.issuerUrl.endsWith('/') 
    ? `${config.issuerUrl}.well-known/openid-configuration`
    : `${config.issuerUrl}/.well-known/openid-configuration`;
  
  const configResponse = await fetch(configUrl);
  const oidcConfig = await configResponse.json() as { introspection_endpoint?: string };
  const introspectionUrl = oidcConfig.introspection_endpoint || tokenUrl.replace('/token', '/token/introspection');

  const params = new URLSearchParams();
  params.append('token', token);
  // Manche Provider wollen client_id im Body, manche via Basic Auth
  params.append('client_id', config.clientId);
  params.append('client_secret', config.clientSecret);

  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json',
  };

  // Basic Auth hinzufügen (wird von OneLogin oft für Introspektion verlangt)
  const credentials = Buffer.from(`${config.clientId}:${config.clientSecret}`).toString('base64');
  headers['Authorization'] = `Basic ${credentials}`;

  console.error(`Verifying token against: ${introspectionUrl}`);
  const response = await fetch(introspectionUrl, {
    method: 'POST',
    body: params,
    headers: headers,
  });

  if (!response.ok) {
    const errText = await response.text();
    console.error(`Token verification failed at provider (${response.status}): ${errText}`);
    return false;
  }

  const data = await response.json() as { active: boolean };
  console.error(`Token introspection result: active=${data.active}`);
  return data.active === true;
}

export function createNeo4jDriver(uri: string, accessToken: string) {
  return neo4j.driver(uri, neo4j.auth.bearer(accessToken));
}

export function createNeo4jDriverWithBasic(uri: string, user: string, pass: string) {
  return neo4j.driver(uri, neo4j.auth.basic(user, pass));
}
