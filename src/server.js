'use strict';

/**
 * The shared frame of a kapio MCP server: HTTP, CORS, health, sessions, SSE,
 * OAuth discovery (RFC 9728), sign-in through Mosaic and one log line per tool
 * call. A server brings only its handler with the tools.
 *
 * Built from the six `server.js` copies of kapio-*-mcp (ticket 188b); the
 * behaviour those servers had stays unless the ticket changes it:
 *   - the deliberate 404 on `/.well-known/oauth-*` is gone, discovery answers
 *   - a 401 carries `WWW-Authenticate: Bearer resource_metadata="…"`
 *   - `?token=` only when the server opts in with `allowQueryToken`
 */

const http = require('node:http');
const crypto = require('node:crypto');
const { createJwksClient, looksLikeJwt, verifyAccessToken } = require('./verify');
const { matchToken, normalizeTokens } = require('./tokens');

const UA_MAX_BYTES = 120;
const MAX_BODY_BYTES = 4 * 1024 * 1024;

class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigError';
  }
}

function requireUrl(name, value) {
  if (!value) throw new ConfigError(`${name} is not set - refusing to start without the Mosaic sign-in`);
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new ConfigError(`${name} is not a URL`);
  }
  if (url.protocol !== 'https:' && url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') {
    throw new ConfigError(`${name} must use https`);
  }
  return value.replace(/\/+$/, '');
}

function capBytes(value, max) {
  const buf = Buffer.from(String(value || ''), 'utf8');
  if (buf.length <= max) return buf.toString('utf8');
  // Cut on a character boundary: decoding a partial sequence yields U+FFFD.
  return buf.subarray(0, max).toString('utf8').replace(/\uFFFD+$/, '');
}

function defaultLog(line) {
  process.stdout.write(`${JSON.stringify(line)}\n`);
}

/** A token entry without its secret `value` — the handler gets `instances`/`write`, never the token itself. */
function scopeOf(entry) {
  const { value, ...rest } = entry;
  return rest;
}

/**
 * @param {object} options
 * @param {string} options.service              name in health and log, e.g. `kapio-harvest-mcp`
 * @param {string} [options.version]            server version for health
 * @param {string} [options.protocol]           MCP protocol version for health
 * @param {{ handleRequest(request: object, sessionId?: string, identity?: object): Promise<object|null> }} options.handler
 * @param {() => object} [options.extraHealth]  service fields merged into `/health`
 * @param {Array<{ name: string, value: string, instances?: string[]|'*', write?: boolean }>} [options.tokens]
 * @param {boolean} [options.allowQueryToken]   accept `?token=` for the static tokens (transition only)
 * @param {string} [options.issuer]             defaults to env OAUTH_ISSUER
 * @param {string} [options.resource]           defaults to env MCP_RESOURCE
 * @param {string[]} [options.allowedOrigins]   defaults to env ALLOWED_ORIGINS or https://claude.ai
 * @param {object} [options.jwks]               JWKS client or `{ keys }`; defaults to `${issuer}/jwks`
 * @param {(line: object) => void} [options.log]
 * @param {NodeJS.ProcessEnv} [options.env]
 * @throws {ConfigError} when issuer or resource is missing — the caller exits
 */
function createMcpServer(options) {
  const o = options || {};
  const env = o.env || process.env;
  if (!o.service) throw new ConfigError('service is required');
  if (!o.handler || typeof o.handler.handleRequest !== 'function') throw new ConfigError('handler.handleRequest is required');

  const issuer = requireUrl('OAUTH_ISSUER', o.issuer ?? env.OAUTH_ISSUER);
  const resource = requireUrl('MCP_RESOURCE', o.resource ?? env.MCP_RESOURCE);
  const resourceUrl = new URL(resource);
  const metadataPath = `/.well-known/oauth-protected-resource${resourceUrl.pathname === '/' ? '' : resourceUrl.pathname}`;
  const metadataUrl = `${resourceUrl.origin}${metadataPath}`;
  const jwks = o.jwks || createJwksClient({ uri: `${issuer}/jwks` });
  const staticWays = normalizeTokens(o.tokens);
  const queryWayOpen = o.allowQueryToken === true;
  const allowedOrigins = o.allowedOrigins
    || (env.ALLOWED_ORIGINS || 'https://claude.ai').split(',').map((s) => s.trim()).filter(Boolean);
  const log = o.log || defaultLog;
  const handler = o.handler;
  const sessions = new Map();

  const metadata = {
    resource,
    authorization_servers: [issuer],
    bearer_methods_supported: ['header'],
    resource_name: o.service
  };

  /** Who is calling, or `{ error }`. Never throws. */
  async function identify(req, url) {
    const auth = req.headers.authorization || '';
    const bearer = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
    const fromQuery = url.searchParams.get('token') || '';

    if (bearer) {
      const entry = matchToken(bearer, staticWays);
      if (entry) return { via: entry.name, scope: scopeOf(entry), query: false };
      if (!looksLikeJwt(bearer)) return { error: 'invalid_token' };
      try {
        const claims = await verifyAccessToken(bearer, { issuer, resource, jwks });
        return { via: 'oauth', email: claims.email, sub: claims.sub, azp: claims.azp, scope: claims.scope };
      } catch (err) {
        return { error: 'invalid_token', reason: err.reason || 'error' };
      }
    }
    if (fromQuery && queryWayOpen) {
      const entry = matchToken(fromQuery, staticWays);
      if (entry) return { via: entry.name, scope: scopeOf(entry), query: true };
      return { error: 'invalid_token' };
    }
    return { error: fromQuery ? 'invalid_request' : null };
  }

  function unauthorized(res, error) {
    let challenge = `Bearer resource_metadata="${metadataUrl}"`;
    if (error) challenge += `, error="${error}"`;
    res.writeHead(401, { 'Content-Type': 'application/json', 'WWW-Authenticate': challenge });
    res.end(JSON.stringify({ error: 'Unauthorized', message: 'Sign in through Mosaic or send a Bearer token' }));
  }

  function logCall(request, result, identity, req) {
    if (!request || request.method !== 'tools/call') return;
    const failed = !result || result.error || (result.result && result.result.isError === true);
    const line = {
      ts: new Date().toISOString(),
      service: o.service,
      event: 'tools/call',
      tool: request.params && typeof request.params.name === 'string' ? request.params.name : null,
      via: identity.via,
      ok: !failed
    };
    if (identity.via === 'oauth') {
      line.email = identity.email ?? null;
      line.sub = identity.sub ?? null;
      line.azp = identity.azp ?? null;
    } else {
      line.query = identity.query === true;
      line.ua = capBytes(req.headers['user-agent'], UA_MAX_BYTES);
    }
    try {
      log(line);
    } catch {
      // Logging must never break the call.
    }
  }

  const server = http.createServer(async (req, res) => {
    const origin = req.headers.origin;
    if (origin && allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept, Authorization, Mcp-Session-Id, Mcp-Protocol-Version');
    res.setHeader('Access-Control-Expose-Headers', 'Mcp-Session-Id, WWW-Authenticate');

    let url;
    try {
      url = new URL(req.url, 'http://localhost');
    } catch {
      res.writeHead(400);
      res.end();
      return;
    }
    const pathname = url.pathname;

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    if ((pathname === '/' || pathname === '/health') && req.method === 'GET'
      && !(req.headers.accept || '').includes('text/event-stream')) {
      let extra = {};
      try {
        extra = o.extraHealth ? o.extraHealth() || {} : {};
      } catch {
        extra = {};
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'ok',
        service: o.service,
        ...(o.protocol && { protocol: o.protocol }),
        ...(o.version && { version: o.version }),
        auth: { oauth: true, issuer, resource, query: queryWayOpen },
        ...extra
      }));
      return;
    }

    if (req.method === 'GET' && (pathname === '/.well-known/oauth-protected-resource' || pathname === metadataPath)) {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'max-age=300' });
      res.end(JSON.stringify(metadata));
      return;
    }

    const isMcpEndpoint = pathname === '/mcp' || pathname === '/sse' || pathname === '/';
    if (!isMcpEndpoint) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
      return;
    }

    const identity = await identify(req, url);
    if (identity.error !== undefined) {
      unauthorized(res, identity.error);
      return;
    }

    if (req.method === 'POST') {
      const wantsSSE = (req.headers.accept || '').includes('text/event-stream');
      let sessionId = req.headers['mcp-session-id'];
      const chunks = [];
      let size = 0;
      let tooLarge = false;
      req.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          tooLarge = true;
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', async () => {
        if (tooLarge) {
          res.writeHead(413, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Request too large' } }));
          return;
        }
        let request;
        try {
          request = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        } catch (e) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: `Parse error: ${e.message}` } }));
          return;
        }
        try {
          if (request.method === 'initialize') {
            sessionId = crypto.randomUUID();
            sessions.set(sessionId, { created: Date.now() });
          }
          const result = await handler.handleRequest(request, sessionId, identity);
          logCall(request, result, identity, req);

          if (result === null || result === undefined) {
            res.writeHead(202);
            res.end();
            return;
          }
          const headers = sessionId ? { 'Mcp-Session-Id': sessionId } : {};
          if (wantsSSE) {
            res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive', ...headers });
            res.write(`data: ${JSON.stringify(result)}\n\n`);
            res.end();
          } else {
            res.writeHead(200, { 'Content-Type': 'application/json', ...headers });
            res.end(JSON.stringify(result));
          }
        } catch {
          logCall(request, null, identity, req);
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ jsonrpc: '2.0', id: request.id ?? null, error: { code: -32603, message: 'Internal error' } }));
        }
      });
      return;
    }

    if (req.method === 'GET' && (req.headers.accept || '').includes('text/event-stream')) {
      const sessionId = crypto.randomUUID();
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive', 'Mcp-Session-Id': sessionId });
      res.write(`event: endpoint\ndata: ${resourceUrl.origin}/mcp\n\n`);
      const keepAlive = setInterval(() => res.write(': keepalive\n\n'), 15000);
      sessions.set(sessionId, { keepAlive });
      req.on('close', () => {
        clearInterval(keepAlive);
        sessions.delete(sessionId);
      });
      return;
    }

    if (req.method === 'DELETE') {
      const sessionId = req.headers['mcp-session-id'];
      const session = sessionId && sessions.get(sessionId);
      if (session) {
        if (session.keepAlive) clearInterval(session.keepAlive);
        sessions.delete(sessionId);
      }
      res.writeHead(204);
      res.end();
      return;
    }

    res.writeHead(405, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Method not allowed' }));
  });

  return {
    server,
    issuer,
    resource,
    metadataUrl,
    /** What a registrar announces to Mosaic (ticket 201b); no secrets. */
    describe() {
      return { service: o.service, version: o.version ?? null, protocol: o.protocol ?? null, resource, issuer, metadataUrl };
    },
    /** @returns {Promise<import('node:net').AddressInfo>} */
    listen(port) {
      return new Promise((resolve) => server.listen(port, () => resolve(server.address())));
    },
    close() {
      for (const s of sessions.values()) if (s.keepAlive) clearInterval(s.keepAlive);
      sessions.clear();
      server.closeAllConnections?.();
      return new Promise((resolve) => server.close(() => resolve()));
    }
  };
}

module.exports = { ConfigError, createMcpServer };
