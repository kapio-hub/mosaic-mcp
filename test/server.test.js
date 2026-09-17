'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { createMcpServer, ConfigError } = require('../src');

const ISSUER = 'https://mosaic.example.com/api/auth';
const RESOURCE = 'https://harvest-mcp.example.com/mcp';
const EMERGENCY = crypto.randomBytes(32).toString('hex');

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const jwks = { keys: [{ ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'EdDSA' }] };

function mint(over = {}) {
  const now = Math.floor(Date.now() / 1000);
  const h = Buffer.from(JSON.stringify({ alg: 'EdDSA', kid: 'k1' })).toString('base64url');
  const p = Buffer.from(JSON.stringify({
    iss: ISSUER, aud: RESOURCE, sub: 'u1', email: 'martin@example.com', azp: 'claude', exp: now + 300, iat: now, ...over
  })).toString('base64url');
  return `${h}.${p}.${crypto.sign(null, Buffer.from(`${h}.${p}`), privateKey).toString('base64url')}`;
}

async function start(extra = {}) {
  const lines = [];
  const seen = [];
  const handler = {
    async handleRequest(request, sessionId, identity) {
      seen.push({ request, sessionId, identity });
      if (request.method === 'initialize') return { jsonrpc: '2.0', id: request.id, result: { protocolVersion: '2025-11-25' } };
      if (request.method === 'tools/call') {
        const isError = request.params.name === 'fails';
        return { jsonrpc: '2.0', id: request.id, result: { content: [{ type: 'text', text: 'secret result' }], isError } };
      }
      return null;
    }
  };
  const app = createMcpServer({
    service: 'test-mcp', version: '1.2.3', protocol: '2025-11-25', handler, jwks,
    env: { OAUTH_ISSUER: ISSUER, MCP_RESOURCE: RESOURCE },
    tokens: [{ name: 'notzugang', value: EMERGENCY }],
    log: (l) => lines.push(l),
    ...extra
  });
  const { port } = await app.listen(0);
  const base = `http://127.0.0.1:${port}`;
  return { app, base, lines, seen };
}

const call = (name, args = { password: 'hunter2' }) => JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name, arguments: args } });
const post = (base, path, body, headers = {}) =>
  fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body });

test('refuses to start without OAUTH_ISSUER or MCP_RESOURCE', () => {
  const handler = { handleRequest: async () => null };
  assert.throws(() => createMcpServer({ service: 's', handler, env: { MCP_RESOURCE: RESOURCE } }), (e) => e instanceof ConfigError && /OAUTH_ISSUER/.test(e.message));
  assert.throws(() => createMcpServer({ service: 's', handler, env: { OAUTH_ISSUER: ISSUER } }), (e) => e instanceof ConfigError && /MCP_RESOURCE/.test(e.message));
  assert.throws(() => createMcpServer({ service: 's', handler, env: { OAUTH_ISSUER: 'http://mosaic.example.com', MCP_RESOURCE: RESOURCE } }), /https/);
});

test('discovery answers on both paths with resource and the one issuer', async (t) => {
  const { app, base } = await start();
  t.after(() => app.close());
  for (const p of ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp']) {
    const res = await fetch(`${base}${p}`);
    assert.strictEqual(res.status, 200, p);
    assert.deepStrictEqual(await res.json(), {
      resource: RESOURCE, authorization_servers: [ISSUER], bearer_methods_supported: ['header'], resource_name: 'test-mcp'
    });
  }
  const other = await fetch(`${base}/.well-known/oauth-authorization-server`);
  assert.strictEqual(other.status, 404);
  assert.deepStrictEqual(app.describe(), {
    service: 'test-mcp', version: '1.2.3', protocol: '2025-11-25', resource: RESOURCE, issuer: ISSUER,
    metadataUrl: 'https://harvest-mcp.example.com/.well-known/oauth-protected-resource/mcp'
  });
});

test('health stays open and tells the auth mode', async (t) => {
  const { app, base } = await start({ extraHealth: () => ({ harvest: true }) });
  t.after(() => app.close());
  const res = await fetch(`${base}/health`);
  const body = await res.json();
  assert.strictEqual(body.status, 'ok');
  assert.strictEqual(body.harvest, true);
  assert.deepStrictEqual(body.auth, { oauth: true, issuer: ISSUER, resource: RESOURCE, query: false });
});

test('POST /mcp without sign-in is 401 with resource_metadata', async (t) => {
  const { app, base, seen } = await start();
  t.after(() => app.close());
  const res = await post(base, '/mcp', call('x'));
  assert.strictEqual(res.status, 401);
  assert.strictEqual(res.headers.get('www-authenticate'),
    'Bearer resource_metadata="https://harvest-mcp.example.com/.well-known/oauth-protected-resource/mcp"');
  assert.strictEqual(seen.length, 0);
});

test('a Mosaic token reaches the handler with the person and logs one line without arguments', async (t) => {
  const { app, base, lines, seen } = await start();
  t.after(() => app.close());
  const res = await post(base, '/mcp', call('harvest_list_projects'), { authorization: `Bearer ${mint()}` });
  assert.strictEqual(res.status, 200);
  assert.deepStrictEqual(seen[0].identity, { via: 'oauth', email: 'martin@example.com', sub: 'u1', azp: 'claude', scope: undefined });
  assert.strictEqual(lines.length, 1);
  const line = lines[0];
  assert.deepStrictEqual(Object.keys(line).sort(), ['azp', 'email', 'event', 'ok', 'service', 'sub', 'tool', 'ts', 'via']);
  assert.strictEqual(line.email, 'martin@example.com');
  assert.strictEqual(line.tool, 'harvest_list_projects');
  assert.strictEqual(line.ok, true);
  assert.ok(!JSON.stringify(line).includes('hunter2') && !JSON.stringify(line).includes('secret result'));

  await post(base, '/mcp', call('fails'), { authorization: `Bearer ${mint()}` });
  assert.strictEqual(lines[1].ok, false);
});

test('non tool calls write no log line', async (t) => {
  const { app, base, lines } = await start();
  t.after(() => app.close());
  const res = await post(base, '/mcp', JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }), { authorization: `Bearer ${mint()}` });
  assert.strictEqual(res.status, 200);
  assert.ok(res.headers.get('mcp-session-id'));
  assert.strictEqual(lines.length, 0);
});

test('cross check: a token for another server is refused', async (t) => {
  const { app, base, seen } = await start();
  t.after(() => app.close());
  const res = await post(base, '/mcp', call('x'), { authorization: `Bearer ${mint({ aud: 'https://n8n-mcp.example.com/mcp' })}` });
  assert.strictEqual(res.status, 401);
  assert.match(res.headers.get('www-authenticate'), /error="invalid_token"/);
  assert.strictEqual(seen.length, 0);
});

test('expired, foreign-issuer and tampered tokens are refused over HTTP', async (t) => {
  const { app, base } = await start();
  t.after(() => app.close());
  const now = Math.floor(Date.now() / 1000);
  const good = mint();
  const tampered = `${good.split('.')[0]}.${Buffer.from(JSON.stringify({ iss: ISSUER, aud: RESOURCE, email: 'x@example.com', exp: now + 300 })).toString('base64url')}.${good.split('.')[2]}`;
  for (const token of [mint({ exp: now - 120 }), mint({ iss: 'https://evil.example.com/api/auth' }), tampered, 'garbage']) {
    const res = await post(base, '/mcp', call('x'), { authorization: `Bearer ${token}` });
    assert.strictEqual(res.status, 401);
  }
});

test('emergency token by header is logged as notzugang', async (t) => {
  const { app, base, lines, seen } = await start();
  t.after(() => app.close());
  const res = await post(base, '/mcp', call('x'), { authorization: `Bearer ${EMERGENCY}`, 'user-agent': 'ü'.repeat(100) });
  assert.strictEqual(res.status, 200);
  assert.strictEqual(seen[0].identity.via, 'notzugang');
  assert.strictEqual(lines[0].via, 'notzugang');
  assert.strictEqual(lines[0].query, false);
  assert.ok(Buffer.byteLength(lines[0].ua) <= 120);
  assert.ok(!('email' in lines[0]));
  assert.ok(!JSON.stringify(lines).includes(EMERGENCY));
});

test('query token is refused unless the server allows it', async (t) => {
  const closed = await start();
  t.after(() => closed.app.close());
  const res = await post(closed.base, `/mcp?token=${EMERGENCY}`, call('x'));
  assert.strictEqual(res.status, 401);
  assert.match(res.headers.get('www-authenticate'), /error="invalid_request"/);
  assert.strictEqual(closed.seen.length, 0);

  const open = await start({ allowQueryToken: true });
  t.after(() => open.app.close());
  const ok = await post(open.base, `/mcp?token=${EMERGENCY}`, call('x'));
  assert.strictEqual(ok.status, 200);
  assert.strictEqual(open.lines[0].query, true);
  const wrong = await post(open.base, '/mcp?token=nope', call('x'));
  assert.strictEqual(wrong.status, 401);
  const jwtInQuery = await post(open.base, `/mcp?token=${mint()}`, call('x'));
  assert.strictEqual(jwtInQuery.status, 401, 'Mosaic tokens only by header');
});

test('handler failure answers 500 and still logs the call as failed', async (t) => {
  const lines = [];
  const app = createMcpServer({
    service: 'boom', jwks, env: { OAUTH_ISSUER: ISSUER, MCP_RESOURCE: RESOURCE }, log: (l) => lines.push(l),
    handler: { handleRequest: async () => { throw new Error('inner detail'); } }
  });
  const { port } = await app.listen(0);
  t.after(() => app.close());
  const res = await post(`http://127.0.0.1:${port}`, '/mcp', call('x'), { authorization: `Bearer ${mint()}` });
  assert.strictEqual(res.status, 500);
  assert.ok(!(await res.text()).includes('inner detail'));
  assert.strictEqual(lines[0].ok, false);
});
