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

test('a JSON body that is not an object gets 400 -32600 and the server stays up', async (t) => {
  const { app, base, seen } = await start();
  t.after(() => app.close());
  const auth = { authorization: `Bearer ${EMERGENCY}` };
  for (const body of ['null', '[]', '5', '"x"', 'true']) {
    const res = await post(base, '/mcp', body, auth);
    assert.strictEqual(res.status, 400, body);
    const json = await res.json();
    assert.strictEqual(json.error.code, -32600, body);
    assert.strictEqual(json.id, null);
  }
  assert.strictEqual(seen.length, 0, 'the handler never sees a non-object');
  const alive = await post(base, '/mcp', call('ok'), auth);
  assert.strictEqual(alive.status, 200);
});

test('a handler failure on a valid request still answers 500 with its id', async (t) => {
  const { app, base } = await start({ handler: { handleRequest: async () => { throw new Error('boom'); } } });
  t.after(() => app.close());
  const res = await post(base, '/mcp', call('x'), { authorization: `Bearer ${EMERGENCY}` });
  assert.strictEqual(res.status, 500);
  assert.strictEqual((await res.json()).id, 7);
});

test('a body over the limit is answered 413 and not read to the end', async (t) => {
  const { app, base, seen } = await start({ maxBodyBytes: 1024 });
  t.after(() => app.close());
  const auth = { authorization: `Bearer ${EMERGENCY}` };
  // Declared length over the limit: refused before any byte is read.
  const big = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'x', pad: 'a'.repeat(4096) } });
  const res = await post(base, '/mcp', big, auth);
  assert.strictEqual(res.status, 413);
  assert.strictEqual((await res.json()).error.code, -32600);
  // Chunked body without a length: cut off once the limit is crossed.
  const { port } = new URL(base);
  const status = await new Promise((resolve, reject) => {
    const req = require('node:http').request({ port, method: 'POST', path: '/mcp', headers: { 'content-type': 'application/json', ...auth } }, (r) => {
      r.resume();
      resolve(r.statusCode);
    });
    req.on('error', reject);
    req.write('{"a":"' + 'a'.repeat(2048));
    setTimeout(() => req.write('a'.repeat(2048)), 50);
    setTimeout(() => req.destroy(), 500);
  });
  assert.strictEqual(status, 413);
  assert.strictEqual(seen.length, 0);
  const small = await post(base, '/mcp', call('ok'), auth);
  assert.strictEqual(small.status, 200);
});

test('sessions expire and are capped', async (t) => {
  const { app, base } = await start({ maxSessions: 3, sessionTtlMs: 150 });
  t.after(() => app.close());
  const auth = { authorization: `Bearer ${EMERGENCY}` };
  const init = () => post(base, '/mcp', JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }), auth);
  for (let i = 0; i < 10; i++) await init();
  assert.strictEqual(app.sessionCount(), 3, 'cap holds, oldest evicted');
  await new Promise((r) => setTimeout(r, 250));
  await init();
  assert.strictEqual(app.sessionCount(), 1, 'expired sessions are dropped on the next initialize');
});

test('an open SSE stream is never evicted by the session cap or expiry', async (t) => {
  const { app, base } = await start({ maxSessions: 2, sessionTtlMs: 100 });
  t.after(() => app.close());
  const auth = { authorization: `Bearer ${EMERGENCY}` };
  const { port } = new URL(base);
  const sse = require('node:http').request({ port, method: 'GET', path: '/mcp', headers: { accept: 'text/event-stream', ...auth } });
  await new Promise((resolve, reject) => {
    sse.on('response', (r) => { r.resume(); resolve(); });
    sse.on('error', reject);
    sse.end();
  });
  t.after(() => sse.destroy());
  assert.strictEqual(app.sessionCount(), 1);
  const init = () => post(base, '/mcp', JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }), auth);
  for (let i = 0; i < 6; i++) await init();
  assert.strictEqual(app.sessionCount(), 2, 'cap evicts initialize sessions only, the SSE entry stays');
  await new Promise((r) => setTimeout(r, 200));
  await init();
  assert.strictEqual(app.sessionCount(), 2, 'expiry drops the old initialize session, the SSE entry stays');
  sse.destroy();
  await new Promise((r) => setTimeout(r, 100));
  assert.strictEqual(app.sessionCount(), 1, 'closing the stream removes its entry');
});
