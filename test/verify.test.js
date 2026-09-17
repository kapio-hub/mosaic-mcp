'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { createJwksClient, verifyAccessToken, TokenError } = require('../src');

const fixtureFile = path.join(__dirname, '..', 'fixtures', 'verify-cases.json');
const fixtureText = fs.readFileSync(fixtureFile, 'utf8');
const fx = JSON.parse(fixtureText);
const at = () => fx.now * 1000;

test('fixture file matches its pinned checksum (188d relies on it)', () => {
  const pinned = fs.readFileSync(`${fixtureFile}.sha256`, 'utf8').split(/\s+/)[0];
  assert.strictEqual(crypto.createHash('sha256').update(fixtureText).digest('hex'), pinned);
});

for (const c of fx.cases) {
  test(`fixture case: ${c.name}`, async () => {
    const run = verifyAccessToken(c.token, { issuer: fx.issuer, resource: fx.resource, jwks: fx.jwks, now: at });
    if (c.expect.ok) {
      const claims = await run;
      if (c.expect.email) assert.strictEqual(claims.email, c.expect.email);
      if (c.expect.sub) assert.strictEqual(claims.sub, c.expect.sub);
    } else {
      await assert.rejects(run, (err) => err instanceof TokenError && err.reason === c.expect.reason);
    }
  });
}

test('fixtures cover every rule named in ticket 188b', () => {
  const reasons = new Set(fx.cases.filter((c) => !c.expect.ok).map((c) => c.expect.reason));
  for (const r of ['aud', 'iss', 'exp', 'nbf', 'signature', 'alg', 'kid']) assert.ok(reasons.has(r), `missing case for ${r}`);
});

function jwksServer() {
  const calls = [];
  let body = { keys: [] };
  return {
    calls,
    set(list) {
      body = { keys: list };
    },
    fetch: async (uri) => {
      calls.push(uri);
      return { ok: true, status: 200, json: async () => body };
    }
  };
}

test('unknown kid reloads the JWKS once, then refuses', async () => {
  const src = jwksServer();
  src.set(fx.jwks.keys);
  let clock = at();
  const jwks = createJwksClient({ uri: 'https://x/jwks', fetch: src.fetch, now: () => clock });
  const unknown = fx.cases.find((c) => c.name === 'unknown-kid');
  const valid = fx.cases.find((c) => c.name === 'valid');
  const opts = { issuer: fx.issuer, resource: fx.resource, jwks, now: () => clock };

  await verifyAccessToken(valid.token, opts);
  assert.strictEqual(src.calls.length, 1, 'first use loads');

  clock += 61_000;
  await assert.rejects(verifyAccessToken(unknown.token, opts), (e) => e.reason === 'kid');
  assert.strictEqual(src.calls.length, 2, 'unknown kid reloads exactly once');

  clock += 5_000;
  await assert.rejects(verifyAccessToken(unknown.token, opts), (e) => e.reason === 'kid');
  assert.strictEqual(src.calls.length, 2, 'no second reload within a minute');

  await verifyAccessToken(valid.token, { ...opts, now: () => at() });
  assert.strictEqual(src.calls.length, 2, 'known kid is served from cache');
});

test('a key rotated in at the issuer is found by the reload', async () => {
  const src = jwksServer();
  let clock = at();
  const jwks = createJwksClient({ uri: 'https://x/jwks', fetch: src.fetch, now: () => clock });
  const valid = fx.cases.find((c) => c.name === 'valid');
  const opts = { issuer: fx.issuer, resource: fx.resource, jwks, now: () => at() };

  await assert.rejects(verifyAccessToken(valid.token, opts), (e) => e.reason === 'kid');
  src.set(fx.jwks.keys);
  clock += 60_000;
  await verifyAccessToken(valid.token, opts);
  assert.strictEqual(src.calls.length, 2);
});

test('JWKS cache expires after ten minutes', async () => {
  const src = jwksServer();
  src.set(fx.jwks.keys);
  let clock = at();
  const jwks = createJwksClient({ uri: 'https://x/jwks', fetch: src.fetch, now: () => clock });
  await jwks.getKey('fixture-main');
  clock += 9 * 60_000;
  await jwks.getKey('fixture-main');
  assert.strictEqual(src.calls.length, 1);
  clock += 60_000;
  await jwks.getKey('fixture-main');
  assert.strictEqual(src.calls.length, 2);
});

test('issuer unreachable with nothing cached refuses, with a stale cache still verifies', async () => {
  let up = true;
  let clock = at();
  const fetch = async () => {
    if (!up) throw new Error('ECONNREFUSED');
    return { ok: true, status: 200, json: async () => fx.jwks };
  };
  const cold = createJwksClient({ uri: 'https://x/jwks', fetch: async () => { throw new Error('down'); }, now: () => clock });
  await assert.rejects(cold.getKey('fixture-main'), (e) => e.reason === 'jwks');

  const warm = createJwksClient({ uri: 'https://x/jwks', fetch, now: () => clock });
  assert.ok(await warm.getKey('fixture-main'));
  up = false;
  clock += 11 * 60_000;
  assert.ok(await warm.getKey('fixture-main'));
});

test('Mosaic weg: repeated calls on an expired cache do not repeat the fetch', async () => {
  const calls = [];
  let up = true;
  const fetch = async (uri) => {
    calls.push(uri);
    if (!up) throw new Error('ECONNREFUSED');
    return { ok: true, status: 200, json: async () => fx.jwks };
  };
  let clock = at();
  const jwks = createJwksClient({ uri: 'https://x/jwks', fetch, now: () => clock });
  assert.ok(await jwks.getKey('fixture-main'), 'primes the cache while Mosaic is up');
  assert.strictEqual(calls.length, 1);

  up = false;
  clock += 11 * 60_000; // TTL expired
  for (let i = 0; i < 20; i++) {
    assert.ok(await jwks.getKey('fixture-main'), 'the stale cache keeps verifying while Mosaic is down');
  }
  assert.strictEqual(calls.length, 2, '20 calls trigger one throttled reload attempt, not 20 fetches');
});

test('Mosaic hängt: a call ends with the cache key once the fetch times out', async () => {
  const calls = [];
  let primed = false;
  const fetch = (uri, opts) => {
    calls.push(uri);
    if (!primed) {
      primed = true;
      return Promise.resolve({ ok: true, status: 200, json: async () => fx.jwks });
    }
    // Simulates Mosaic hanging: the fetch never settles on its own, only the
    // abort from AbortSignal.timeout ends it — same as a real stuck request.
    return new Promise((_resolve, reject) => {
      opts.signal.addEventListener('abort', () => reject(new DOMException('The operation was aborted.', 'AbortError')), { once: true });
    });
  };
  let clock = at();
  const jwks = createJwksClient({ uri: 'https://x/jwks', fetch, now: () => clock, fetchTimeoutMs: 30 });
  assert.ok(await jwks.getKey('fixture-main'));

  clock += 11 * 60_000; // TTL expired, next getKey hits the hanging fetch
  const key = await jwks.getKey('fixture-main');
  assert.ok(key, 'the call resolves from the stale cache instead of hanging on the stuck fetch');
  assert.strictEqual(calls.length, 2);
});

test('JWKS entries with another algorithm are ignored', async () => {
  const valid = fx.cases.find((c) => c.name === 'valid');
  const rs256 = fx.jwks.keys.map((k) => ({ ...k, alg: 'RS256' }));
  await assert.rejects(
    verifyAccessToken(valid.token, { issuer: fx.issuer, resource: fx.resource, jwks: { keys: rs256 }, now: at }),
    (e) => e.reason === 'kid'
  );
});
