#!/usr/bin/env node
'use strict';

/**
 * Writes fixtures/verify-cases.json: the token check cases shared by this kit
 * and the Python agent template (ticket 188d). Every case carries the token,
 * the verification input and the expected outcome, so both implementations
 * run the same list. The private keys are thrown away after signing.
 *
 * Rerun only on purpose — new keys change every token, and 188d pins the file
 * by its SHA-256 (fixtures/verify-cases.json.sha256).
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const NOW = 1790000000; // fixed clock for every case, seconds
const ISSUER = 'https://mosaic.example.com/api/auth';
const RESOURCE = 'https://harvest-mcp.example.com/mcp';

const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');

function keypair(kid) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' });
  return { kid, privateKey, jwk: { ...jwk, alg: 'EdDSA', kid } };
}

function sign(key, header, payload) {
  const input = `${b64(header)}.${b64(payload)}`;
  const sig = crypto.sign(null, Buffer.from(input), key.privateKey).toString('base64url');
  return `${input}.${sig}`;
}

const main = keypair('fixture-main');
const stranger = keypair('fixture-stranger');

const claims = (over = {}) => ({
  iss: ISSUER,
  aud: RESOURCE,
  sub: 'user-1',
  email: 'person@example.com',
  azp: 'https://claude.ai/oauth/mcp-oauth-client-metadata',
  scope: 'openid email',
  iat: NOW - 30,
  exp: NOW + 270,
  ...over
});
const header = (over = {}) => ({ alg: 'EdDSA', kid: main.kid, ...over });

const valid = sign(main, header(), claims());
const [vh, vp] = valid.split('.');
const flipped = Buffer.from(valid.split('.')[2], 'base64url');
flipped[0] ^= 0xff;

const cases = [
  { name: 'valid', token: valid, expect: { ok: true, email: 'person@example.com', sub: 'user-1' } },
  { name: 'valid-aud-array', token: sign(main, header(), claims({ aud: ['https://other.example.com/mcp', RESOURCE] })), expect: { ok: true } },
  { name: 'valid-exp-within-leeway', token: sign(main, header(), claims({ exp: NOW - 59 })), expect: { ok: true } },
  { name: 'valid-nbf-within-leeway', token: sign(main, header(), claims({ nbf: NOW + 59 })), expect: { ok: true } },
  { name: 'wrong-aud', token: sign(main, header(), claims({ aud: 'https://n8n-mcp.example.com/mcp' })), expect: { ok: false, reason: 'aud' } },
  { name: 'wrong-iss', token: sign(main, header(), claims({ iss: 'https://other-mosaic.example.com/api/auth' })), expect: { ok: false, reason: 'iss' } },
  { name: 'iss-trailing-slash', token: sign(main, header(), claims({ iss: `${ISSUER}/` })), expect: { ok: false, reason: 'iss' } },
  { name: 'expired', token: sign(main, header(), claims({ exp: NOW - 61 })), expect: { ok: false, reason: 'exp' } },
  { name: 'no-exp', token: sign(main, header(), claims({ exp: undefined })), expect: { ok: false, reason: 'exp' } },
  { name: 'nbf-in-future', token: sign(main, header(), claims({ nbf: NOW + 61 })), expect: { ok: false, reason: 'nbf' } },
  { name: 'bad-signature', token: `${vh}.${vp}.${flipped.toString('base64url')}`, expect: { ok: false, reason: 'signature' } },
  { name: 'payload-swapped', token: `${vh}.${b64(claims({ email: 'someone-else@example.com' }))}.${valid.split('.')[2]}`, expect: { ok: false, reason: 'signature' } },
  { name: 'signed-by-unknown-key-with-known-kid', token: sign({ ...stranger, kid: main.kid }, header(), claims()), expect: { ok: false, reason: 'signature' } },
  { name: 'alg-hs256', token: `${b64(header({ alg: 'HS256' }))}.${vp}.${crypto.createHmac('sha256', 'x').update(`${b64(header({ alg: 'HS256' }))}.${vp}`).digest('base64url')}`, expect: { ok: false, reason: 'alg' } },
  { name: 'alg-none', token: `${b64(header({ alg: 'none' }))}.${vp}.AA`, expect: { ok: false, reason: 'alg' } },
  { name: 'unknown-kid', token: sign(stranger, header({ kid: stranger.kid }), claims()), expect: { ok: false, reason: 'kid' } },
  { name: 'no-kid', token: sign(main, { alg: 'EdDSA' }, claims()), expect: { ok: false, reason: 'kid' } },
  { name: 'malformed', token: 'not-a-jwt', expect: { ok: false, reason: 'malformed' } }
];

const out = {
  about: 'Shared token check cases, ticket 188b (Node kit) and 188d (Python agent template). Verify each token with issuer, resource and jwks below at now (seconds); expect.reason names the failing rule.',
  now: NOW,
  issuer: ISSUER,
  resource: RESOURCE,
  leewaySeconds: 60,
  jwks: { keys: [main.jwk] },
  cases
};

const dir = path.join(__dirname, '..', 'fixtures');
const file = path.join(dir, 'verify-cases.json');
const text = `${JSON.stringify(out, null, 2)}\n`;
fs.writeFileSync(file, text);
const sum = crypto.createHash('sha256').update(text).digest('hex');
fs.writeFileSync(`${file}.sha256`, `${sum}  verify-cases.json\n`);
console.log(`wrote ${cases.length} cases, sha256 ${sum}`);
