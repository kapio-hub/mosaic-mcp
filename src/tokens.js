'use strict';

/**
 * Static token ways next to the Mosaic login (ticket 188b, F2/F3).
 *
 * A token entry is `{ name, value, instances?, write? }`. `name` is what the
 * call log shows in `via`; the emergency token (`MCP_ACCESS_TOKEN`) is named
 * `notzugang`. The server decides what `instances` and `write` mean — the kit
 * only finds the entry.
 *
 * The comparison runs against every candidate without leaving early and on
 * fixed-length digests, so neither the position of the matching token nor the
 * length of a candidate is measurable (pattern `tokenGleich`/`scopeVon` from
 * kapio-n8n-mcp, `requireJobToken` in Mosaic ticket 059).
 */

const crypto = require('node:crypto');

function digest(value) {
  return crypto.createHash('sha256').update(String(value)).digest();
}

/**
 * @param {string} given the presented token
 * @param {Array<{ name: string, value: string }>} tokens
 * @returns {object|null} the matching entry
 */
function matchToken(given, tokens) {
  if (!given || !Array.isArray(tokens) || tokens.length === 0) return null;
  const presented = digest(given);
  let match = null;
  for (const entry of tokens) {
    if (!entry || !entry.value) continue;
    if (crypto.timingSafeEqual(presented, digest(entry.value))) match = entry;
  }
  return match;
}

/** Drops entries without a value and refuses duplicate names or values. */
function normalizeTokens(tokens) {
  const list = (tokens || []).filter((t) => t && t.value);
  const names = new Set();
  const values = new Set();
  for (const t of list) {
    if (!t.name) throw new Error('token entry without name');
    if (t.name === 'oauth') throw new Error('token name "oauth" is reserved for the Mosaic login');
    if (names.has(t.name)) throw new Error(`token name "${t.name}" is used twice`);
    if (values.has(t.value)) throw new Error(`token "${t.name}" has the same value as another entry`);
    names.add(t.name);
    values.add(t.value);
  }
  return list;
}

module.exports = { matchToken, normalizeTokens };
