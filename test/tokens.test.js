'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { matchToken } = require('../src');
const { normalizeTokens } = require('../src/tokens');

const ways = [
  { name: 'notzugang', value: 'a'.repeat(64) },
  { name: 'read', value: 'b'.repeat(64) },
  { name: 'ecom', value: 'c'.repeat(20), instances: ['ecom'], write: true }
];

test('finds the matching entry', () => {
  assert.strictEqual(matchToken('b'.repeat(64), ways).name, 'read');
  assert.strictEqual(matchToken('c'.repeat(20), ways).name, 'ecom');
  assert.strictEqual(matchToken('d'.repeat(64), ways), null);
  assert.strictEqual(matchToken('', ways), null);
  assert.strictEqual(matchToken('a'.repeat(63), ways), null);
});

test('compares against every candidate, also when the first one matches', (t) => {
  let compares = 0;
  const original = crypto.timingSafeEqual;
  t.after(() => {
    crypto.timingSafeEqual = original;
  });
  crypto.timingSafeEqual = (a, b) => {
    compares += 1;
    assert.strictEqual(a.length, b.length, 'fixed-length digests, no length leak');
    return original(a, b);
  };
  matchToken('a'.repeat(64), ways);
  assert.strictEqual(compares, ways.length);
  compares = 0;
  matchToken('nothing', ways);
  assert.strictEqual(compares, ways.length);
});

test('refuses ambiguous token lists', () => {
  assert.throws(() => normalizeTokens([{ name: 'x', value: '1' }, { name: 'x', value: '2' }]), /twice/);
  assert.throws(() => normalizeTokens([{ name: 'x', value: '1' }, { name: 'y', value: '1' }]), /same value/);
  assert.throws(() => normalizeTokens([{ name: 'oauth', value: '1' }]), /reserved/);
  assert.deepStrictEqual(normalizeTokens([{ name: 'unset', value: '' }]), []);
});
