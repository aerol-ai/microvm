'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const CachePolicy = require('./index.js');

const now = Date.parse('2026-10-03T00:00:00Z');

function policyFor(resHeaders, { shared = true, ageMs = 10_000 } = {}) {
    const policy = new CachePolicy(
        { headers: { host: 'example.test' } },
        {
            status: 200,
            headers: { date: new Date(now).toUTCString(), ...resHeaders },
        },
        { shared },
    );
    policy.now = () => now + ageMs;
    return policy;
}

function request(cacheControl) {
    return {
        headers: { host: 'example.test', 'cache-control': cacheControl },
    };
}

test('max-stale cannot reuse a shared Set-Cookie response', () => {
    const policy = policyFor({
        'cache-control': 'max-age=60',
        'set-cookie': 'sid=other-user',
    });
    assert.equal(
        policy.satisfiesWithoutRevalidation(request('max-stale=999999')),
        false,
    );
});

test('max-stale cannot reuse a shared proxy-revalidate response', () => {
    const policy = policyFor({
        'cache-control': 'max-age=1, proxy-revalidate',
    });
    assert.equal(
        policy.satisfiesWithoutRevalidation(request('max-stale=999999')),
        false,
    );
});

test('max-stale cannot reuse a shared no-cache response', () => {
    const policy = policyFor({ 'cache-control': 'no-cache' }, { ageMs: 0 });
    assert.equal(
        policy.satisfiesWithoutRevalidation(request('max-stale=999999')),
        false,
    );
});

test('max-stale still reuses an ordinary expired response', () => {
    const policy = policyFor({ 'cache-control': 'max-age=1' });
    assert.equal(
        policy.satisfiesWithoutRevalidation(request('max-stale=999999')),
        true,
    );
});

test('public opt-in still allows a stale shared Set-Cookie response', () => {
    const policy = policyFor({
        'cache-control': 'public, max-age=1',
        'set-cookie': 'sid=other-user',
    });
    assert.equal(
        policy.satisfiesWithoutRevalidation(request('max-stale=999999')),
        true,
    );
});

test('a private cache may reuse its own stale Set-Cookie response', () => {
    const policy = policyFor(
        { 'cache-control': 'max-age=1', 'set-cookie': 'sid=self' },
        { shared: false },
    );
    assert.equal(
        policy.satisfiesWithoutRevalidation(request('max-stale=999999')),
        true,
    );
});

test('a fresh ordinary response is reusable without max-stale', () => {
    const policy = policyFor({ 'cache-control': 'max-age=60' }, { ageMs: 1000 });
    assert.equal(policy.satisfiesWithoutRevalidation(request('')), true);
});
