import assert from 'node:assert/strict';
import test from 'node:test';

import { AgentEnvelopeApiError, AgentEnvelopeClient } from 'agent-envelope-sdk/client';

const BASE = 'https://jemdjwteae.execute-api.us-east-1.amazonaws.com/v1';

test('getStoredDelegate uses explicit client subpath and mocked hosted API', async () => {
    const originalFetch = globalThis.fetch;
    const calls = [];
    globalThis.fetch = async (url, init) => {
        calls.push({ url, init });
        return {
            ok: true,
            async json() {
                return { type: 'agentenvelope.mintDelegate', delegateId: 'ae-delegate-test' };
            },
        };
    };

    try {
        const client = new AgentEnvelopeClient({ apiKey: 'test-key' });
        const delegate = await client.getStoredDelegate('ae-delegate-test');

        assert.deepEqual(delegate, { type: 'agentenvelope.mintDelegate', delegateId: 'ae-delegate-test' });
        assert.equal(calls.length, 1);
        assert.equal(calls[0].url, `${BASE}/sovereign/delegates/ae-delegate-test`);
        assert.equal(calls[0].init.method, 'GET');
        assert.deepEqual(calls[0].init.headers, { 'Content-Type': 'application/json', 'X-Api-Key': 'test-key' });
    } finally {
        globalThis.fetch = originalFetch;
    }
});

test('client rejects invalid delegate ids before fetch', async () => {
    const originalFetch = globalThis.fetch;
    let called = false;
    globalThis.fetch = async () => {
        called = true;
        throw new Error('fetch should not be called');
    };

    try {
        const client = new AgentEnvelopeClient({ apiKey: 'test-key' });
        await assert.rejects(() => client.getStoredDelegate('../nope'), /delegateId is invalid/);
        assert.equal(called, false);
    } finally {
        globalThis.fetch = originalFetch;
    }
});

test('client wraps hosted errors without making hosted authority required', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => ({
        ok: false,
        status: 403,
        async json() {
            return { code: 'forbidden', message: 'not allowed', legitimacy: { decision: 'denied' } };
        },
    });

    try {
        const client = new AgentEnvelopeClient({ apiKey: 'test-key' });
        await assert.rejects(
            () => client.getStoredDelegate('ae-delegate-test'),
            (err) => {
                assert.equal(err instanceof AgentEnvelopeApiError, true);
                assert.equal(err.status, 403);
                assert.equal(err.code, 'forbidden');
                assert.deepEqual(err.legitimacy, { decision: 'denied' });
                return true;
            },
        );
    } finally {
        globalThis.fetch = originalFetch;
    }
});
