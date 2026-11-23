import assert from 'node:assert/strict';
import test from 'node:test';
import { session, snapshot } from '../fixtures/workspace.mjs';
import { browserTransport, Denied, InvalidCode } from '../src/lib/transport.ts';

test('browser transport scopes and bounds every auth and workspace request', async (t) => {
  const calls = [];
  let response;
  t.mock.method(globalThis, 'fetch', async (path, options) => {
    assert.equal(options.credentials, 'same-origin');
    assert.equal(options.mode, 'same-origin');
    assert.equal(options.cache, 'no-store');
    assert.equal(options.redirect, 'error');
    assert.equal(options.referrerPolicy, 'no-referrer');
    assert.equal(options.headers['X-OC-UI'], '1');
    calls.push({ path, options });
    return response;
  });

  const transport = browserTransport();
  const { signal } = new AbortController();
  response = Response.json(session());
  assert.deepEqual(await transport.session(signal), session());
  assert.equal(calls[0].options.signal, signal);

  response = Response.json(session());
  assert.deepEqual(await transport.exchange('synthetic'), session());
  assert.deepEqual(JSON.parse(calls[1].options.body), { code: 'synthetic' });
  assert.equal(calls[1].options.method, 'POST');
  assert.equal(calls[1].options.signal, undefined);

  response = new Response(null, { status: 204 });
  await transport.logout(session().csrf_token);
  assert.equal(calls[2].options.headers['X-OC-CSRF'], session().csrf_token);
  assert.equal(calls[2].options.signal, undefined);

  response = Response.json(snapshot());
  assert.deepEqual(await transport.load(signal), snapshot());
  assert.deepEqual(calls.map(({ path }) => path), [
    '/api/auth/session', '/api/auth/exchange', '/api/auth/logout', '/api/v1/workspace'
  ]);

  for (const status of [401, 403]) {
    response = new Response(null, { status });
    await assert.rejects(transport.load(signal), Denied);
  }
  response = new Response(null, { status: 401 });
  await assert.rejects(transport.exchange('invalid'), InvalidCode);
  response = new Response(null, { status: 205 });
  await assert.rejects(transport.logout(session().csrf_token));

  response = Response.json(session({ bad: true }));
  await assert.rejects(transport.session(signal));
  const { expires_in_ms, ...auth } = session();
  for (const invalid of [0, NaN, Infinity, 1_800_001, 1.5]) {
    response = Response.json({ ...auth, expires_in_ms: invalid });
    await assert.rejects(transport.session(signal));
  }
  response = new Response(JSON.stringify(session()).padEnd(4097), {
    headers: { 'Content-Type': 'application/json' }
  });
  await assert.rejects(transport.session(signal));
});

test('early response rejection cancels open bodies without waiting for cancellation', async (t) => {
  let response;
  let cancellations = 0;
  t.mock.method(globalThis, 'fetch', async () => response);
  const transport = browserTransport();
  const { signal } = new AbortController();
  const openBody = () => new ReadableStream({
    cancel() {
      ++cancellations;
      return new Promise(() => {});
    }
  });
  const verify = async (operation, errorType) => {
    const before = cancellations;
    let timeout;
    try {
      await assert.rejects(Promise.race([
        operation(),
        new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error('Cancellation stalled')), 500); })
      ]), errorType);
      assert.equal(cancellations, before + 1);
    } finally {
      clearTimeout(timeout);
    }
  };

  response = new Response(openBody(), { headers: { 'Content-Type': 'text/plain' } });
  await verify(() => transport.load(signal), /Invalid workspace response/);
  response = new Response(openBody(), { status: 403 });
  await verify(() => transport.session(signal), Denied);
  response = new Response(openBody(), { status: 401 });
  await verify(() => transport.exchange('synthetic'), InvalidCode);
  response = new Response(openBody(), { status: 200 });
  await verify(() => transport.logout(session().csrf_token), /Request did not complete/);
});
