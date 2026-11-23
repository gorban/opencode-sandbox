import assert from 'node:assert/strict';
import test from 'node:test';
import { fixtureCode, session, snapshot } from '../fixtures/workspace.mjs';
import { Denied } from '../src/lib/transport.ts';
import { Workspace } from '../src/lib/workspace.ts';

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

const settle = () => new Promise((resolve) => setImmediate(resolve));

function fixture(t, options = {}) {
  let mono = 0;
  let wall = 0;
  let view;
  let generation = 0;
  const callbacks = [];
  const defaults = {
    async session() { throw new Denied(); },
    async exchange() { return session(++generation); },
    async logout() {},
    async load() { return snapshot(generation); },
    subscribe(signal, callback) {
      callbacks.push({ signal, callback });
      return () => {};
    }
  };
  const controller = new Workspace({ ...defaults, ...options }, (next) => { view = next; }, {
    monotonic: () => mono, wall: () => wall
  });
  t.after(() => controller.suspend());
  return { controller, callbacks, advance: (m, w = m) => { mono += m; wall += w; }, view: () => view };
}

test('old request and queued event are discarded after logout and a new exchange', async (t) => {
  const oldRead = deferred();
  let calls = 0;
  const h = fixture(t, {
    load() { return ++calls === 1 ? oldRead.promise : Promise.resolve(snapshot(2)); }
  });
  await h.controller.resume();
  await h.controller.exchange(fixtureCode);
  await h.controller.logout();
  assert.equal(h.view().snapshot, null);
  await h.controller.exchange(fixtureCode);
  await settle();
  assert.equal(h.view().snapshot.session_generation, 2);
  assert(h.callbacks[0].signal.aborted);
  oldRead.resolve(snapshot(1));
  h.callbacks[0].callback('refresh');
  h.callbacks[0].callback('session-ended');
  await settle();
  assert.equal(calls, 2);
  assert.equal(h.view().snapshot.session_generation, 2);
});

test('held auth replies past a pre-request deadline install no session', async (t) => {
  const auth = deferred();
  const exchange = deferred();
  const h = fixture(t, {
    session() { return auth.promise; },
    exchange() { return exchange.promise; },
    load() { assert.fail('expired auth enabled a workspace load'); }
  });
  const checking = h.controller.resume();
  h.advance(0, 51);
  auth.resolve(session(1, 50));
  await checking;
  assert.equal(h.view().phase, 'signed-out');
  const signingIn = h.controller.exchange(fixtureCode);
  h.advance(51);
  exchange.resolve(session(2, 50));
  await signingIn;
  assert.equal(h.view().phase, 'signed-out');
  assert.equal(h.view().snapshot, null);
});

test('suspend clears the snapshot and retires old work before revalidation', async (t) => {
  const old = deferred();
  const next = deferred();
  let calls = 0;
  const h = fixture(t, {
    session() { return ++calls === 1 ? old.promise : next.promise; }
  });
  const original = h.controller.resume();
  h.controller.suspend();
  assert.equal(h.view().snapshot, null);
  const resumed = h.controller.resume();
  old.resolve(session(1));
  await original;
  assert.equal(h.view().phase, 'checking');
  next.resolve(session(2));
  await resumed;
  await settle();
  assert.equal(h.view().phase, 'signed-out');
  assert.equal(h.view().snapshot, null);
});

test('logout serializes until confirmation and uncertainty disables exchange', async (t) => {
  const logout = deferred();
  let exchanges = 0;
  const h = fixture(t, {
    async exchange() { return session(++exchanges); },
    logout() { return logout.promise; },
    async load() { return snapshot(1); }
  });
  await h.controller.resume();
  await h.controller.exchange(fixtureCode);
  await settle();
  assert.equal(h.view().phase, 'ready');
  const signingOut = h.controller.logout();
  assert.equal(h.view().snapshot, null);
  await h.controller.exchange(fixtureCode);
  assert.equal(exchanges, 1);
  logout.reject(new Error('lost reply'));
  await signingOut;
  assert(h.view().authBlocked);
  await h.controller.resume();
  await h.controller.exchange(fixtureCode);
  assert.equal(exchanges, 1);
});

test('backwards wall movement fences held workspace even with monotonic progress', async (t) => {
  const reply = deferred();
  const h = fixture(t, { load() { return reply.promise; } });
  await h.controller.resume();
  await h.controller.exchange(fixtureCode);
  h.advance(10, -1);
  reply.resolve(snapshot());
  await settle();
  assert.equal(h.view().phase, 'signed-out');
  assert.equal(h.view().snapshot, null);
});

test('ready rows expire at a bounded wake when wall time advances without a visibility event', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const h = fixture(t);
  await h.controller.resume();
  await h.controller.exchange(fixtureCode);
  await settle();
  assert.equal(h.view().phase, 'ready');
  h.advance(0, 60_001);
  t.mock.timers.tick(1000);
  assert.equal(h.view().phase, 'signed-out');
  assert.equal(h.view().snapshot, null);
});

test('restore during exchange revalidates only after confirmation', async (t) => {
  const exchange = deferred();
  let checks = 0;
  let loads = 0;
  const h = fixture(t, {
    async session() {
      if (++checks === 1) throw new Denied();
      return session(2);
    },
    exchange() { return exchange.promise; },
    async load() { ++loads; return snapshot(2); }
  });
  await h.controller.resume();
  const signingIn = h.controller.exchange(fixtureCode);
  h.controller.suspend();
  await h.controller.resume();
  assert.equal(checks, 1);
  assert.equal(h.view().snapshot, null);
  exchange.resolve(session(1));
  await signingIn;
  await settle();
  assert.equal(checks, 2);
  assert.equal(loads, 1);
  assert.equal(h.view().snapshot.session_generation, 2);
});

test('malformed bootstrap input stays local and a valid retry can sign in', async (t) => {
  let exchanges = 0;
  const h = fixture(t, {
    async exchange(code) {
      ++exchanges;
      if (code !== fixtureCode) throw new Error('400 body validation failure');
      return session(1);
    },
    async load() { return snapshot(1); }
  });
  await h.controller.resume();
  for (const code of ['bad', 'a'.repeat(44), 'a'.repeat(42) + '.', 'a'.repeat(42) + ' ']) {
    await h.controller.exchange(code);
    assert.equal(h.view().authBlocked, false);
  }
  assert.equal(exchanges, 0);
  await h.controller.exchange(fixtureCode);
  await settle();
  assert.equal(exchanges, 1);
  assert.equal(h.view().phase, 'ready');
});
