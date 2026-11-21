// Run with node --test. Only synthetic sockets and fixture rows are used.
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { test } from 'node:test';
import { runProbe } from './clients/node_tls_probe.mjs';

const fixture = 'D\tdns-row\t12345\tlocalhost\tdns\nD\tip-row\t12346\t127.0.0.1\tip\n';
const TLS_ERROR = Object.assign(new Error('test verification error'), { code: 'TEST_VERIFY' });
const version = `node-${process.version}-openssl-${process.versions.openssl}`;

async function run({ events = [], readError = null, connectError = null }) {
  const rows = [];
  const diagnostics = [];
  const attempts = [];
  const exitCode = await runProbe('D', {
    read() {
      if (readError) throw readError;
      return fixture;
    },
    connect(options, ready) {
      if (connectError) throw connectError;
      const socket = new EventEmitter();
      const script = events[attempts.length] ?? [];
      const attempt = { options, destroys: 0 };
      attempts.push(attempt);
      socket.destroy = () => {
        attempt.destroys++;
        socket.emit('close');
      };
      process.nextTick(() => {
        for (const event of script) {
          if (event === 'ready') ready();
          else socket.emit(event, TLS_ERROR);
        }
      });
      return socket;
    },
    log: row => rows.push(row),
    logError: line => diagnostics.push(line),
  });
  return { rows, diagnostics, attempts, exitCode };
}

test('normal rows settle once and keep their order and TLS result details', async () => {
  const result = await run({ events: [['ready', 'error', 'close'], ['error', 'close']] });
  assert.equal(result.exitCode, 0);
  assert.deepEqual(result.rows, [
    `${version}\tD\tdns-row\tOK\t`,
    `${version}\tD\tip-row\tFAIL\tTEST_VERIFY test verification error`,
  ]);
  assert.deepEqual(result.attempts.map(item => item.destroys), [1, 1]);
  assert.equal(result.attempts[0].options.servername, 'localhost');
  assert.equal(result.attempts[1].options.servername, undefined);
});

for (const event of ['timeout', 'close']) {
  test(`${event} before a TLS result aborts without a matrix row`, async () => {
    const result = await run({ events: [[event, 'error', 'close']] });
    assert.equal(result.exitCode, 1);
    assert.deepEqual(result.rows, []);
    assert.equal(result.attempts[0].destroys, 1);
    assert.match(result.diagnostics[0], /D\/dns-row/);
  });
}

for (const failure of ['readError', 'connectError']) {
  test(`${failure} is reported as a setup failure without a row`, async () => {
    const result = await run({ [failure]: new Error('test setup failure') });
    assert.equal(result.exitCode, 1);
    assert.deepEqual(result.rows, []);
    assert.deepEqual(result.diagnostics, ['Node TLS probe incomplete: test setup failure']);
  });
}
