// Run with node --test. Only synthetic sockets and fixture rows are used.
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const { setImmediate } = require('node:timers/promises');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, 'clients/node_tls.js'), 'utf8');
const fixture = 'D\tdns-row\t12345\tlocalhost\tdns\nD\tip-row\t12346\t127.0.0.1\tip\n';
const TLS_ERROR = Object.assign(new Error('test verification error'), { code: 'TEST_VERIFY' });

async function run({ events = [], readError = null, connectError = null }) {
  const rows = [];
  const diagnostics = [];
  const attempts = [];
  const localProcess = { argv: ['node', 'node_tls.js', 'D'], version: 'v24', versions: { openssl: 'test' }, exitCode: 0 };
  const fsFixture = {
    readFileSync() {
      if (readError) throw readError;
      return fixture;
    },
  };
  const tlsFixture = {
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
  };
  const promise = vm.runInNewContext(source, {
    require(name) {
      if (name === 'node:fs' || name === 'fs') return fsFixture;
      if (name === 'node:tls' || name === 'tls') return tlsFixture;
      throw new Error(`Unexpected import ${name}`);
    },
    console: { log: row => rows.push(row), error: line => diagnostics.push(line) },
    process: localProcess,
  });
  // Observe the exit and diagnostics even when an older client left a promise pending.
  promise?.catch(() => {});
  await setImmediate();
  return { rows, diagnostics, attempts, exitCode: localProcess.exitCode };
}

test('normal rows settle once and keep their order and TLS result details', async () => {
  const result = await run({ events: [['ready', 'error', 'close'], ['error', 'close']] });
  assert.equal(result.exitCode, 0);
  assert.deepEqual(result.rows, [
    'node-v24-openssl-test\tD\tdns-row\tOK\t',
    'node-v24-openssl-test\tD\tip-row\tFAIL\tTEST_VERIFY test verification error',
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
