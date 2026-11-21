import { readFileSync } from 'node:fs';
import { connect as connectTls } from 'node:tls';

const ver = 'node-' + process.version + '-openssl-' + process.versions.openssl;

function probe(line, connect, log) {
  const [variant, leaf, port, check, kind] = line.split('\t');
  const options = { host: check, port: +port, timeout: 10000 };
  if (kind === 'dns') options.servername = check;

  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = connect(options, () => report('OK', ''));

    function settle(complete) {
      if (settled) return;
      settled = true;
      try {
        complete();
      } finally {
        socket.destroy();
      }
    }

    function report(result, detail) {
      settle(() => {
        log([ver, variant, leaf, result, detail].join('\t'));
        resolve();
      });
    }

    function abort(reason) {
      settle(() => reject(new Error(`${variant}/${leaf} ${reason}`)));
    }

    // The matrix checker still classifies reported TLS errors. Keep the listener for late errors.
    socket.on('error', error => report('FAIL', (error.code || '') + ' ' + error.message));
    socket.once('timeout', () => abort('timed out before a TLS result'));
    socket.once('close', () => abort('closed before a TLS result'));
  });
}

export async function runProbe(variant, {
  read = readFileSync,
  connect = connectTls,
  log = console.log,
  logError = console.error,
} = {}) {
  try {
    const rows = read('/w/combos.tsv', 'utf8').trim().split('\n')
      .filter(line => line.startsWith(variant + '\t'));
    // Chain each row so the fixture owns only one active socket at a time.
    await rows.reduce((previous, line) => previous.then(() => probe(line, connect, log)), Promise.resolve());
    return 0;
  } catch (error) {
    logError(`Node TLS probe incomplete: ${error.message}`);
    return 1;
  }
}
