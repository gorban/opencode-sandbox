// Run with NODE_EXTRA_CA_CERTS=/w/ca/<V>/ca.pem; argument: V. Default root store plus the extra CA.
const tls = require('node:tls');
const fs = require('node:fs');
const ver = 'node-' + process.version + '-openssl-' + process.versions.openssl;

function probe(line) {
  const [variant, leaf, port, check, kind] = line.split('\t');
  const options = { host: check, port: +port, timeout: 10000 };
  if (kind === 'dns') options.servername = check;

  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = tls.connect(options, () => report('OK', ''));

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
        console.log([ver, variant, leaf, result, detail].join('\t'));
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

async function main() {
  const variant = process.argv[2];
  const rows = fs.readFileSync('/w/combos.tsv', 'utf8').trim().split('\n')
    .filter(line => line.startsWith(variant + '\t'));
  for (const line of rows) {
    await probe(line);
  }
}

main().catch(error => {
  console.error(`Node TLS probe incomplete: ${error.message}`);
  process.exitCode = 1;
});
