// Run with NODE_EXTRA_CA_CERTS=/w/ca/<V>/ca.pem; argument: V. Default root store plus the extra CA.
const tls = require('tls'), fs = require('fs');
const V = process.argv[2];
const ver = 'node-' + process.version + '-openssl-' + process.versions.openssl;
const rows = fs.readFileSync('/w/combos.tsv', 'utf8').trim().split('\n').filter(l => l.startsWith(V + '\t'));
(async () => {
  for (const line of rows) {
    const [v, L, port, check, kind] = line.split('\t');
    await new Promise(res => {
      const opt = { host: check, port: +port, timeout: 10000 };
      if (kind === 'dns') opt.servername = check;
      const s = tls.connect(opt, () => { console.log([ver, v, L, 'OK', ''].join('\t')); s.destroy(); res(); });
      s.on('error', e => { console.log([ver, v, L, 'FAIL', (e.code || '') + ' ' + e.message].join('\t')); s.destroy(); res(); });
    });
  }
})();
