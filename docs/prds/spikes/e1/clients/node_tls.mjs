// Run with NODE_EXTRA_CA_CERTS=/w/ca/<V>/ca.pem; argument: V. Default root store plus the extra CA.
import { runProbe } from './node_tls_probe.mjs';

process.exitCode = await runProbe(process.argv[2]);
