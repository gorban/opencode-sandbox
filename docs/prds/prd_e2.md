# prd_e2: Per-instance leaf certificates

Parent: [prd_e](prd_e.md)

- [ ] Issue a leaf for `feat-a.<suffix>` (plus `localhost` and `127.0.0.1`, so in-pod tools work) on
      the host, on instance start, in a host-only directory. Reuse it while its SANs match and it isn't
      near expiry; short validity (e.g. 30 days) with automatic renewal.
- [ ] Deliver it to the pod read-only at a fixed path, e.g. `/run/oc-tls/{cert.pem,key.pem,ca.pem}`,
      with env vars `OC_TLS_CERT`/`OC_TLS_KEY`. Document examples for Vite, Next, Node, Python and Caddy.
- [ ] The key in the pod is readable by the agent (it serves the app). Accept this: it's valid only for
      that instance's name.
- [ ] Remove the leaf with `-d -i NAME -a`.
