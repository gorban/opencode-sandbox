import socket, ssl, sys
ver = "py%s-%s" % (sys.version.split()[0], ssl.OPENSSL_VERSION.split()[1])
for line in open("/w/combos.tsv"):
    V, L, port, check, kind = line.rstrip("\n").split("\t")
    ctx = ssl.create_default_context(cafile="/w/ca/%s/ca.pem" % V)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with (
            socket.create_connection((check, int(port)), timeout=10) as s,
            ctx.wrap_socket(s, server_hostname=check) as t,
        ):
            r, d = "OK", ""
    except Exception as e:
        r, d = "FAIL", (getattr(e, "verify_message", None) or str(e)).replace("\n", " ")
    print("\t".join([ver, V, L, r, d]))
