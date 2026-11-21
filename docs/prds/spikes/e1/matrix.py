"""Merge results/*.tsv from the probe's private working directory and run validity checks.
Exit status 1 when the run cannot be trusted: a client or a row is missing, a rejection lacks recognized per-client certificate verification
evidence, or the unconstrained control CA X does not
behave as expected (plain leaves and the CA-twin chain accepted, the unconstrained intermediate
rejected by pathlen:0). The separate control endpoint and generic certificate errors do not prove each individual cause."""
import collections
import csv
import io
import os
import re
import stat
import sys

ROW_FORMAT = "%-*s %s"
MAX_RESULT_FILES = 32
MAX_RESULT_BYTES = 1024 * 1024


def file_version(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def result_names(directory):
    names = []
    with os.scandir(directory) as entries:
        for entry in entries:
            if entry.name.startswith(".") or not entry.name.endswith(".tsv"):
                continue
            names.append(entry.name)
            if len(names) > MAX_RESULT_FILES:
                raise ValueError("too many result files")
    return sorted(names)


def read_result(directory, name):
    before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError(f"result must be a single-link regular file: {name!r}")
    if before.st_size > MAX_RESULT_BYTES:
        raise ValueError(f"result exceeds the byte limit: {name!r}")
    expected = file_version(before)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        if file_version(os.fstat(fd)) != expected:
            raise ValueError(f"result changed before reading: {name!r}")
        with open(fd, "rb", buffering=0, closefd=False) as result:
            data = result.read(MAX_RESULT_BYTES + 1)
        after = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (len(data) != before.st_size or file_version(after) != expected
                or file_version(os.fstat(fd)) != expected):
            raise ValueError(f"result changed while reading: {name!r}")
        return data
    finally:
        os.close(fd)


def read_results():
    results = collections.OrderedDict()
    directory = os.open("results", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        expected = file_version(os.fstat(directory))
        if file_version(os.stat("results", follow_symlinks=False)) != expected:
            raise ValueError("results directory changed before reading")
        for name in result_names(directory):
            data = read_result(directory, name)
            with io.TextIOWrapper(io.BytesIO(data)) as decoded:
                for row in csv.reader(decoded, delimiter="\t"):
                    if len(row) < 4:
                        continue
                    client, variant, leaf, result = row[:4]
                    detail = row[4] if len(row) > 4 else ""
                    results.setdefault(client, {})[(variant, leaf)] = (result, detail)
        if (file_version(os.stat("results", follow_symlinks=False)) != expected
                or file_version(os.fstat(directory)) != expected):
            raise ValueError("results directory changed while reading")
    finally:
        os.close(directory)
    return results


# Historical replays may pass the literal ".". The host sets the workspace through cwd.
if sys.argv[1:] not in ([], ["."]):
    sys.exit("Run the matrix from the probe's private working directory")
try:
    res = read_results()
except (OSError, ValueError, csv.Error) as error:
    sys.exit(f"Cannot read matrix results: {error}")
variants = [l.split("\t")[0] for l in open("variants.tsv").read().splitlines() if l]
leaves = [l.split("\t")[0] for l in open("leaves.tsv").read().splitlines() if l]
mode = {l.split("\t")[0]: l.split("\t")[4] for l in open("leaves.tsv").read().splitlines() if l}
combos = [tuple(l.split("\t")[:2]) for l in open("combos.tsv").read().splitlines() if l]

def short(c):
    host = "4.0" in c.split("-")[-1] and c.startswith("openssl")
    for pre, nm in (("openssl-verify+host", "vfy+h"), ("openssl-verify", "vfy"), ("openssl-s_client", "s_cli"),
                    ("curl", "curl"), ("py", "py"), ("node", "node"), ("go", "go"), ("psql", "psql"),
                    ("chromium", "chrom"), ("nss", "nss")):
        if c.startswith(pre):
            if c.startswith("openssl-verify"):
                return ("H" if host else "A") + nm
            return nm
    return c[:5]
order = ["Hvfy", "Hvfy+h", "Avfy", "Avfy+h", "s_cli", "curl", "py", "node", "go", "psql", "chrom", "nss"]
clients = sorted(res, key=lambda c: order.index(short(c)) if short(c) in order else 99)
w = max(len(l) for l in leaves) + 1

# ---- validity checks
problems = []
expect = [x for x in os.environ.get("OC_E1_EXPECT", "").split(",") if x]
have = {short(c) for c in clients}
for e in expect:
    if e not in have: problems.append("client %s produced no results" % e)
for c in clients:
    miss = [k for k in combos if k not in res[c]]
    if miss: problems.append("%s: %d of %d rows missing (first %s)" % (short(c), len(miss), len(combos), miss[0]))
# Fail closed: each client must report recognizable certificate-validation evidence.
# TLS protocol, connection, and unknown errors are not evidence of a name constraint.
CONSTRAINT_ERROR = r"^(permitted subtree violation|excluded subtree violation|path length constraint exceeded)$"
VERIFY = {
    "Hvfy": CONSTRAINT_ERROR,
    "Hvfy+h": CONSTRAINT_ERROR,
    "Avfy": CONSTRAINT_ERROR,
    "Avfy+h": CONSTRAINT_ERROR,
    "s_cli": r"^num=(47:permitted subtree violation|48:excluded subtree violation|25:path length constraint exceeded)$",
    "curl": r"^SSL certificate problem: (permitted subtree violation|excluded subtree violation|path length constraint exceeded)$",
    "py": CONSTRAINT_ERROR,
    "node": r"^(UNSPECIFIED (permitted|excluded) subtree violation|PATH_LENGTH_EXCEEDED path length constraint exceeded)$",
    "go": r"^tls: failed to (verify certificate: x509: (a root or intermediate certificate is not authorized to sign for this name: .+|too many intermediates for path length constraint|certificate relies on legacy Common Name field, use SANs instead)|parse certificate from server: x509: SAN iPAddress contains IPv4-mapped IPv6 address)$",
    "psql": r"^connection to server at .+ failed: SSL error: certificate verify failed$",
    "chrom": r"^net::ERR_CERT_(INVALID|COMMON_NAME_INVALID)$",
    "nss": r"^certutil: certificate is invalid: (Peer's Certificate issuer is not recognized\.|The Certifying Authority for this certificate is not permitted to issue a certificate with this name\.|Peer's certificate issuer has been marked as not trusted by the user\.)$",
}
for c in clients:
    for (V, L), (r, d) in sorted(res[c].items()):
        if r not in ("OK", "FAIL"):
            problems.append("%s %s/%s: invalid result %r" % (short(c), V, L, r))
        elif r == "FAIL" and not re.fullmatch(VERIFY.get(short(c), r"(?!)"), d):
            problems.append("%s %s/%s: rejection is not a recognized verification error: %r" % (short(c), V, L, d[:100]))
# control CA X: connectivity and the profile itself are fine, so rejections under A-F are the constraint's
if "X" in variants:
    for c in clients:
        for L in leaves:
            r = res[c].get(("X", L))
            if r is None: continue
            # known client behaviour unrelated to constraints: Go and Chromium reject a CN-only leaf, and Go refuses
            # to parse a certificate whose SAN holds an IPv4-mapped IPv6 address (seen in the control's go.tsv)
            want_ok = mode[L] != "unc" and not (L == "cnonly" and short(c) in ("go", "chrom")) \
                and not (L == "ip6map" and short(c) == "go")
            if (r[0] == "OK") != want_ok:
                problems.append("control X: %s %s expected %s got %s %s" % (short(c), L, "OK" if want_ok else "reject", r[0], r[1][:80]))

# ---- matrices
for V in variants:
    print("\nCA variant %s%s" % (V, " (control: no nameConstraints, pathlen:0)" if V == "X" else ""))
    print((" " * w + " ".join("%-6s" % short(c) for c in clients)).rstrip())
    for L in leaves:
        cells = []
        for c in clients:
            r = res[c].get((V, L))
            if r is None:
                cells.append("?     ")
            else:
                cells.append("ok    " if r[0] == "OK" else "--    ")
        print((ROW_FORMAT % (w, L, " ".join(cells))).rstrip())
print("\nSUMMARY (cell: all = every client accepts, none = every client rejects, else the accepting subset)")
print((ROW_FORMAT % (w, "", " ".join("%-24s" % ("CA " + V) for V in variants))).rstrip())
for L in leaves:
    cells = []
    for V in variants:
        acc = [short(c) for c in clients if res[c].get((V, L), ("?",))[0] == "OK"]
        if len(acc) == len(clients):
            cells.append("all")
        elif not acc:
            cells.append("none")
        else:
            cells.append("ok: " + ",".join(acc))
    print((ROW_FORMAT % (w, L, " ".join("%-24s" % x for x in cells))).rstrip())
print("\nclients:")
for c in clients: print("%-7s %s" % (short(c), c))
NAMED = re.compile(r"permitted subtree|not permitted by any constraint|not permitted to issue|path length|pathlen", re.I)
print("\nDo the error messages name the cause? (rejections under A-F: total / message names a name constraint or path length)")
for c in clients:
    rej = [(k, v) for k, v in res[c].items() if v[0] != "OK" and k[0] != "X"]
    named = sum(1 for k, v in rej if NAMED.search(v[1]))
    print("  %-7s %3d / %3d" % (short(c), len(rej), named))
print("\nfailure reasons per client (most frequent first, rejections under A-F):")
for c in clients:
    cnt = collections.Counter(d[:150] for (V, L), (r, d) in res[c].items() if r != "OK" and V != "X")
    for d, n in cnt.most_common(8): print(("  %-7s %3d x %s" % (short(c), n, d)).rstrip())
print("\nCHECKS: %s" % ("all passed (rows complete, recognized verification errors, control X as expected)" if not problems else "%d PROBLEM(S)" % len(problems)))
for p in problems[:40]: print("  PROBLEM: " + p)
sys.exit(1 if problems else 0)
