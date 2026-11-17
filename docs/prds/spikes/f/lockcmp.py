#!/usr/bin/env python3
"""Compare two mise.lock files by content, ignoring the lock format version and key order.

Compared per tool: version, backend, options; per platform: url, checksum, conda_deps; plus every
[conda-packages.*] entry (url, checksum). Fields that only newer mise versions add (for example
provenance data or url_api) are reported but do not make the files differ unless --strict is given.
Exit 0: same artifacts and checksums; 1: different; 2: usage or parse error.
"""
import sys
import tomllib

CORE = ("url", "checksum", "conda_deps")


def load(path):
    with open(path, "rb") as f:
        return tomllib.load(f)


def flatten(doc):
    out, extra = {}, {}
    for k, v in doc.items():
        if k not in ("lockfile_version", "tools", "conda-packages"):
            extra[("top-level", k)] = v
    for name, entries in doc.get("tools", {}).items():
        for index, e in enumerate(entries if isinstance(entries, list) else [entries]):
            # [[tools.X]] holds version/backend; [tools.X."platforms.P"] holds artifacts (a dict inside the list
            # entry or beside it, depending on the TOML shape); handle both.
            for k, v in e.items():
                if k.startswith("platforms."):
                    for f, val in v.items():
                        (out if f in CORE else extra)[(name, index, k, f)] = val
                elif k == "options":
                    for f, val in v.items():
                        out[(name, index, "options", f)] = val
                elif k in ("version", "backend"):
                    out[(name, index, k)] = v
                else:
                    extra[(name, index, k)] = v
    for plat, pk in doc.get("conda-packages", {}).items():
        for fn, spec in pk.items():
            for f, val in spec.items():
                out[("conda-package", plat, fn, f)] = val
    return out, extra


def main(argv):
    strict = "--strict" in argv
    files = [a for a in argv[1:] if not a.startswith("--")]
    if len(files) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        da, db = load(files[0]), load(files[1])
        (a, ea), (b, eb) = flatten(da), flatten(db)
    except Exception as exc:  # noqa: BLE001
        print(f"cannot parse: {exc}", file=sys.stderr)
        return 2
    if strict:
        # Compare the complete parsed document, including empty tables and unknown fields.
        # Only the format version is intentionally excluded across mise versions.
        da.pop("lockfile_version", None)
        db.pop("lockfile_version", None)
        if da != db:
            print("DIFF complete lock structures differ")
            return 1
        a.update({("extra",) + k: v for k, v in ea.items()})
        b.update({("extra",) + k: v for k, v in eb.items()})
    missing = object()
    diff = [k for k in sorted(set(a) | set(b), key=str) if a.get(k, missing) != b.get(k, missing)]
    for k in diff:
        print(f"DIFF {k}: {a.get(k)!r} != {b.get(k)!r}")
    only = sorted(set(ea) ^ set(eb), key=str)
    if only and not strict:
        print(f"note: {len(only)} non-artifact field(s) present in only one file (ignored)")
    print(f"{len(a)} comparable fields in first, {len(b)} in second, {len(diff)} differ")
    return 1 if diff else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
