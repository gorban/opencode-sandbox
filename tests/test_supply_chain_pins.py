#!/usr/bin/env python3
"""Defensive supply-chain pinning, launch-verification, and image-age invariants.

Runs completely offline using stubbed Podman/Git and synthetic scratch fixtures.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oc_openai.session_broker import generate_opencode_config
from oc_providers import catalog as provider_catalog

BAKED_MCP_COMMAND = [
    "/usr/local/bin/chrome-devtools-mcp",
    "--browserUrl",
    "http://127.0.0.1:9222",
]


def _extract_heredoc(source: str, target_leaf: str, token: str = "EOF") -> str:
    marker = f'atomic_host_file "$BUILD/{target_leaf}" 0644 <<\'{token}\'\n'
    start = source.index(marker) + len(marker)
    end = source.index(f"\n{token}\n", start)
    return source[start:end]


class SupplyChainPinningInvariants(unittest.TestCase):
    def setUp(self):
        self.launcher = (ROOT / "oc-sandbox").read_text(encoding="utf-8")

    def test_all_container_bases_and_default_dind_are_digest_pinned(self):
        agent_cf = _extract_heredoc(self.launcher, "Containerfile.agent")
        chrome_cf = _extract_heredoc(self.launcher, "Containerfile.chromium")
        relay_cf = _extract_heredoc(self.launcher, "Containerfile.relay")
        for name, cf in (("agent", agent_cf), ("chromium", chrome_cf), ("relay", relay_cf)):
            from_lines = [line.strip() for line in cf.splitlines() if line.strip().startswith("FROM ")]
            self.assertTrue(from_lines, f"{name} Containerfile missing FROM")
            for line in from_lines:
                self.assertRegex(
                    line,
                    r"^FROM \S+@sha256:[0-9a-f]{64}$",
                    f"{name} base image must be digest-pinned: {line}",
                )
        dind_match = re.search(r"^DIND_IMG=\$\{OC_DIND_IMAGE:-([^}]+)\}$", self.launcher, re.MULTILINE)
        self.assertIsNotNone(dind_match, "default DIND_IMG definition missing")
        self.assertRegex(dind_match.group(1), r"@sha256:[0-9a-f]{64}$")
        self.assertNotIn(":latest", dind_match.group(1))
        self.assertNotIn("--allow-untrusted", agent_cf)
        self.assertNotIn("--nogpgcheck", chrome_cf)

    def test_chrome_devtools_mcp_is_baked_and_unified_across_all_three_configs(self):
        agent_cf = _extract_heredoc(self.launcher, "Containerfile.agent")
        self.assertIn("chrome-devtools-mcp-1.14.0.tgz", agent_cf)
        self.assertIn("sha512sum -c -", agent_cf)
        self.assertIn("sha256sum -c -", agent_cf)
        self.assertIn("/usr/local/bin/chrome-devtools-mcp", agent_cf)
        self.assertNotIn("npm install", agent_cf)
        self.assertNotIn("npx ", agent_cf)

        # 1) oc-sandbox opencode-sandbox.json
        sandbox_cfg = json.loads(_extract_heredoc(self.launcher, "opencode-sandbox.json"))
        self.assertEqual(sandbox_cfg["mcp"]["chrome-devtools"]["command"], BAKED_MCP_COMMAND)

        # 2) oc_providers/catalog.py constant
        self.assertEqual(list(getattr(provider_catalog, "CHROME_DEVTOOLS_MCP_COMMAND", ())), BAKED_MCP_COMMAND)

        # 3) oc_openai/session_broker.py generator
        broker_cfg = generate_opencode_config(worker_token="t" * 32, models=("gpt-6.2-sol",))
        self.assertEqual(broker_cfg["mcp"]["chrome-devtools"]["command"], BAKED_MCP_COMMAND)

        # No npx or @latest Chrome DevTools MCP references remain in launcher or provider/broker code.
        for path in (
            ROOT / "oc-sandbox",
            ROOT / "oc_openai" / "session_broker.py",
            ROOT / "oc_providers" / "catalog.py",
        ):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("chrome-devtools-mcp@latest", text, str(path))
            self.assertNotIn('"npx"', text, str(path))

    def test_shell_plugins_are_commit_pinned_with_no_floating_clones(self):
        omz = re.search(r"^OHMYZSH_COMMIT=([0-9a-f]{40})$", self.launcher, re.MULTILINE)
        zvm = re.search(r"^ZSH_VI_MODE_COMMIT=([0-9a-f]{40})$", self.launcher, re.MULTILINE)
        self.assertIsNotNone(omz, "OHMYZSH_COMMIT must be a 40-hex SHA")
        self.assertIsNotNone(zvm, "ZSH_VI_MODE_COMMIT must be a 40-hex SHA")
        self.assertNotIn("host_git clone", self.launcher)
        self.assertIn("oh-my-zsh-pinned.receipt", self.launcher)
        self.assertIn("oh-my-zsh-host.receipt", self.launcher)

    def test_agent_container_default_path_excludes_writable_volume_bin(self):
        agent_cf = _extract_heredoc(self.launcher, "Containerfile.agent")
        self.assertNotIn("/root/.opencode/bin", agent_cf)

    def test_updater_no_longer_downloads_or_runs_remote_shell_installer(self):
        updater = (ROOT / "oc-opencode-update.py").read_text(encoding="utf-8")
        self.assertNotIn("https://opencode.ai/v2/install", updater)
        self.assertNotIn("https://opencode.ai/install", updater)
        self.assertNotIn("'bash'", updater)


class LaunchWrapperVerificationTests(unittest.TestCase):
    """Verify oc-opencode-run.py fixed baked default, sealed memfd verification, and compat mode."""

    _WRAPPER_HARNESS = (
        "import importlib.util, sys; "
        "spec = importlib.util.spec_from_file_location('oc_run', sys.argv[1]); "
        "mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); "
        "mod.BAKED_OPENCODE = sys.argv[2]; "
        "sys.argv = ['oc-opencode-run.py', *sys.argv[3:]]; "
        "sys.exit(mod.main())"
    )

    def _make_stub(self, path: Path, marker: str):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"#!/bin/sh\nprintf '%s:%s\\n' '{marker}' \"$*\"\n",
            encoding="utf-8",
        )
        path.chmod(0o755)
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _run_wrapper(self, *, home: Path, baked_bin: Path, path_env: str, extra_env: dict[str, str], args=()):
        env = {
            "HOME": str(home),
            "PATH": path_env,
            **extra_env,
        }
        return subprocess.run(
            [sys.executable, "-I", "-c", self._WRAPPER_HARNESS, str(ROOT / "oc-opencode-run.py"), str(baked_bin), *args],
            env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10,
        )

    def test_default_mode_runs_fixed_baked_binary_ignoring_path_and_volume_candidates(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            baked_dir = root / "baked"
            extra_path_dir = root / "external_path"
            vol_bin = home / ".opencode" / "bin" / "opencode"
            path_bin = extra_path_dir / "opencode"
            baked_bin = baked_dir / "opencode"
            self._make_stub(vol_bin, "VOLUME")
            self._make_stub(path_bin, "PATH_SHADOW")
            self._make_stub(baked_bin, "BAKED")
            path_env = f"{extra_path_dir}:{vol_bin.parent}:/usr/bin:/bin"
            res = self._run_wrapper(home=home, baked_bin=baked_bin, path_env=path_env, extra_env={}, args=("hello",))
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout.strip(), "BAKED:hello")

    def test_verified_mode_closes_source_fd_once_if_memfd_allocation_fails(self):
        import errno
        import importlib.util
        from unittest.mock import patch

        spec = importlib.util.spec_from_file_location("oc_run_fdcheck", ROOT / "oc-opencode-run.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / "home"
            vol_bin = home / ".opencode" / "bin" / "opencode"
            expected_sha = self._make_stub(vol_bin, "VERIFIED")
            opened_fds = []
            closed_fds = []
            real_open_vol = mod._open_volume_binary
            real_close = os.close

            def track_open(h):
                fd = real_open_vol(h)
                opened_fds.append(fd)
                return fd

            def track_close(fd):
                closed_fds.append(fd)
                return real_close(fd)

            with patch.object(mod, "_open_volume_binary", side_effect=track_open), \
                    patch.object(mod.os, "memfd_create", side_effect=OSError(errno.ENOMEM, "fixture")), \
                    patch.object(mod.os, "close", side_effect=track_close):
                with self.assertRaises(OSError):
                    mod._load_verified_memfd(str(home), expected_sha)
            self.assertEqual(len(opened_fds), 1)
            self.assertEqual(closed_fds.count(opened_fds[0]), 1)

    def test_verified_mode_executes_matching_volume_binary_and_refuses_tampering(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            baked_dir = root / "sysbin"
            vol_bin = home / ".opencode" / "bin" / "opencode"
            baked_bin = baked_dir / "opencode"
            expected_sha = self._make_stub(vol_bin, "VERIFIED")
            self._make_stub(baked_bin, "BAKED")
            path_env = f"{baked_dir}:/usr/bin:/bin"

            # Matching digest executes verified binary via sealed memfd.
            ok = self._run_wrapper(
                home=home, baked_bin=baked_bin, path_env=path_env,
                extra_env={"OC_OPENCODE_EXPECTED_SHA256": expected_sha},
                args=("--flag",),
            )
            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertEqual(ok.stdout.strip(), "VERIFIED:--flag")

            # Substituting an ordinary different file between promote and launch fails closed.
            tampered_marker = root / "tampered.ran"
            vol_bin.write_text(f"#!/bin/sh\necho RAN > {str(tampered_marker)!r}\necho TAMPERED\n", encoding="utf-8")
            vol_bin.chmod(0o755)
            bad = self._run_wrapper(
                home=home, baked_bin=baked_bin, path_env=path_env,
                extra_env={"OC_OPENCODE_EXPECTED_SHA256": expected_sha},
            )
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("digest does not match", bad.stderr)
            self.assertFalse(tampered_marker.exists())
            self.assertEqual(bad.stdout, "")

            # Conflicting verified + compat env fails closed.
            conflict = self._run_wrapper(
                home=home, baked_bin=baked_bin, path_env=path_env,
                extra_env={"OC_OPENCODE_EXPECTED_SHA256": expected_sha, "OC_OPENCODE_USE_VOLUME": "1"},
            )
            self.assertNotEqual(conflict.returncode, 0)
            self.assertIn("cannot both be set", conflict.stderr)

    def test_explicit_compat_mode_selects_volume_binary_when_present(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            baked_dir = root / "sysbin"
            vol_bin = home / ".opencode" / "bin" / "opencode"
            baked_bin = baked_dir / "opencode"
            self._make_stub(vol_bin, "COMPAT")
            self._make_stub(baked_bin, "BAKED")
            path_env = f"{baked_dir}:/usr/bin:/bin"
            res = self._run_wrapper(
                home=home, baked_bin=baked_bin, path_env=path_env,
                extra_env={"OC_OPENCODE_USE_VOLUME": "1"},
                args=("ok",),
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout.strip(), "COMPAT:ok")


class LauncherSupplyChainBehaviorTests(unittest.TestCase):
    """Stubbed scratch-HOME tests for launcher validation, age bounds, cache receipts, and fallback."""

    def _make_env(self, root: Path, *, with_host_omz: bool = True, fail_updater_stage: bool = False):
        home = root / "home"
        state = home / ".local/share/oc-sandbox"
        policy = state / "policy"
        runtime = root / "runtime"
        stub = root / "stub"
        images = root / "images"
        podman_log = root / "podman.log"
        for d in (home / "opencode-sandbox", policy, runtime, stub, images):
            d.mkdir(parents=True, mode=0o700)
        if with_host_omz:
            (home / ".oh-my-zsh/custom/plugins/zsh-vi-mode").mkdir(parents=True, mode=0o700)

        # Seed policy installed marker to match oc-sandbox so no host semodule is needed.
        src = (ROOT / "oc-sandbox").read_text(encoding="utf-8")
        m = re.search(r"(?ms)^(; SELinux type.*?\n)POL\n", src)
        self.assertIsNotNone(m)
        (policy / "installed").write_text(hashlib.sha256(m.group(1).encode()).hexdigest()[:16] + "\n", encoding="utf-8")

        podman = stub / "podman"
        podman.write_text(
            f"""#!/usr/bin/python3
import hashlib, json, os, pathlib, sys
args = sys.argv[1:]
log = pathlib.Path({str(podman_log)!r})
images = pathlib.Path({str(images)!r})
with log.open("a", encoding="utf-8") as f:
    f.write(json.dumps(args) + "\\n")
if not args or args[0] == "--version":
    print("podman version 5.0.0"); sys.exit(0)
if args[:2] == ["image", "inspect"]:
    fmt = args[3] if len(args) > 3 else ""
    if "RepoTags" in fmt:
        print("1")
        sys.exit(0)
    name = args[-1]
    rec = images / name
    if not rec.exists(): sys.exit(125)
    meta = json.loads(rec.read_text(encoding="utf-8"))
    if "oc.hash" in fmt:
        print(f"{{meta['id']}} {{meta['hash']}} {{meta.get('epoch', '')}}")
    else:
        print(meta["id"])
    sys.exit(0)
if args[0] == "build":
    tag = h = epoch = ""
    i = 1
    while i < len(args):
        if args[i] == "-t":
            tag = args[i + 1]; i += 2
        elif args[i] == "--label":
            val = args[i + 1]
            if val.startswith("oc.hash="): h = val.split("=", 1)[1]
            elif val.startswith("oc.built_epoch="): epoch = val.split("=", 1)[1]
            i += 2
        else:
            i += 1
    img_id = hashlib.sha256(tag.encode()).hexdigest()
    (images / tag).write_text(json.dumps({{"id": img_id, "hash": h, "epoch": epoch}}), encoding="utf-8")
    sys.exit(0)
if args[:2] == ["volume", "exists"] or args[:2] == ["volume", "create"]:
    sys.exit(0)
if args[:2] == ["pod", "exists"]:
    sys.exit(1)
if args[:2] == ["container", "exists"]:
    sys.exit(1)
if args[:2] == ["container", "inspect"]:
    if "--format" in args and "{{{{.State.Status}}}}" in args:
        sys.exit(1)
    if "--format" in args and "oc.chrome.mode" in args[args.index("--format") + 1]:
        print("running headless " + hashlib.sha256(b"oc-chromium").hexdigest()); sys.exit(0)
    print(args[-1], "tok"); sys.exit(0)
if args[0] == "create":
    if "--cidfile" in args:
        cidfile = pathlib.Path(args[args.index("--cidfile") + 1])
        phase = args[-1]
        cid = hashlib.sha256(phase.encode()).hexdigest()
        cidfile.write_text(cid, encoding="utf-8")
        print(cid); sys.exit(0)
    print("c" * 64); sys.exit(0)
if args[0] == "start":
    if {fail_updater_stage!r} and len(args) >= 2 and args[-1] == hashlib.sha256(b"stage").hexdigest():
        sys.exit(4)
    if len(args) >= 2 and args[-1] == hashlib.sha256(b"snapshot").hexdigest():
        sys.stdout.buffer.write(b"OC-OPENCODE-SOURCE-2\\nnull\\n\\nOC-OPENCODE-UPDATE-END\\n")
    sys.exit(0)
if args[0] in ("run", "rm", "ps", "pod", "images", "rmi"):
    sys.exit(0)
sys.exit(0)
""",
            encoding="utf-8",
        )
        podman.chmod(0o755)
        fake_systemctl = stub / "systemctl"
        manager_fixture = ROOT / "tests/bridge-manager-fixture.sh"
        fake_systemctl.write_text(
            "#!/bin/sh\n" + shlex.join(("/usr/bin/bash", str(manager_fixture))) + ' "$@"\n',
            encoding="utf-8",
        )
        fake_systemctl.chmod(0o755)
        for name in ("semodule", "pkexec", "sudo", "curl"):
            p = stub / name
            p.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            p.chmod(0o755)
        env = {
            "HOME": str(home),
            "PATH": f"{stub}:/usr/bin:/bin",
            "XDG_RUNTIME_DIR": str(runtime),
            "OC_CHROMIUM_MODE": "headless",
            "OC_CODE_BIN": "/bin/true",
            "OC_BCOMPARE_BIN": "/bin/true",
        }
        return home, state, images, podman_log, env

    def _prepare_unmanaged_launcher(self, root: Path) -> Path:
        """Stage a scratch copy whose managed-mode check inspects only the scratch HOME."""
        import shutil
        copy_dir = root / "launcher"
        copy_dir.mkdir(mode=0o700, exist_ok=True)
        for helper in ("oc-bridge.py", "oc-bridge-unit.py", "oc-setup-lock.py", "oc-opencode-run.py",
                       "oc-opencode-update.py", "oc-opencode-supervisor.py"):
            shutil.copy2(ROOT / helper, copy_dir / helper)
        launcher_text = (ROOT / "oc-sandbox").read_text(encoding="utf-8")
        needle = "account_home = pwd.getpwuid(os.geteuid()).pw_dir"
        self.assertIn(needle, launcher_text)
        launcher_copy = copy_dir / "oc-sandbox"
        launcher_copy.write_text(launcher_text.replace(needle, "account_home = sys.argv[1]", 1), encoding="utf-8")
        launcher_copy.chmod(0o755)
        return launcher_copy

    def _run_launcher(self, env: dict[str, str], args=("-n", "-i", "t3", "-K"), extra_env=None, script: Path | None = None):
        full_env = dict(env)
        if extra_env:
            full_env.update(extra_env)
        return subprocess.run(
            ["bash", str(script or (ROOT / "oc-sandbox")), *args],
            env=full_env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30,
        )

    def test_invalid_opencode_and_age_env_vars_fail_closed_before_podman(self):
        with tempfile.TemporaryDirectory() as td:
            _, _, _, log, env = self._make_env(Path(td))
            bad_cases = [
                {"OC_OPENCODE_VERSION": "2.3.0"},
                {"OC_OPENCODE_VERSION": "2.3.0", "OC_OPENCODE_SHA256": "short"},
                {"OC_OPENCODE_VERSION": "1.19.2", "OC_OPENCODE_SHA256": "a" * 64},
                {"OC_OPENCODE_SHA256": "a" * 64},
                {"OC_OPENCODE_VERSION": "keep", "OC_OPENCODE_SHA256": "a" * 64},
                {"OC_OPENCODE_VERSION": "baked", "OC_OPENCODE_ARCHIVE_SHA256": "a" * 64},
                {"OC_IMAGE_MAX_AGE_DAYS": "0"},
                {"OC_IMAGE_MAX_AGE_DAYS": "-5"},
                {"OC_IMAGE_MAX_AGE_DAYS": "014"},
                {"OC_IMAGE_MAX_AGE_DAYS": "3651"},
                {"OC_IMAGE_MAX_AGE_DAYS": "abc"},
                {"OC_IMAGE_MAX_AGE_DAYS": "99999999999999999999"},
            ]
            for extra in bad_cases:
                with self.subTest(extra=extra):
                    if log.exists():
                        log.unlink()
                    res = self._run_launcher(env, extra_env=extra)
                    self.assertNotEqual(res.returncode, 0, f"expected refusal for {extra}")
                    self.assertFalse(log.exists(), f"Podman called despite invalid config {extra}")

    def test_updater_failure_falls_back_to_baked_and_never_sets_volume_env(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _, _, _, log, env = self._make_env(root, fail_updater_stage=True)
            script = self._prepare_unmanaged_launcher(root)
            res = self._run_launcher(
                env,
                args=("-i", "t3fail", "-K"),
                extra_env={"OC_OPENCODE_VERSION": "2.3.0", "OC_OPENCODE_SHA256": "b" * 64},
                script=script,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("falling back to baked-in image binary", res.stderr)
            actions = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
            agent_creates = [a for a in actions if a and a[0] == "create" and "--name" in a and "oc-t3fail-agent" in a]
            self.assertEqual(len(agent_creates), 1)
            joined = " ".join(agent_creates[0])
            self.assertNotIn("OC_OPENCODE_EXPECTED_SHA256", joined)
            self.assertNotIn("OC_OPENCODE_USE_VOLUME", joined)

    def test_keep_passes_compat_env_and_default_passes_neither(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _, _, _, log, env = self._make_env(root)
            script = self._prepare_unmanaged_launcher(root)
            res_default = self._run_launcher(env, args=("-i", "t3def", "-K"), script=script)
            self.assertEqual(res_default.returncode, 0, res_default.stderr)
            actions = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
            def_create = [a for a in actions if a and a[0] == "create" and "oc-t3def-agent" in a][0]
            self.assertNotIn("OC_OPENCODE_USE_VOLUME=1", def_create)
            self.assertNotIn("OC_OPENCODE_EXPECTED_SHA256", " ".join(def_create))
            self.assertFalse(any("oc-opencode-update" in " ".join(a) for a in actions))

            log.unlink()
            res_keep = self._run_launcher(env, args=("-i", "t3keep", "-K"), extra_env={"OC_OPENCODE_VERSION": "keep"}, script=script)
            self.assertEqual(res_keep.returncode, 0, res_keep.stderr)
            actions2 = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
            keep_create = [a for a in actions2 if a and a[0] == "create" and "oc-t3keep-agent" in a][0]
            self.assertIn("OC_OPENCODE_USE_VOLUME=1", keep_create)
            self.assertNotIn("OC_OPENCODE_EXPECTED_SHA256", " ".join(keep_create))

    def test_image_age_validation_handles_fresh_stale_missing_future_and_overflow_epochs(self):
        with tempfile.TemporaryDirectory() as td:
            _, _, images, _, env = self._make_env(Path(td))
            # First run builds fresh images.
            first = self._run_launcher(env)
            self.assertEqual(first.returncode, 0, first.stderr)

            chrome_rec = images / "oc-chromium"
            meta = json.loads(chrome_rec.read_text(encoding="utf-8"))
            now = int(time.time())

            # Fresh image -> no warning
            meta["epoch"] = str(now - 3600)
            chrome_rec.write_text(json.dumps(meta), encoding="utf-8")
            fresh = self._run_launcher(env)
            self.assertEqual(fresh.returncode, 0, fresh.stderr)
            self.assertNotIn("warning: image 'oc-chromium'", fresh.stderr)

            # Stale image -> warning with days, -r, and inner sandbox note
            meta["epoch"] = str(now - 20 * 86400)
            chrome_rec.write_text(json.dumps(meta), encoding="utf-8")
            stale = self._run_launcher(env)
            self.assertEqual(stale.returncode, 0, stale.stderr)
            self.assertIn("warning: image 'oc-chromium' is 20 days old", stale.stderr)
            self.assertIn("oc-sandbox -r", stale.stderr)
            self.assertIn("without its inner sandbox", stale.stderr)

            # Missing, non-numeric, pre-2020, future, and 64-bit-overflow epochs -> safe warning, no arithmetic error
            for label, bad_epoch in (
                ("missing", ""),
                ("non-numeric", "not-an-epoch"),
                ("pre-2020", "1000000000"),
                ("future", str(now + 7200)),
                ("overflow", "99999999999999999999999999"),
            ):
                with self.subTest(epoch=label):
                    meta["epoch"] = bad_epoch
                    chrome_rec.write_text(json.dumps(meta), encoding="utf-8")
                    res = self._run_launcher(env)
                    self.assertEqual(res.returncode, 0, res.stderr)
                    self.assertIn("warning: image 'oc-chromium' has", res.stderr)
                    self.assertIn("oc-sandbox -r", res.stderr)

    def test_reproducible_build_context_and_distinct_shell_cache_provenance(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # Two clean runs from identical source produce byte-identical Containerfiles & hashes.
            hashes = []
            artifacts = []
            for idx in (1, 2):
                _, state, images, _, env = self._make_env(root / f"run{idx}", with_host_omz=True)
                res = self._run_launcher(env)
                self.assertEqual(res.returncode, 0, res.stderr)
                build = state / "build"
                self.assertTrue((build / "oh-my-zsh-host.receipt").is_file())
                self.assertFalse((build / "oh-my-zsh-pinned.receipt").exists())
                self.assertIn("source=host-legacy", (build / "oh-my-zsh-host.receipt").read_text(encoding="utf-8"))
                agent_meta = json.loads((images / "oc-agent").read_text(encoding="utf-8"))
                chrome_meta = json.loads((images / "oc-chromium").read_text(encoding="utf-8"))
                hashes.append((agent_meta["hash"], chrome_meta["hash"]))
                artifacts.append((
                    (build / "Containerfile.agent").read_bytes(),
                    (build / "Containerfile.chromium").read_bytes(),
                    (build / "opencode-sandbox.json").read_bytes(),
                ))
            self.assertEqual(hashes[0], hashes[1])
            self.assertEqual(artifacts[0], artifacts[1])

            # Switching to pinned upstream checkout uses separate cache root & receipt and distinct agent_hash.
            run_pinned = root / "run_pinned"
            home, state, images, _, env = self._make_env(run_pinned, with_host_omz=False)
            # Stub git to emit the exact pinned commit SHAs without network.
            src = (ROOT / "oc-sandbox").read_text(encoding="utf-8")
            omz_sha = re.search(r"^OHMYZSH_COMMIT=([0-9a-f]{40})$", src, re.MULTILINE).group(1)
            zvm_sha = re.search(r"^ZSH_VI_MODE_COMMIT=([0-9a-f]{40})$", src, re.MULTILINE).group(1)
            fake_git = run_pinned / "stub" / "git"
            fake_git.write_text(
                f"""#!/usr/bin/python3
import pathlib, sys
args = sys.argv[1:]
if "config" in args:
    sys.exit(0)
if "init" in args:
    d = pathlib.Path(args[-1]); (d / ".git").mkdir(parents=True, exist_ok=True); sys.exit(0)
if "fetch" in args:
    d = pathlib.Path(args[args.index("-C") + 1])
    (d / ".git" / "FETCH_HEAD").write_text(args[-1], encoding="utf-8")
    (d / "oh-my-zsh.sh").write_text("# pinned\\n", encoding="utf-8")
    sys.exit(0)
if "checkout" in args:
    sys.exit(0)
if "rev-parse" in args:
    d = pathlib.Path(args[args.index("-C") + 1])
    print((d / ".git" / "FETCH_HEAD").read_text(encoding="utf-8").strip())
    sys.exit(0)
sys.exit(0)
""",
                encoding="utf-8",
            )
            fake_git.chmod(0o755)
            res_pinned = self._run_launcher(env)
            self.assertEqual(res_pinned.returncode, 0, res_pinned.stderr)
            build_p = state / "build"
            self.assertTrue((build_p / "oh-my-zsh-pinned.receipt").is_file())
            self.assertFalse((build_p / "oh-my-zsh-host.receipt").exists())
            receipt = (build_p / "oh-my-zsh-pinned.receipt").read_text(encoding="utf-8")
            self.assertIn("source=upstream-pinned", receipt)
            self.assertIn(f"ohmyzsh_commit={omz_sha}", receipt)
            self.assertIn(f"zsh_vi_mode_commit={zvm_sha}", receipt)
            pinned_hash = json.loads((images / "oc-agent").read_text(encoding="utf-8"))["hash"]
            self.assertNotEqual(pinned_hash, hashes[0][0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
