"""Offline security and regression harness for AGY Slice 2 (OpenAI interactive shell e2e).

All tests are strictly offline (zero real credentials, zero live network, zero real host changes).
Covers direct CLI opt-in parsing, read-only snapshot provenance, ambient FD immunity, 3-state
ProofGate arming and whole-request canonicalization, lock-safe 12-file exposure accounting,
pinned image IDs against tag drift, and lifecycle-locked SIGKILL-surviving cleanup ownership.
"""

from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from oc_openai.connection import ConnectionError
from oc_openai.exposure import ExposureLedger
from oc_openai.managed import relay as relay_mod
from oc_openai.proof_gate import (
    EXPECTED_REPLY,
    OPENCODE_ZERO_TOOL_INSTRUCTIONS_SHA256,
    PROOF_PROMPT,
    STATE_ARMED,
    STATE_CLOSED_DISCOVERY,
    STATE_SPENT,
    ClosedProofSlotGate,
    ProofApproval,
    ProofGate,
    ProofGateError,
    canonical_proof_body,
    compute_exposure_history_digest,
    compute_providers_config_digest,
)
from oc_openai.session_broker import (
    REQUEST_LENGTH,
    SessionBroker,
    SessionPolicy,
    _SessionJob,
)
from oc_openai.shell_cleanup_owner import (
    PROOF_OWNER_LABEL,
    CleanupOwnerError,
    DetachedShellCleanupOwner,
    JournalSpec,
    _OwnershipJournal,
)
from tests.e2e.live import conftest as live_conftest
from tests.e2e.live import openai_shell_driver as shell_driver
from tests.e2e.live import run_openai_shell_live as snap_runner
from tests.e2e.live import test_openai_shell_e2e as live_test_mod


REPO_ROOT = Path(__file__).resolve().parents[1]
LIVE_FLAG = "--run-openai-shell-live"
MODE_OPT = "--openai-shell-mode"
MODEL_OPT = "--openai-shell-model"
INSTANCE_OPT = "--openai-shell-instance"
SOURCE_OPT = "--openai-shell-source-sha256"
AGENT_IMG_OPT = "--openai-shell-agent-image-id"
RELAY_IMG_OPT = "--openai-shell-relay-image-id"
TARGET_REL = "tests/e2e/live/test_openai_shell_e2e.py"
TEST_MODEL = "gpt-5.4"
TEST_SCOPED = "openai--personal"
TEST_SCOPED_WORK = "openai--work"
TEST_INSTANCE = "e2e-deadbeef"
TEST_POD = "oc-e2e-deadbeef"
TEST_VOLUME = "oc-e2e-deadbeef-openai-home"
TEST_AGENT_TAG = "localhost/oc-agent:latest"
TEST_PYTEST_ADDOPTS = "PYTEST_ADDOPTS"
TEST_PARTIAL = "partial_delivery"
KEY_OUTPUT_INDEX = "output_index"
KEY_CONTENT_INDEX = "content_index"
KEY_OUTPUT_TEXT = "output_text"
KEY_CLEANUP_VERIFIED = "cleanup_verified"
FILE_OC_SANDBOX = "oc-sandbox"
FILE_SETUP_LOCK = "oc-setup-lock.py"
FILE_PROVIDERS_TOML = "providers.toml"
FAKE_EDITOR_NAME = "fake-editor"
TEST_HEX_A = "a" * 64
TEST_HEX_B = "b" * 64
TEST_HEX_C = "c" * 64
TEST_RUN_ID = "1" * 32
TEST_LEVEL = "s0:c10,c20"
TEST_CWD = "wt/e2e-deadbeef"
FAKE_INSTRUCTIONS_TEMPLATE = (
    "OpenCode Synthetic System Prompt\n"
    "Today's date: Wed Nov 25 2026\n"
    "<env>\n"
    "  Working directory: /sandbox/wt/e2e-deadbeef\n"
    "  Workspace root folder: /sandbox/wt/e2e-deadbeef\n"
    "</env>\n"
)
FAKE_INSTRUCTIONS_DIGEST = sha256(
    (
        "OpenCode Synthetic System Prompt\n"
        "Today's date: [date]\n"
        "<env>\n"
        "  Working directory: /sandbox\n"
        "  Workspace root folder: /sandbox\n"
        "</env>\n"
    ).encode("utf-8")
).hexdigest()


def _make_fake_request(
    *,
    worker_token: str,
    body_bytes: bytes,
    port: int = 8401,
    path: str = "/v1/responses",
    method: str = "POST",
) -> bytes:
    headers = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        f"Authorization: Bearer {worker_token}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"\r\n"
    ).encode("ascii")
    return headers + body_bytes


def _send_framed_request(
    sock_path: Path,
    proof: bytes,
    raw_http: bytes,
    *,
    delay_before_body: threading.Event | None = None,
    entered_event: threading.Event | None = None,
    disconnect_mid_response: bool = False,
) -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5.0)
        sock.connect(str(sock_path))
        if entered_event is not None:
            entered_event.set()
        if delay_before_body is not None:
            delay_before_body.wait(timeout=5.0)
        frame = relay_mod.PROOF_PREFIX + proof + REQUEST_LENGTH.pack(len(raw_http)) + raw_http
        sock.sendall(frame)
        if disconnect_mid_response:
            chunk = sock.recv(64)
            return chunk
        chunks = bytearray()
        while True:
            try:
                data = sock.recv(4096)
            except (ConnectionResetError, BrokenPipeError):
                break
            if not data:
                break
            chunks.extend(data)
        return bytes(chunks)


def _ok_sse_events(model: str = TEST_MODEL) -> list[dict[str, object]]:
    return [
        {
            "type": "response.created",
            "response": {"id": "resp_up_1", "object": "response", "status": "in_progress", "model": model, "output": []},
        },
        {
            "type": "response.output_item.added",
            KEY_OUTPUT_INDEX: 0,
            "item": {"id": "msg_1", "type": "message", "status": "in_progress", "role": "assistant", "content": []},
        },
        {
            "type": "response.content_part.added",
            "item_id": "msg_1",
            KEY_OUTPUT_INDEX: 0,
            KEY_CONTENT_INDEX: 0,
            "part": {"type": KEY_OUTPUT_TEXT, "text": "", "annotations": []},
        },
        {
            "type": "response.output_text.delta",
            "item_id": "msg_1",
            KEY_OUTPUT_INDEX: 0,
            KEY_CONTENT_INDEX: 0,
            "delta": EXPECTED_REPLY,
        },
        {
            "type": "response.output_text.done",
            "item_id": "msg_1",
            KEY_OUTPUT_INDEX: 0,
            KEY_CONTENT_INDEX: 0,
            "text": EXPECTED_REPLY,
        },
        {
            "type": "response.content_part.done",
            "item_id": "msg_1",
            KEY_OUTPUT_INDEX: 0,
            KEY_CONTENT_INDEX: 0,
            "part": {"type": KEY_OUTPUT_TEXT, "text": EXPECTED_REPLY, "annotations": []},
        },
        {
            "type": "response.output_item.done",
            KEY_OUTPUT_INDEX: 0,
            "item": {
                "id": "msg_1",
                "type": "message",
                "status": "completed",
                "role": "assistant",
                "content": [{"type": KEY_OUTPUT_TEXT, "text": EXPECTED_REPLY, "annotations": []}],
            },
        },
        {
            "type": "response.completed",
            "response": {
                "id": "resp_up_1",
                "object": "response",
                "status": "completed",
                "model": model,
                "output": [{
                    "id": "msg_1",
                    "type": "message",
                    "status": "completed",
                    "role": "assistant",
                    "content": [{"type": KEY_OUTPUT_TEXT, "text": EXPECTED_REPLY, "annotations": []}],
                }],
                "usage": {"input_tokens": 10, "output_tokens": 1, "total_tokens": 11},
            },
        },
    ]


class _FakeConnection:
    def __init__(self, *, fail_after_write: bool = False, slow_events: bool = False):
        self.calls: list[dict[str, object]] = []
        self.fail_after_write = fail_after_write
        self.slow_events = slow_events

    def require_active(self, _binding) -> None:
        return None

    @contextmanager
    def interactive_responses(self, _binding, body, before_write, **kwargs):
        write_fence = kwargs.get("write_fence")
        fence_cm = write_fence() if write_fence is not None else _null_cm()
        with fence_cm:
            before_write()
            self.calls.append(dict(body))
        if self.fail_after_write:
            raise ConnectionError("chatgpt_unavailable")

        def _gen():
            for ev in _ok_sse_events(body["model"]):
                if self.slow_events:
                    time.sleep(0.05)
                yield ev

        yield _gen()


@contextmanager
def _null_cm():
    yield


def _valid_proof_payload(
    *,
    model: str = TEST_MODEL,
    prompt: str = PROOF_PROMPT,
    instructions: str = FAKE_INSTRUCTIONS_TEMPLATE,
    extra: dict[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "model": model,
        "stream": True,
        "store": False,
        "instructions": instructions,
        "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": prompt}]}],
    }
    if extra:
        payload.update(extra)
    return payload


class TestLiveConftestDirectCliParsing(unittest.TestCase):
    def test_explicit_cli_flag_and_option_arity_rules(self) -> None:
        argv = [TARGET_REL, LIVE_FLAG, MODE_OPT, "mini", MODEL_OPT, TEST_MODEL, INSTANCE_OPT, "personal"]
        self.assertTrue(live_conftest.explicit_cli_flag(LIVE_FLAG, argv))
        self.assertEqual(live_conftest.explicit_cli_option(MODE_OPT, argv), (True, "mini"))
        self.assertEqual(live_conftest.explicit_cli_option(MODEL_OPT, argv), (True, TEST_MODEL))
        self.assertEqual(live_conftest.explicit_cli_option(INSTANCE_OPT, argv), (True, "personal"))

        # Spoofing through preceding option value slots or after '--' must be ignored.
        self.assertFalse(live_conftest.explicit_cli_flag(LIVE_FLAG, ["-k", LIVE_FLAG, TARGET_REL]))
        self.assertFalse(live_conftest.explicit_cli_flag(LIVE_FLAG, [f"-k{LIVE_FLAG}", TARGET_REL]))
        self.assertFalse(live_conftest.explicit_cli_flag(LIVE_FLAG, ["--", LIVE_FLAG]))
        self.assertFalse(live_conftest.explicit_cli_flag(LIVE_FLAG, ["--unknown-opt", LIVE_FLAG]))
        self.assertEqual(live_conftest.explicit_cli_option(MODE_OPT, ["-k", MODE_OPT, "mini"]), (False, None))

        # Duplicates and missing/ambiguous values fail closed.
        with self.assertRaises(ValueError):
            live_conftest.explicit_cli_flag(LIVE_FLAG, [LIVE_FLAG, LIVE_FLAG])
        with self.assertRaises(ValueError):
            live_conftest.explicit_cli_option(MODE_OPT, [MODE_OPT, "mini", MODE_OPT, "full"])
        with self.assertRaises(ValueError):
            live_conftest.explicit_cli_option(MODE_OPT, [MODE_OPT, LIVE_FLAG])

    def test_validate_source_sha256_pin(self) -> None:
        self.assertEqual(live_conftest.validate_source_sha256_pin(TEST_HEX_A), TEST_HEX_A)
        for bad in (None, "", "A" * 64, "a" * 63, "g" * 64):
            with self.assertRaises(ValueError):
                live_conftest.validate_source_sha256_pin(bad)

    def test_assert_no_inherited_live_options_rejects_env_and_ini_forms(self) -> None:
        prefixes = (LIVE_FLAG, "--openai-shell-")
        old_env = os.environ.get(TEST_PYTEST_ADDOPTS)
        try:
            os.environ[TEST_PYTEST_ADDOPTS] = f"{AGENT_IMG_OPT}={TEST_HEX_A}"
            req = SimpleNamespace(config=SimpleNamespace(getini=lambda _k: []))
            with self.assertRaises(ValueError):
                live_conftest.assert_no_inherited_live_options(req, prefixes, target_relpath=TARGET_REL)
            os.environ.pop(TEST_PYTEST_ADDOPTS, None)

            req_str = SimpleNamespace(config=SimpleNamespace(getini=lambda _k: f"{LIVE_FLAG} {MODE_OPT}=mini"))
            with self.assertRaises(ValueError):
                live_conftest.assert_no_inherited_live_options(req_str, prefixes, target_relpath=TARGET_REL)

            req_list = SimpleNamespace(config=SimpleNamespace(getini=lambda _k: [TARGET_REL]))
            with self.assertRaises(ValueError):
                live_conftest.assert_no_inherited_live_options(req_list, prefixes, target_relpath=TARGET_REL)

            req_clean = SimpleNamespace(config=SimpleNamespace(getini=lambda _k: ["-q"]))
            live_conftest.assert_no_inherited_live_options(req_clean, prefixes, target_relpath=TARGET_REL)
        finally:
            if old_env is None:
                os.environ.pop(TEST_PYTEST_ADDOPTS, None)
            else:
                os.environ[TEST_PYTEST_ADDOPTS] = old_env

    def test_require_explicit_test_target(self) -> None:
        target = (REPO_ROOT / TARGET_REL).resolve()
        req = SimpleNamespace(
            config=SimpleNamespace(
                invocation_params=SimpleNamespace(args=[TARGET_REL, LIVE_FLAG], dir=REPO_ROOT),
                args=[TARGET_REL],
            )
        )
        self.assertTrue(live_conftest.require_explicit_test_target(req, target))
        req_missing = SimpleNamespace(
            config=SimpleNamespace(
                invocation_params=SimpleNamespace(args=[LIVE_FLAG], dir=REPO_ROOT),
                args=[TARGET_REL],
            )
        )
        self.assertFalse(live_conftest.require_explicit_test_target(req_missing, target))

    def test_validate_live_invocation_branches_without_pytest(self) -> None:
        digest, _ = snap_runner.capture_manifest(REPO_ROOT)

        def _fake_req(argv, opts, *, args_list, inv_dir, ini_addopts=()):
            return SimpleNamespace(
                config=SimpleNamespace(
                    invocation_params=SimpleNamespace(args=argv, dir=inv_dir),
                    args=args_list,
                    getoption=lambda key, default=None: opts.get(key, default),
                    getini=lambda _k: ini_addopts,
                )
            )

        # Default invocation skips cleanly.
        req_skip = _fake_req([TARGET_REL], {LIVE_FLAG: False}, args_list=[TARGET_REL], inv_dir=REPO_ROOT)
        with self.assertRaises(live_test_mod.SkipLiveTest):
            live_test_mod.validate_live_invocation(req_skip, test_file=REPO_ROOT / TARGET_REL)

        # Direct mutable checkout invocation with all valid options fails closed.
        full_argv = [
            TARGET_REL, LIVE_FLAG,
            MODE_OPT, "mini",
            MODEL_OPT, TEST_MODEL,
            INSTANCE_OPT, "personal",
            SOURCE_OPT, digest,
            AGENT_IMG_OPT, TEST_HEX_A,
            RELAY_IMG_OPT, TEST_HEX_B,
        ]
        full_opts = {
            LIVE_FLAG: True,
            MODE_OPT: "mini",
            MODEL_OPT: TEST_MODEL,
            INSTANCE_OPT: "personal",
            SOURCE_OPT: digest,
            AGENT_IMG_OPT: TEST_HEX_A,
            RELAY_IMG_OPT: TEST_HEX_B,
        }
        req_mutable = _fake_req(full_argv, full_opts, args_list=[TARGET_REL], inv_dir=REPO_ROOT)
        with self.assertRaises(live_test_mod.InvalidLiveInvocation):
            live_test_mod.validate_live_invocation(req_mutable, test_file=REPO_ROOT / TARGET_REL)

        # Identical agent and relay image IDs must be rejected.
        same_img_argv = [
            TARGET_REL, LIVE_FLAG, MODE_OPT, "mini", MODEL_OPT, TEST_MODEL,
            INSTANCE_OPT, "personal", SOURCE_OPT, digest,
            AGENT_IMG_OPT, TEST_HEX_A, RELAY_IMG_OPT, TEST_HEX_A,
        ]
        same_img_opts = dict(full_opts, **{RELAY_IMG_OPT: TEST_HEX_A})
        req_same = _fake_req(same_img_argv, same_img_opts, args_list=[TARGET_REL], inv_dir=REPO_ROOT)
        with self.assertRaises(live_test_mod.InvalidLiveInvocation):
            live_test_mod.validate_live_invocation(req_same, test_file=REPO_ROOT / TARGET_REL)

        # Verified read-only snapshot passes validate_live_invocation cleanly.
        with tempfile.TemporaryDirectory(prefix="oc-val-snap-") as td:
            os.chmod(td, 0o700)
            snapshot = snap_runner.build_read_only_snapshot(REPO_ROOT, digest, base_dir=Path(td))
            try:
                snap_test = snapshot / TARGET_REL
                snap_argv = [
                    str(snap_test), LIVE_FLAG,
                    MODE_OPT, "mini",
                    MODEL_OPT, TEST_MODEL,
                    INSTANCE_OPT, "personal",
                    SOURCE_OPT, digest,
                    AGENT_IMG_OPT, TEST_HEX_A,
                    RELAY_IMG_OPT, TEST_HEX_B,
                ]
                req_snap = _fake_req(snap_argv, full_opts, args_list=[str(snap_test)], inv_dir=snapshot)
                cfg = live_test_mod.validate_live_invocation(req_snap, test_file=snap_test)
                self.assertEqual(cfg.ui_mode, "mini")
                self.assertEqual(cfg.model, TEST_MODEL)
                self.assertEqual(cfg.instance_label, "personal")
                self.assertEqual(cfg.source_sha256, digest)
                self.assertEqual(cfg.agent_image_id, TEST_HEX_A)
                self.assertEqual(cfg.relay_image_id, TEST_HEX_B)
                self.assertEqual(cfg.snapshot_root, snapshot.resolve())

                # Verify constrained pytest args & env produced by run_openai_shell_live.
                ns = SimpleNamespace(
                    mode="mini", model=TEST_MODEL, instance="personal",
                    source_sha256=digest, agent_image_id=TEST_HEX_A, relay_image_id=TEST_HEX_B,
                )
                pytest_cmd = snap_runner._build_pytest_args(ns, snapshot)
                pytest_env = snap_runner._clean_pytest_env(snapshot)
                self.assertEqual(pytest_env.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD"), "1")
                self.assertIn("no:cacheprovider", pytest_cmd)
                self.assertIn("/dev/null", pytest_cmd)
                self.assertIn("addopts=", pytest_cmd)
                self.assertIn("--confcutdir", pytest_cmd)
                self.assertIn("--rootdir", pytest_cmd)
            finally:
                snap_runner.cleanup_snapshot(snapshot)


class TestReadOnlySnapshotProvenance(unittest.TestCase):
    def test_mutable_checkout_refused_and_readonly_snapshot_verified(self) -> None:
        digest, _ = snap_runner.capture_manifest(REPO_ROOT)
        with self.assertRaises(snap_runner.SnapshotError):
            snap_runner.verify_read_only_snapshot(REPO_ROOT, digest)

        with tempfile.TemporaryDirectory(prefix="oc-snap-test-") as td:
            os.chmod(td, 0o700)
            base = Path(td)
            with self.assertRaises(snap_runner.SnapshotError):
                snap_runner.build_read_only_snapshot(REPO_ROOT, TEST_HEX_B, base_dir=base)
            self.assertEqual(list(base.iterdir()), [])

            snapshot = snap_runner.build_read_only_snapshot(REPO_ROOT, digest, base_dir=base)
            try:
                self.assertEqual(snap_runner.verify_read_only_snapshot(snapshot, digest), digest)
                self.assertEqual(stat.S_IMODE(snapshot.lstat().st_mode), 0o500)
                conftest_mode = stat.S_IMODE((snapshot / "tests/e2e/live/conftest.py").lstat().st_mode)
                self.assertEqual(conftest_mode, 0o400)

                # Tampering a file after restoring write bit must fail verification.
                target_file = snapshot / "tests/e2e/live/conftest.py"
                os.chmod(target_file.parent, 0o700)
                os.chmod(target_file, 0o600)
                target_file.write_text("# tampered\n", encoding="utf-8")
                os.chmod(target_file, 0o400)
                os.chmod(target_file.parent, 0o500)
                with self.assertRaises(snap_runner.SnapshotError):
                    snap_runner.verify_read_only_snapshot(snapshot, digest)
            finally:
                snap_runner.cleanup_snapshot(snapshot)
            self.assertFalse(snapshot.exists())


class TestAmbientFdImmunity(unittest.TestCase):
    def test_direct_oc_openai_session_ignores_caller_fds_4_and_5(self) -> None:
        with tempfile.TemporaryDirectory(prefix="oc-fd-test-") as td:
            os.chmod(td, 0o700)
            grant_path = Path(td) / "grant.json"
            grant_path.write_text('{"approved_model":"gpt-5.4"}\n', encoding="utf-8")
            os.chmod(grant_path, 0o600)
            spec_path = Path(td) / "spec.json"
            spec_path.write_text(
                json.dumps({
                    "instance": TEST_INSTANCE,
                    "pod": TEST_POD,
                    "agent": f"{TEST_POD}-agent",
                    "relay": f"{TEST_POD}-openai-relay",
                    "relay_image": TEST_HEX_A,
                    "agent_image": TEST_HEX_B,
                    "agent_mem": "4g",
                    "level": TEST_LEVEL,
                    "sandbox": str(Path.home() / "opencode-sandbox"),
                    "cwd": TEST_CWD,
                    "home_vol": TEST_VOLUME,
                    "chromium": f"{TEST_POD}-chromium",
                    "postgres": "",
                    "pg_secret": "",
                    "dind": "",
                    "dind_run": "",
                    "provider_filter": "",
                    "cli_ui_mode": "mini",
                }),
                encoding="utf-8",
            )
            os.chmod(spec_path, 0o600)
            proc = subprocess.run(
                [
                    "bash",
                    "-c",
                    'exec "$1" -IB "$2" 3<"$3" 4<"$4" 5< <(sleep 2)',
                    "_",
                    sys.executable,
                    str(REPO_ROOT / "oc-openai-session.py"),
                    str(spec_path),
                    str(grant_path),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            self.assertEqual(proc.returncode, 2, proc.stderr.decode("utf-8", errors="replace"))
            self.assertIn(b"attended foreground workstation terminal", proc.stderr)

    def test_ordinary_oc_sandbox_ignores_fds_4_5_and_matches_session_spec_schema(self) -> None:
        with tempfile.TemporaryDirectory(prefix="oc-sb-parity-") as td_raw:
            td = Path(td_raw)
            os.chmod(td, 0o700)
            launcher_dir = td / "launcher"
            launcher_dir.mkdir(mode=0o700)
            for fname in (FILE_OC_SANDBOX, FILE_SETUP_LOCK, "oc-bridge.py",
                          "oc-opencode-run.py", "oc-opencode-update.py", "oc-opencode-supervisor.py"):
                dst = launcher_dir / fname
                dst.write_bytes((REPO_ROOT / fname).read_bytes())
                os.chmod(dst, 0o755 if fname == FILE_OC_SANDBOX else 0o644)

            # Stub oc-openai-session.py inside scratch launcher dir to capture exact fd 3 JSON.
            spec_out = td / "emitted_spec.json"
            stub_helper = launcher_dir / "oc-openai-session.py"
            stub_helper.write_text(
                "import os, sys\n"
                "from pathlib import Path\n"
                "data = os.fdopen(3, 'rb').read()\n"
                f"Path({str(spec_out)!r}).write_bytes(data)\n"
                "raise SystemExit(0)\n",
                encoding="utf-8",
            )
            os.chmod(stub_helper, 0o644)

            stub_bin = td / "bin"
            stub_bin.mkdir(mode=0o700)
            for tool in ("systemctl", FAKE_EDITOR_NAME):
                p = stub_bin / tool
                p.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                os.chmod(p, 0o755)

            fake_podman = stub_bin / "podman"
            fake_podman.write_text(
                f"""#!/usr/bin/bash
case "$1 $2" in
  "--version "*) echo "podman version 5.0.0"; exit 0 ;;
  "image inspect")
    if [[ "$*" == *"oc.hash"* ]]; then echo ""; exit 1; fi
    if [[ "$*" == *"oc-openai-relay"* ]]; then echo "{TEST_HEX_B}"; exit 0; fi
    echo "{TEST_HEX_A}"; exit 0 ;;
  "volume exists") exit 0 ;;
  "pod exists") exit 1 ;;
  "pod inspect")
    if [[ "$*" == *"oc.ports"* ]]; then echo ""; exit 0; fi
    if [[ "$*" == *"PortBindings"* ]]; then echo "{{}}"; exit 0; fi
    if [[ "$*" == *"oc.podcfg"* ]]; then echo "v1|"; exit 0; fi
    exit 0 ;;
  "container exists") exit 1 ;;
  "container inspect")
    target="${{@: -1}}"
    if [[ "$*" == *".State.Status"* && "$target" == *-chromium ]]; then echo "running"; exit 0; fi
    if [[ "$*" == *".Image"* && "$target" == *-chromium ]]; then echo "{TEST_HEX_A}"; exit 0; fi
    exit 1 ;;
  *) exit 0 ;;
esac
""",
                encoding="utf-8",
            )
            os.chmod(fake_podman, 0o755)

            home = td / "home"
            home.mkdir(mode=0o700)
            (home / ".oh-my-zsh/custom/plugins/zsh-vi-mode").mkdir(parents=True, mode=0o700)
            pol_dir = home / ".local/share/oc-sandbox/policy"
            pol_dir.mkdir(parents=True, mode=0o700)
            cil_text = (REPO_ROOT / FILE_OC_SANDBOX).read_text(encoding="utf-8")
            start = cil_text.index("; SELinux type for the sandboxed Chromium container only")
            end = cil_text.index("\nPOL\n", start)
            pol_hash = sha256((cil_text[start:end] + "\n").encode("utf-8")).hexdigest()[:16]
            (pol_dir / "installed").write_text(pol_hash + "\n", encoding="utf-8")
            (home / ".local/share/oc-sandbox/sb-level").write_text(f"{TEST_LEVEL}\n", encoding="utf-8")
            cfg_dir = home / ".config/oc-sandbox"
            cfg_dir.mkdir(parents=True, mode=0o700)
            (cfg_dir / FILE_PROVIDERS_TOML).write_text("[launch]\n", encoding="utf-8")
            os.chmod(cfg_dir / FILE_PROVIDERS_TOML, 0o600)
            grant_file = td / "ambient_grant.json"
            grant_file.write_text('{"approved_model":"gpt-5.4"}\n', encoding="utf-8")
            os.chmod(grant_file, 0o600)

            env = {
                "PATH": f"{stub_bin}:/usr/bin:/bin",
                "HOME": str(home),
                "OC_CHROMIUM_MODE": "headless",
                "OC_CODE_BIN": str(stub_bin / FAKE_EDITOR_NAME),
                "OC_BCOMPARE_BIN": str(stub_bin / FAKE_EDITOR_NAME),
            }
            for extra_args, want_ui in (([], "default"), (["--mini"], "mini")):
                spec_out.unlink(missing_ok=True)
                args_str = " ".join(extra_args)
                proc = subprocess.run(
                    [
                        "bash", "-c",
                        f'exec bash "$1" -i {TEST_INSTANCE} -K {args_str} 4<"$2" 5< <(sleep 2)',
                        "_",
                        str(launcher_dir / FILE_OC_SANDBOX),
                        str(grant_file),
                    ],
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=20,
                    check=False,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", errors="replace"))
                emitted = json.loads(spec_out.read_text(encoding="utf-8"))
                self.assertEqual(emitted["instance"], TEST_INSTANCE)
                self.assertEqual(emitted["pod"], TEST_POD)
                self.assertEqual(emitted["agent"], f"{TEST_POD}-agent")
                self.assertEqual(emitted["relay"], f"{TEST_POD}-openai-relay")
                self.assertEqual(emitted["relay_image"], TEST_HEX_B)
                self.assertEqual(emitted["agent_image"], TEST_HEX_A)
                self.assertEqual(emitted["level"], TEST_LEVEL)
                self.assertEqual(emitted["sandbox"], str(home / "opencode-sandbox"))
                self.assertEqual(emitted["cwd"], TEST_CWD)
                self.assertEqual(emitted["home_vol"], TEST_VOLUME)
                self.assertEqual(emitted["chromium"], f"{TEST_POD}-chromium")
                self.assertEqual(emitted["provider_filter"], "")
                self.assertEqual(emitted["cli_ui_mode"], want_ui)

    def test_pytest_live_default_skip_and_mutable_checkout_refusal(self) -> None:
        check = subprocess.run(
            [sys.executable, "-IB", "-m", "pytest", "--version"],
            capture_output=True,
            check=False,
        )
        if check.returncode != 0:
            self.skipTest("pytest not installed in interpreter")
        base_env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", ""),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        # 1. Default run skips cleanly with 0 dispatches.
        skip_run = subprocess.run(
            [sys.executable, "-IB", "-m", "pytest", "-q", TARGET_REL],
            cwd=str(REPO_ROOT),
            env=base_env,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(skip_run.returncode, 0, skip_run.stdout + skip_run.stderr)
        self.assertIn("1 skipped", skip_run.stdout)

        # 2. PYTEST_ADDOPTS injection fails closed.
        env_inject = dict(base_env, PYTEST_ADDOPTS=LIVE_FLAG)
        inject_run = subprocess.run(
            [sys.executable, "-IB", "-m", "pytest", "-q", TARGET_REL],
            cwd=str(REPO_ROOT),
            env=env_inject,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertNotEqual(inject_run.returncode, 0)
        self.assertIn("inherited pytest option forbidden", inject_run.stdout + inject_run.stderr)

        # 3. Direct mutable checkout run with all valid flags fails closed before any provider access.
        digest, _ = snap_runner.capture_manifest(REPO_ROOT)
        mutable_run = subprocess.run(
            [
                sys.executable, "-IB", "-m", "pytest", "-q",
                TARGET_REL, LIVE_FLAG,
                MODE_OPT, "mini",
                MODEL_OPT, TEST_MODEL,
                INSTANCE_OPT, "personal",
                SOURCE_OPT, digest,
            ],
            cwd=str(REPO_ROOT),
            env=base_env,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertNotEqual(mutable_run.returncode, 0)
        self.assertIn("owner-only read-only verified snapshot", mutable_run.stdout + mutable_run.stderr)


class TestProofGateThreeStateAndAccounting(unittest.TestCase):
    def _make_gate(self, td: Path, exposure_dir: Path, *, cwd: str = TEST_CWD) -> ProofGate:
        evidence_dir = td / "evidence"
        evidence_dir.mkdir(mode=0o700)
        os.chmod(evidence_dir, 0o700)
        hist = compute_exposure_history_digest(exposure_dir)
        approval = ProofApproval(
            run_id=TEST_RUN_ID,
            instance_label="personal",
            scoped_provider_id=TEST_SCOPED,
            approved_model=TEST_MODEL,
            ui_mode="mini",
            cwd=cwd,
            selection_epoch="E" * 43,
            credential_generation=1,
            history_digest_all_12_files=hist,
        )
        return ProofGate(
            approval,
            evidence_dir=evidence_dir,
            exposure_dir=exposure_dir,
            expected_instructions_sha256=FAKE_INSTRUCTIONS_DIGEST,
        )

    def test_three_state_queued_prearming_whole_request_and_closed_slot_sequence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="oc-gate-test-") as td_raw:
            td = Path(td_raw)
            os.chmod(td, 0o700)
            exposure_dir = td / "exposure"
            exposure_dir.mkdir(mode=0o700)
            os.chmod(exposure_dir, 0o700)
            slot_root = td / "slot0"
            slot_root.mkdir(mode=0o700)
            os.chmod(slot_root, 0o700)
            other_root = td / "slot1"
            other_root.mkdir(mode=0o700)
            os.chmod(other_root, 0o700)

            gate = self._make_gate(td, exposure_dir)
            closed_slot_gate = ClosedProofSlotGate(TEST_SCOPED_WORK)

            job0 = _SessionJob(slot_root, "inc_slot0_12345678")
            job0.prepare(config_payload=None)
            job0.activate()
            gate.bind_incarnation(job0.incarnation, job0.generation)
            with self.assertRaises(ProofGateError):
                gate.bind_incarnation(job0.incarnation, job0.generation)

            job1 = _SessionJob(other_root, "inc_slot1_87654321")
            job1.prepare(config_payload=None)
            job1.activate()

            conn0 = _FakeConnection()
            conn1 = _FakeConnection()
            tok0 = "tok-personal-valid"
            tok1 = "tok-work-valid"
            broker0 = SessionBroker(
                socket_path=job0.provider_socket,
                relay_proof=job0.relay_proof,
                worker_token=tok0,
                lease=job0.lease,
                connection=conn0,
                binding=SimpleNamespace(generation=1),
                models=(TEST_MODEL, "gpt-5.4-mini"),
                profile_label="personal",
                expected_port=8401,
                policy=SessionPolicy(
                    exposure_dir=exposure_dir,
                    proof_gate=gate,
                    job_incarnation=job0.incarnation,
                ),
            )
            broker1 = SessionBroker(
                socket_path=job1.provider_socket,
                relay_proof=job1.relay_proof,
                worker_token=tok1,
                lease=job1.lease,
                connection=conn1,
                binding=SimpleNamespace(generation=1),
                models=(TEST_MODEL,),
                profile_label="work",
                expected_port=8402,
                policy=SessionPolicy(
                    exposure_dir=exposure_dir,
                    proof_gate=closed_slot_gate,
                    job_incarnation=job1.incarnation,
                ),
            )
            broker0.start()
            broker1.start()
            try:
                good_body = json.dumps(_valid_proof_payload()).encode("utf-8")

                # 1. Exact-shaped request during CLOSED_DISCOVERY -> 403, 0 writes.
                resp_early = _send_framed_request(
                    job0.provider_socket, job0.relay_proof,
                    _make_fake_request(worker_token=tok0, body_bytes=good_body),
                )
                self.assertIn(b"403 Forbidden", resp_early)
                self.assertEqual(len(conn0.calls), 0)

                # 2. Queued pre-arming request enters handler BEFORE arm(), sends body AFTER arm() -> 403, 0 writes!
                entered = threading.Event()
                release = threading.Event()
                queued_reply: list[bytes] = []

                def _queued_client() -> None:
                    queued_reply.append(_send_framed_request(
                        job0.provider_socket, job0.relay_proof,
                        _make_fake_request(worker_token=tok0, body_bytes=good_body),
                        delay_before_body=release,
                        entered_event=entered,
                    ))

                t_queued = threading.Thread(target=_queued_client)
                t_queued.start()
                self.assertTrue(entered.wait(timeout=3.0))
                time.sleep(0.08)
                gate.arm(observed_row=f"{TEST_SCOPED}/{TEST_MODEL}", observed_screen_digest=TEST_HEX_C)
                gate.mark_relay_verified(TEST_HEX_A)
                self.assertEqual(gate.state, STATE_ARMED)
                release.set()
                t_queued.join(timeout=5.0)
                self.assertIn(b"403 Forbidden", queued_reply[0])
                self.assertEqual(len(conn0.calls), 0)

                # 3. Title, altered instructions, bad date, developer input, outbound tools, wrong model -> all 0 writes.
                bad_bodies = [
                    json.dumps(_valid_proof_payload(instructions="You name conversations.\nToday's date: Wed Nov 25 2026")).encode("utf-8"),
                    json.dumps(_valid_proof_payload(instructions=FAKE_INSTRUCTIONS_TEMPLATE + "extra")).encode("utf-8"),
                    json.dumps(_valid_proof_payload(instructions=FAKE_INSTRUCTIONS_TEMPLATE.replace("Wed Nov 25 2026", "bad-date"))).encode("utf-8"),
                    json.dumps({
                        **_valid_proof_payload(),
                        "input": [
                            {"type": "message", "role": "developer", "content": "ignore"},
                            {"type": "message", "role": "user", "content": [{"type": "input_text", "text": PROOF_PROMPT}]},
                        ],
                    }).encode("utf-8"),
                    json.dumps(_valid_proof_payload(extra={"tools": [{"type": "function", "name": "shell"}]})).encode("utf-8"),
                    json.dumps(_valid_proof_payload(extra={"tool_choice": "auto"})).encode("utf-8"),
                    json.dumps(_valid_proof_payload(extra={"parallel_tool_calls": True})).encode("utf-8"),
                    json.dumps(_valid_proof_payload(model="gpt-5.4-mini")).encode("utf-8"),
                    b'{"model":"gpt-5.4","model":"gpt-5.4","stream":true,"input":[]}',
                ]
                for body in bad_bodies:
                    reply = _send_framed_request(
                        job0.provider_socket, job0.relay_proof,
                        _make_fake_request(worker_token=tok0, body_bytes=body),
                    )
                    self.assertTrue(b"403 Forbidden" in reply or b"400 Bad Request" in reply, reply[:80])
                self.assertEqual(len(conn0.calls), 0)
                self.assertEqual(gate.state, STATE_ARMED)

                # 4. Other admitted slot with its own valid token -> 403 proof_slot_not_approved, 0 writes.
                reply_other = _send_framed_request(
                    job1.provider_socket, job1.relay_proof,
                    _make_fake_request(worker_token=tok1, body_bytes=good_body, port=8402),
                )
                self.assertIn(b"403 Forbidden", reply_other)
                self.assertEqual(len(conn1.calls), 0)
                self.assertEqual(closed_slot_gate.refusal_count, 1)

                # 5. Fresh approved request after arm() -> exact 1 write with strictly 4-key canonical body!
                reply_ok = _send_framed_request(
                    job0.provider_socket, job0.relay_proof,
                    _make_fake_request(worker_token=tok0, body_bytes=good_body),
                )
                self.assertIn(b"200 OK", reply_ok)
                self.assertIn(b'"delta":"ok"', reply_ok)
                self.assertEqual(len(conn0.calls), 1)
                self.assertEqual(conn0.calls[0], canonical_proof_body(TEST_MODEL))
                self.assertEqual(gate.state, STATE_SPENT)
                self.assertEqual(gate.admitted_writes, 1)
                self.assertTrue(gate.exact_ok_delivered)

                # 6. Post-spend second request -> 403 proof_gate_spent, 0 additional writes.
                reply_second = _send_framed_request(
                    job0.provider_socket, job0.relay_proof,
                    _make_fake_request(worker_token=tok0, body_bytes=good_body),
                )
                self.assertIn(b"403 Forbidden", reply_second)
                self.assertEqual(len(conn0.calls), 1)
            finally:
                broker0.close()
                broker1.close()
                job0.revoke()
                job1.revoke()

    def test_unsettled_retained_on_upstream_error_and_partial_delivery(self) -> None:
        for scenario in ("upstream_error", TEST_PARTIAL):
            with tempfile.TemporaryDirectory(prefix="oc-unsettled-") as td_raw:
                td = Path(td_raw)
                os.chmod(td, 0o700)
                exposure_dir = td / "exposure"
                exposure_dir.mkdir(mode=0o700)
                os.chmod(exposure_dir, 0o700)
                slot_root = td / "slot"
                slot_root.mkdir(mode=0o700)
                os.chmod(slot_root, 0o700)

                gate = self._make_gate(td, exposure_dir)
                job = _SessionJob(slot_root, f"inc_{scenario}_1234")
                job.prepare(config_payload=None)
                job.activate()
                ev_path = gate.bind_incarnation(job.incarnation, job.generation)
                gate.arm(observed_row=f"{TEST_SCOPED}/{TEST_MODEL}", observed_screen_digest=TEST_HEX_C)
                gate.mark_relay_verified(TEST_HEX_A)

                conn = _FakeConnection(
                    fail_after_write=(scenario == "upstream_error"),
                    slow_events=(scenario == TEST_PARTIAL),
                )
                broker = SessionBroker(
                    socket_path=job.provider_socket,
                    relay_proof=job.relay_proof,
                    worker_token="tok-unsettled",
                    lease=job.lease,
                    connection=conn,
                    binding=SimpleNamespace(generation=1),
                    models=(TEST_MODEL,),
                    profile_label="personal",
                    expected_port=8401,
                    policy=SessionPolicy(
                        exposure_dir=exposure_dir,
                        proof_gate=gate,
                        job_incarnation=job.incarnation,
                    ),
                )
                broker.start()
                try:
                    good_body = json.dumps(_valid_proof_payload()).encode("utf-8")
                    _send_framed_request(
                        job.provider_socket, job.relay_proof,
                        _make_fake_request(worker_token="tok-unsettled", body_bytes=good_body),
                        disconnect_mid_response=(scenario == TEST_PARTIAL),
                    )
                    time.sleep(0.25)
                finally:
                    broker.close()
                    job.revoke()

                evidence = json.loads(ev_path.read_text(encoding="utf-8"))
                self.assertEqual(evidence["admitted_writes"], 1)
                self.assertTrue(evidence["write_attempted"])
                self.assertFalse(evidence["exact_ok_delivered"])
                self.assertEqual(evidence["outcome"], "unsettled")

    def test_unblocked_12_file_digest_distinguishes_histories_and_blocks_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="oc-hist-") as td_raw:
            td = Path(td_raw)
            os.chmod(td, 0o700)
            exp = td / "exposure"
            exp.mkdir(mode=0o700)
            os.chmod(exp, 0o700)

            d1 = compute_exposure_history_digest(exp)
            self.assertEqual(len(d1), 64)
            canary_file = exp / "canary.json"
            canary_file.write_text('{"outcome":"exact_ok"}\n', encoding="utf-8")
            os.chmod(canary_file, 0o600)
            d2 = compute_exposure_history_digest(exp)
            self.assertEqual(len(d2), 64)
            self.assertNotEqual(d1, d2)

            # Mutating an unblocked receipt after approval blocks claim_for_write with 0 writes.
            gate = self._make_gate(td, exp)
            gate.bind_incarnation("inc_hist_mut_1234", 1)
            gate.arm(observed_row=f"{TEST_SCOPED}/{TEST_MODEL}", observed_screen_digest=TEST_HEX_C)
            gate.mark_relay_verified(TEST_HEX_A)
            arrival = gate.snapshot_arrival()
            canon = canonical_proof_body(TEST_MODEL)
            canary_file.write_text('{"outcome":"changed"}\n', encoding="utf-8")
            with self.assertRaises(ProofGateError):
                gate.claim_for_write(arrival, canon, job_incarnation="inc_hist_mut_1234")
            self.assertEqual(gate.admitted_writes, 0)

    def test_split_discovery_cutover_and_replacement_listener_before_verify(self) -> None:
        with tempfile.TemporaryDirectory(prefix="oc-cutover-") as td_raw:
            td = Path(td_raw)
            os.chmod(td, 0o700)
            exp = td / "exposure"
            exp.mkdir(mode=0o700)
            os.chmod(exp, 0o700)
            disc_root = td / "disc"
            disc_root.mkdir(mode=0o700)
            os.chmod(disc_root, 0o700)
            turn_root = td / "turn"
            turn_root.mkdir(mode=0o700)
            os.chmod(turn_root, 0o700)

            gate = self._make_gate(td, exp)
            disc_gate = ClosedProofSlotGate(TEST_SCOPED, refusal_code="proof_gate_not_armed")
            disc_job = _SessionJob(disc_root, "disc_1234567890ab")
            disc_job.prepare(config_payload=None)
            disc_job.activate()
            conn = _FakeConnection()
            tok = "tok-cutover-valid"
            good_body = json.dumps(_valid_proof_payload()).encode("utf-8")
            raw_req = _make_fake_request(worker_token=tok, body_bytes=good_body)

            # Case 1a: a complete request queued on an unaccepted discovery socket dies with the old listener.
            raw_disc_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            raw_disc_sock = disc_root / "queued_disc.sock"
            raw_disc_listener.bind(str(raw_disc_sock))
            raw_disc_listener.listen(4)
            queued_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            queued_sock.settimeout(2.0)
            queued_sock.connect(str(raw_disc_sock))
            queued_sock.sendall(
                relay_mod.PROOF_PREFIX + disc_job.relay_proof + REQUEST_LENGTH.pack(len(raw_req)) + raw_req
            )
            raw_disc_listener.close()
            raw_disc_sock.unlink(missing_ok=True)
            try:
                data = queued_sock.recv(128)
                self.assertEqual(data, b"")
            except (ConnectionResetError, BrokenPipeError):
                pass
            finally:
                queued_sock.close()
            self.assertEqual(len(conn.calls), 0)

            # Case 1b: a held discovery handler blocks cutover until it exits (0 turn listener started, 0 writes).
            disc_broker = SessionBroker(
                socket_path=disc_job.provider_socket,
                relay_proof=disc_job.relay_proof,
                worker_token=tok,
                lease=disc_job.lease,
                connection=conn,
                binding=SimpleNamespace(generation=1),
                models=(TEST_MODEL,),
                profile_label="personal",
                expected_port=8401,
                policy=SessionPolicy(exposure_dir=exp, proof_gate=disc_gate, job_incarnation=disc_job.incarnation),
            )
            in_handler = threading.Event()
            release_handler = threading.Event()
            orig_handle = disc_broker._handle_peer

            def _held_handle(peer):
                in_handler.set()
                release_handler.wait(timeout=5.0)
                return orig_handle(peer)

            disc_broker._handle_peer = _held_handle
            disc_broker.start()
            held_reply: list[bytes] = []
            t_held = threading.Thread(
                target=lambda: held_reply.append(_send_framed_request(disc_job.provider_socket, disc_job.relay_proof, raw_req))
            )
            t_held.start()
            self.assertTrue(in_handler.wait(timeout=3.0))
            with disc_broker._lock:
                self.assertTrue(bool(disc_broker._clients))
            release_handler.set()
            t_held.join(timeout=5.0)
            disc_broker.close()
            disc_job.revoke()
            self.assertEqual(len(conn.calls), 0)
            self.assertTrue(b"403 Forbidden" in held_reply[0] or held_reply[0] == b"")

            # Case 1c: replacement turn listener BEFORE mark_relay_verified() returns 403 (0 writes);
            # after mark_relay_verified(), one fresh control request succeeds with exact 1 write!
            turn_job = _SessionJob(turn_root, "inc_turn_12345678")
            turn_job.prepare(config_payload=None)
            turn_job.activate()
            self.assertNotEqual(turn_job.relay_proof, disc_job.relay_proof)
            gate.bind_incarnation(turn_job.incarnation, turn_job.generation)
            gate.arm(observed_row=f"{TEST_SCOPED}/{TEST_MODEL}", observed_screen_digest=TEST_HEX_C)
            turn_broker = SessionBroker(
                socket_path=turn_job.provider_socket,
                relay_proof=turn_job.relay_proof,
                worker_token=tok,
                lease=turn_job.lease,
                connection=conn,
                binding=SimpleNamespace(generation=1),
                models=(TEST_MODEL,),
                profile_label="personal",
                expected_port=8401,
                policy=SessionPolicy(exposure_dir=exp, proof_gate=gate, job_incarnation=turn_job.incarnation),
            )
            turn_broker.start()
            try:
                # Replaying old discovery_proof against turn broker -> 0 writes.
                replay_resp = _send_framed_request(turn_job.provider_socket, disc_job.relay_proof, raw_req)
                self.assertEqual(replay_resp, b"")
                self.assertEqual(len(conn.calls), 0)

                # Valid turn_relay_proof on replacement listener BEFORE mark_relay_verified() -> 403, 0 writes!
                pre_verify_resp = _send_framed_request(turn_job.provider_socket, turn_job.relay_proof, raw_req)
                self.assertIn(b"403 Forbidden", pre_verify_resp)
                self.assertIn(b"proof_gate_relay_unverified", pre_verify_resp)
                self.assertEqual(len(conn.calls), 0)

                # After mark_relay_verified(), fresh control request succeeds with exact 1 canonical write!
                gate.mark_relay_verified(TEST_HEX_A)
                fresh_resp = _send_framed_request(turn_job.provider_socket, turn_job.relay_proof, raw_req)
                self.assertIn(b"200 OK", fresh_resp)
                self.assertEqual(len(conn.calls), 1)
                self.assertEqual(conn.calls[0], canonical_proof_body(TEST_MODEL))
            finally:
                turn_broker.close()
                turn_job.revoke()

    @staticmethod
    def _pick_free_relay_port() -> int:
        for candidate in range(8410, 8480):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                try:
                    probe.bind(("127.0.0.1", candidate))
                except OSError:
                    continue
                return candidate
        raise AssertionError("No free relay port in 8410..8479")

    @staticmethod
    def _wait_tcp_port_bound(port: int, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    return True
            except OSError:
                time.sleep(0.05)
        return False

    @staticmethod
    def _send_tcp_http(port: int, raw_req: bytes) -> bytes:
        with socket.create_connection(("127.0.0.1", port), timeout=3.0) as sock:
            sock.settimeout(3.0)
            sock.sendall(raw_req)
            chunks = []
            while True:
                part = sock.recv(4096)
                if not part:
                    break
                chunks.append(part)
        return b"".join(chunks)

    def test_ordinary_session_omits_defer_bind_binds_while_pending_and_matches_source(self) -> None:
        import contextlib
        from oc_openai import session_broker, session_relay
        from oc_openai.session_adapter import OpenAISessionAdapter, _OpenAISlotTarget
        from oc_providers.contracts import InstancePreflight, ProviderInstanceSpec, ReadinessState

        class _MiniAdapterBackend:
            def __init__(self, state_dir: Path):
                self._state = state_dir

            @contextlib.contextmanager
            def profile_session_lease(self, *_args, **_kwargs):
                yield SimpleNamespace(root="r")

            def profile_fence(self, *_args, **_kwargs):
                return contextlib.nullcontext()

            def profile_valid(self, *_args, **_kwargs):
                return True

        with tempfile.TemporaryDirectory(prefix="oc-ord-relay-") as td_raw:
            td = Path(td_raw)
            os.chmod(td, 0o700)
            exp = td / "exposure"
            exp.mkdir(mode=0o700)
            os.chmod(exp, 0o700)
            ord_root = td / "ord"
            ord_root.mkdir(mode=0o700)
            os.chmod(ord_root, 0o700)
            ord_port = self._pick_free_relay_port()
            ord_job = _SessionJob(ord_root, "inc_" + "f" * 32)
            ord_job.prepare(config_payload=None)
            self.assertEqual(
                (ord_job.source_dir / "session_relay.py").read_bytes(),
                (REPO_ROOT / "oc_openai" / "session_relay.py").read_bytes(),
            )
            self.assertEqual(
                (ord_job.source_dir / "relay.py").read_bytes(),
                (REPO_ROOT / "oc_openai" / "managed" / "relay.py").read_bytes(),
            )
            spec_stub = {
                "pod": TEST_POD, "instance": TEST_INSTANCE, "relay": f"{TEST_POD}-relay",
                "relay_image": TEST_HEX_B,
            }
            ord_argv = session_broker._build_relay_args(spec_stub, ord_job, slot_index=0, port=ord_port)
            self.assertNotIn("--defer-bind", ord_argv)
            self.assertEqual(
                ord_argv[-7:-2],
                ["python3", "-B", "/source/session_relay.py", ord_job.incarnation, str(ord_job.generation)],
            )
            self.assertEqual(ord_argv[-1], str(ord_port))
            turn_argv = session_broker._build_relay_args(
                spec_stub, ord_job, slot_index=0, port=ord_port, defer_bind=True,
            )
            self.assertEqual(turn_argv[-2:], [str(ord_port), "--defer-bind"])

            fake_profile = SimpleNamespace(
                label="personal", epoch="E" * 43, directory=td / "prof", client_id="cid-1",
            )
            fake_preflight = InstancePreflight(
                spec=ProviderInstanceSpec(kind="openai", label="personal", enabled=True, auth_mode="subscription"),
                readiness=ReadinessState.READY,
                models=(TEST_MODEL,),
                exposure_hold=None,
                handle=_OpenAISlotTarget(profile=fake_profile, conn=_FakeConnection(), binding=SimpleNamespace(generation=1)),
            )
            ord_adapter = OpenAISessionAdapter(_MiniAdapterBackend(exp), proof_gate=None)
            with ord_adapter.open_slot(
                fake_preflight, slot_index=0, slot_root=td / "adp_ord",
                port=ord_port, worker_token="tok-ord",
                acknowledged_exposure_digest=None, on_revoke=lambda _i: None,
            ) as h_ord:
                self.assertNotIn("--defer-bind", h_ord.build_relay_args(spec_stub))

            gate_adp = self._make_gate(td, exp)
            proof_adapter = OpenAISessionAdapter(_MiniAdapterBackend(exp), proof_gate=gate_adp)
            with proof_adapter.open_discovery_slot(
                fake_preflight, slot_index=0, slot_root=td / "adp_disc",
                port=ord_port, worker_token="tok-disc",
                acknowledged_exposure_digest=None, on_revoke=lambda _i: None,
            ) as h_disc:
                self.assertNotIn("--defer-bind", h_disc.build_relay_args(spec_stub))
            with proof_adapter.open_slot(
                fake_preflight, slot_index=0, slot_root=td / "adp_turn",
                port=ord_port, worker_token="tok-turn",
                acknowledged_exposure_digest=None, on_revoke=lambda _i: None,
            ) as h_turn:
                self.assertEqual(h_turn.build_relay_args(spec_stub)[-2:], [str(ord_port), "--defer-bind"])

            t_ord = threading.Thread(
                target=session_relay.serve,
                args=(ord_job.lease, ord_job.relay_proof),
                kwargs={"port": ord_port, "defer_bind": False},
                daemon=True,
            )
            t_ord.start()
            try:
                self.assertTrue(
                    self._wait_tcp_port_bound(ord_port),
                    "Ordinary relay (defer_bind=False) must bind while lease is pending",
                )
            finally:
                ord_job.revoke()
                t_ord.join(timeout=5.0)

    def test_deferred_bind_relay_blocks_pre_verify_backlog_and_allows_fresh_control(self) -> None:
        from oc_openai import session_relay

        # 1. CLI fail-closed on unknown 6th arg.
        bad_cli = subprocess.run(
            [sys.executable, "-IB", str(REPO_ROOT / "oc_openai" / "session_relay.py"),
             "inc_cli_12345678", "1", str(time.monotonic_ns() + 60_000_000_000), "8401", "--unknown"],
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(bad_cli.returncode, 0)

        with tempfile.TemporaryDirectory(prefix="oc-defer-bind-") as td_raw:
            td = Path(td_raw)
            os.chmod(td, 0o700)
            exp = td / "exposure"
            exp.mkdir(mode=0o700)
            os.chmod(exp, 0o700)
            turn_root = td / "turn"
            turn_root.mkdir(mode=0o700)
            os.chmod(turn_root, 0o700)
            revoke_root = td / "revoke"
            revoke_root.mkdir(mode=0o700)
            os.chmod(revoke_root, 0o700)

            # 2. Revoking a pending deferred-bind relay exits without ever binding the TCP port.
            revoke_port = self._pick_free_relay_port()
            revoke_job = _SessionJob(revoke_root, "inc_rev_12345678")
            revoke_job.prepare(config_payload=None)
            t_rev = threading.Thread(
                target=session_relay.serve,
                args=(revoke_job.lease, revoke_job.relay_proof),
                kwargs={"port": revoke_port, "defer_bind": True},
                daemon=True,
            )
            t_rev.start()
            time.sleep(0.1)
            with self.assertRaises(ConnectionRefusedError):
                socket.create_connection(("127.0.0.1", revoke_port), timeout=0.5).close()
            revoke_job.revoke()
            t_rev.join(timeout=5.0)
            self.assertFalse(t_rev.is_alive())

            # 3. Active B4 -> B5 cutover on real session_relay.serve(..., defer_bind=True):
            turn_port = self._pick_free_relay_port()
            gate = self._make_gate(td, exp)
            turn_job = _SessionJob(turn_root, "inc_def_12345678")
            turn_job.prepare(config_payload=None)
            gate.bind_incarnation(turn_job.incarnation, turn_job.generation)
            gate.arm(observed_row=f"{TEST_SCOPED}/{TEST_MODEL}", observed_screen_digest=TEST_HEX_C)

            conn = _FakeConnection()
            tok = "tok-defer-valid"
            good_body = json.dumps(_valid_proof_payload()).encode("utf-8")
            raw_req = _make_fake_request(worker_token=tok, body_bytes=good_body, port=turn_port)

            broker = SessionBroker(
                socket_path=turn_job.provider_socket,
                relay_proof=turn_job.relay_proof,
                worker_token=tok,
                lease=turn_job.lease,
                connection=conn,
                binding=SimpleNamespace(generation=1),
                models=(TEST_MODEL,),
                profile_label="personal",
                expected_port=turn_port,
                policy=SessionPolicy(exposure_dir=exp, proof_gate=gate, job_incarnation=turn_job.incarnation),
            )
            broker.start()
            with patch.object(relay_mod, "PROVIDER_SOCKET", str(turn_job.provider_socket)):
                t_relay = threading.Thread(
                    target=session_relay.serve,
                    args=(turn_job.lease, turn_job.relay_proof),
                    kwargs={"port": turn_port, "defer_bind": True},
                    daemon=True,
                )
                t_relay.start()
                try:
                    time.sleep(0.15)
                    # B4: pending & unverified -> TCP listener does not exist yet!
                    with self.assertRaises(ConnectionRefusedError):
                        socket.create_connection(("127.0.0.1", turn_port), timeout=0.5).close()
                    self.assertEqual(len(conn.calls), 0)

                    # B5: mark verified -> activate -> wait bound (empty readiness probe).
                    gate.mark_relay_verified(TEST_HEX_A)
                    turn_job.activate()
                    self.assertTrue(
                        self._wait_tcp_port_bound(turn_port),
                        "Deferred-bind relay did not bind after activation",
                    )
                    time.sleep(0.1)
                    self.assertEqual(len(conn.calls), 0)
                    self.assertEqual(gate.state, STATE_ARMED)

                    # Step C: fresh control POST through real TCP relay -> exact 1 canonical write!
                    resp1 = self._send_tcp_http(turn_port, raw_req)
                    self.assertIn(b"200 OK", resp1)
                    self.assertEqual(len(conn.calls), 1)
                    self.assertEqual(conn.calls[0], canonical_proof_body(TEST_MODEL))

                    # Second POST on same active listener -> 403 proof_gate_spent, 0 extra writes.
                    resp2 = self._send_tcp_http(turn_port, raw_req)
                    self.assertIn(b"403 Forbidden", resp2)
                    self.assertIn(b"proof_gate_spent", resp2)
                    self.assertEqual(len(conn.calls), 1)
                finally:
                    turn_job.revoke()
                    t_relay.join(timeout=5.0)
                    broker.close()

    def test_post_arming_drift_foreground_loss_and_fsync_failure_produce_zero_writes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="oc-drift-") as td_raw:
            td = Path(td_raw)
            os.chmod(td, 0o700)
            exp = td / "exposure"
            exp.mkdir(mode=0o700)
            os.chmod(exp, 0o700)
            cfg_dir = td / "cfg"
            cfg_dir.mkdir(mode=0o700)
            os.chmod(cfg_dir, 0o700)

            # Missing providers.toml must fail closed for configuration-first proof.
            with self.assertRaises(ProofGateError):
                compute_providers_config_digest(cfg_dir)

            (cfg_dir / FILE_PROVIDERS_TOML).write_text("[launch]\n", encoding="utf-8")
            os.chmod(cfg_dir / FILE_PROVIDERS_TOML, 0o600)
            cfg_digest = compute_providers_config_digest(cfg_dir)

            # 1. Foreground TTY loss or cancellation after arming -> 0 writes.
            fg_state = {"ok": True}
            ev1 = td / "ev1"
            ev1.mkdir(mode=0o700)
            os.chmod(ev1, 0o700)
            appr = ProofApproval(
                run_id=TEST_RUN_ID, instance_label="personal", scoped_provider_id=TEST_SCOPED,
                approved_model=TEST_MODEL, ui_mode="mini", cwd=TEST_CWD,
                selection_epoch="E" * 43, credential_generation=1,
                history_digest_all_12_files=compute_exposure_history_digest(exp),
                profile_directory="/prof/p1", client_id="cid-1",
                auth_mode="subscription", route_policy="subscription-only",
                providers_config_digest=cfg_digest,
            )

            def _check_fg():
                if not fg_state["ok"]:
                    raise ProofGateError("proof_gate_foreground_lost")

            gate1 = ProofGate(
                appr, evidence_dir=ev1, exposure_dir=exp,
                check_owner_alive=_check_fg, expected_instructions_sha256=FAKE_INSTRUCTIONS_DIGEST,
            )
            gate1.bind_incarnation("inc_fg_12345678", 1)
            gate1.arm(observed_row=f"{TEST_SCOPED}/{TEST_MODEL}", observed_screen_digest=TEST_HEX_C)
            gate1.mark_relay_verified(TEST_HEX_A)
            arrival1 = gate1.snapshot_arrival()
            fg_state["ok"] = False
            canon = canonical_proof_body(TEST_MODEL)
            with self.assertRaises(ProofGateError):
                gate1.claim_for_write(arrival1, canon, job_incarnation="inc_fg_12345678")
            self.assertEqual(gate1.admitted_writes, 0)

            # 2. Registration/config drift after arming -> 0 writes.
            drift_state = {"client_id": "cid-1"}
            ev2 = td / "ev2"
            ev2.mkdir(mode=0o700)
            os.chmod(ev2, 0o700)

            def _check_drift(a):
                if drift_state["client_id"] != a.client_id or compute_providers_config_digest(cfg_dir) != a.providers_config_digest:
                    raise ProofGateError("proof_gate_approval_drift")

            gate2 = ProofGate(
                appr, evidence_dir=ev2, exposure_dir=exp,
                check_binding_intact=_check_drift, expected_instructions_sha256=FAKE_INSTRUCTIONS_DIGEST,
            )
            gate2.bind_incarnation("inc_dr_12345678", 1)
            gate2.arm(observed_row=f"{TEST_SCOPED}/{TEST_MODEL}", observed_screen_digest=TEST_HEX_C)
            gate2.mark_relay_verified(TEST_HEX_A)
            arrival2 = gate2.snapshot_arrival()
            drift_state["client_id"] = "cid-reconnected"
            with self.assertRaises(ProofGateError):
                gate2.claim_for_write(arrival2, canon, job_incarnation="inc_dr_12345678")
            self.assertEqual(gate2.admitted_writes, 0)

            # 3. File or directory fsync failure prevents upstream write (0 writes).
            for fail_on_call in (1, 2):
                ev3 = td / f"ev_sync_{fail_on_call}"
                ev3.mkdir(mode=0o700)
                os.chmod(ev3, 0o700)
                gate3 = ProofGate(
                    appr, evidence_dir=ev3, exposure_dir=exp,
                    expected_instructions_sha256=FAKE_INSTRUCTIONS_DIGEST,
                )
                inc = f"inc_sy{fail_on_call}_123456"
                gate3.bind_incarnation(inc, 1)
                gate3.arm(observed_row=f"{TEST_SCOPED}/{TEST_MODEL}", observed_screen_digest=TEST_HEX_C)
                gate3.mark_relay_verified(TEST_HEX_A)
                arr3 = gate3.snapshot_arrival()
                real_fsync = os.fsync
                calls = {"n": 0}

                def _failing_fsync(fd):
                    calls["n"] += 1
                    if calls["n"] == fail_on_call:
                        raise OSError("simulated fsync failure")
                    return real_fsync(fd)

                with patch("os.fsync", side_effect=_failing_fsync):
                    with self.assertRaises(ProofGateError):
                        gate3.claim_for_write(arr3, canon, job_incarnation=inc)

    def test_harden_opencode_config_strips_mcp_and_disables_tools(self) -> None:
        with tempfile.TemporaryDirectory(prefix="oc-cfg-") as td_raw:
            td = Path(td_raw)
            os.chmod(td, 0o700)
            exp = td / "exposure"
            exp.mkdir(mode=0o700)
            os.chmod(exp, 0o700)
            gate = self._make_gate(td, exp)
            cfg: dict[str, object] = {
                "model": f"{TEST_SCOPED_WORK}/other-model",
                "mcp": {"chrome-devtools": {"type": "local", "command": ["npx", "-y", "chrome-devtools-mcp@latest"]}},
                "providers": {
                    TEST_SCOPED: {"models": {TEST_MODEL: {"capabilities": {"tools": True, "input": ["text"]}}}},
                    TEST_SCOPED_WORK: {"models": {"other-model": {"capabilities": {"tools": True}}}},
                },
                "policies": [{"action": "provider.use", "resource": "*", "effect": "deny"}],
            }
            hardened = gate.harden_opencode_config(cfg)
            self.assertNotIn("mcp", hardened)
            self.assertEqual(hardened["model"], f"{TEST_SCOPED}/{TEST_MODEL}")
            self.assertFalse(hardened["providers"][TEST_SCOPED]["models"][TEST_MODEL]["capabilities"]["tools"])
            self.assertFalse(hardened["providers"][TEST_SCOPED_WORK]["models"]["other-model"]["capabilities"]["tools"])
            self.assertEqual(hardened["plugins"], ["-opencode.tool.*"])


class TestPinnedImagesAndLifecycleOwnership(unittest.TestCase):
    def test_unowned_local_image_refused_and_tag_drift_cannot_redirect(self) -> None:
        with tempfile.TemporaryDirectory(prefix="oc-img-") as td_raw:
            td = Path(td_raw)
            os.chmod(td, 0o700)
            built = td / "built-images"
            built.write_text(f"{TEST_HEX_A}\n{TEST_HEX_B}\n", encoding="utf-8")
            os.chmod(built, 0o600)

            role_map = {
                TEST_HEX_A: "agent",
                TEST_HEX_B: "relay",
                TEST_HEX_C: "agent",
            }

            def fake_pm(args, timeout=15.0):
                del timeout
                target = args[-1]
                if target in role_map:
                    data = [{"Id": target, "Labels": {"io.github.gorban.opencode-sandbox.image": role_map[target]}}]
                    return subprocess.CompletedProcess(args, 0, json.dumps(data).encode(), b"")
                return subprocess.CompletedProcess(args, 1, b"", b"not found")

            # Unowned image not in built-images is rejected.
            with self.assertRaises(shell_driver.ShellDriverError):
                shell_driver.verify_reviewed_role_image(
                    role="agent", image_id=TEST_HEX_C, built_images_path=built, podman_runner=fake_pm,
                )

            # Wrong role label (passing relay image ID for agent role) is rejected.
            with self.assertRaises(shell_driver.ShellDriverError):
                shell_driver.verify_reviewed_role_image(
                    role="agent", image_id=TEST_HEX_B, built_images_path=built, podman_runner=fake_pm,
                )

            # Matching owned role image verifies and pins exact 64-hex ID.
            pinned = shell_driver.verify_reviewed_role_image(
                role="agent", image_id=TEST_HEX_A, built_images_path=built, podman_runner=fake_pm,
            )
            self.assertEqual(pinned, TEST_HEX_A)

            # Worktree creation uses pinned ID directly (never mutable tag!).
            seen_cmds: list[list[str]] = []

            def fake_owner_pm(args, timeout=20.0):
                del timeout
                seen_cmds.append(list(args))
                if args[:2] == ["pod", "exists"] or args[:2] == ["volume", "exists"]:
                    return subprocess.CompletedProcess(args, 1, b"", b"")
                if args[:2] == ["pod", "create"]:
                    return subprocess.CompletedProcess(args, 0, (TEST_HEX_B + "\n").encode(), b"")
                if args[:2] == ["volume", "create"]:
                    return subprocess.CompletedProcess(args, 0, b"ok\n", b"")
                if args[0] == "run":
                    return subprocess.CompletedProcess(args, 0, b"42:999\n", b"")
                return subprocess.CompletedProcess(args, 0, b"", b"")

            journal = _OwnershipJournal(
                JournalSpec(
                    run_id=TEST_RUN_ID,
                    instance=TEST_INSTANCE,
                    pod_name=TEST_POD,
                    volume_name=TEST_VOLUME,
                    sandbox_dir=td,
                    cwd=TEST_CWD,
                    level=TEST_LEVEL,
                    agent_image_id=pinned,
                    journal_path=td / "owner.json",
                ),
                podman_runner=fake_owner_pm,
            )
            journal.create_under_lock(REPO_ROOT / FILE_SETUP_LOCK, td / "state")
            run_cmds = [cmd for cmd in seen_cmds if cmd and cmd[0] == "run"]
            self.assertEqual(len(run_cmds), 1)
            self.assertIn(TEST_HEX_A, run_cmds[0])
            self.assertNotIn(TEST_AGENT_TAG, run_cmds[0])
            self.assertNotIn(TEST_HEX_C, run_cmds[0])

    def test_inflight_slot_create_and_untracked_pod_member_retain_uncertainty(self) -> None:
        with tempfile.TemporaryDirectory(prefix="oc-inflight-") as td_raw:
            td = Path(td_raw)
            os.chmod(td, 0o700)
            slot_root = td / "slot_root"
            grant_dir = slot_root / "grant"
            grant_dir.mkdir(parents=True, mode=0o700)
            (grant_dir / "lock").touch(mode=0o600)
            (grant_dir / "state").write_text("active\n", encoding="utf-8")
            orig_grant_ino = (grant_dir.lstat().st_dev, grant_dir.lstat().st_ino)
            orig_lock_ino = ((grant_dir / "lock").lstat().st_dev, (grant_dir / "lock").lstat().st_ino)
            journal_path = td / "owner.json"
            rm_calls: list[list[str]] = []

            def fake_pm(args, timeout=20.0):
                del timeout
                if args[:2] in (["rm", "-f"], ["pod", "rm"], ["volume", "rm"]):
                    rm_calls.append(list(args))
                if args[:2] == ["pod", "inspect"]:
                    data = [{
                        "Id": TEST_HEX_B,
                        "InfraContainerID": "9" * 64,
                        "Labels": {PROOF_OWNER_LABEL: TEST_RUN_ID},
                        "Containers": [{"Id": "9" * 64}, {"Id": "8" * 64}],
                    }]
                    return subprocess.CompletedProcess(args, 0, json.dumps(data).encode(), b"")
                return subprocess.CompletedProcess(args, 0, b"", b"")

            spec = JournalSpec(
                run_id=TEST_RUN_ID, instance=TEST_INSTANCE, pod_name=TEST_POD,
                volume_name=TEST_VOLUME, sandbox_dir=td, cwd=TEST_CWD,
                level=TEST_LEVEL, agent_image_id=TEST_HEX_A, journal_path=journal_path,
            )
            # Case 2a: Kill immediately after lease acquisition (prepare_slot only, before podman create).
            j_pre = _OwnershipJournal(spec, podman_runner=fake_pm)
            j_pre.pod_id = TEST_HEX_B
            j_pre.prepare_slot("turn-0", container_name="oc-e2e-deadbeef-relay-0", slot_root=str(slot_root))
            res_pre = j_pre.teardown()
            self.assertFalse(res_pre[KEY_CLEANUP_VERIFIED])
            self.assertTrue(res_pre["ownership_uncertain"])
            self.assertIn("lease_unreleased:turn-0", res_pre["errors"])
            self.assertEqual((grant_dir / "state").read_text(encoding="utf-8"), "revoked\n")
            self.assertEqual((grant_dir.lstat().st_dev, grant_dir.lstat().st_ino), orig_grant_ino)
            self.assertEqual(((grant_dir / "lock").lstat().st_dev, (grant_dir / "lock").lstat().st_ino), orig_lock_ino)
            self.assertIn("pod_has_untracked_members", res_pre["errors"])
            self.assertEqual([c for c in rm_calls if c[:2] == ["pod", "rm"]], [])

            # Case 2b: Kill after confirmed relay CID removal, BEFORE exact lease release -> retain grant inodes & False!
            clean_rm: list[list[str]] = []
            slot_root2 = td / "slot_root2"
            grant_dir2 = slot_root2 / "grant"
            grant_dir2.mkdir(parents=True, mode=0o700)
            (grant_dir2 / "lock").touch(mode=0o600)
            (grant_dir2 / "state").write_text("active\n", encoding="utf-8")

            def clean_pm(args, timeout=20.0):
                del timeout
                if args[:2] in (["rm", "-f"], ["pod", "rm"], ["volume", "rm"]):
                    clean_rm.append(list(args))
                if args[:2] == ["container", "exists"] or args[:2] == ["pod", "exists"] or args[:2] == ["volume", "exists"]:
                    return subprocess.CompletedProcess(args, 1, b"", b"")
                if args[:2] == ["pod", "inspect"]:
                    data = [{
                        "Id": TEST_HEX_B,
                        "InfraContainerID": "9" * 64,
                        "Labels": {PROOF_OWNER_LABEL: TEST_RUN_ID},
                        "Containers": [{"Id": "9" * 64}, {"Id": TEST_HEX_C}],
                    }]
                    return subprocess.CompletedProcess(args, 0, json.dumps(data).encode(), b"")
                return subprocess.CompletedProcess(args, 0, b"", b"")

            j_unreleased = _OwnershipJournal(spec, podman_runner=clean_pm)
            j_unreleased._lock_helper = REPO_ROOT / FILE_SETUP_LOCK
            j_unreleased._state_dir = td / "state2"
            j_unreleased.pod_id = TEST_HEX_B
            j_unreleased.begin_slot_create(
                "turn-0", container_name="oc-e2e-deadbeef-relay-0",
                grant_dir=str(grant_dir2), slot_root=str(slot_root2),
            )
            j_unreleased.finish_slot_create("turn-0", TEST_HEX_C)
            res_unrel = j_unreleased.teardown()
            self.assertFalse(res_unrel[KEY_CLEANUP_VERIFIED])
            self.assertIn("lease_unreleased:turn-0", res_unrel["errors"])
            self.assertIn(["rm", "-f", TEST_HEX_C], clean_rm)
            self.assertTrue(slot_root2.exists())
            self.assertEqual((grant_dir2 / "state").read_text(encoding="utf-8"), "revoked\n")

            # Case 2c: After trusted foreground path releases exact lease -> slot_root removed & cleanup_verified=True!
            j_clean = _OwnershipJournal(spec, podman_runner=clean_pm)
            j_clean._lock_helper = REPO_ROOT / FILE_SETUP_LOCK
            j_clean._state_dir = td / "state3"
            j_clean.pod_id = TEST_HEX_B
            j_clean.begin_slot_create(
                "turn-0", container_name="oc-e2e-deadbeef-relay-0",
                grant_dir=str(grant_dir2), slot_root=str(slot_root2),
            )
            j_clean.finish_slot_create("turn-0", TEST_HEX_C)
            j_clean.mark_lease_released("turn-0")
            res_clean = j_clean.teardown()
            self.assertTrue(res_clean[KEY_CLEANUP_VERIFIED], res_clean)
            self.assertFalse(slot_root2.exists())
            self.assertIn(["pod", "rm", "-f", TEST_HEX_B], clean_rm)

    def test_positive_lease_release_evidence_and_pre_create_post_release_recovery(self) -> None:
        import pwd
        from oc_openai.connection import Connection, PhysicalHost
        from oc_openai.connection_job import WorkerLease
        from oc_openai.session_broker import _SessionSlotCoordinator
        from oc_providers.contracts import SlotHandle
        from test_openai_connection import FixtureBrowser, FixtureTransport, FixtureVerifier

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        with (
            tempfile.TemporaryDirectory(prefix="oc-lease-p2-", dir=str(home)) as td_raw,
            tempfile.TemporaryDirectory(prefix="oc-chat-", dir="/tmp") as slot_a_raw,
            tempfile.TemporaryDirectory(prefix="oc-chat-", dir="/tmp") as slot_b_raw,
            tempfile.TemporaryDirectory(prefix="oc-chat-", dir="/tmp") as slot_g_raw,
            tempfile.TemporaryDirectory(prefix="oc-chat-", dir="/tmp") as slot_abs_raw,
            tempfile.TemporaryDirectory(prefix="oc-chat-", dir="/tmp") as slot_c_raw,
        ):
            td = Path(td_raw)
            os.chmod(td, 0o700)
            conn_dir = td / "conn_reg"
            host = PhysicalHost("a" * 64, "11111111-2222-3333-4444-555555555555")
            verifier = FixtureVerifier()
            transport = FixtureTransport()
            conn = Connection(
                conn_dir,
                browser=FixtureBrowser(),
                verifier=verifier,
                transport=transport,
                host_probe=lambda: host,
            )
            binding = conn.connect()

            def _make_clean_pm():
                def _pm(args, timeout=20.0):
                    del timeout
                    if args[:2] in (["container", "exists"], ["pod", "exists"], ["volume", "exists"]):
                        return subprocess.CompletedProcess(args, 1, b"", b"")
                    if args[:2] == ["pod", "inspect"]:
                        data = [{"Id": TEST_HEX_B, "InfraContainerID": "9" * 64,
                                 "Labels": {PROOF_OWNER_LABEL: TEST_RUN_ID}, "Containers": [{"Id": "9" * 64}]}]
                        return subprocess.CompletedProcess(args, 0, json.dumps(data).encode(), b"")
                    return subprocess.CompletedProcess(args, 0, b"", b"")
                return _pm

            spec = JournalSpec(
                run_id=TEST_RUN_ID, instance=TEST_INSTANCE, pod_name=TEST_POD,
                volume_name=TEST_VOLUME, sandbox_dir=td, cwd=TEST_CWD,
                level=TEST_LEVEL, agent_image_id=TEST_HEX_A, journal_path=td / "owner.json",
            )

            # 2a: Kill between real Connection.session_lease() persistence and begin_slot_create
            #     (only prepare_slot is durable). Verify retained root lets trusted recovery match
            #     stored incarnation, generation, and grant/lock/lifetime inodes!
            slot_a = Path(slot_a_raw)
            os.chmod(slot_a, 0o700)
            job_a = _SessionJob(slot_a, "inc_" + "a" * 32)
            job_a.prepare(config_payload=None)
            j_2a = _OwnershipJournal(spec, podman_runner=_make_clean_pm())
            j_2a.pod_id = TEST_HEX_B
            j_2a.prepare_slot("turn-0", container_name="oc-e2e-deadbeef-relay-0", slot_root=str(slot_a))
            cm_a = conn.session_lease(binding, job_a)
            cm_a.__enter__()
            # Simulate SIGKILL before begin_slot_create: close lifetime fd (owner process died) & teardown journal.
            os.close(job_a._lifetime_fd)
            job_a._lifetime_fd = None
            res_2a = j_2a.teardown()
            self.assertFalse(res_2a[KEY_CLEANUP_VERIFIED])
            self.assertIn("lease_unreleased:turn-0", res_2a["errors"])
            self.assertTrue(slot_a.exists())
            # Trusted recovery reads exact stored record and matches incarnation, generation, and all 3 inodes.
            with conn._store.locked() as sdir:
                stored_rec = conn._store.read(sdir)["worker_leases"][slot_a.name]
            parsed_a = WorkerLease.parse(stored_rec)
            self.assertEqual(parsed_a.incarnation, job_a.incarnation)
            self.assertEqual(parsed_a.generation, job_a.generation)
            self.assertEqual((parsed_a.grant_dev, parsed_a.grant_ino),
                             (job_a.grant.lstat().st_dev, job_a.grant.lstat().st_ino))
            self.assertEqual((parsed_a.lock_dev, parsed_a.lock_ino),
                             ((job_a.grant / "lock").lstat().st_dev, (job_a.grant / "lock").lstat().st_ino))
            self.assertEqual((parsed_a.lifetime_dev, parsed_a.lifetime_ino),
                             ((job_a.grant / "lifetime").lstat().st_dev, (job_a.grant / "lifetime").lstat().st_ino))
            parsed_a.terminal(host)
            parsed_a.confirm_terminal()
            cm_a.__exit__(None, None, None)

            # 2b-i: Conflicting record in worker_leases[lease.root] on __exit__() -> "retained_conflict",
            #       coordinator records cleanup error, slot_root & original grant inodes retained!
            slot_b = Path(slot_b_raw)
            os.chmod(slot_b, 0o700)
            job_b = _SessionJob(slot_b, "inc_" + "b" * 32)
            job_b.prepare(config_payload=None)
            outcomes_b: list[str] = []
            cm_b = conn.session_lease(binding, job_b, on_release_result=outcomes_b.append)
            lease_b = cm_b.__enter__()
            with conn._store.locked() as sdir:
                rec = conn._store.read(sdir)
                rec["worker_leases"][slot_b.name]["generation"] = lease_b.generation + 99
                conn._store.write(sdir, rec)
            coord_b = _SessionSlotCoordinator(threading.Event())
            handle_b = SlotHandle(
                slot_index=0, scoped_id=TEST_SCOPED, provider_label=TEST_SCOPED, port=8401,
                job=job_b, broker=SimpleNamespace(_revoked=threading.Event(), close=lambda: None),
                lease=lease_b, build_relay_args=lambda _s: [],
                lease_release_confirmed=lambda: bool(outcomes_b and outcomes_b[-1] in ("removed", "absent")),
            )
            coord_b.register_slot(cm_b, handle_b, slot_b)
            err_b = coord_b.teardown_all(None)
            self.assertIsNotNone(err_b)
            self.assertEqual(outcomes_b, ["retained_conflict"])
            self.assertFalse(coord_b._slots[0].lease_confirmed_released)
            coord_b.remove_slot_roots(require_confirmed_leases=True)
            self.assertTrue((slot_b / "grant" / "state").exists())
            # Clean conflicting test record from store so subsequent checks run on clean store.
            with conn._store.locked() as sdir:
                rec = conn._store.read(sdir)
                rec.pop("worker_leases", None)
                conn._store.write(sdir, rec)

            # 2b-i-b: Both worker_lease AND matching worker_leases[lease.root] reference the same root ->
            #         must return "retained_conflict" and retain grant inodes even though multi-lease entry matches!
            with tempfile.TemporaryDirectory(prefix="oc-chat-", dir="/tmp") as slot_both_raw:
                slot_both = Path(slot_both_raw)
                os.chmod(slot_both, 0o700)
                job_both = _SessionJob(slot_both, "inc_" + "7" * 32)
                job_both.prepare(config_payload=None)
                outcomes_both: list[str] = []
                cm_both = conn.session_lease(binding, job_both, on_release_result=outcomes_both.append)
                lease_both = cm_both.__enter__()
                with conn._store.locked() as sdir:
                    rec = conn._store.read(sdir)
                    rec["worker_lease"] = dict(rec["worker_leases"][slot_both.name])
                    conn._store.write(sdir, rec)
                coord_both = _SessionSlotCoordinator(threading.Event())
                handle_both = SlotHandle(
                    slot_index=0, scoped_id=TEST_SCOPED, provider_label=TEST_SCOPED, port=8401,
                    job=job_both, broker=SimpleNamespace(_revoked=threading.Event(), close=lambda: None),
                    lease=lease_both, build_relay_args=lambda _s: [],
                    lease_release_confirmed=lambda: bool(outcomes_both and outcomes_both[-1] in ("removed", "absent")),
                )
                coord_both.register_slot(cm_both, handle_both, slot_both)
                err_both = coord_both.teardown_all(None)
                self.assertIsNotNone(err_both)
                self.assertEqual(outcomes_both, ["retained_conflict"])
                self.assertFalse(coord_both._slots[0].lease_confirmed_released)
                coord_both.remove_slot_roots(require_confirmed_leases=True)
                self.assertTrue((slot_both / "grant" / "state").exists())
                with conn._store.locked() as sdir:
                    rec = conn._store.read(sdir)
                    rec.pop("worker_lease", None)
                    rec.pop("worker_leases", None)
                    conn._store.write(sdir, rec)

            # 2b-ii: release_gate() == False -> "retained_gate_closed", not confirmed!
            slot_g = Path(slot_g_raw)
            os.chmod(slot_g, 0o700)
            job_g = _SessionJob(slot_g, "inc_" + "c" * 32)
            job_g.prepare(config_payload=None)
            outcomes_g: list[str] = []
            cm_g = conn.session_lease(
                binding, job_g, release_gate=lambda: False, on_release_result=outcomes_g.append,
            )
            cm_g.__enter__()
            job_g.revoke()
            cm_g.__exit__(None, None, None)
            self.assertEqual(outcomes_g, ["retained_gate_closed"])
            with conn._store.locked() as sdir:
                rec = conn._store.read(sdir)
                rec.pop("worker_leases", None)
                conn._store.write(sdir, rec)

            # 2b-iii: Exact root absent in genuinely locked empty store (state.lock present, connection.json absent)
            #         AND in exact matching registration -> "absent" (positive confirmation).
            slot_abs = Path(slot_abs_raw)
            os.chmod(slot_abs, 0o700)
            job_abs = _SessionJob(slot_abs, "inc_" + "d" * 32)
            job_abs.prepare(config_payload=None)
            outcomes_abs: list[str] = []
            cm_abs = conn.session_lease(binding, job_abs, on_release_result=outcomes_abs.append)
            cm_abs.__enter__()
            # Remove only state.json while keeping state.lock so Store.locked() genuinely locks and reads {}.
            (conn_dir / "state.json").unlink()
            self.assertTrue((conn_dir / "state.lock").exists())
            job_abs.revoke()
            cm_abs.__exit__(None, None, None)
            self.assertEqual(outcomes_abs, ["absent"])

            # 2b-iv: Unlocked / unavailable store (directory is None when both state.lock and state.json
            #        are absent or store dir missing) -> "retained_store_unavailable", NEVER "absent"!
            conn2_dir = td / "conn_reg_unavail"
            conn2 = Connection(
                conn2_dir,
                browser=FixtureBrowser(),
                verifier=FixtureVerifier(),
                transport=FixtureTransport(),
                host_probe=lambda: host,
            )
            binding2 = conn2.connect()
            with tempfile.TemporaryDirectory(prefix="oc-chat-", dir="/tmp") as slot_u_raw:
                slot_u = Path(slot_u_raw)
                os.chmod(slot_u, 0o700)
                job_u = _SessionJob(slot_u, "inc_" + "9" * 32)
                job_u.prepare(config_payload=None)
                outcomes_u: list[str] = []
                cm_u = conn2.session_lease(binding2, job_u, on_release_result=outcomes_u.append)
                lease_u = cm_u.__enter__()
                # Remove both state.json and state.lock so Store.locked() yields None without locking.
                (conn2_dir / "state.json").unlink()
                (conn2_dir / "state.lock").unlink()
                coord_u = _SessionSlotCoordinator(threading.Event())
                handle_u = SlotHandle(
                    slot_index=0, scoped_id=TEST_SCOPED, provider_label=TEST_SCOPED, port=8401,
                    job=job_u, broker=SimpleNamespace(_revoked=threading.Event(), close=lambda: None),
                    lease=lease_u, build_relay_args=lambda _s: [],
                    lease_release_confirmed=lambda: bool(outcomes_u and outcomes_u[-1] in ("removed", "absent")),
                )
                coord_u.register_slot(cm_u, handle_u, slot_u)
                err_u = coord_u.teardown_all(None)
                self.assertIsNotNone(err_u)
                self.assertEqual(outcomes_u, ["retained_store_unavailable"])
                self.assertFalse(coord_u._slots[0].lease_confirmed_released)
                coord_u.remove_slot_roots(require_confirmed_leases=True)
                self.assertTrue((slot_u / "grant" / "state").exists())

            # Reconnect conn for 2c since 2b-iii cleared connection.json.
            conn3_dir = td / "conn_reg_2c"
            conn3 = Connection(
                conn3_dir,
                browser=FixtureBrowser(),
                verifier=FixtureVerifier(),
                transport=FixtureTransport(),
                host_probe=lambda: host,
            )
            binding3 = conn3.connect()

            # 2c: Kill AFTER actual store release ("removed"), BEFORE mark_lease_released ack ->
            #     conservative retention (cleanup_verified=False, slot_root retained) until reconciled.
            slot_c = Path(slot_c_raw)
            os.chmod(slot_c, 0o700)
            job_c = _SessionJob(slot_c, "inc_" + "e" * 32)
            job_c.prepare(config_payload=None)
            outcomes_c: list[str] = []
            j_2c = _OwnershipJournal(spec, podman_runner=_make_clean_pm())
            j_2c.pod_id = TEST_HEX_B
            j_2c.prepare_slot("turn-0", container_name="oc-e2e-deadbeef-relay-0", slot_root=str(slot_c))
            cm_c = conn3.session_lease(binding3, job_c, on_release_result=outcomes_c.append)
            cm_c.__enter__()
            job_c.revoke()
            cm_c.__exit__(None, None, None)
            self.assertEqual(outcomes_c, ["removed"])
            # Driver killed BEFORE j_2c.mark_lease_released("turn-0") runs:
            res_2c = j_2c.teardown()
            self.assertFalse(res_2c[KEY_CLEANUP_VERIFIED])
            self.assertIn("lease_unreleased:turn-0", res_2c["errors"])
            self.assertTrue(slot_c.exists())
            # Trusted store check confirms absence in worker_leases.
            with conn3._store.locked() as sdir:
                self.assertNotIn(slot_c.name, conn3._store.read(sdir).get("worker_leases") or {})

    def test_same_name_racing_resource_survives_and_uncertain_create_does_not_delete(self) -> None:
        with tempfile.TemporaryDirectory(prefix="oc-race-") as td_raw:
            td = Path(td_raw)
            os.chmod(td, 0o700)
            rm_calls: list[list[str]] = []

            def racing_pm(args, timeout=20.0):
                del timeout
                if args[:2] in (["pod", "rm"], ["volume", "rm"]):
                    rm_calls.append(list(args))
                if args[:2] == ["pod", "exists"]:
                    return subprocess.CompletedProcess(args, 1, b"", b"")
                if args[:2] == ["volume", "exists"]:
                    return subprocess.CompletedProcess(args, 1, b"", b"")
                if args[:2] == ["pod", "create"]:
                    # Simulates same-name pod appearing right after absence check -> create fails!
                    return subprocess.CompletedProcess(args, 125, b"", b"pod already exists")
                return subprocess.CompletedProcess(args, 0, b"", b"")

            spec = JournalSpec(
                run_id=TEST_RUN_ID,
                instance=TEST_INSTANCE,
                pod_name=TEST_POD,
                volume_name=TEST_VOLUME,
                sandbox_dir=td,
                cwd=TEST_CWD,
                level=TEST_LEVEL,
                agent_image_id=TEST_HEX_A,
            )
            journal = _OwnershipJournal(spec, podman_runner=racing_pm)
            with self.assertRaises(CleanupOwnerError):
                journal.create_under_lock(REPO_ROOT / FILE_SETUP_LOCK, td / "state")
            self.assertTrue(journal.ownership_uncertain)
            result = journal.teardown()
            self.assertFalse(result["cleanup_verified"])
            self.assertTrue(result["ownership_uncertain"])
            self.assertEqual(rm_calls, [])

            # Even if a same-name pod/volume exists later with a foreign label, teardown refuses removal!
            foreign_rm_calls: list[list[str]] = []

            def foreign_pm(args, timeout=20.0):
                del timeout
                if args[:2] in (["pod", "rm"], ["volume", "rm"]):
                    foreign_rm_calls.append(list(args))
                if args[:2] == ["pod", "inspect"]:
                    data = [{"Id": TEST_HEX_B, "Labels": {PROOF_OWNER_LABEL: "foreign_run"}}]
                    return subprocess.CompletedProcess(args, 0, json.dumps(data).encode(), b"")
                if args[:2] == ["volume", "inspect"]:
                    data = [{"Labels": {PROOF_OWNER_LABEL: "foreign_run"}}]
                    return subprocess.CompletedProcess(args, 0, json.dumps(data).encode(), b"")
                return subprocess.CompletedProcess(args, 0, b"", b"")

            foreign_journal = _OwnershipJournal(spec, podman_runner=foreign_pm)
            foreign_journal.pod_id = TEST_HEX_B
            foreign_journal.volume_owned = True
            res = foreign_journal.teardown()
            self.assertFalse(res[KEY_CLEANUP_VERIFIED])
            self.assertEqual(foreign_rm_calls, [])

    def test_sigkill_of_foreground_driver_triggers_detached_cleanup_owner(self) -> None:
        with tempfile.TemporaryDirectory(prefix="oc-sigkill-") as td_raw:
            td = Path(td_raw)
            os.chmod(td, 0o700)
            marker = td / "cleanup_ran"
            ready_file = td / "owner_ready"
            # Tiny zero-network mock owner module exercising the exact DetachedShellCleanupOwner lifeline protocol.
            helper = td / "mock_owner.py"
            helper.write_text(
                "import os, select, signal, socket, sys\n"
                "from pathlib import Path\n"
                "signal.signal(signal.SIGINT, signal.SIG_IGN)\n"
                "sock = socket.socket(fileno=int(sys.argv[2]))\n"
                "life_fd = int(sys.argv[3])\n"
                f"Path({str(ready_file)!r}).write_text('ready')\n"
                "while True:\n"
                "    r, _, _ = select.select([sock, life_fd], [], [], 0.2)\n"
                "    if life_fd in r and not os.read(life_fd, 64):\n"
                f"        Path({str(marker)!r}).write_text('teardown_after_sigkill')\n"
                "        break\n",
                encoding="utf-8",
            )
            driver_script = (
                "import sys, time\n"
                f"sys.path.insert(0, {str(REPO_ROOT)!r})\n"
                "from pathlib import Path\n"
                "from oc_openai.shell_cleanup_owner import DetachedShellCleanupOwner\n"
                f"owner = DetachedShellCleanupOwner(helper_module=Path({str(helper)!r}))\n"
                "owner.start()\n"
                "time.sleep(30)\n"
            )
            parent = subprocess.Popen([sys.executable, "-IB", "-c", driver_script])
            try:
                deadline = time.monotonic() + 5.0
                while not ready_file.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(ready_file.exists())
                os.kill(parent.pid, signal.SIGKILL)
                parent.wait(timeout=5)
                deadline = time.monotonic() + 5.0
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(marker.exists())
                self.assertEqual(marker.read_text(encoding="utf-8"), "teardown_after_sigkill")
            finally:
                if parent.poll() is None:
                    parent.kill()
                    parent.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
