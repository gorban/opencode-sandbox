"""Offline security and regression harness for OpenAI interactive shell e2e.

All tests are strictly offline (zero real credentials, zero live network, zero real host changes).
Covers direct CLI opt-in parsing, read-only snapshot provenance, ambient FD immunity, 3-state
ProofGate arming and whole-request canonicalization, lock-safe 12-file exposure accounting,
pinned image IDs against tag drift, and lifecycle-locked SIGKILL-surviving cleanup ownership.
"""

from contextlib import contextmanager, suppress
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
    ArrivalSnapshot,
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
        with patch.dict(os.environ, {TEST_PYTEST_ADDOPTS: f"{AGENT_IMG_OPT}={TEST_HEX_A}"}, clear=False):
            req = SimpleNamespace(config=SimpleNamespace(getini=lambda _k: []))
            with self.assertRaises(ValueError):
                live_conftest.assert_no_inherited_live_options(req, prefixes, target_relpath=TARGET_REL)

        clean_env = {k: v for k, v in os.environ.items() if k != TEST_PYTEST_ADDOPTS}
        with patch.dict(os.environ, clean_env, clear=True):
            req_str = SimpleNamespace(config=SimpleNamespace(getini=lambda _k: f"{LIVE_FLAG} {MODE_OPT}=mini"))
            with self.assertRaises(ValueError):
                live_conftest.assert_no_inherited_live_options(req_str, prefixes, target_relpath=TARGET_REL)

            req_list = SimpleNamespace(config=SimpleNamespace(getini=lambda _k: [TARGET_REL]))
            with self.assertRaises(ValueError):
                live_conftest.assert_no_inherited_live_options(req_list, prefixes, target_relpath=TARGET_REL)

            req_clean = SimpleNamespace(config=SimpleNamespace(getini=lambda _k: ["-q"]))
            live_conftest.assert_no_inherited_live_options(req_clean, prefixes, target_relpath=TARGET_REL)

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
            for tool, script in (
                ("systemctl", 'if [ "${2-}" = show ]; then printf '
                 "'LoadState=not-found\\nActiveState=inactive\\nJob=\\n'; fi\n"),
                (FAKE_EDITOR_NAME, "exit 0\n"),
            ):
                p = stub_bin / tool
                p.write_text("#!/bin/sh\n" + script, encoding="utf-8")
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
            for extra_args, driver_mode, want_ui in (([], "full", "default"), (["--mini"], "mini", "mini")):
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
                jspec = JournalSpec(
                    run_id=TEST_RUN_ID,
                    instance=TEST_INSTANCE,
                    pod_name=TEST_POD,
                    volume_name=TEST_VOLUME,
                    sandbox_dir=home / "opencode-sandbox",
                    cwd=TEST_CWD,
                    level=TEST_LEVEL,
                    agent_image_id=TEST_HEX_A,
                )
                expected_driver_spec = shell_driver.build_driver_session_spec(
                    jspec,
                    relay_image_id=TEST_HEX_B,
                    ui_mode=driver_mode,
                    agent_mem=emitted["agent_mem"],
                )
                self.assertEqual(emitted["cli_ui_mode"], want_ui)
                self.assertEqual(emitted, expected_driver_spec)

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
                AGENT_IMG_OPT, TEST_HEX_A,
                RELAY_IMG_OPT, TEST_HEX_B,
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
                socket.create_connection(("127.0.0.1", revoke_port), timeout=0.5)
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
                        socket.create_connection(("127.0.0.1", turn_port), timeout=0.5)
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
            actual_grant_ino = (grant_dir.lstat().st_dev, grant_dir.lstat().st_ino)
            actual_lock_ino = ((grant_dir / "lock").lstat().st_dev, (grant_dir / "lock").lstat().st_ino)
            self.assertEqual(actual_grant_ino, orig_grant_ino)
            self.assertEqual(actual_lock_ino, orig_lock_ino)
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

    def test_live_binding_recheck_under_held_fences_and_live_generation_drift(self) -> None:
        import pwd
        from oc_openai.connection import Connection, PhysicalHost
        from oc_openai.profile_backend import ProfileBackend
        from oc_openai.session_adapter import OpenAISessionAdapter, _OpenAISlotTarget
        from oc_providers.contracts import InstancePreflight, ProviderInstanceSpec, ReadinessState
        from test_openai_connection import FixtureBrowser, FixtureTransport, FixtureVerifier

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        with (
            tempfile.TemporaryDirectory(prefix="oc-g2-fence-", dir=str(home)) as td_raw,
            tempfile.TemporaryDirectory(prefix="oc-chat-", dir="/tmp") as slot_raw,
        ):
            td = Path(td_raw)
            os.chmod(td, 0o700)
            state_dir = td / "openai"
            state_dir.mkdir(mode=0o700)
            os.chmod(state_dir, 0o700)
            cfg_dir = td / "cfg"
            cfg_dir.mkdir(mode=0o700)
            os.chmod(cfg_dir, 0o700)
            (cfg_dir / FILE_PROVIDERS_TOML).write_text("[launch]\n", encoding="utf-8")
            os.chmod(cfg_dir / FILE_PROVIDERS_TOML, 0o600)
            ev_dir = td / "evidence"
            ev_dir.mkdir(mode=0o700)
            os.chmod(ev_dir, 0o700)

            host = PhysicalHost("a" * 64, "11111111-2222-3333-4444-555555555555")

            class _OkTransport(FixtureTransport):
                @contextmanager
                def responses(self, body, bearer, cancellation, dispatch, **_kwargs):
                    def send():
                        self.sent += 1
                        self.calls.append(("api", "/v1/responses", body, bearer))
                    dispatch(send)
                    yield iter(_ok_sse_events(TEST_MODEL))

            transport = _OkTransport()
            transport.models_outcome = (200, {"models": [{"slug": TEST_MODEL, "visibility": "list"}]})
            backend = ProfileBackend(
                state_dir,
                reviewed=True,
                connection=lambda reg_dir: Connection(
                    reg_dir,
                    browser=FixtureBrowser(),
                    verifier=FixtureVerifier(),
                    transport=transport,
                    host_probe=lambda: host,
                ),
            )
            backend.connect("personal")
            prof, conn, binding = backend.profile_connection("personal")
            self.assertEqual(conn.models(binding), (TEST_MODEL,))

            from oc_providers.config import load_provider_config_with_digest
            _, loaded_cfg_digest = load_provider_config_with_digest(config_dir=cfg_dir, sandbox_dir=td / "sb")
            approval = ProofApproval(
                run_id=TEST_RUN_ID,
                instance_label="personal",
                scoped_provider_id=TEST_SCOPED,
                approved_model=TEST_MODEL,
                ui_mode="mini",
                cwd=TEST_CWD,
                selection_epoch=prof.epoch,
                credential_generation=binding.generation,
                history_digest_all_12_files=compute_exposure_history_digest(state_dir),
                profile_directory=str(prof.directory),
                client_id=str(prof.client_id),
                auth_mode="subscription",
                route_policy="subscription-only",
                providers_config_digest=loaded_cfg_digest or "",
            )
            gate = ProofGate(
                approval,
                evidence_dir=ev_dir,
                exposure_dir=state_dir,
                check_binding_intact=lambda a: shell_driver._verify_live_binding_intact(
                    a, backend=backend, config_dir=cfg_dir, target_binding=binding,
                ),
                expected_instructions_sha256=FAKE_INSTRUCTIONS_DIGEST,
            )
            preflight = InstancePreflight(
                spec=ProviderInstanceSpec(kind="openai", label="personal", enabled=True, auth_mode="subscription"),
                readiness=ReadinessState.READY,
                models=(TEST_MODEL,),
                exposure_hold=None,
                handle=_OpenAISlotTarget(profile=prof, conn=conn, binding=binding),
            )
            adapter = OpenAISessionAdapter(backend, proof_gate=gate)
            slot_root = Path(slot_raw)
            os.chmod(slot_root, 0o700)
            with adapter.open_slot(
                preflight, slot_index=0, slot_root=slot_root,
                port=8401, worker_token="tok-fence-live",
                acknowledged_exposure_digest=None, on_revoke=lambda _i: None,
            ) as handle:
                gate.arm(observed_row=f"{TEST_SCOPED}/{TEST_MODEL}", observed_screen_digest=TEST_HEX_C)
                gate.mark_relay_verified(TEST_HEX_A)
                handle.job.activate()
                good_body = json.dumps(_valid_proof_payload()).encode("utf-8")
                reply = _send_framed_request(
                    handle.job.provider_socket,
                    handle.job.relay_proof,
                    _make_fake_request(worker_token="tok-fence-live", body_bytes=good_body),
                )
                self.assertIn(b"200 OK", reply)
                self.assertEqual(gate.admitted_writes, 1)
                self.assertTrue(gate.exact_ok_delivered)

            # Live store generation drift (with frozen target_binding unchanged) must raise ProofGateError.
            with conn._store.locked() as sdir:
                rec = conn._store.read(sdir)
                rec["generation"] = str(binding.generation) + "-drifted"
                conn._store.write(sdir, rec)
            with self.assertRaises(ProofGateError):
                shell_driver._verify_live_binding_intact(
                    approval, backend=backend, config_dir=cfg_dir, target_binding=binding,
                )

    def test_single_slot_cutover_arm_turn_route_and_arrival_relay_verified_latch(self) -> None:
        import pwd
        from oc_openai import session_broker
        from oc_openai.connection import Connection, PhysicalHost
        from oc_openai.profile_backend import ProfileBackend
        from oc_openai.session_adapter import OpenAISessionAdapter, _OpenAISlotTarget
        from oc_openai.session_broker import ProofSessionOptions, _ProofTurnCutover, _SessionSlotCoordinator
        from oc_providers.contracts import InstancePreflight, ProviderInstanceSpec, ReadinessState
        from test_openai_connection import FixtureBrowser, FixtureTransport, FixtureVerifier

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        with (
            tempfile.TemporaryDirectory(prefix="oc-g2-cutover-", dir=str(home)) as td_raw,
            tempfile.TemporaryDirectory(prefix="oc-chat-", dir="/tmp") as disc_raw,
        ):
            td = Path(td_raw)
            os.chmod(td, 0o700)
            state_dir = td / "openai"
            state_dir.mkdir(mode=0o700)
            os.chmod(state_dir, 0o700)
            ev_dir = td / "evidence"
            ev_dir.mkdir(mode=0o700)
            os.chmod(ev_dir, 0o700)
            host = PhysicalHost("a" * 64, "11111111-2222-3333-4444-555555555555")
            backend = ProfileBackend(
                state_dir,
                reviewed=True,
                connection=lambda reg_dir: Connection(
                    reg_dir,
                    browser=FixtureBrowser(),
                    verifier=FixtureVerifier(),
                    transport=FixtureTransport(),
                    host_probe=lambda: host,
                ),
            )
            backend.connect("personal")
            prof, conn, binding = backend.profile_connection("personal")

            approval = ProofApproval(
                run_id=TEST_RUN_ID,
                instance_label="personal",
                scoped_provider_id=TEST_SCOPED,
                approved_model=TEST_MODEL,
                ui_mode="mini",
                cwd=TEST_CWD,
                selection_epoch=prof.epoch,
                credential_generation=binding.generation,
                history_digest_all_12_files=compute_exposure_history_digest(state_dir),
                profile_directory=str(prof.directory),
                client_id=str(prof.client_id),
            )
            stop_event = threading.Event()
            gate = ProofGate(
                approval,
                evidence_dir=ev_dir,
                exposure_dir=state_dir,
                check_owner_alive=lambda: (_ for _ in ()).throw(ProofGateError("proof_gate_foreground_lost")) if stop_event.is_set() else None,
                expected_instructions_sha256=FAKE_INSTRUCTIONS_DIGEST,
            )
            preflight = InstancePreflight(
                spec=ProviderInstanceSpec(kind="openai", label="personal", enabled=True, auth_mode="subscription"),
                readiness=ReadinessState.READY,
                models=(TEST_MODEL,),
                exposure_hold=None,
                handle=_OpenAISlotTarget(profile=prof, conn=conn, binding=binding),
            )
            adapter = OpenAISessionAdapter(backend, proof_gate=gate)
            coord = _SessionSlotCoordinator(stop_event)
            released_keys: list[str] = []
            proof_options = ProofSessionOptions(
                proof_gate=gate,
                on_slot_lease_released=released_keys.append,
            )
            spec = {
                "pod": TEST_POD, "instance": TEST_INSTANCE, "relay": f"{TEST_POD}-relay",
                "relay_image": TEST_HEX_B, "level": TEST_LEVEL,
            }
            disc_root = Path(disc_raw)
            os.chmod(disc_root, 0o700)
            disc_cm = adapter.open_discovery_slot(
                preflight, slot_index=0, slot_root=disc_root,
                port=8401, worker_token="tok-cut-1",
                acknowledged_exposure_digest=None, on_revoke=coord.on_revoke,
            )
            disc_handle = disc_cm.__enter__()
            coord.register_slot(disc_cm, disc_handle, disc_root)
            cutover = _ProofTurnCutover(
                spec=spec, pod_id=TEST_HEX_A, coordinator=coord, sidecars=[],
                started_relay_ids=[], stop_event=stop_event, proof_options=proof_options,
            )
            cutover.tracked_slot_keys.append("disc-0")
            cutover.tracked_slot_indices["disc-0"] = 0
            cutover.record_discovery_slot(
                slot_index=0, item=preflight, adapter=adapter,
                port=8401, worker_token="tok-cut-1", ack_digest=None,
            )
            with (
                patch.object(session_broker, "_start_slot_relay_deferred", return_value=TEST_HEX_C),
                patch.object(session_broker, "_wait_relay_bound"),
            ):
                nonce = cutover.arm_turn_route(f"{TEST_SCOPED}/{TEST_MODEL}", TEST_HEX_B)
            try:
                self.assertTrue(nonce)
                self.assertFalse(stop_event.is_set(), "single-slot cutover must not set stop_event")
                self.assertIn("disc-0", released_keys)
                self.assertEqual(gate.state, STATE_ARMED)
                # Arrival snapshot captured with relay_verified=False must remain ineligible even after verification.
                stale_arrival = ArrivalSnapshot(
                    state=STATE_ARMED, arm_nonce=nonce,
                    job_incarnation=gate._job_incarnation, relay_verified=False,
                )
                stale_body = canonical_proof_body(TEST_MODEL)
                with self.assertRaises(ProofGateError):
                    gate.claim_for_write(
                        stale_arrival, stale_body,
                        job_incarnation=gate._job_incarnation or "",
                    )
                self.assertEqual(gate.admitted_writes, 0)
            finally:
                err = coord.teardown_all(None)
                self.assertIsNone(err)
                coord.remove_slot_roots(require_confirmed_leases=True)

    def test_gate2_isolated_import_subdir_readonly_volume_safety_and_root_allowlist(self) -> None:
        from oc_openai.session_broker import _SessionSlotCoordinator

        with tempfile.TemporaryDirectory(prefix="oc-g2-misc-") as td_raw:
            td = Path(td_raw)
            os.chmod(td, 0o700)
            # 1. Standalone import of test_openai_shell_e2e.py under python3 -IB (no PYTHONPATH, no __init__.py).
            digest, _ = snap_runner.capture_manifest(REPO_ROOT)
            snap = snap_runner.build_read_only_snapshot(REPO_ROOT, digest, base_dir=td)
            try:
                probe = subprocess.run(
                    [
                        sys.executable, "-IB", "-c",
                        "import importlib.util, sys; "
                        "spec = importlib.util.spec_from_file_location('test_openai_shell_e2e', sys.argv[1]); "
                        "mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); "
                        "print(mod.LIVE_FLAG)",
                        str(snap / "tests/e2e/live/test_openai_shell_e2e.py"),
                    ],
                    env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                    capture_output=True, text=True, timeout=15, check=False,
                )
                self.assertEqual(probe.returncode, 0, probe.stderr)
                self.assertIn(LIVE_FLAG, probe.stdout)

                # 2. Writable intermediate directory (0700) inside snapshot must be rejected by verify_read_only_snapshot.
                live_dir = snap / "tests/e2e/live"
                os.chmod(live_dir, 0o700)
                with self.assertRaises(snap_runner.SnapshotError):
                    snap_runner.verify_read_only_snapshot(snap, digest)
                os.chmod(live_dir, 0o500)
            finally:
                snap_runner.cleanup_snapshot(snap)

            # 3. _OwnershipJournal skips volume/worktree teardown when pod has untracked members,
            #    and normal volume removal omits '-f'.
            vol_rm_cmds: list[list[str]] = []

            def _untracked_pm(args, timeout=20.0):
                del timeout
                if args[:2] == ["volume", "rm"]:
                    vol_rm_cmds.append(list(args))
                if args[:2] == ["pod", "inspect"]:
                    data = [{
                        "Id": TEST_HEX_B, "InfraContainerID": "9" * 64,
                        "Labels": {PROOF_OWNER_LABEL: TEST_RUN_ID},
                        "Containers": [{"Id": "9" * 64}, {"Id": "8" * 64}],
                    }]
                    return subprocess.CompletedProcess(args, 0, json.dumps(data).encode(), b"")
                return subprocess.CompletedProcess(args, 0, b"", b"")

            spec = JournalSpec(
                run_id=TEST_RUN_ID, instance=TEST_INSTANCE, pod_name=TEST_POD,
                volume_name=TEST_VOLUME, sandbox_dir=td, cwd=TEST_CWD,
                level=TEST_LEVEL, agent_image_id=TEST_HEX_A, journal_path=td / "owner_u.json",
            )
            j_u = _OwnershipJournal(spec, podman_runner=_untracked_pm)
            j_u.pod_id = TEST_HEX_B
            j_u.volume_owned = True
            res_u = j_u.teardown()
            self.assertFalse(res_u[KEY_CLEANUP_VERIFIED])
            self.assertEqual(vol_rm_cmds, [], "volume teardown must be skipped when pod has untracked members")

            def _clean_vol_pm(args, timeout=20.0):
                del timeout
                if args[:2] == ["volume", "rm"]:
                    vol_rm_cmds.append(list(args))
                    return subprocess.CompletedProcess(args, 0, b"", b"")
                if args[:2] == ["volume", "inspect"]:
                    return subprocess.CompletedProcess(
                        args, 0, json.dumps([{"Labels": {PROOF_OWNER_LABEL: TEST_RUN_ID}}]).encode(), b"",
                    )
                if args[:2] == ["volume", "exists"]:
                    return subprocess.CompletedProcess(args, 1, b"", b"")
                return subprocess.CompletedProcess(args, 0, b"", b"")

            j_v = _OwnershipJournal(spec, podman_runner=_clean_vol_pm)
            j_v.volume_owned = True
            j_v.teardown()
            self.assertEqual(vol_rm_cmds, [["volume", "rm", TEST_VOLUME]])

            # 4. remove_slot_roots(require_confirmed_leases=True) uses strict allowlist (keeps unregistered root).
            unreg_root = td / "unreg_root"
            unreg_root.mkdir(mode=0o700)
            coord = _SessionSlotCoordinator(threading.Event())
            coord.track_slot_root(unreg_root)
            coord.remove_slot_roots(require_confirmed_leases=True)
            self.assertTrue(unreg_root.exists())

    def test_reciprocal_g2_config_digest_preconfirmed_plan_and_export_strictness(self) -> None:
        from oc_openai import session_broker
        from oc_providers.catalog import LaunchRefusedError, ResolvedLaunchPlan
        from oc_providers.config import load_provider_config_with_digest
        from oc_providers.contracts import (
            InstancePreflight,
            ProviderInstanceSpec,
            ReadinessState,
        )

        with tempfile.TemporaryDirectory(prefix="oc-g2-cfg-") as td_raw:
            td = Path(td_raw)
            os.chmod(td, 0o700)
            cfg_dir = td / "cfg"
            cfg_dir.mkdir(mode=0o700)
            os.chmod(cfg_dir, 0o700)
            toml_path = cfg_dir / FILE_PROVIDERS_TOML
            toml_bytes = (
                '[providers.openai.personal]\n'
                'enabled = true\n'
                'auth_mode = "subscription"\n'
                '[providers.openai.work]\n'
                'enabled = true\n'
                'auth_mode = "subscription"\n'
            ).encode("utf-8")
            toml_path.write_bytes(toml_bytes)
            os.chmod(toml_path, 0o600)
            cfg, digest = load_provider_config_with_digest(config_dir=cfg_dir, sandbox_dir=td / "sb")
            self.assertIsNotNone(cfg)
            self.assertEqual(digest, compute_providers_config_digest(cfg_dir))

            exp = td / "exp"
            exp.mkdir(mode=0o700)
            os.chmod(exp, 0o700)
            ev = td / "ev"
            ev.mkdir(mode=0o700)
            os.chmod(ev, 0o700)
            approval = ProofApproval(
                run_id=TEST_RUN_ID, instance_label="personal", scoped_provider_id=TEST_SCOPED,
                approved_model=TEST_MODEL, ui_mode="mini", cwd=TEST_CWD,
                selection_epoch="E" * 43, credential_generation=1,
                history_digest_all_12_files=compute_exposure_history_digest(exp),
                providers_config_digest=digest or "",
            )
            gate = ProofGate(approval, evidence_dir=ev, exposure_dir=exp)
            personal_preflight = InstancePreflight(
                spec=ProviderInstanceSpec(kind="openai", label="personal", enabled=True, auth_mode="subscription"),
                readiness=ReadinessState.READY,
                models=(TEST_MODEL,),
            )
            work_preflight = InstancePreflight(
                spec=ProviderInstanceSpec(kind="openai", label="work", enabled=True, auth_mode="subscription"),
                readiness=ReadinessState.READY,
                models=(TEST_MODEL,),
            )
            plan = ResolvedLaunchPlan(
                admitted=(personal_preflight, work_preflight),
                excluded=(),
                acknowledged_digests={},
                initial_provider_id=TEST_SCOPED,
                initial_model=TEST_MODEL,
                ui_mode="mini",
                ui_source="cli",
            )
            opts = session_broker.ProofSessionOptions(proof_gate=gate, preconfirmed_plan=plan)
            # Empty/missing current config must reject preconfirmed plan.
            with self.assertRaises(LaunchRefusedError):
                session_broker._resolve_session_plan({}, None, {}, None, opts, live_config_digest=digest)
            # Disabled route in current config must reject preconfirmed plan.
            toml_path.write_text('[providers.openai.personal]\nenabled = false\nauth_mode = "subscription"\n', encoding="utf-8")
            cfg_dis, digest_dis = load_provider_config_with_digest(config_dir=cfg_dir, sandbox_dir=td / "sb")
            with self.assertRaises(LaunchRefusedError):
                session_broker._resolve_session_plan({}, cfg_dis, {}, None, opts, live_config_digest=digest_dis)
            # Digest mismatch on enabled config must reject preconfirmed plan.
            with self.assertRaises(LaunchRefusedError):
                session_broker._resolve_session_plan({}, cfg, {}, None, opts, live_config_digest="0" * 64)
            # Multi-instance preconfirmed plan with matching enabled config & digest succeeds.
            resolved = session_broker._resolve_session_plan({}, cfg, {}, None, opts, live_config_digest=digest)
            self.assertIs(resolved, plan)
            # Duplicate slot in preconfirmed plan is rejected.
            dup_plan = ResolvedLaunchPlan(
                admitted=(personal_preflight, personal_preflight),
                excluded=(),
                acknowledged_digests={},
                initial_provider_id=TEST_SCOPED,
                initial_model=TEST_MODEL,
                ui_mode="mini",
                ui_source="cli",
            )
            dup_opts = session_broker.ProofSessionOptions(proof_gate=gate, preconfirmed_plan=dup_plan)
            with self.assertRaises(LaunchRefusedError):
                session_broker._resolve_session_plan({}, cfg, {}, None, dup_opts, live_config_digest=digest)

        # Export corroboration strictness: reject missing user msg, padded " ok ", wrong prompt, or tool call.
        bad_exports = [
            {"messages": [{"info": {"role": "assistant"}, "parts": [{"type": "text", "text": " ok "}]}]},
            {"messages": [
                {"info": {"role": "user"}, "parts": [{"type": "text", "text": PROOF_PROMPT}]},
                {"info": {"role": "assistant"}, "parts": [{"type": "text", "text": " ok "}]},
            ]},
            {"messages": [
                {"info": {"role": "user"}, "parts": [{"type": "text", "text": "wrong prompt"}]},
                {"info": {"role": "assistant"}, "parts": [{"type": "text", "text": EXPECTED_REPLY}]},
            ]},
            {"messages": [
                {"info": {"role": "user"}, "parts": [{"type": "text", "text": PROOF_PROMPT}]},
                {"info": {"role": "assistant"}, "parts": [{"type": "text", "text": EXPECTED_REPLY}, {"type": "tool"}]},
            ]},
        ]
        for bad in bad_exports:
            with self.assertRaises(shell_driver.ShellDriverError):
                shell_driver._verify_export_messages(bad)
        shell_driver._verify_export_messages({
            "messages": [
                {"info": {"role": "user"}, "parts": [{"type": "text", "text": PROOF_PROMPT}]},
                {"info": {"role": "assistant"}, "parts": [{"type": "text", "text": EXPECTED_REPLY}]},
            ]
        })

    @staticmethod
    def _drive_pty_approval_subprocess(reply_line: str) -> tuple[int, str]:
        import pty as pty_mod
        import select

        master_fd, slave_fd = pty_mod.openpty()
        child_code = (
            "import fcntl, os, sys, termios\n"
            f"sys.path.insert(0, {str(REPO_ROOT)!r})\n"
            f"sys.path.insert(0, {str(REPO_ROOT / 'tests/e2e/live')!r})\n"
            "os.setsid()\n"
            "fcntl.ioctl(0, termios.TIOCSCTTY, 0)\n"
            "import openai_shell_driver as drv\n"
            "drv.prompt_attended_approval({\n"
            f"    'run_id': {TEST_RUN_ID!r}, 'instance_label': 'personal',\n"
            f"    'scoped_provider_id': {TEST_SCOPED!r}, 'approved_model': {TEST_MODEL!r},\n"
            "    'ui_mode': 'mini', 'route_policy': 'subscription-only', 'client_id': 'c1',\n"
            "    'selection_epoch': 'e1', 'registration_generation': 1,\n"
            f"    'providers_config_digest': {TEST_HEX_A!r}, 'history_digest_all_12_files': {TEST_HEX_B!r},\n"
            f"    'agent_image_id': {TEST_HEX_A!r}, 'relay_image_id': {TEST_HEX_B!r},\n"
            f"    'source_sha256': {TEST_HEX_C!r},\n"
            "})\n"
        )
        proc = subprocess.Popen(
            [sys.executable, "-IB", "-c", child_code],
            stdin=slave_fd, stdout=slave_fd, stderr=slave_fd, close_fds=True,
        )
        os.close(slave_fd)
        buf = bytearray()
        sent = False
        deadline = time.monotonic() + 10.0
        try:
            while time.monotonic() < deadline and proc.poll() is None:
                if not select.select([master_fd], [], [], 0.1)[0]:
                    continue
                try:
                    chunk = os.read(master_fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                buf.extend(chunk)
                if not sent and b"to authorize" in buf:
                    os.write(master_fd, (reply_line + "\n").encode("utf-8"))
                    sent = True
            rc = proc.wait(timeout=5)
        finally:
            os.close(master_fd)
        return rc, buf.decode("utf-8", errors="replace")

    def test_reciprocal_g2_real_controlling_pty_approval_and_strict_route_observation(self) -> None:
        rc_ok, out_ok = self._drive_pty_approval_subprocess(f"APPROVE {TEST_RUN_ID[:8]}")
        self.assertEqual(rc_ok, 0, out_ok)
        self.assertIn("Live OpenAI Interactive Shell E2E Approval", out_ok)
        rc_no, _ = self._drive_pty_approval_subprocess("WRONG PHRASE")
        self.assertNotEqual(rc_no, 0)

        # Strict route observation: wrong instance or suffix-extended model must NOT arm.
        appr = ProofApproval(
            run_id=TEST_RUN_ID, instance_label="personal", scoped_provider_id=TEST_SCOPED,
            approved_model=TEST_MODEL, ui_mode="full", cwd=TEST_CWD,
            selection_epoch="E" * 43, credential_generation=1, history_digest_all_12_files=TEST_HEX_A,
        )
        for bad_screen in (
            f"openai--work/{TEST_MODEL}-v2",
            f"openai--work/{TEST_MODEL}",
            f"openai--personal/{TEST_MODEL}-v2",
            f"OpenAI (work)  {TEST_MODEL}",
            f"OpenAI (personal)  {TEST_MODEL}-v2",
            f"ChatGPT Subscription (work)  {TEST_MODEL}",
            f"ChatGPT Subscription (work)  openai--personal/{TEST_MODEL}",
            f"ChatGPT Subscription (personal)  other/{TEST_MODEL}",
            f"{TEST_MODEL}",
        ):
            self.assertIsNone(shell_driver.extract_observed_route_row(bad_screen, appr), bad_screen)
        for good_screen in (
            f"Status: OpenAI (personal) / {TEST_MODEL}",
            f"Model: openai--personal/{TEST_MODEL}",
            f"ChatGPT Subscription (personal)  {TEST_MODEL}",
        ):
            row = shell_driver.extract_observed_route_row(good_screen, appr)
            self.assertEqual(row, " ".join(good_screen.split()))

    def test_reciprocal_g2_owner_partial_create_snapshot_delete_teardown_and_settlement_fsync(self) -> None:
        from oc_openai import shell_cleanup_owner as owner_mod

        with tempfile.TemporaryDirectory(prefix="oc-g2-owner-") as td_raw:
            td = Path(td_raw)
            os.chmod(td, 0o700)
            # 1. Partial create in _owner_loop installs journal BEFORE create_under_lock so teardown runs!
            teardown_called = {"n": 0}
            s_client, s_server = socket.socketpair()
            life_r, life_w = os.pipe()
            orig_build = owner_mod._build_journal_from_msg

            def _partial_build(msg):
                j = orig_build(msg)
                def _fail_create(_lh, _sd):
                    j.pod_id = TEST_HEX_B
                    j.ownership_uncertain = True
                    raise CleanupOwnerError("simulated partial create failure")
                def _track_teardown():
                    teardown_called["n"] += 1
                    return {"cleanup_verified": False, "ownership_uncertain": True, "errors": ["partial_create"]}
                j.create_under_lock = _fail_create
                j.teardown = _track_teardown
                return j

            with (
                patch.object(owner_mod, "_build_journal_from_msg", side_effect=_partial_build),
                patch.object(owner_mod.signal, "signal"),
            ):
                t_loop = threading.Thread(target=owner_mod._owner_loop, args=(s_server.fileno(), life_r), daemon=True)
                t_loop.start()
                try:
                    s_client.settimeout(5.0)
                    owner_mod._send_line(s_client, {
                        "op": "create", "run_id": TEST_RUN_ID, "instance": TEST_INSTANCE,
                        "level": TEST_LEVEL, "agent_image_id": TEST_HEX_A, "sandbox_dir": str(td),
                        "lock_helper": str(REPO_ROOT / FILE_SETUP_LOCK), "state_dir": str(td / "st"),
                    })
                    resp_create = json.loads(s_client.makefile("rb").readline().decode("ascii"))
                    self.assertFalse(resp_create["ok"])
                    owner_mod._send_line(s_client, {"op": "teardown"})
                    resp_td = json.loads(s_client.makefile("rb").readline().decode("ascii"))
                    self.assertTrue(resp_td["ok"])
                    self.assertFalse(resp_td["result"][KEY_CLEANUP_VERIFIED])
                    self.assertEqual(teardown_called["n"], 1)
                finally:
                    s_client.close()
                    os.close(life_w)
                    t_loop.join(timeout=5.0)
                    with suppress(OSError):
                        s_server.close()

            # 2. In-memory verified lock helper survives snapshot deletion during teardown!
            lock_copy = td / FILE_SETUP_LOCK
            lock_copy.write_bytes((REPO_ROOT / FILE_SETUP_LOCK).read_bytes())
            os.chmod(lock_copy, 0o500)

            def _clean_pm(args, timeout=20.0):
                del timeout
                if args[:2] in (["pod", "exists"], ["volume", "exists"], ["container", "exists"]):
                    return subprocess.CompletedProcess(args, 1, b"", b"")
                if args[:2] == ["pod", "create"]:
                    return subprocess.CompletedProcess(args, 0, (TEST_HEX_B + "\n").encode(), b"")
                if args[:2] == ["pod", "inspect"]:
                    data = [{"Id": TEST_HEX_B, "InfraContainerID": "9" * 64,
                             "Labels": {PROOF_OWNER_LABEL: TEST_RUN_ID}, "Containers": [{"Id": "9" * 64}]}]
                    return subprocess.CompletedProcess(args, 0, json.dumps(data).encode(), b"")
                if args[:2] == ["volume", "inspect"]:
                    return subprocess.CompletedProcess(
                        args, 0, json.dumps([{"Labels": {PROOF_OWNER_LABEL: TEST_RUN_ID}}]).encode(), b"",
                    )
                if args[0] == "run":
                    return subprocess.CompletedProcess(args, 0, b"12:34\n", b"")
                return subprocess.CompletedProcess(args, 0, b"", b"")

            jspec = JournalSpec(
                run_id=TEST_RUN_ID, instance=TEST_INSTANCE, pod_name=TEST_POD,
                volume_name=TEST_VOLUME, sandbox_dir=td, cwd=TEST_CWD,
                level=TEST_LEVEL, agent_image_id=TEST_HEX_A, journal_path=td / "j_mem.json",
            )
            j_mem = _OwnershipJournal(jspec, podman_runner=_clean_pm)
            j_mem.create_under_lock(lock_copy, td / "state_mem")
            lock_copy.unlink()
            res_mem = j_mem.teardown()
            self.assertTrue(res_mem[KEY_CLEANUP_VERIFIED], res_mem)

            # 3. Incomplete pod membership & pod/volume exists rc=125 fail closed!
            self.assertTrue(j_mem._pod_has_untracked_members({"InfraContainerID": "9" * 64}))
            self.assertTrue(j_mem._pod_has_untracked_members({"InfraContainerID": "9" * 64, "Containers": [{}]}))
            def _rc125_pm(args, timeout=20.0):
                del timeout
                if args[:2] in (["pod", "exists"], ["volume", "exists"]):
                    return subprocess.CompletedProcess(args, 125, b"", b"podman error")
                return subprocess.CompletedProcess(args, 1, b"", b"inspect failed")
            j_125 = _OwnershipJournal(jspec, podman_runner=_rc125_pm)
            j_125.pod_id = TEST_HEX_B
            j_125.volume_owned = True
            res_125 = j_125.teardown()
            self.assertFalse(res_125[KEY_CLEANUP_VERIFIED])
            self.assertTrue(res_125["ownership_uncertain"])

            # 4. Failed settlement fsync must keep exact_ok_delivered=False and verify_settled_evidence()=False!
            exp = td / "exp_s"
            exp.mkdir(mode=0o700)
            os.chmod(exp, 0o700)
            ev = td / "ev_s"
            ev.mkdir(mode=0o700)
            os.chmod(ev, 0o700)
            appr_s = ProofApproval(
                run_id=TEST_RUN_ID, instance_label="personal", scoped_provider_id=TEST_SCOPED,
                approved_model=TEST_MODEL, ui_mode="mini", cwd=TEST_CWD,
                selection_epoch="E" * 43, credential_generation=1,
                history_digest_all_12_files=compute_exposure_history_digest(exp),
            )
            gate_s = ProofGate(appr_s, evidence_dir=ev, exposure_dir=exp, expected_instructions_sha256=FAKE_INSTRUCTIONS_DIGEST)
            gate_s.bind_incarnation("inc_" + "1" * 32, 1)
            gate_s.arm(observed_row=f"{TEST_SCOPED}/{TEST_MODEL}", observed_screen_digest=TEST_HEX_C)
            gate_s.mark_relay_verified(TEST_HEX_A)
            arr_s = gate_s.snapshot_arrival()
            gate_s.claim_for_write(arr_s, canonical_proof_body(TEST_MODEL), job_incarnation="inc_" + "1" * 32)
            with patch("os.fsync", side_effect=OSError("disk full")):
                with self.assertRaises(ProofGateError):
                    gate_s.record_delivery_complete(
                        usage=(1, 1, 2), completed_text=EXPECTED_REPLY, streamed_text=EXPECTED_REPLY, tool_calls=0,
                    )
            self.assertFalse(gate_s.exact_ok_delivered)
            self.assertFalse(gate_s.verify_settled_evidence())
            gate_s.record_delivery_complete(
                usage=(1, 1, 2), completed_text=EXPECTED_REPLY, streamed_text=EXPECTED_REPLY, tool_calls=0,
            )
            self.assertTrue(gate_s.exact_ok_delivered)
            self.assertTrue(gate_s.verify_settled_evidence())

            # 5. Snapshot verifier rejects unmeasured extra .py file & build rejects world-writable parent!
            digest, _ = snap_runner.capture_manifest(REPO_ROOT)
            snap = snap_runner.build_read_only_snapshot(REPO_ROOT, digest, base_dir=td)
            try:
                live_dir = snap / "tests/e2e/live"
                os.chmod(live_dir, 0o700)
                extra = live_dir / "unmeasured_extra.py"
                extra.write_text("X = 1\n", encoding="utf-8")
                os.chmod(extra, 0o400)
                os.chmod(live_dir, 0o500)
                with self.assertRaises(snap_runner.SnapshotError):
                    snap_runner.verify_read_only_snapshot(snap, digest)
            finally:
                snap_runner.cleanup_snapshot(snap)

            bad_parent = td / "world_writable"
            bad_parent.mkdir()
            os.chmod(bad_parent, 0o777)
            with self.assertRaises(snap_runner.SnapshotError):
                snap_runner.build_read_only_snapshot(REPO_ROOT, digest, base_dir=bad_parent)

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
                f"        tmp = Path({str(marker)!r} + '.tmp')\n"
                "        tmp.write_text('teardown_after_sigkill')\n"
                f"        os.replace(tmp, {str(marker)!r})\n"
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

    def test_reciprocal_g2_r2_erased_tui_numeric_pod_id_slot_rmtree_and_receipt_attribution(self) -> None:
        with tempfile.TemporaryDirectory(prefix="oc-g2-r2-") as td_raw:
            td = Path(td_raw)
            os.chmod(td, 0o700)
            exp = td / "exp"
            exp.mkdir(mode=0o700)
            os.chmod(exp, 0o700)
            ev = td / "ev"
            ev.mkdir(mode=0o700)
            os.chmod(ev, 0o700)

            approval = ProofApproval(
                run_id=TEST_RUN_ID,
                instance_label="personal",
                scoped_provider_id=TEST_SCOPED,
                approved_model=TEST_MODEL,
                ui_mode="mini",
                cwd=TEST_CWD,
                selection_epoch="E" * 43,
                credential_generation=1,
                history_digest_all_12_files=compute_exposure_history_digest(exp),
                profile_directory="prof-a",
                client_id="client-a",
                auth_mode="subscription",
                route_policy="subscription-only",
                providers_config_digest=TEST_HEX_A,
            )

            # 1. Erased TUI row (clear screen / alt screen / erase line / CR overwrite) must NEVER arm!
            erased_screens = (
                f"openai--personal/{TEST_MODEL}\x1b[2J\x1b[Hopenai--work/{TEST_MODEL}",
                f"ChatGPT Subscription (personal)  {TEST_MODEL}\x1b[?1049hChatGPT Subscription (work)  {TEST_MODEL}",
                f"openai--personal/{TEST_MODEL}\r\x1b[2Kopenai--work/{TEST_MODEL}",
                f"openai--personal/{TEST_MODEL}\ropenai--work/{TEST_MODEL}      ",
                f"openai--personal/{TEST_MODEL}\nopenai--work/{TEST_MODEL}",
            )
            for raw_screen in erased_screens:
                self.assertIsNone(shell_driver.extract_observed_route_row(raw_screen, approval), raw_screen)
            visible_after_clear = f"openai--work/{TEST_MODEL}\x1b[2J\x1b[HChatGPT Subscription (personal)  {TEST_MODEL}"
            self.assertEqual(
                shell_driver.extract_observed_route_row(visible_after_clear, approval),
                f"ChatGPT Subscription (personal) {TEST_MODEL}",
            )

            # Real _drive_agent_pty subprocess: prints personal, clears screen, prints work -> must NOT arm.
            gate_pty = ProofGate(approval, evidence_dir=ev, exposure_dir=exp)
            gate_pty.bind_incarnation("inc-pty-erased-01", 1)
            armed_calls: list[tuple[str, str]] = []
            stop_ev = threading.Event()
            fake_tui = (
                "import sys, time; "
                f"sys.stdout.write('openai--personal/{TEST_MODEL}\\n'); sys.stdout.flush(); "
                "time.sleep(0.1); "
                f"sys.stdout.write('\\x1b[2J\\x1b[Hopenai--work/{TEST_MODEL}\\n'); sys.stdout.flush(); "
                "time.sleep(1.9)"
            )
            with patch.object(
                shell_driver,
                "_agent_start_command",
                return_value=([sys.executable, "-IB", "-c", fake_tui], dict(os.environ)),
            ):
                shell_driver._drive_agent_pty(
                    TEST_HEX_A, stop_ev, gate_pty, lambda row, dig: armed_calls.append((row, dig)),
                )
            self.assertEqual(armed_calls, [])

            # 2. Numeric or non-64-hex pod/member IDs and pod ID mismatch fail closed without pod rm!
            rm_calls: list[list[str]] = []

            def _numeric_pod_pm(args, timeout=20.0):
                del timeout
                if args[:2] == ["pod", "rm"]:
                    rm_calls.append(list(args))
                if args[:2] == ["pod", "inspect"]:
                    data = [{
                        "Id": TEST_HEX_B,
                        "InfraContainerID": 42,
                        "Labels": {PROOF_OWNER_LABEL: TEST_RUN_ID},
                        "Containers": [{"Id": 42}],
                    }]
                    return subprocess.CompletedProcess(args, 0, json.dumps(data).encode(), b"")
                return subprocess.CompletedProcess(args, 1, b"", b"")

            jspec = JournalSpec(
                run_id=TEST_RUN_ID, instance=TEST_INSTANCE, pod_name=TEST_POD,
                volume_name=TEST_VOLUME, sandbox_dir=td, cwd=TEST_CWD,
                level=TEST_LEVEL, agent_image_id=TEST_HEX_A, journal_path=td / "j_num.json",
            )
            j_num = _OwnershipJournal(jspec, podman_runner=_numeric_pod_pm)
            j_num.pod_id = TEST_HEX_B
            self.assertTrue(j_num._pod_has_untracked_members({"InfraContainerID": 42, "Containers": [{"Id": 42}]}))
            self.assertTrue(j_num._pod_has_untracked_members({"InfraContainerID": "short", "Containers": [{"Id": "short"}]}))
            res_num = j_num.teardown()
            self.assertFalse(res_num[KEY_CLEANUP_VERIFIED])
            self.assertTrue(res_num["ownership_uncertain"])
            self.assertIn("pod_has_untracked_members", res_num["errors"])
            self.assertEqual(rm_calls, [])

            # 3. Confirmed lease release with surviving slot directory (real PermissionError) reports failure!
            slot_parent = td / "slot_parent"
            slot_parent.mkdir(mode=0o700)
            slot_dir = slot_parent / "turn-0"
            slot_dir.mkdir(mode=0o700)
            (slot_dir / "keep.txt").write_text("x", encoding="utf-8")
            j_slot = _OwnershipJournal(jspec, podman_runner=_numeric_pod_pm)
            j_slot.prepare_slot("turn-0", container_name="oc-e2e-deadbeef-relay-0", slot_root=str(slot_dir))
            j_slot.mark_lease_released("turn-0")
            os.chmod(slot_parent, 0o500)
            try:
                res_slot = j_slot.teardown()
            finally:
                os.chmod(slot_parent, 0o700)
            self.assertFalse(res_slot[KEY_CLEANUP_VERIFIED])
            self.assertIn("slot_root_remove_failed:turn-0", res_slot["errors"])
            self.assertTrue(slot_dir.exists())

            # 4. Settlement read-back rejects tampered scoped_provider_id, job_incarnation, digest, or usage!
            gate = ProofGate(approval, evidence_dir=ev, exposure_dir=exp)
            ev_path = gate.bind_incarnation("inc-settle-attr-01", 2)
            nonce = gate.arm(observed_row=f"openai--personal/{TEST_MODEL}", observed_screen_digest=TEST_HEX_B)
            gate.mark_relay_verified(TEST_HEX_C)
            arrival = ArrivalSnapshot(
                state=STATE_ARMED, arm_nonce=nonce, job_incarnation="inc-settle-attr-01", relay_verified=True,
            )
            gate.claim_for_write(
                arrival, canonical_proof_body(TEST_MODEL), job_incarnation="inc-settle-attr-01",
            )
            gate.record_delivery_complete(
                usage=(10, 2, 12), completed_text=EXPECTED_REPLY, streamed_text=EXPECTED_REPLY, tool_calls=0,
            )
            self.assertTrue(gate.verify_settled_evidence())
            good_raw = ev_path.read_bytes()
            good_obj = json.loads(good_raw.decode("utf-8"))
            tamper_cases = (
                {"scoped_provider_id": "openai--work"},
                {"job_incarnation": "inc-other-999999"},
                {"canonical_request_digest": "0" * 64},
                {"usage": None},
                {"usage": [True, 2, 12]},
                {"approved_model": "gpt-other"},
            )
            for patch_fields in tamper_cases:
                bad_obj = dict(good_obj)
                bad_obj.update(patch_fields)
                ev_path.write_text(json.dumps(bad_obj), encoding="utf-8")
                self.assertFalse(gate.verify_settled_evidence(), f"accepted tamper {patch_fields}")
            ev_path.write_bytes(good_raw)
            self.assertTrue(gate.verify_settled_evidence())

    def test_reciprocal_g2_r3_delete_line_unknown_csi_pinned_slot_owner_and_exact_reply(self) -> None:
        from oc_openai import session_broker

        with tempfile.TemporaryDirectory(prefix="oc-g2-r3-") as td_raw:
            td = Path(td_raw)
            os.chmod(td, 0o700)
            exp = td / "exp"
            exp.mkdir(mode=0o700)
            os.chmod(exp, 0o700)
            ev = td / "ev"
            ev.mkdir(mode=0o700)
            os.chmod(ev, 0o700)

            approval = ProofApproval(
                run_id=TEST_RUN_ID, instance_label="personal", scoped_provider_id=TEST_SCOPED,
                approved_model=TEST_MODEL, ui_mode="mini", cwd=TEST_CWD,
                selection_epoch="E" * 43, credential_generation=1,
                history_digest_all_12_files=compute_exposure_history_digest(exp),
                providers_config_digest=TEST_HEX_A,
            )

            # 1. Xterm delete-line (CSI M) and unknown mutating CSI fail closed; full clear recovers.
            for raw in (
                f"openai--personal/{TEST_MODEL}\x1b[1;1H\x1b[M",
                f"openai--personal/{TEST_MODEL}\x1b[1;1H\x1b[1M",
                f"openai--personal/{TEST_MODEL}\x1b[1;1H\x1b[L\x1b[1;1H\x1b[2M",
                f"openai--personal/{TEST_MODEL}\x1b[5$z",
                f"openai--personal/{TEST_MODEL}\x1b[?9999h",
            ):
                self.assertIsNone(shell_driver.extract_observed_route_row(raw, approval), raw)
            recovered = f"openai--personal/{TEST_MODEL}\x1b[5$z\x1b[2J\x1b[Hopenai--personal/{TEST_MODEL}"
            self.assertEqual(
                shell_driver.extract_observed_route_row(recovered, approval),
                f"openai--personal/{TEST_MODEL}",
            )

            # Subprocess PTY deletes approved row with CSI M -> must NOT arm!
            gate_dl = ProofGate(approval, evidence_dir=ev, exposure_dir=exp)
            gate_dl.bind_incarnation("inc-pty-del-line-01", 1)
            armed_dl: list[tuple[str, str]] = []
            fake_dl_tui = (
                "import sys, time; "
                f"sys.stdout.write('openai--personal/{TEST_MODEL}\\n'); sys.stdout.flush(); "
                "time.sleep(0.1); "
                "sys.stdout.write('\\x1b[1;1H\\x1b[M'); sys.stdout.flush(); "
                "time.sleep(1.8)"
            )
            with patch.object(
                shell_driver,
                "_agent_start_command",
                return_value=([sys.executable, "-IB", "-c", fake_dl_tui], dict(os.environ)),
            ):
                shell_driver._drive_agent_pty(
                    TEST_HEX_A, threading.Event(), gate_dl, lambda r, d: armed_dl.append((r, d)),
                )
            self.assertEqual(armed_dl, [])

            # 2. Single slot-root deletion owner + inode-pinned removal never deletes replacements!
            jspec = JournalSpec(
                run_id=TEST_RUN_ID, instance=TEST_INSTANCE, pod_name=TEST_POD,
                volume_name=TEST_VOLUME, sandbox_dir=td, cwd=TEST_CWD,
                level=TEST_LEVEL, agent_image_id=TEST_HEX_A, journal_path=td / "j_pin.json",
            )
            no_pm = lambda args, timeout=20.0: subprocess.CompletedProcess(args, 1, b"", b"")
            # 2a. Replacement regular file at released slot path survives untouched!
            slot_f = td / "slot_replaced_file"
            slot_f.mkdir(mode=0o700)
            j_f = _OwnershipJournal(jspec, podman_runner=no_pm)
            j_f.prepare_slot("turn-0", container_name="oc-e2e-deadbeef-relay-0", slot_root=str(slot_f))
            j_f.mark_lease_released("turn-0")
            slot_f.rmdir()
            slot_f.write_text("unrelated-user-file", encoding="utf-8")
            res_f = j_f.teardown()
            self.assertFalse(res_f[KEY_CLEANUP_VERIFIED])
            self.assertTrue(res_f["ownership_uncertain"])
            self.assertIn("slot_root_identity_mismatch:turn-0", res_f["errors"])
            self.assertTrue(slot_f.is_file())
            self.assertEqual(slot_f.read_text(encoding="utf-8"), "unrelated-user-file")

            # 2b. Replacement directory at released slot path survives untouched!
            slot_d = td / "slot_replaced_dir"
            slot_d.mkdir(mode=0o700)
            j_d = _OwnershipJournal(jspec, podman_runner=no_pm)
            j_d.prepare_slot("turn-0", container_name="oc-e2e-deadbeef-relay-0", slot_root=str(slot_d))
            j_d.mark_lease_released("turn-0")
            slot_d.rmdir()
            slot_d.mkdir(mode=0o700)
            keeper = slot_d / "precious.txt"
            keeper.write_text("do-not-delete", encoding="utf-8")
            res_d = j_d.teardown()
            self.assertFalse(res_d[KEY_CLEANUP_VERIFIED])
            self.assertIn("slot_root_identity_mismatch:turn-0", res_d["errors"])
            self.assertEqual(keeper.read_text(encoding="utf-8"), "do-not-delete")

            # 2c. _finalize_session_teardown delegates slot-root deletion solely to detached cleanup owner!
            coord_slot_dir = td / "coord_owned_by_journal"
            coord_slot_dir.mkdir(mode=0o700)
            released_notified: list[str] = []
            fake_coord = SimpleNamespace(
                _lock=threading.Lock(),
                _slots={
                    0: SimpleNamespace(
                        lease_confirmed_released=True,
                        handle=SimpleNamespace(lease_release_confirmed=True),
                    ),
                },
                teardown_all=lambda _aid: None,
                remove_slot_roots=lambda **_kw: (_ for _ in ()).throw(AssertionError("coordinator must not remove roots")),
            )
            fake_cutover = SimpleNamespace(tracked_slot_keys=["turn-0"], tracked_slot_indices={"turn-0": 0})
            proof_opts = session_broker.ProofSessionOptions(
                proof_gate=gate_dl, on_slot_lease_released=released_notified.append,
            )
            cstate = {"clean": False}
            ok_fin = session_broker._finalize_session_teardown(
                fake_coord, None, fake_cutover, proof_opts, cstate, td, SimpleNamespace(error=lambda _m: None),
            )
            self.assertTrue(ok_fin)
            self.assertTrue(cstate["clean"])
            self.assertIn("turn-0", released_notified)
            self.assertTrue(coord_slot_dir.is_dir())

            # 3. Reply observation rejects "token usage" / zero post-prompt bytes / echoed prompt / stale "ok".
            r_fd, w_fd = os.pipe()
            try:
                fake_gate = SimpleNamespace(admitted_writes=1, exact_ok_delivered=True)
                st = shell_driver._PtyState(armed=True, prompt_sent=True, pre_prompt_lines=("token usage", "ok"))
                self.assertFalse(
                    shell_driver._step_pty_driver(w_fd, "token usage", 5.0, fake_gate, lambda _r, _d: None, st, post_prompt_text=""),
                )
                self.assertFalse(
                    shell_driver._step_pty_driver(w_fd, "token usage", 5.0, fake_gate, lambda _r, _d: None, st, post_prompt_text="token usage"),
                )
                self.assertFalse(
                    shell_driver._step_pty_driver(
                        w_fd, f"token usage\n{PROOF_PROMPT}", 5.0, fake_gate, lambda _r, _d: None, st, post_prompt_text=PROOF_PROMPT,
                    ),
                )
                # Stale pre-prompt "ok" without a second newly rendered "ok" must still fail!
                self.assertFalse(
                    shell_driver._step_pty_driver(
                        w_fd, "token usage\nok", 5.0, fake_gate, lambda _r, _d: None, st, post_prompt_text="status",
                    ),
                )
                # Newly rendered exact assistant reply ("ok" / "Assistant: ok") succeeds and sends Ctrl-C!
                with patch.object(shell_driver.time, "sleep"):
                    done = shell_driver._step_pty_driver(
                        w_fd, "token usage\nok\nAssistant: ok", 5.0, fake_gate, lambda _r, _d: None, st, post_prompt_text="Assistant: ok",
                    )
                self.assertTrue(done)
                self.assertEqual(os.read(r_fd, 16), b"\x03")
            finally:
                os.close(r_fd)
                os.close(w_fd)

    def test_reciprocal_g2_r4_concealed_sgr_pinned_grant_revoke_reply_verdict_and_session_root(self) -> None:
        from oc_openai import session_broker, shell_cleanup_owner as owner_mod

        with tempfile.TemporaryDirectory(prefix="oc-g2-r4-") as td_raw:
            td = Path(td_raw)
            os.chmod(td, 0o700)
            exp = td / "exp"
            exp.mkdir(mode=0o700)
            os.chmod(exp, 0o700)
            ev = td / "ev"
            ev.mkdir(mode=0o700)
            os.chmod(ev, 0o700)

            approval = ProofApproval(
                run_id=TEST_RUN_ID, instance_label="personal", scoped_provider_id=TEST_SCOPED,
                approved_model=TEST_MODEL, ui_mode="mini", cwd=TEST_CWD,
                selection_epoch="E" * 43, credential_generation=1,
                history_digest_all_12_files=compute_exposure_history_digest(exp),
                providers_config_digest=TEST_HEX_A,
            )

            # 1. Concealed SGR 8 and same-color fg==bg text must NOT arm; visible controls MUST arm!
            for concealed in (
                f"\x1b[8mopenai--personal/{TEST_MODEL}\x1b[28m",
                f"\x1b[30;40mopenai--personal/{TEST_MODEL}\x1b[0m",
                f"\x1b[38;2;12;34;56;48;2;12;34;56mChatGPT Subscription (personal)  {TEST_MODEL}\x1b[0m",
                f"\x1b[38:2::12:34:0;48:2::12:34:0mopenai--personal/{TEST_MODEL}\x1b[0m",
                f"\x1b[38:2::12:34:56;48;2;12;34;56mopenai--personal/{TEST_MODEL}\x1b[0m",
            ):
                self.assertIsNone(shell_driver.extract_observed_route_row(concealed, approval), concealed)
            for visible, want in (
                (f"\x1b[8mhidden\x1b[28m\x1b[32mopenai--personal/{TEST_MODEL}\x1b[0m", f"openai--personal/{TEST_MODEL}"),
                (f"\x1b[38:2::12:34:8mopenai--personal/{TEST_MODEL}\x1b[0m", f"openai--personal/{TEST_MODEL}"),
                (
                    f"\x1b[37;40mChatGPT Subscription (personal)  {TEST_MODEL}\x1b[0m",
                    f"ChatGPT Subscription (personal) {TEST_MODEL}",
                ),
            ):
                self.assertEqual(shell_driver.extract_observed_route_row(visible, approval), want)

            gate_sgr = ProofGate(approval, evidence_dir=ev, exposure_dir=exp)
            gate_sgr.bind_incarnation("inc-pty-concealed-01", 1)
            armed_sgr: list[tuple[str, str]] = []
            fake_concealed = (
                "import sys, time; "
                f"sys.stdout.write('\\x1b[8mopenai--personal/{TEST_MODEL}\\x1b[28m\\n'); sys.stdout.flush(); "
                "time.sleep(1.8)"
            )
            with patch.object(
                shell_driver,
                "_agent_start_command",
                return_value=([sys.executable, "-IB", "-c", fake_concealed], dict(os.environ)),
            ):
                pty_out_no_reply: dict[str, bool] = {}
                rc_child = shell_driver._drive_agent_pty(
                    TEST_HEX_A, threading.Event(), gate_sgr,
                    lambda r, d: armed_sgr.append((r, d)), outcome=pty_out_no_reply,
                )
            self.assertEqual(rc_child, 0)
            self.assertEqual(armed_sgr, [])
            # 3. Clean child rc=0 exit without a fresh visible reply records reply_observed=False!
            self.assertFalse(pty_out_no_reply["reply_observed"])

            # 2a. Unreleased crash cleanup revokes ONLY the pinned root's grant, NEVER a replacement at stale path!
            jspec = JournalSpec(
                run_id=TEST_RUN_ID, instance=TEST_INSTANCE, pod_name=TEST_POD,
                volume_name=TEST_VOLUME, sandbox_dir=td, cwd=TEST_CWD,
                level=TEST_LEVEL, agent_image_id=TEST_HEX_A, journal_path=td / "j_r4.json",
            )
            no_pm = lambda args, timeout=20.0: subprocess.CompletedProcess(args, 1, b"", b"")
            orig_slot = td / "slot_unrel_swap"
            orig_grant = orig_slot / "grant"
            orig_grant.mkdir(parents=True, mode=0o700)
            (orig_grant / "lock").touch(mode=0o600)
            (orig_grant / "state").write_text("active\n", encoding="utf-8")

            j_unrel = _OwnershipJournal(jspec, podman_runner=no_pm)
            j_unrel.prepare_slot("turn-0", container_name="oc-e2e-deadbeef-relay-0", slot_root=str(orig_slot))
            j_unrel.begin_slot_create(
                "turn-0", container_name="oc-e2e-deadbeef-relay-0",
                grant_dir=str(orig_grant), slot_root=str(orig_slot),
            )
            moved_slot = td / "slot_unrel_moved"
            orig_slot.rename(moved_slot)
            repl_grant = orig_slot / "grant"
            repl_grant.mkdir(parents=True, mode=0o700)
            (repl_grant / "lock").touch(mode=0o600)
            (repl_grant / "state").write_text("active\n", encoding="utf-8")
            j_unrel.teardown()
            self.assertEqual((moved_slot / "grant" / "state").read_text(encoding="utf-8"), "revoked\n")
            self.assertEqual((repl_grant / "state").read_text(encoding="utf-8"), "active\n")

            # 2b. Released-root deletion detects split name/identity swap right before final os.rmdir
            # and preserves a non-empty replacement directory intact!
            swap_slot = td / "slot_rmdir_race"
            swap_slot.mkdir(mode=0o700)
            j_race = _OwnershipJournal(jspec, podman_runner=no_pm)
            j_race.prepare_slot("turn-0", container_name="oc-e2e-deadbeef-relay-0", slot_root=str(swap_slot))
            j_race.mark_lease_released("turn-0")
            moved_race = td / "slot_rmdir_moved"
            real_rmdir = os.rmdir

            def _swap_before_rmdir(path, *, dir_fd=None):
                if path == swap_slot.name and not moved_race.exists():
                    swap_slot.rename(moved_race)
                    swap_slot.mkdir(mode=0o700)
                    (swap_slot / "keep.txt").write_text("unowned\n", encoding="utf-8")
                return real_rmdir(path, dir_fd=dir_fd)

            with patch.object(owner_mod.os, "rmdir", side_effect=_swap_before_rmdir):
                res_race = j_race.teardown()
            self.assertFalse(res_race[KEY_CLEANUP_VERIFIED])
            self.assertTrue(res_race["ownership_uncertain"])
            self.assertIn("slot_root_identity_mismatch:turn-0", res_race["errors"])
            self.assertEqual((swap_slot / "keep.txt").read_text(encoding="utf-8"), "unowned\n")

            # 4. Session config root registered before first slot opens & cleaned by detached owner!
            j_sess = _OwnershipJournal(jspec, podman_runner=no_pm)
            seen_events: list[str] = []
            cfg_dir = td / "cfg_r4"
            cfg_dir.mkdir(mode=0o700)
            os.chmod(cfg_dir, 0o700)
            (cfg_dir / FILE_PROVIDERS_TOML).write_text(
                '[providers.openai.personal]\nenabled = true\nauth_mode = "subscription"\n', encoding="utf-8",
            )
            os.chmod(cfg_dir / FILE_PROVIDERS_TOML, 0o600)
            from oc_providers.catalog import ResolvedLaunchPlan
            from oc_providers.config import load_provider_config_with_digest
            from oc_providers.contracts import InstancePreflight, ProviderInstanceSpec, ReadinessState

            _, cfg_dig = load_provider_config_with_digest(config_dir=cfg_dir, sandbox_dir=td / "sb")
            appr_sess = ProofApproval(
                run_id=TEST_RUN_ID, instance_label="personal", scoped_provider_id=TEST_SCOPED,
                approved_model=TEST_MODEL, ui_mode="mini", cwd=TEST_CWD,
                selection_epoch="E" * 43, credential_generation=1,
                history_digest_all_12_files=compute_exposure_history_digest(exp),
                providers_config_digest=cfg_dig or "",
            )
            gate_sess = ProofGate(appr_sess, evidence_dir=ev, exposure_dir=exp)
            plan_sess = ResolvedLaunchPlan(
                admitted=(
                    InstancePreflight(
                        spec=ProviderInstanceSpec(kind="openai", label="personal", enabled=True, auth_mode="subscription"),
                        readiness=ReadinessState.READY, models=(TEST_MODEL,),
                    ),
                ),
                excluded=(), acknowledged_digests={},
                initial_provider_id=TEST_SCOPED, initial_model=TEST_MODEL,
                ui_mode="mini", ui_source="cli",
            )
            captured_roots: list[str] = []

            def _on_sess_root(r: str) -> None:
                seen_events.append("session_root")
                captured_roots.append(r)
                j_sess.register_session_root(r)

            def _abort_before_slot(*_a, **_kw):
                seen_events.append("before_slot")
                raise RuntimeError("simulated foreground crash before first slot")

            term = SimpleNamespace(attended=lambda: True, write=lambda _m: None, error=lambda _m: None)
            opts_sess = session_broker.ProofSessionOptions(
                proof_gate=gate_sess, preconfirmed_plan=plan_sess,
                on_session_root_created=_on_sess_root,
            )
            spec_sess = shell_driver.build_driver_session_spec(jspec, relay_image_id=TEST_HEX_B, ui_mode="mini")
            lock_d = td / "locks_r4"
            lock_d.mkdir(mode=0o700)
            os.chmod(lock_d, 0o700)
            with (
                patch.object(session_broker, "check_devbox"),
                patch.object(session_broker, "check_host"),
                patch.object(session_broker, "_run_multi_slot_session", side_effect=_abort_before_slot),
            ):
                rc_s = session_broker.run_interactive_session(
                    spec_sess, term, config_dir=cfg_dir, adapters={"openai": SimpleNamespace()},
                    lock_dir=lock_d, proof_options=opts_sess,
                )
            self.assertNotEqual(rc_s, 0)
            self.assertEqual(seen_events, ["session_root", "before_slot"])
            self.assertEqual(len(captured_roots), 1)
            self.assertTrue(Path(captured_roots[0]).is_dir())
            persisted = json.loads((td / "j_r4.json").read_text(encoding="utf-8"))
            self.assertEqual(persisted["session_root"], captured_roots[0])
            res_sess = j_sess.teardown()
            self.assertTrue(res_sess[KEY_CLEANUP_VERIFIED], res_sess)
            self.assertFalse(Path(captured_roots[0]).exists())

    def test_reciprocal_g2_r5_osc_split_and_wrapped_prompt_reply_guard(self) -> None:
        with tempfile.TemporaryDirectory(prefix="oc-g2-r5-tui-") as td_raw:
            exp = Path(td_raw) / "exp"
            exp.mkdir(mode=0o700)
            os.chmod(exp, 0o700)
            approval = ProofApproval(
                run_id=TEST_RUN_ID, instance_label="personal", scoped_provider_id=TEST_SCOPED,
                approved_model=TEST_MODEL, ui_mode="mini", cwd=TEST_CWD,
                selection_epoch="E" * 43, credential_generation=1,
                history_digest_all_12_files=compute_exposure_history_digest(exp),
                providers_config_digest=TEST_HEX_A,
            )

            # 1. Long (>256B) and chunk-split OSC/ST/C1 control strings never leak into screen cells.
            scr_bel = shell_driver._TerminalScreen()
            scr_bel.feed("\x1b]0;title-" + ("x" * 300))
            self.assertFalse(scr_bel.is_certain)
            self.assertEqual(scr_bel.render(), "")
            scr_bel.feed(f"openai--personal/{TEST_MODEL}\x07")
            self.assertTrue(scr_bel.is_certain)
            self.assertIsNone(shell_driver.extract_observed_route_row(scr_bel.render(), approval))
            self.assertNotIn(TEST_MODEL, scr_bel.render())

            scr_st = shell_driver._TerminalScreen()
            scr_st.feed("\x1b]2;" + ("y" * 400) + f"openai--personal/{TEST_MODEL}\x1b")
            self.assertFalse(scr_st.is_certain)
            self.assertEqual(scr_st.render(), "")
            scr_st.feed("\\")
            self.assertTrue(scr_st.is_certain)
            self.assertNotIn(TEST_MODEL, scr_st.render())

            scr_dcs = shell_driver._TerminalScreen()
            scr_dcs.feed("\x1bP" + ("z" * 300) + f"openai--personal/{TEST_MODEL}\x1b\\")
            self.assertFalse(scr_dcs.is_certain)
            self.assertEqual(scr_dcs.render(), "")

            scr_c1 = shell_driver._TerminalScreen()
            scr_c1.feed("\x9d" + ("q" * 300) + f"openai--personal/{TEST_MODEL}\x9c")
            self.assertTrue(scr_c1.is_certain)
            self.assertNotIn(TEST_MODEL, scr_c1.render())

            # 2. Wrapped user prompt echoes and bare unattributed "ok" must never satisfy reply observation.
            prompt_head = PROOF_PROMPT.removesuffix(f" {shell_driver.EXPECTED_REPLY}")
            fake_gate = SimpleNamespace(
                admitted_writes=1,
                exact_ok_delivered=True,
                approval=SimpleNamespace(approved_model=TEST_MODEL),
            )
            r_fd, w_fd = os.pipe()
            try:
                for screen_text, pre_lines in (
                    (f"{prompt_head}\nok", ()),
                    (f"│ > {prompt_head} │\n│ > ok │", ()),
                    (f"{prompt_head}\nok\n▣ Build · {TEST_MODEL}", ()),
                    ("token usage\nok", ()),
                    (
                        f"ChatGPT Subscription (personal)\nok\n{prompt_head}\nok",
                        ("ChatGPT Subscription (personal)", "ok"),
                    ),
                ):
                    st = shell_driver._PtyState(armed=True, prompt_sent=True, pre_prompt_lines=pre_lines)
                    self.assertFalse(
                        shell_driver._step_pty_driver(
                            w_fd, screen_text, 5.0, fake_gate, lambda _r, _d: None, st, post_prompt_text=screen_text,
                        ),
                        screen_text,
                    )
                    self.assertFalse(st.reply_observed, screen_text)

                # Positive controls: explicit assistant prefix and unwrapped prompt + footer-adjacent "ok".
                for screen_text in (
                    "Assistant: ok",
                    "● ok",
                    f"{PROOF_PROMPT}\n\nok\n▣ Build · {TEST_MODEL}",
                ):
                    st_ok = shell_driver._PtyState(armed=True, prompt_sent=True, pre_prompt_lines=())
                    with patch.object(shell_driver.time, "sleep"):
                        done = shell_driver._step_pty_driver(
                            w_fd, screen_text, 5.0, fake_gate, lambda _r, _d: None, st_ok, post_prompt_text="ok",
                        )
                    self.assertTrue(done, screen_text)
                    self.assertTrue(st_ok.reply_observed, screen_text)
                    self.assertEqual(os.read(r_fd, 16), b"\x03")
            finally:
                os.close(r_fd)
                os.close(w_fd)

    def test_reciprocal_g2_r5_empty_replacement_survives_and_grant_lock_pinned(self) -> None:
        from oc_openai import shell_cleanup_owner as owner_mod

        with tempfile.TemporaryDirectory(prefix="oc-g2-r5-pin-") as td_raw:
            td = Path(td_raw)
            os.chmod(td, 0o700)
            jspec = JournalSpec(
                run_id=TEST_RUN_ID, instance=TEST_INSTANCE, pod_name=TEST_POD,
                volume_name=TEST_VOLUME, sandbox_dir=td, cwd=TEST_CWD,
                level=TEST_LEVEL, agent_image_id=TEST_HEX_A, journal_path=td / "j_r5.json",
            )
            no_pm = lambda args, timeout=20.0: subprocess.CompletedProcess(args, 1, b"", b"")
            relay_cname = "oc-e2e-deadbeef-relay-0"
            mismatch_err = "slot_root_identity_mismatch:turn-0"
            active_state = "active\n"

            # 1. Swap right after _clear_dir_fd (before final rmdir): empty replacement MUST survive untouched.
            swap_slot = td / "slot_post_clear_swap"
            swap_slot.mkdir(mode=0o700)
            (swap_slot / "junk.txt").write_text("old\n", encoding="utf-8")
            j_swap = _OwnershipJournal(jspec, podman_runner=no_pm)
            j_swap.prepare_slot("turn-0", container_name=relay_cname, slot_root=str(swap_slot))
            j_swap.mark_lease_released("turn-0")
            moved_swap = td / "slot_post_clear_moved"
            real_clear = owner_mod._clear_dir_fd
            rmdir_calls: list[str] = []
            real_rmdir = os.rmdir

            def _clear_then_swap(dir_fd: int) -> None:
                real_clear(dir_fd)
                if not moved_swap.exists():
                    swap_slot.rename(moved_swap)
                    swap_slot.mkdir(mode=0o700)

            def _spy_rmdir(path, *, dir_fd=None):
                rmdir_calls.append(str(path))
                return real_rmdir(path, dir_fd=dir_fd)

            with (
                patch.object(owner_mod, "_clear_dir_fd", side_effect=_clear_then_swap),
                patch.object(owner_mod.os, "rmdir", side_effect=_spy_rmdir),
            ):
                res_swap = j_swap.teardown()
            self.assertFalse(res_swap[KEY_CLEANUP_VERIFIED])
            self.assertTrue(res_swap["ownership_uncertain"])
            self.assertIn(mismatch_err, res_swap["errors"])
            self.assertTrue(swap_slot.is_dir())
            self.assertEqual(rmdir_calls, [])

            # 1b. Ancestor swap after _clear_dir_fd also preserves replacement untouched and fails closed.
            anc_parent = td / "anc_parent"
            anc_parent.mkdir(mode=0o700)
            anc_slot = anc_parent / "slot_anc"
            anc_slot.mkdir(mode=0o700)
            j_anc = _OwnershipJournal(jspec, podman_runner=no_pm)
            j_anc.prepare_slot("turn-0", container_name=relay_cname, slot_root=str(anc_slot))
            j_anc.mark_lease_released("turn-0")
            anc_moved = td / "anc_parent_moved"
            anc_rmdirs: list[str] = []

            def _clear_then_swap_anc(dir_fd: int) -> None:
                real_clear(dir_fd)
                if not anc_moved.exists():
                    anc_parent.rename(anc_moved)
                    anc_parent.mkdir(mode=0o700)
                    anc_slot.mkdir(mode=0o700)

            def _spy_anc_rmdir(path, *, dir_fd=None):
                anc_rmdirs.append(str(path))
                return real_rmdir(path, dir_fd=dir_fd)

            with (
                patch.object(owner_mod, "_clear_dir_fd", side_effect=_clear_then_swap_anc),
                patch.object(owner_mod.os, "rmdir", side_effect=_spy_anc_rmdir),
            ):
                res_anc = j_anc.teardown()
            self.assertFalse(res_anc[KEY_CLEANUP_VERIFIED])
            self.assertIn(mismatch_err, res_anc["errors"])
            self.assertTrue(anc_slot.is_dir())
            self.assertEqual(anc_rmdirs, [])

            # 2a. Same slot_root with replaced grant/ dir: replacement grant/state MUST stay "active\n".
            slot_gswap = td / "slot_same_root_grant_swap"
            grant_orig = slot_gswap / "grant"
            grant_orig.mkdir(parents=True, mode=0o700)
            (grant_orig / "lock").touch(mode=0o600)
            (grant_orig / "state").write_text(active_state, encoding="utf-8")
            j_gswap = _OwnershipJournal(jspec, podman_runner=no_pm)
            j_gswap.prepare_slot("turn-0", container_name=relay_cname, slot_root=str(slot_gswap))
            j_gswap.begin_slot_create(
                "turn-0", container_name=relay_cname,
                grant_dir=str(grant_orig), slot_root=str(slot_gswap),
            )
            grant_orig.rename(slot_gswap / "grant_old")
            grant_orig.mkdir(mode=0o700)
            (grant_orig / "lock").touch(mode=0o600)
            (grant_orig / "state").write_text(active_state, encoding="utf-8")
            j_gswap.teardown()
            self.assertEqual((grant_orig / "state").read_text(encoding="utf-8"), active_state)

            # 2b. Same slot_root and same grant/ with replaced grant/lock file: state MUST stay "active\n".
            slot_lswap = td / "slot_same_grant_lock_swap"
            grant_l = slot_lswap / "grant"
            grant_l.mkdir(parents=True, mode=0o700)
            lock_l = grant_l / "lock"
            lock_l.touch(mode=0o600)
            (grant_l / "state").write_text(active_state, encoding="utf-8")
            j_lswap = _OwnershipJournal(jspec, podman_runner=no_pm)
            j_lswap.prepare_slot("turn-0", container_name=relay_cname, slot_root=str(slot_lswap))
            j_lswap.begin_slot_create(
                "turn-0", container_name=relay_cname,
                grant_dir=str(grant_l), slot_root=str(slot_lswap),
            )
            lock_l.rename(grant_l / "lock_old")
            lock_l.touch(mode=0o600)
            j_lswap.teardown()
            self.assertEqual((grant_l / "state").read_text(encoding="utf-8"), active_state)

            # 2c. Unmodified slot_root + grant/ + grant/lock (prepared before grant existed) revokes cleanly.
            slot_ok = td / "slot_ok_revoke"
            slot_ok.mkdir(mode=0o700)
            j_ok = _OwnershipJournal(jspec, podman_runner=no_pm)
            j_ok.prepare_slot("turn-0", container_name=relay_cname, slot_root=str(slot_ok))
            grant_ok = slot_ok / "grant"
            grant_ok.mkdir(mode=0o700)
            (grant_ok / "lock").touch(mode=0o600)
            (grant_ok / "state").write_text(active_state, encoding="utf-8")
            j_ok.begin_slot_create(
                "turn-0", container_name=relay_cname,
                grant_dir=str(grant_ok), slot_root=str(slot_ok),
            )
            j_ok.teardown()
            self.assertEqual((grant_ok / "state").read_text(encoding="utf-8"), "revoked\n")

    def test_reciprocal_g2_r6_pty_decoder_c1_bytes_and_footer_only_repaint(self) -> None:
        import codecs

        with tempfile.TemporaryDirectory(prefix="oc-g2-r6-pty-") as td_raw:
            exp = Path(td_raw) / "exp"
            exp.mkdir(mode=0o700)
            os.chmod(exp, 0o700)
            ev = Path(td_raw) / "ev"
            ev.mkdir(mode=0o700)
            os.chmod(ev, 0o700)
            approval = ProofApproval(
                run_id=TEST_RUN_ID, instance_label="personal", scoped_provider_id=TEST_SCOPED,
                approved_model=TEST_MODEL, ui_mode="mini", cwd=TEST_CWD,
                selection_epoch="E" * 43, credential_generation=1,
                history_digest_all_12_files=compute_exposure_history_digest(exp),
                providers_config_digest=TEST_HEX_A,
            )

            # 1. Validate raw 8-bit C1 bytes and UTF-8 C1 bytes through the real PTY decoder path.
            gate_c1 = ProofGate(approval, evidence_dir=ev, exposure_dir=exp)
            gate_c1.bind_incarnation("inc-pty-c1-raw-01", 1)
            armed_c1: list[tuple[str, str]] = []
            raw_c1_child = (
                "import sys, time; "
                f"sys.stdout.buffer.write(b'\\x9d0;openai--personal/{TEST_MODEL}\\x9c\\n'); "
                "sys.stdout.buffer.flush(); time.sleep(1.8)"
            )
            with patch.object(
                shell_driver,
                "_agent_start_command",
                return_value=([sys.executable, "-IB", "-c", raw_c1_child], dict(os.environ)),
            ):
                pty_out: dict[str, bool] = {}
                rc_child = shell_driver._drive_agent_pty(
                    TEST_HEX_A, threading.Event(), gate_c1,
                    lambda r, d: armed_c1.append((r, d)), outcome=pty_out,
                )
            self.assertEqual(rc_child, 0)
            self.assertEqual(armed_c1, [])
            self.assertFalse(pty_out["reply_observed"])

            for raw_payload in (
                b"\x9d0;" + b"x" * 40 + f"openai--personal/{TEST_MODEL}".encode("ascii") + b"\x9c",
                b"\x9b32m" + f"openai--personal/{TEST_MODEL}".encode("ascii"),
            ):
                scr = shell_driver._TerminalScreen()
                dec = codecs.getincrementaldecoder("utf-8")(errors="strict")
                shell_driver._feed_pty_bytes(scr, dec, raw_payload, final=False)
                self.assertFalse(scr.is_certain)
                self.assertEqual(scr.render(), "")
                # Subsequent clear-screen escape in a later chunk must NOT clear sticky stream invalidation!
                shell_driver._feed_pty_bytes(
                    scr, dec, f"\x1b[2J\x1b[Hopenai--personal/{TEST_MODEL}\x07".encode("ascii"), final=False,
                )
                self.assertFalse(scr.is_certain)
                self.assertEqual(scr.render(), "")

            self.assertIsNone(
                shell_driver.extract_observed_route_row(f"\ufffd0;openai--personal/{TEST_MODEL}", approval),
            )

            # Cursor-positioned TUI reply (\x1b[row;colH) must preserve row boundaries and observe "ok"!
            gate_cursor = SimpleNamespace(
                approval=approval,
                admitted_writes=0,
                exact_ok_delivered=False,
            )
            armed_cursor: list[tuple[str, str]] = []
            cursor_tui_child = (
                "import sys, time; "
                f"sys.stdout.write('\\x1b[1;1Hopenai--personal/{TEST_MODEL}\\n'); sys.stdout.flush(); "
                "line = sys.stdin.readline(); "
                f"sys.stdout.write('\\x1b[10;1HAssistant\\x1b[11;1Hok\\x1b[12;1H{TEST_MODEL}'); "
                "sys.stdout.flush(); time.sleep(0.9)"
            )

            def _arm_and_deliver(row: str, dig: str) -> None:
                armed_cursor.append((row, dig))
                gate_cursor.admitted_writes = 1
                gate_cursor.exact_ok_delivered = True

            with (
                patch.object(
                    shell_driver,
                    "_agent_start_command",
                    return_value=([sys.executable, "-IB", "-c", cursor_tui_child], dict(os.environ)),
                ),
                patch.object(shell_driver.time, "sleep"),
            ):
                pty_cursor_out: dict[str, bool] = {}
                shell_driver._drive_agent_pty(
                    TEST_HEX_A, threading.Event(), gate_cursor, _arm_and_deliver, outcome=pty_cursor_out,
                )
            self.assertEqual(len(armed_cursor), 1)
            self.assertTrue(pty_cursor_out["reply_observed"])

            utf8_c1 = ("\x9d0;" + ("q" * 300) + f"openai--personal/{TEST_MODEL}\x9c").encode("utf-8")
            scr_u = shell_driver._TerminalScreen()
            dec_u = codecs.getincrementaldecoder("utf-8")(errors="strict")
            shell_driver._feed_pty_bytes(scr_u, dec_u, utf8_c1[:120], final=False)
            self.assertFalse(scr_u.is_certain)
            self.assertEqual(scr_u.render(), "")
            shell_driver._feed_pty_bytes(scr_u, dec_u, utf8_c1[120:], final=True)
            self.assertTrue(scr_u.is_certain)
            self.assertNotIn(TEST_MODEL, scr_u.render())

            # 2. Footer-only repaint next to an old visible "ok" must NOT count as a fresh reply.
            prompt_head = PROOF_PROMPT.removesuffix(f" {shell_driver.EXPECTED_REPLY}")
            footer_line = f"▣ Build · {TEST_MODEL}"
            fake_gate = SimpleNamespace(
                admitted_writes=1,
                exact_ok_delivered=True,
                approval=SimpleNamespace(approved_model=TEST_MODEL),
            )
            r_fd, w_fd = os.pipe()
            try:
                old_pre = ("token usage", "ok")
                for screen_text, post_text in (
                    (f"token usage\nok\n{footer_line}", footer_line),
                    (f"token usage\nok\n{footer_line}", None),
                    (
                        f"token usage\nok\n{footer_line}\n{prompt_head}\nok",
                        f"{prompt_head}\nok\n{footer_line}",
                    ),
                ):
                    st = shell_driver._PtyState(armed=True, prompt_sent=True, pre_prompt_lines=old_pre)
                    self.assertFalse(
                        shell_driver._step_pty_driver(
                            w_fd, screen_text, 5.0, fake_gate, lambda _r, _d: None, st, post_prompt_text=post_text,
                        ),
                        (screen_text, post_text),
                    )
                    self.assertFalse(st.reply_observed)

                # Positive control: genuine newly rendered assistant "ok" still succeeds.
                fresh_screen = f"token usage\nok\n{PROOF_PROMPT}\n\nok\n{footer_line}"
                fresh_post = f"{PROOF_PROMPT}\n\nok\n{footer_line}"
                st_ok = shell_driver._PtyState(armed=True, prompt_sent=True, pre_prompt_lines=old_pre)
                with patch.object(shell_driver.time, "sleep"):
                    done = shell_driver._step_pty_driver(
                        w_fd, fresh_screen, 5.0, fake_gate, lambda _r, _d: None, st_ok, post_prompt_text=fresh_post,
                    )
                self.assertTrue(done)
                self.assertTrue(st_ok.reply_observed)
                self.assertEqual(os.read(r_fd, 16), b"\x03")
            finally:
                os.close(r_fd)
                os.close(w_fd)

    def test_reciprocal_g2_r6_worktree_empty_replacement_survives_and_grant_lock_timeout(self) -> None:
        import fcntl
        import time

        with tempfile.TemporaryDirectory(prefix="oc-g2-r6-wt-") as td_raw:
            td = Path(td_raw)
            os.chmod(td, 0o700)
            wt_dir = td / "wt"
            wt_dir.mkdir(mode=0o700)
            leaf = TEST_CWD.split("/", 1)[1]

            def _make_wt_runner(swap_before_recheck: bool = False):
                def _runner(args, timeout=20.0):
                    del timeout
                    c_idx = args.index("-c")
                    script = args[c_idx + 1].replace("'/sandbox/wt'", repr(str(wt_dir)))
                    if swap_before_recheck:
                        # Inject a concurrent agent swap right before final identity verification.
                        swap_hook = (
                            "if os.listdir(leaf_fd):\n"
                            "            raise SystemExit(3)\n"
                            "        os.rename(leaf, leaf + '.moved', src_dir_fd=wt_fd, dst_dir_fd=wt_fd)\n"
                            "        os.mkdir(leaf, 0o700, dir_fd=wt_fd)\n"
                        )
                        script = script.replace(
                            "if os.listdir(leaf_fd):\n            raise SystemExit(3)\n", swap_hook, 1,
                        )
                    leaf_arg, dev_s, ino_s = args[c_idx + 2], args[c_idx + 3], args[c_idx + 4]
                    return subprocess.run(
                        [sys.executable, "-IB", "-c", script, leaf_arg, dev_s, ino_s, str(wt_dir)],
                        capture_output=True,
                        check=False,
                    )
                return _runner

            # 1a. Genuine owned empty worktree: verified intact and directory preserved (no rmdir in /sandbox/wt).
            wt_leaf = wt_dir / leaf
            wt_leaf.mkdir(mode=0o700)
            wt_st = os.lstat(wt_leaf)
            jspec = JournalSpec(
                run_id=TEST_RUN_ID, instance=TEST_INSTANCE, pod_name=TEST_POD,
                volume_name=TEST_VOLUME, sandbox_dir=td, cwd=TEST_CWD,
                level=TEST_LEVEL, agent_image_id=TEST_HEX_A, journal_path=td / "j_r6_wt.json",
            )
            j_ok = _OwnershipJournal(jspec, podman_runner=_make_wt_runner())
            j_ok.worktree_owned = True
            j_ok.worktree_dev_ino = (wt_st.st_dev, wt_st.st_ino)
            res_ok = j_ok.teardown()
            self.assertTrue(res_ok[KEY_CLEANUP_VERIFIED], res_ok)
            self.assertTrue(wt_leaf.is_dir())
            self.assertEqual(list(wt_leaf.iterdir()), [])

            # 1b. Empty replacement swapped at final check MUST survive untouched and fail closed.
            j_swap = _OwnershipJournal(jspec, podman_runner=_make_wt_runner(swap_before_recheck=True))
            j_swap.worktree_owned = True
            j_swap.worktree_dev_ino = (wt_st.st_dev, wt_st.st_ino)
            res_swap = j_swap.teardown()
            self.assertFalse(res_swap[KEY_CLEANUP_VERIFIED])
            self.assertTrue(res_swap["ownership_uncertain"])
            self.assertIn("worktree_identity_mismatch", res_swap["errors"])
            self.assertTrue(wt_leaf.is_dir())
            self.assertNotEqual((os.lstat(wt_leaf).st_dev, os.lstat(wt_leaf).st_ino), (wt_st.st_dev, wt_st.st_ino))

            # 2. Crash-cleanup grant-lock acquisition is bounded and persists uncertainty on timeout.
            lock_journal = td / "j_r6_lock.json"
            jspec_lock = JournalSpec(
                run_id=TEST_RUN_ID, instance=TEST_INSTANCE, pod_name=TEST_POD,
                volume_name=TEST_VOLUME, sandbox_dir=td, cwd=TEST_CWD,
                level=TEST_LEVEL, agent_image_id=TEST_HEX_A, journal_path=lock_journal,
            )
            no_pm = lambda args, timeout=20.0: subprocess.CompletedProcess(args, 1, b"", b"")
            slot_locked = td / "slot_locked_grant"
            grant_locked = slot_locked / "grant"
            grant_locked.mkdir(parents=True, mode=0o700)
            lock_file = grant_locked / "lock"
            lock_file.touch(mode=0o600)
            (grant_locked / "state").write_text("active\n", encoding="utf-8")

            j_lock = _OwnershipJournal(jspec_lock, podman_runner=no_pm, grant_lock_timeout=0.15)
            j_lock.prepare_slot("turn-0", container_name="oc-e2e-deadbeef-relay-0", slot_root=str(slot_locked))
            j_lock.begin_slot_create(
                "turn-0", container_name="oc-e2e-deadbeef-relay-0",
                grant_dir=str(grant_locked), slot_root=str(slot_locked),
            )
            holder_fd = os.open(lock_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                fcntl.flock(holder_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                t0 = time.monotonic()
                res_lock = j_lock.teardown()
                elapsed = time.monotonic() - t0
            finally:
                with suppress(OSError):
                    fcntl.flock(holder_fd, fcntl.LOCK_UN)
                os.close(holder_fd)

            self.assertLess(elapsed, 2.0)
            self.assertFalse(res_lock[KEY_CLEANUP_VERIFIED])
            self.assertTrue(res_lock["ownership_uncertain"])
            self.assertIn("grant_lock_timeout:turn-0", res_lock["errors"])
            self.assertEqual((grant_locked / "state").read_text(encoding="utf-8"), "active\n")
            persisted = json.loads(lock_journal.read_text(encoding="utf-8"))
            self.assertTrue(persisted["ownership_uncertain"])
            self.assertIn("grant_lock_timeout:turn-0", persisted["cleanup_errors"])

    def test_reciprocal_g2_r7_worktree_preserve_missing_clipped_prompt_and_fifo_lock(self) -> None:
        import time

        with tempfile.TemporaryDirectory(prefix="oc-g2-r7-") as td_raw:
            td = Path(td_raw)
            os.chmod(td, 0o700)
            wt_dir = td / "wt"
            wt_dir.mkdir(mode=0o700)
            leaf = TEST_CWD.split("/", 1)[1]

            def _run_wt_script(args, timeout=20.0):
                del timeout
                c_idx = args.index("-c")
                script = args[c_idx + 1].replace("'/sandbox/wt'", repr(str(wt_dir)))
                leaf_arg, dev_s, ino_s = args[c_idx + 2], args[c_idx + 3], args[c_idx + 4]
                return subprocess.run(
                    [sys.executable, "-IB", "-c", script, leaf_arg, dev_s, ino_s, str(wt_dir)],
                    capture_output=True,
                    check=False,
                )

            jspec = JournalSpec(
                run_id=TEST_RUN_ID, instance=TEST_INSTANCE, pod_name=TEST_POD,
                volume_name=TEST_VOLUME, sandbox_dir=td, cwd=TEST_CWD,
                level=TEST_LEVEL, agent_image_id=TEST_HEX_A, journal_path=td / "j_r7.json",
            )

            # 1a. Renamed/missing journaled worktree must NOT report false success; moved files remain intact.
            wt_missing = wt_dir / leaf
            wt_missing.mkdir(mode=0o700)
            (wt_missing / "sample.txt").write_text("keep\n", encoding="utf-8")
            wt_st = os.lstat(wt_missing)
            moved_wt = wt_dir / f"{leaf}.renamed"
            wt_missing.rename(moved_wt)
            j_miss = _OwnershipJournal(jspec, podman_runner=_run_wt_script)
            j_miss.worktree_owned = True
            j_miss.worktree_dev_ino = (wt_st.st_dev, wt_st.st_ino)
            res_miss = j_miss.teardown()
            self.assertFalse(res_miss[KEY_CLEANUP_VERIFIED])
            self.assertTrue(res_miss["ownership_uncertain"])
            self.assertIn("worktree_identity_mismatch", res_miss["errors"])
            self.assertEqual((moved_wt / "sample.txt").read_text(encoding="utf-8"), "keep\n")

            # 1b. Non-empty worktree under worker-writable /sandbox/wt preserves all contents untouched.
            wt_nonempty = wt_dir / leaf
            wt_nonempty.mkdir(mode=0o700)
            (wt_nonempty / "unowned.txt").write_text("do-not-delete\n", encoding="utf-8")
            wt_ne_st = os.lstat(wt_nonempty)
            j_ne = _OwnershipJournal(jspec, podman_runner=_run_wt_script)
            j_ne.worktree_owned = True
            j_ne.worktree_dev_ino = (wt_ne_st.st_dev, wt_ne_st.st_ino)
            res_ne = j_ne.teardown()
            self.assertFalse(res_ne[KEY_CLEANUP_VERIFIED])
            self.assertTrue(res_ne["ownership_uncertain"])
            self.assertIn("worktree_nonempty_preserved", res_ne["errors"])
            self.assertEqual((wt_nonempty / "unowned.txt").read_text(encoding="utf-8"), "do-not-delete\n")

            # 2. Clipped user prompt scrolled out of 32-row renderer must NOT satisfy fresh-reply check.
            prompt_head = PROOF_PROMPT.removesuffix(f" {shell_driver.EXPECTED_REPLY}")
            footer_line = f"▣ Build · {TEST_MODEL}"
            scr_clip = shell_driver._TerminalScreen(rows=32, cols=120)
            scr_clip.feed(f"{prompt_head}\nok\n" + ("\n" * 30) + footer_line)
            clipped_rendered = scr_clip.render()
            self.assertNotIn(prompt_head, clipped_rendered)
            self.assertIn("ok", clipped_rendered)
            self.assertIn(footer_line, clipped_rendered)
            self.assertFalse(
                shell_driver._has_new_exact_reply(
                    clipped_rendered, (), f"ok\n{footer_line}", approved_model=TEST_MODEL,
                ),
            )
            self.assertFalse(
                shell_driver._has_new_exact_reply(
                    clipped_rendered, (), None, approved_model=TEST_MODEL,
                ),
            )
            # Positive controls that survive clipping or have explicit attribution still succeed.
            self.assertTrue(
                shell_driver._has_new_exact_reply("Assistant: ok", (), "Assistant: ok", approved_model=TEST_MODEL),
            )
            self.assertTrue(
                shell_driver._has_new_exact_reply(
                    f"Assistant\nok\n{TEST_MODEL}", (), "Assistant\nok", approved_model=TEST_MODEL,
                ),
            )
            self.assertTrue(
                shell_driver._has_new_exact_reply(
                    f"{PROOF_PROMPT}\n\nok\n{footer_line}",
                    (),
                    f"{PROOF_PROMPT}\n\nok\n{footer_line}",
                    approved_model=TEST_MODEL,
                ),
            )

            # 3. FIFO at grant/lock must never block open() in either pinning or revocation paths.
            no_pm = lambda args, timeout=20.0: subprocess.CompletedProcess(args, 1, b"", b"")
            relay_cname = "oc-e2e-deadbeef-relay-0"
            active_state = "active\n"

            # 3a. FIFO present at pinning time (begin_slot_create) and at teardown.
            fifo_journal_a = td / "j_r7_fifo_a.json"
            jspec_fa = JournalSpec(
                run_id=TEST_RUN_ID, instance=TEST_INSTANCE, pod_name=TEST_POD,
                volume_name=TEST_VOLUME, sandbox_dir=td, cwd=TEST_CWD,
                level=TEST_LEVEL, agent_image_id=TEST_HEX_A, journal_path=fifo_journal_a,
            )
            slot_fa = td / "slot_fifo_pin"
            grant_fa = slot_fa / "grant"
            grant_fa.mkdir(parents=True, mode=0o700)
            os.mkfifo(grant_fa / "lock", 0o600)
            (grant_fa / "state").write_text(active_state, encoding="utf-8")
            j_fa = _OwnershipJournal(jspec_fa, podman_runner=no_pm, grant_lock_timeout=0.15)
            t0 = time.monotonic()
            j_fa.prepare_slot("turn-0", container_name=relay_cname, slot_root=str(slot_fa))
            j_fa.begin_slot_create("turn-0", container_name=relay_cname, grant_dir=str(grant_fa), slot_root=str(slot_fa))
            res_fa = j_fa.teardown()
            self.assertLess(time.monotonic() - t0, 1.5)
            self.assertFalse(res_fa[KEY_CLEANUP_VERIFIED])
            self.assertTrue(res_fa["ownership_uncertain"])
            self.assertIn("grant_lock_mismatch:turn-0", res_fa["errors"])
            self.assertEqual((grant_fa / "state").read_text(encoding="utf-8"), active_state)

            # 3b. Regular lock replaced by FIFO before revocation teardown.
            fifo_journal_b = td / "j_r7_fifo_b.json"
            jspec_fb = JournalSpec(
                run_id=TEST_RUN_ID, instance=TEST_INSTANCE, pod_name=TEST_POD,
                volume_name=TEST_VOLUME, sandbox_dir=td, cwd=TEST_CWD,
                level=TEST_LEVEL, agent_image_id=TEST_HEX_A, journal_path=fifo_journal_b,
            )
            slot_fb = td / "slot_fifo_revoke"
            grant_fb = slot_fb / "grant"
            grant_fb.mkdir(parents=True, mode=0o700)
            lock_fb = grant_fb / "lock"
            lock_fb.touch(mode=0o600)
            (grant_fb / "state").write_text(active_state, encoding="utf-8")
            j_fb = _OwnershipJournal(jspec_fb, podman_runner=no_pm, grant_lock_timeout=0.15)
            j_fb.prepare_slot("turn-0", container_name=relay_cname, slot_root=str(slot_fb))
            j_fb.begin_slot_create("turn-0", container_name=relay_cname, grant_dir=str(grant_fb), slot_root=str(slot_fb))
            lock_fb.unlink()
            os.mkfifo(lock_fb, 0o600)
            t1 = time.monotonic()
            res_fb = j_fb.teardown()
            self.assertLess(time.monotonic() - t1, 1.5)
            self.assertFalse(res_fb[KEY_CLEANUP_VERIFIED])
            self.assertTrue(res_fb["ownership_uncertain"])
            self.assertIn("grant_lock_mismatch:turn-0", res_fb["errors"])
            self.assertEqual((grant_fb / "state").read_text(encoding="utf-8"), active_state)
            persisted_fb = json.loads(fifo_journal_b.read_text(encoding="utf-8"))
            self.assertTrue(persisted_fb["ownership_uncertain"])
            self.assertIn("grant_lock_mismatch:turn-0", persisted_fb["cleanup_errors"])

    def test_reciprocal_g2_r8_dec_graphics_charset_and_stock_full_footer(self) -> None:
        with tempfile.TemporaryDirectory(prefix="oc-g2-r8-") as td_raw:
            td = Path(td_raw)
            os.chmod(td, 0o700)
            exp = td / "exp"
            exp.mkdir(mode=0o700)
            os.chmod(exp, 0o700)
            ev = td / "ev"
            ev.mkdir(mode=0o700)
            os.chmod(ev, 0o700)
            approval = ProofApproval(
                run_id=TEST_RUN_ID, instance_label="personal", scoped_provider_id=TEST_SCOPED,
                approved_model=TEST_MODEL, ui_mode="full", cwd=TEST_CWD,
                selection_epoch="E" * 43, credential_generation=1,
                history_digest_all_12_files=compute_exposure_history_digest(exp),
                providers_config_digest=TEST_HEX_A,
            )

            # 1a. DEC Special Graphics (G0 via ESC ( 0, G1 via ESC ) 0 + SO) renders glyphs, not ASCII route.
            route_txt = f"openai--personal/{TEST_MODEL}"
            self.assertIsNone(
                shell_driver.extract_observed_route_row(f"\x1b(0{route_txt}\x1b(B", approval),
            )
            self.assertIsNone(
                shell_driver.extract_observed_route_row(f"\x1b)0\x0e{route_txt}\x0f", approval),
            )
            # Chunk-split ESC ( / 0 keeps observation disabled while incomplete and translates payload.
            scr_cs = shell_driver._TerminalScreen()
            scr_cs.feed("\x1b(")
            self.assertFalse(scr_cs.is_certain)
            scr_cs.feed(f"0{route_txt}\n")
            self.assertIsNone(shell_driver.extract_observed_route_row(scr_cs.render(), approval))
            # Returning to ordinary US-ASCII (ESC ( B) restores normal route observation.
            scr_cs.feed(f"\x1b(B{route_txt}\n")
            self.assertEqual(shell_driver.extract_observed_route_row(scr_cs.render(), approval), route_txt)
            # Returning from G1 graphics via SI (\x0f) also restores ordinary US-ASCII.
            scr_so = shell_driver._TerminalScreen()
            scr_so.feed(f"\x1b)0\x0e{route_txt}\n\x0f{route_txt}\n")
            self.assertEqual(shell_driver.extract_observed_route_row(scr_so.render(), approval), route_txt)
            # Unknown character set (e.g. ESC ( A UK) fails closed.
            scr_unk = shell_driver._TerminalScreen()
            scr_unk.feed(f"\x1b(A{route_txt}")
            self.assertFalse(scr_unk.is_certain)
            self.assertEqual(scr_unk.render(), "")
            # Mixed CSI s/u, ESC 7/8, CSI ?1048h/l, and alternate-screen return match xterm charset restoration.
            self.assertEqual(shell_driver.render_terminal_screen("\x1b[uok").strip(), "ok")
            self.assertEqual(shell_driver.render_terminal_screen("\x1b7\x1b[uok").strip(), "ok")
            self.assertEqual(shell_driver.render_terminal_screen("\x1b[s\x1b8ok").strip(), "ok")
            self.assertEqual(shell_driver.render_terminal_screen("\x1b(0\x1b[s\x1b(B\x1b[uq").strip(), "─")
            self.assertEqual(shell_driver.render_terminal_screen("\x1b(0\x1b7\x1b(B\x1b[uq").strip(), "─")
            self.assertEqual(shell_driver.render_terminal_screen("\x1b(0\x1b[s\x1b(B\x1b8q").strip(), "─")
            self.assertEqual(shell_driver.render_terminal_screen("\x1b(0\x1b[?1049h\x1b(B\x1b[?1049lq").strip(), "─")
            # Cursor save inside alternate screen must NOT overwrite main screen's saved charset!
            self.assertEqual(
                shell_driver.render_terminal_screen("\x1b(0\x1b[?1049h\x1b(B\x1b7\x1b[?1049lq").strip(), "─",
            )
            self.assertEqual(
                shell_driver.render_terminal_screen("\x1b(0\x1b[?1049h\x1b(B\x1b[s\x1b[?1049lq").strip(), "─",
            )
            # Redundant ?1049l on main screen restores main saved state (xterm CursorRestore).
            self.assertEqual(
                shell_driver.render_terminal_screen("\x1b(0\x1b7\x1b(B\x1b[?1049lq").strip(), "─",
            )
            self.assertEqual(
                shell_driver.render_terminal_screen("\x1b(0\x1b[?1049lq").strip(), "q",
            )
            self.assertIsNone(
                shell_driver.extract_observed_route_row(
                    f"\x1b[8m\x1b7\x1b[0m\x1b[?1049l{route_txt}", approval,
                ),
            )
            # Repeated ?1049h while already in alt screen saves alt cursor and clears display,
            # preserving main saved charset and making erased route text ineligible for arming.
            self.assertEqual(
                shell_driver.render_terminal_screen("\x1b[?1049hstatus\x1b[?1049h").strip(), "",
            )
            self.assertIsNone(
                shell_driver.extract_observed_route_row(
                    f"\x1b[?1049h{route_txt}\x1b[?1049h", approval,
                ),
            )
            self.assertEqual(
                shell_driver.render_terminal_screen("\x1b[?1049h\x1b(0\x1b[?1049h\x1b(B\x1b8q").strip(), "─",
            )
            self.assertEqual(
                shell_driver.render_terminal_screen("\x1b(0\x1b[?1049h\x1b(B\x1b[?1049h\x1b[?1049lq").strip(), "─",
            )
            # Dual screen buffers preserve live main/alt contents across ?1049l, ?1047h/l, and ?47h/l
            # so conflicting routes and surviving partial-repaint suffixes still visible in xterm are retained.
            self.assertEqual(
                shell_driver.render_terminal_screen("panel-old\x1b[?1049h\x1b[?1049l\x1b[1;1Hnew").strip(),
                "newel-old",
            )
            self.assertEqual(
                shell_driver.render_terminal_screen("\x1b[?47hpanel-old\x1b[?47h\x1b[1;1Hnew").strip(),
                "newel-old",
            )
            self.assertEqual(
                shell_driver.render_terminal_screen("\x1b[?47hpanel-old\x1b[?47l\x1b[?47h\x1b[1;1Hnew").strip(),
                "newel-old",
            )
            self.assertEqual(
                shell_driver.render_terminal_screen("\x1b[?1047hpanel-old\x1b[?1047l\x1b[?1047h\x1b[1;1Hnew").strip(),
                "new",
            )
            # Leaving alt screen via ?1049l preserves the alt grid and its uncertainty for later ?47h/?1047h re-entry.
            self.assertEqual(
                shell_driver.render_terminal_screen("\x1b[?1049hpanel-old\x1b[?1049l\x1b[?47h\x1b[1;1Hnew").strip(),
                "newel-old",
            )
            alt_uncertain_screen = shell_driver._TerminalScreen()
            alt_uncertain_screen.feed(f"\x1b[?1049h\x1b[?9999h\x1b[?1049l\x1b[?47h{route_txt}")
            self.assertFalse(alt_uncertain_screen.is_certain)
            # CSI 3J erases scrollback only, preserving visible grid contents and certainty.
            self.assertEqual(
                shell_driver.render_terminal_screen("panel-old\x1b[3J\x1b[1;1Hnew").strip(),
                "newel-old",
            )
            scrollback_uncertain_screen = shell_driver._TerminalScreen()
            scrollback_uncertain_screen.feed(f"\x1b[?9999h\x1b[3J{route_txt}")
            self.assertFalse(scrollback_uncertain_screen.is_certain)
            # DECAWM off (?7l / ?07l) overwrites the final column in place instead of wrapping onto row 1.
            self.assertEqual(
                shell_driver.render_terminal_screen(f"\x1b[?7l{' ' * 120}{route_txt}").strip(),
                route_txt[-1],
            )
            self.assertIsNone(
                shell_driver.extract_observed_route_row(f"\x1b[?7l{' ' * 120}{route_txt}", approval),
            )
            self.assertIsNone(
                shell_driver.extract_observed_route_row(f"\x1b[?07l{' ' * 120}{route_txt}", approval),
            )
            # Cursor save/restore preserves pending wrap, NOT DECAWM (?7) autowrap mode (xterm cursor.c).
            self.assertEqual(
                shell_driver.render_terminal_screen("\x1b7\x1b[?7l\x1b8ABCDE", rows=4, cols=4).splitlines()[:2],
                ["ABCE", ""],
            )
            self.assertEqual(
                shell_driver.render_terminal_screen("\x1b[?1049h\x1b[?7l\x1b[?1049lABCDE", rows=4, cols=4).splitlines()[:2],
                ["ABCE", ""],
            )
            self.assertEqual(
                shell_driver.render_terminal_screen("\x1b[?7hABCD\x1b7\x1b[1;1H\x1b8E", rows=4, cols=4).splitlines()[:2],
                ["ABCD", "E"],
            )
            self.assertEqual(
                shell_driver.render_terminal_screen("\x1b[?7hABCD\x1b7\x1b[?7l\x1b8E", rows=4, cols=4).splitlines()[:2],
                ["ABCE", ""],
            )
            # Pending right-margin wrap is recorded even with DECAWM off and kept when HT does not move cursor.
            self.assertEqual(
                shell_driver.render_terminal_screen("\x1b[?7lABCD\x1b[?7hE", rows=4, cols=4).splitlines()[:2],
                ["ABCD", "E"],
            )
            self.assertEqual(
                shell_driver.render_terminal_screen("ABCD\tE", rows=4, cols=4).splitlines()[:2],
                ["ABCD", "E"],
            )
            # Non-allowlisted XTWINOPS / geometry ops permanently invalidate certainty across CSI 2J and ?1049h.
            for resize_op in (
                "\x1b[8;24;80t",
                "\x1b[08;24;80t",
                "\x1b[0008;24;80t",
                "\x1b[4;480;640t",
                "\x1b[9;1t",
                "\x1b[10;1t",
                "\x1b[?3h",
                "\x1b[?6h",
                "\x1b[1;40s",
                "\x1b[24*|",
            ):
                self.assertIsNone(shell_driver.extract_observed_route_row(f"{resize_op}{route_txt}", approval))
                self.assertIsNone(
                    shell_driver.extract_observed_route_row(f"{resize_op}\x1b[2J\x1b[H{route_txt}", approval),
                )
                self.assertIsNone(
                    shell_driver.extract_observed_route_row(f"{resize_op}\x1b[?1049h\x1b[H{route_txt}", approval),
                )
            self.assertEqual(
                shell_driver.extract_observed_route_row(f"\x1b[22;0;0t{route_txt}", approval),
                route_txt,
            )
            # VT (\x0b) and FF (\x0c) clear pending wrap at the right margin (single vertical advance); DEL is ignored.
            self.assertEqual(
                [ln.strip() for ln in shell_driver.render_terminal_screen("a\x0bb\x0cc").splitlines() if ln.strip()],
                ["a", "b", "c"],
            )
            self.assertEqual(
                shell_driver.render_terminal_screen("ABCD\x0bZ", rows=4, cols=4).splitlines()[:3],
                ["ABCD", "   Z", ""],
            )
            self.assertEqual(
                shell_driver.render_terminal_screen("ABCD\x0cZ", rows=4, cols=4).splitlines()[:3],
                ["ABCD", "   Z", ""],
            )
            # Edit CSIs (P/@/X/K/0J/1J/L/M) clear pending wrap; scrollback-only 3J leaves pending wrap intact.
            self.assertEqual(
                shell_driver.render_terminal_screen("ABCD\x1b[1PZ", rows=4, cols=4).splitlines()[:2],
                ["ABCZ", ""],
            )
            self.assertEqual(
                shell_driver.render_terminal_screen("ABCD\x1b[3JZ", rows=4, cols=4).splitlines()[:2],
                ["ABCD", "Z"],
            )
            # CSI L/M outside scrolling region leave cursor and pending wrap untouched;
            # inside scrolling region they move to column 0 and clear pending wrap.
            self.assertEqual(
                shell_driver.render_terminal_screen("\x1b[2;3r\x1b[1;1HABCD\x1b[1LE", rows=4, cols=4).splitlines()[:2],
                ["ABCD", "E"],
            )
            self.assertEqual(
                shell_driver.render_terminal_screen("\x1b[2;3r\x1b[1;1HABCD\x1b[1ME", rows=4, cols=4).splitlines()[:2],
                ["ABCD", "E"],
            )
            self.assertEqual(
                shell_driver.render_terminal_screen("\x1b[1;4r\x1b[1;1HABCD\x1b[1LZ", rows=4, cols=4).splitlines()[:2],
                ["Z", "ABCD"],
            )
            self.assertEqual(
                shell_driver.render_terminal_screen("\x1b[1;4r\x1b[1;1HABCD\x1b[1MZ", rows=4, cols=4).splitlines()[:2],
                ["Z", ""],
            )
            self.assertIsNone(
                shell_driver.extract_observed_route_row(f"\x1b[1;120H \x1b[2K{route_txt}", approval),
            )
            self.assertIsNone(
                shell_driver.extract_observed_route_row(f"\x1b[1;120H \x1b[0J{route_txt}", approval),
            )
            self.assertEqual(shell_driver.render_terminal_screen("ab\x7fc").strip(), "abc")
            wide_old = "x" * (len(route_txt) + 5)
            conflict_txt = f"openai--work/{TEST_MODEL}"
            for dual_buf_conflict in (
                f"{conflict_txt}\x1b[?1049l\x1b[2;1H{route_txt}",
                f"{conflict_txt}\x1b[?1049h\x1b[?1049l\x1b[2;1H{route_txt}",
                f"\x1b[?1047h{conflict_txt}\x1b[?1047h\x1b[2;1H{route_txt}",
                f"{conflict_txt}\x1b[?47l\x1b[2;1H{route_txt}",
                f"{wide_old}\x1b[?1049h\x1b[?1049l\x1b[1;1H{route_txt}",
                f"\x1b[?47h{wide_old}\x1b[?47h\x1b[1;1H{route_txt}",
                f"\x1b[?1049h{wide_old}\x1b[?1049l\x1b[?47h\x1b[1;1H{route_txt}",
                f"\x1b[?1049h\x1b[?9999h\x1b[?1049l\x1b[?47h{route_txt}",
                f"{wide_old}\x1b[3J\x1b[1;1H{route_txt}",
                f"\x1b[?9999h\x1b[3J{route_txt}",
            ):
                self.assertIsNone(shell_driver.extract_observed_route_row(dual_buf_conflict, approval))
            # Returning from ?1049h to an uncertain main screen preserves main-screen uncertainty.
            uncertain_screen = shell_driver._TerminalScreen()
            uncertain_screen.feed(f"\x1b[?9999h\x1b[?1049h\x1b[?1049l{route_txt}")
            self.assertFalse(uncertain_screen.is_certain)
            self.assertIsNone(
                shell_driver.extract_observed_route_row(f"\x1b[?9999h\x1b[?1049h\x1b[?1049l{route_txt}", approval),
            )
            self.assertIsNone(
                shell_driver.extract_observed_route_row(
                    f"\x1b(0\x1b[?1049h\x1b(B\x1b7\x1b[?1049l{route_txt}", approval,
                ),
            )
            self.assertEqual(shell_driver.render_terminal_screen("\x1b[?1047h\x1b(0\x1b[?1047lq").strip(), "─")
            self.assertEqual(shell_driver.render_terminal_screen("\x1b(0\x1b[?1048h\x1b(B\x1b[?1048lq").strip(), "─")
            self.assertIsNone(
                shell_driver.extract_observed_route_row(f"\x1b(0\x1b[?1049h\x1b(B\x1b[?1049l{route_txt}", approval),
            )
            self.assertIsNone(
                shell_driver.extract_observed_route_row(f"\x1b(0\x1b[s\x1b(B\x1b[u{route_txt}", approval),
            )
            # Active SGR conceal / same-color fg==bg is preserved across alternate-screen transitions.
            for alt_hidden in (
                f"\x1b[8m\x1b[?1049h{route_txt}",
                f"\x1b[30;40m\x1b[?1049h{route_txt}",
                f"\x1b[8m\x1b[?1047h{route_txt}",
                f"\x1b[8m\x1b[?47h{route_txt}",
            ):
                self.assertIsNone(shell_driver.extract_observed_route_row(alt_hidden, approval), alt_hidden)

            # End-to-end PTY guard: DEC Special Graphics route never arms _drive_agent_pty.
            gate_gfx = ProofGate(approval, evidence_dir=ev, exposure_dir=exp)
            gate_gfx.bind_incarnation("inc-pty-dec-gfx-01", 1)
            armed_gfx: list[tuple[str, str]] = []
            gfx_child = (
                "import sys, time; "
                f"sys.stdout.write('\\x1b(0{route_txt}\\x1b(B\\n'); sys.stdout.flush(); time.sleep(1.8)"
            )
            with patch.object(
                shell_driver,
                "_agent_start_command",
                return_value=([sys.executable, "-IB", "-c", gfx_child], dict(os.environ)),
            ):
                shell_driver._drive_agent_pty(
                    TEST_HEX_A, threading.Event(), gate_gfx, lambda r, d: armed_gfx.append((r, d)),
                )
            self.assertEqual(armed_gfx, [])

            # 2. Pinned OpenCode 2.3.0 Full stock footer ("Build · <model> · 1s", without "▣") passes
            #    as positive control while clipped prompt and suffix-extended model footers are rejected.
            stock_footer = f"Build · {TEST_MODEL} · 1s"
            full_turn = f"{PROOF_PROMPT}\n\nok\n{stock_footer}"
            self.assertTrue(
                shell_driver._has_new_exact_reply(full_turn, (), full_turn, approved_model=TEST_MODEL),
            )
            for wrong_footer in (
                f"Build · {TEST_MODEL}-v2 · 1s",
                f"Build · prefix-{TEST_MODEL} · 1s",
                f"Build · other-model · {TEST_MODEL}",
                f"▣ {TEST_MODEL}-v2",
            ):
                wrong_turn = f"{PROOF_PROMPT}\n\nok\n{wrong_footer}"
                self.assertFalse(
                    shell_driver._has_new_exact_reply(wrong_turn, (), wrong_turn, approved_model=TEST_MODEL),
                    wrong_footer,
                )
            prompt_head = PROOF_PROMPT.removesuffix(f" {shell_driver.EXPECTED_REPLY}")
            scr_clip = shell_driver._TerminalScreen(rows=32, cols=120)
            scr_clip.feed(f"{prompt_head}\nok\n" + ("\n" * 30) + stock_footer)
            clipped_full = scr_clip.render()
            self.assertNotIn(prompt_head, clipped_full)
            self.assertFalse(
                shell_driver._has_new_exact_reply(
                    clipped_full, (), f"ok\n{stock_footer}", approved_model=TEST_MODEL,
                ),
            )


if __name__ == "__main__":
    unittest.main()
