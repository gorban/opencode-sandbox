"""Portable coverage for the private managed launch handoff. No Podman or provider traffic."""

from contextlib import contextmanager, nullcontext, suppress
from dataclasses import replace
import fcntl
from functools import partial
import io
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from oc_openai import session_admission as admission
from oc_openai import session_attach
from oc_openai import session_broker as broker
from oc_openai.cli import StreamTerminal
from oc_openai.managed import runtime
from oc_openai.session_adapter import OpenAISessionAdapter
from oc_providers.catalog import LaunchRefusedError, ResolvedLaunchPlan, revalidate_interactive_launch
from oc_providers.contracts import ExposureHoldSummary, InstancePreflight, ProviderInstanceSpec, ReadinessState


POD_ID = "a" * 64


@contextmanager
def make_channel():
    request, send = os.pipe()
    receive, reply = os.pipe()
    channel = admission.AdmissionChannel(request, reply, os.getppid())
    try:
        yield channel, send, receive
    finally:
        channel.finish()
        for fd in (request, send, reply, receive):
            with suppress(OSError):
                os.close(fd)


def valid_spec(sandbox, cwd="construct"):
    return {
        "instance": "default", "pod": "oc", "agent": "oc-agent", "relay": "oc-openai-relay",
        "relay_image": "b" * 64, "agent_image": "c" * 64, "agent_mem": "4g", "level": "s0:c1,c2",
        "sandbox": str(sandbox), "cwd": cwd, "home_vol": "oc-openai-home", "chromium": "oc-chromium",
        "postgres": "", "pg_secret": "", "dind": "", "dind_run": "",
        "provider_filter": "openai/personal", "cli_ui_mode": "mini",
    }


def send_frame(fd, frame):
    os.write(fd, json.dumps(frame).encode("ascii") + b"\n")


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        root = self.enterContext(tempfile.TemporaryDirectory())
        self.sandbox = Path(root) / "sandbox"
        self.sandbox.mkdir()
        (self.sandbox / "construct").mkdir()
        self.state = Path(root) / "state"
        self.state.mkdir(mode=0o700)
        self.intent = {
            "instance": "default", "cwd": "construct", "provider_filter": "openai/personal",
            "cli_ui_mode": "mini", "workspace_mode": "automatic", "caller_cwd": "/home/example",
            "lifecycle_dir": str(self.state), "sandbox": str(self.sandbox),
            "worktree_repo": "", "worktree_branch": "",
        }
        self.terminal = StreamTerminal(io.StringIO(), io.StringIO(), io.StringIO())

    def test_bootstrap_requires_launcher_and_does_not_inherit_control_descriptors(self):
        helper = self.state / "oc-openai-session.py"
        shutil.copy(Path(__file__).resolve().parents[1] / helper.name, helper)
        for name in ("oc_openai", "oc_providers"):
            package = self.state / name
            package.mkdir()
            (package / "__init__.py").touch()
        (self.state / "oc_openai" / "cli.py").write_text(
            "def StreamTerminal(*streams): return streams\n", encoding="ascii",
        )
        (self.state / "oc_openai" / "session_admission.py").write_text(
            "import os, subprocess\n"
            "def AdmissionChannel(reader, writer, owner): return reader, writer, owner\n"
            "def run_admission_session(channel, terminal):\n"
            "    reader, writer, owner = channel\n"
            "    check = 'import os; assert not any(os.path.exists(f\"/proc/self/fd/{fd}\") for fd in (3, 4))'\n"
            "    subprocess.run(['/usr/bin/python3', '-IB', '-c', check], close_fds=False, check=True)\n"
            "    os.write(writer, b'VALID\\n')\n"
            "    assert os.read(reader, 5) == b'owner'\n"
            "    return 0\n", encoding="ascii",
        )
        launcher = self.state / "oc-sandbox"
        launcher.write_text(
            "set -euo pipefail\n"
            'coproc ADMISSION { exec /usr/bin/python3 -IB "$1" --admission 3<&0 4>&1; }\n'
            'pid=$!\n'
            'IFS= read -r -t 3 -u "${ADMISSION[0]}" reply\n'
            '[[ $reply == VALID ]]\n'
            'printf owner >&"${ADMISSION[1]}"\n'
            'wait "$pid"\n', encoding="ascii",
        )
        private = subprocess.run(
            ["/usr/bin/bash", "-p", str(launcher), str(helper)],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=5,
        )
        self.assertEqual(private.returncode, 0, private.stderr)
        direct = subprocess.run(
            ["/usr/bin/python3", "-IB", str(helper), "--admission"],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=5,
        )
        self.assertEqual(direct.returncode, 1)
        self.assertIn(b"trusted workstation supervisor unavailable", direct.stderr)

    def test_frame_rejects_duplicates_and_oversize(self):
        for payload in (b'{"key":1,"key":2}\n', b"{}\n{}\n", b"\n"):
            with self.subTest(payload=payload), make_channel() as (channel, send, _):
                os.write(send, payload)
                deadline = time.monotonic() + 1
                with self.assertRaises(ValueError):
                    channel.read_frame(deadline)
        with make_channel() as (channel, send, _), patch.object(admission, "MAX_FRAME", 4):
            os.write(send, b"12345\n")
            deadline = time.monotonic() + 1
            with self.assertRaisesRegex(ValueError, "Oversized"):
                channel.read_frame(deadline)

    def test_idle_terminal_choice_stops_on_owner_loss(self):
        with make_channel() as (channel, send, _):
            prompt = admission.AdmissionTerminal(self.terminal, channel, time.monotonic() + 3)
            with tempfile.TemporaryFile() as tty_fixture:
                os.close(send)
                fd = tty_fixture.fileno()
                with self.assertRaisesRegex(LaunchRefusedError, "owner channel closed"):
                    prompt._read_bounded_line(fd, 8)
            self.assertTrue(channel.cancelled.is_set())

    def test_restart_watch_cancels_on_owner_loss_even_with_pipe_open(self):
        with make_channel() as (channel, _, __):
            channel.watch_owner()
            channel.finish()
            with patch.object(channel, "_owner_missing", return_value=True):
                channel.watch_owner()
                self.assertTrue(channel.cancelled.wait(1))
            self.assertTrue(channel.cancelled.is_set())

    def test_workspace_record_and_replacement(self):
        expected = admission._expected_workspace(self.intent, self.sandbox)
        spec = valid_spec(self.sandbox)
        before = admission._verify_workspace(spec, self.intent, self.sandbox, expected)
        (self.sandbox / "construct").rename(self.sandbox / "old")
        (self.sandbox / "construct").mkdir()
        self.assertNotEqual(admission._verify_workspace(spec, self.intent, self.sandbox, expected), before)
        with self.assertRaisesRegex(ValueError, "differs from the approved request"):
            admission._verify_workspace({**spec, "cwd": "wrong"}, self.intent, self.sandbox, expected)
        (self.sandbox / "construct").rmdir()
        (self.sandbox / "construct").symlink_to(self.sandbox / "old")
        with self.assertRaises(OSError):
            admission._verify_workspace(spec, self.intent, self.sandbox, expected)

    def test_inferred_workspace_requires_original_caller_and_exact_record(self):
        intent = {
            **self.intent, "instance": "work", "cwd": "wt/work", "caller_cwd": str(self.sandbox / "repository" / "sub"),
        }
        expected = admission._expected_workspace(intent, self.sandbox)
        record_dir = self.state / "worktrees"
        record_dir.mkdir(mode=0o700)
        record = record_dir / "work"
        record.write_text("wt/repository/work\nrepository\nwork\n", encoding="ascii")
        record.chmod(0o600)
        (self.sandbox / "wt/repository/work").mkdir(parents=True)
        spec = {**valid_spec(self.sandbox), "instance": "work", "cwd": "wt/repository/work"}
        admission._verify_workspace(spec, intent, self.sandbox, expected)
        with self.assertRaisesRegex(ValueError, "differs from the approved selector"):
            admission._verify_workspace(spec, {**intent, "caller_cwd": "/outside"}, self.sandbox, expected)

    def test_overlap_keeps_lock_when_parent_helper_exits(self):
        helper = Path(__file__).resolve().parents[1] / "oc-setup-lock.py"
        owner = subprocess.Popen(
            ["/usr/bin/python3", "-I", str(helper), str(self.state), "lifecycle", "shared", "default", str(os.getpid())],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            self.assertTrue(select.select([owner.stdout], [], [], 5)[0])
            self.assertEqual(owner.stdout.readline(), b"LOCKED\n")
            with patch.object(admission.os, "getppid", return_value=os.getpid()):
                with admission._lifecycle_guard(self.intent, self.sandbox, os.getpid(), owner.pid, lambda: None):
                    owner.stdin.close()
                    self.assertEqual(owner.wait(timeout=3), 0)
                    with (self.state / "lifecycle.lock").open("rb") as competitor:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with (self.state / "lifecycle.lock").open("rb") as competitor:
                fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            if owner.poll() is None:
                owner.kill()
                owner.wait(timeout=3)
            for pipe in (owner.stdin, owner.stdout, owner.stderr):
                pipe.close()

    def test_qualification_and_config_drift_gate_before_session_effects(self):
        for qualification, configs, should_admit in (
            (2, [(None, None)], False),
            (0, [(None, None), (None, None), (None, "changed")], True),
        ):
            with self.subTest(qualification=qualification), make_channel() as (channel, send, receive):
                events = []
                placement = {"spec": valid_spec(self.sandbox), "pod_id": POD_ID, "lifecycle_pid": 1234}

                def prepare():
                    if select.select([receive], [], [], 2)[0]:
                        events.append(os.read(receive, 64))
                        send_frame(send, placement)

                send_frame(send, self.intent)
                owner = threading.Thread(target=prepare, daemon=True)
                owner.start()
                with (
                    patch.object(broker, "_qualify_session", return_value=qualification),
                    patch.object(admission, "load_provider_config_with_digest", side_effect=configs),
                    patch.object(broker, "_resolve_adapters_and_lock_dir", return_value=({}, self.state)),
                    patch.object(admission, "plan_interactive_launch", return_value=object()) as planner,
                    patch.object(admission, "_lifecycle_guard", return_value=nullcontext()),
                    patch.object(admission, "_report_prepared_workspace"),
                    patch.object(broker, "_run_admitted_session") as guarded_effects,
                ):
                    result = admission.run_admission_session(channel, self.terminal)
                owner.join(timeout=3)
                self.assertEqual(bool(events), should_admit)
                self.assertEqual(events, [b"ADMITTED\n"] if should_admit else [])
                self.assertEqual(result, 1 if should_admit else 2)
                self.assertEqual(planner.call_count, int(should_admit))
                guarded_effects.assert_not_called()

    def test_route_revalidation_compares_all_models_holds_and_registration(self):
        provider = ProviderInstanceSpec("openai", "personal", True, "subscription")
        old = InstancePreflight(provider, ReadinessState.READY, ("choice", "other"), None, "subscription", "v1")
        plan = ResolvedLaunchPlan((old,), (), {}, provider.scoped_id, "choice", "mini", "--mini")
        for update in (
            {"models": ("choice",)},
            {"exposure_hold": ExposureHoldSummary("openai", 1, 0, "d" * 64)},
            {"handle": "v2"},
            {"route_policy": "metered"},
        ):
            adapter = Mock(spec=("is_qualified", "preflight_instance"))
            adapter.is_qualified.return_value = True
            adapter.preflight_instance.return_value = replace(old, **update)
            deadline = time.monotonic() + 1
            cancelled = threading.Event()
            with self.subTest(update=update), self.assertRaisesRegex(LaunchRefusedError, "approved route"):
                revalidate_interactive_launch(
                    plan, {"openai": adapter}, deadline=deadline,
                    cancelled=cancelled, checkpoint=lambda: None,
                )

    def test_admission_observes_hold_created_during_model_discovery(self):
        provider = ProviderInstanceSpec("openai", "personal", True, "subscription")
        hold = ExposureHoldSummary("openai", 1, 0, "d" * 64)
        observed_hold = None
        connection = Mock(spec=("models",))
        backend = SimpleNamespace(profile_connection=lambda _label: (object(), connection, object()))
        adapter = OpenAISessionAdapter(backend)

        def discover(*_args, **_kwargs):
            nonlocal observed_hold
            observed_hold = hold
            return ("choice",)

        connection.models.side_effect = discover
        with patch.object(adapter, "_inspect_shared_exposure", side_effect=lambda _backend: observed_hold):
            route = adapter.preflight_for_admission(
                provider, deadline=time.monotonic() + 1, cancelled=threading.Event(),
            )
        self.assertEqual(route.exposure_hold, hold)

    def test_two_ack_boundaries_preserve_the_plan_and_release_guard(self):
        with make_channel() as (channel, send, receive):
            placement = {"spec": valid_spec(self.sandbox), "pod_id": POD_ID, "lifecycle_pid": 1234}
            plan = object()
            stages = []
            replies = []
            observed = threading.Event()

            @contextmanager
            def guarded(*args):
                stages.append("guard held")
                try:
                    yield
                finally:
                    stages.append("guard released")

            def prepare():
                if select.select([receive], [], [], 2)[0]:
                    replies.append(os.read(receive, 64))
                    send_frame(send, placement)
                if select.select([receive], [], [], 2)[0]:
                    replies.append(os.read(receive, 64))
                    replies.append(os.read(receive, 64))
                observed.set()

            def create(spec, approved, _adapters, _lock_dir, _terminal, _proof_options, **hooks):
                self.assertIs(approved, plan)
                self.assertEqual(spec, placement["spec"])
                self.assertEqual(hooks["prepared_pod"], POD_ID)
                hooks["checkpoint"]()
                hooks["before_lease"]()
                stages.append("created")
                hooks["created"]()
                stages.append("attached")
                return 0

            send_frame(send, self.intent)
            owner = threading.Thread(target=prepare, daemon=True)
            owner.start()
            with (
                patch.object(broker, "_qualify_session", return_value=0),
                patch.object(admission, "load_provider_config_with_digest", return_value=(None, None)),
                patch.object(broker, "_resolve_adapters_and_lock_dir", return_value=({}, self.state)),
                patch.object(admission, "plan_interactive_launch", return_value=plan),
                patch.object(admission, "revalidate_interactive_launch"),
                patch.object(admission, "_lifecycle_guard", side_effect=guarded),
                patch.object(admission, "_report_prepared_workspace"),
                patch.object(broker, "_run_admitted_session", side_effect=create),
            ):
                self.assertEqual(admission.run_admission_session(channel, self.terminal), 0)
            self.assertTrue(observed.wait(3))
            self.assertEqual(replies, [b"ADMITTED\n", b"CREATED\n", b""])
            self.assertEqual(stages, ["guard held", "created", "guard released", "attached"])

    def test_hold_drift_closes_guarded_launch_at_each_lease_and_before_ack(self):
        providers = [ProviderInstanceSpec("openai", label, True, "subscription") for label in ("personal", "work")]
        approved = tuple(
            InstancePreflight(spec, ReadinessState.READY, ("choice",), None, "subscription", spec.label)
            for spec in providers
        )
        plan = ResolvedLaunchPlan(approved, (), {}, providers[0].scoped_id, "choice", "mini", "--mini")
        for drift_phase, lease_count in (("preparation", 0), ("first lease", 1), ("worker create", 2)):
            with self.subTest(drift_phase=drift_phase), make_channel() as (channel, send, receive):
                self._guarded_hold_drift(channel, send, receive, plan, drift_phase, lease_count)

    def _guarded_hold_drift(self, channel, send, receive, plan, drift_phase, lease_count):
        hold = ExposureHoldSummary("openai", 1, 0, "d" * 64)
        observed_hold = None
        replies = []
        opened = []
        retired = []
        placement = {
            "spec": {**valid_spec(self.sandbox), "provider_filter": ""},
            "pod_id": POD_ID, "lifecycle_pid": 1234,
        }
        intent = {**self.intent, "provider_filter": ""}

        def preflight(spec):
            route = next(item for item in plan.admitted if item.spec == spec)
            return replace(route, exposure_hold=observed_hold)

        adapter = Mock(spec=("selection_state", "is_qualified", "preflight_instance"))
        adapter.is_qualified.return_value = True
        adapter.preflight_instance.side_effect = preflight

        def prepare():
            if select.select([receive], [], [], 2)[0]:
                replies.append(os.read(receive, 64))
                send_frame(send, placement)

        def mark_drift(phase):
            nonlocal observed_hold
            if drift_phase == phase:
                observed_hold = hold

        @contextmanager
        def lease(idx):
            try:
                yield
            finally:
                retired.append(idx)

        def open_slot(idx, _route, context):
            opened.append(idx)
            slot_root = self.state / f"slot-{idx}"
            slot_root.mkdir(mode=0o700)
            handle = SimpleNamespace(
                slot_index=idx, mark_relay_created=None, confirm_relay_removed=None,
                lease_release_confirmed=None,
                broker=SimpleNamespace(_revoked=threading.Event(), close=Mock()),
                job=SimpleNamespace(revoke=Mock(), lease=SimpleNamespace(active=lambda: True)),
            )
            slot = lease(idx)
            slot.__enter__()
            coordinator = context["coordinator"]
            coordinator.register_slot(slot, handle, slot_root)
            coordinator.record_container(str(idx) * 64, slot_index=idx)
            if idx == 0:
                mark_drift("first lease")

        worker = "e" * 64

        def start_worker(_spec, _plan, _config, coordinator, _proof):
            coordinator._verified_creates[worker] = Mock()
            mark_drift("worker create")
            return worker

        send_frame(send, intent)
        owner = threading.Thread(target=prepare, daemon=True)
        owner.start()
        with (
            patch.object(broker, "_qualify_session", return_value=0),
            patch.object(admission, "load_provider_config_with_digest", return_value=(None, None)),
            patch.object(broker, "_resolve_adapters_and_lock_dir", return_value=({"openai": adapter}, self.state)),
            patch.object(admission, "plan_interactive_launch", return_value=plan),
            patch.object(admission, "_lifecycle_guard", return_value=nullcontext()),
            patch.object(admission, "_report_prepared_workspace"),
            patch.object(broker, "SHARED_TMP", self.state),
            patch.object(broker, "_verify_pod_with_containers", return_value=(POD_ID, [])),
            patch.object(broker, "build_multi_provider_opencode_config", return_value={}),
            patch.object(broker, "_ensure_containers_idle", side_effect=lambda *_args, **_kwargs: mark_drift("preparation")),
            patch.object(broker, "_open_single_admitted_slot", side_effect=open_slot),
            patch.object(broker, "_start_session_agent", side_effect=start_worker) as create,
            patch.object(broker._SessionSlotCoordinator, "remove_created_container") as remove,
            patch.object(broker, "_verify_prepared_create"),
            patch.object(broker, "filtered_attach_evidence", return_value=nullcontext(Mock())),
            patch.object(broker, "_launch_agent_tty", return_value=0) as attach,
        ):
            self.assertEqual(admission.run_admission_session(channel, self.terminal), 1)
        owner.join(timeout=3)
        self.assertEqual(replies, [b"ADMITTED\n"])
        self.assertEqual(select.select([receive], [], [], 0)[0], [])
        self.assertEqual(opened, list(range(lease_count)))
        self.assertEqual(retired, opened)
        self.assertTrue(channel.cancelled.is_set())
        self.assertEqual(create.call_count, int(drift_phase == "worker create"))
        self.assertEqual(remove.call_count, lease_count + create.call_count)
        attach.assert_not_called()

    def test_failed_worker_stop_still_kills_and_reaps_stubborn_transport(self):
        stop_event = threading.Event()
        process = subprocess.Popen(
            [
                "/usr/bin/python3", "-IB", "-c",
                "import signal; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "print('ready', flush=True); signal.pause()",
            ],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        )
        try:
            self.assertTrue(select.select([process.stdout], [], [], 3)[0])
            self.assertEqual(process.stdout.readline(), b"ready\n")

            def spawn(*_args, **_kwargs):
                stop_event.set()
                return process

            with (
                patch.object(broker.subprocess, "Popen", side_effect=spawn),
                patch.object(broker, "podman", side_effect=runtime.JobRuntimeError("Podman stop failed")) as stop,
                self.assertRaises(runtime.JobRuntimeError),
            ):
                broker._launch_agent_tty("e" * 64, stop_event)
            stop.assert_called_once_with("stop", "-t", "2", "e" * 64, check=False, timeout=6)
            self.assertIsNotNone(process.returncode, "Owned transport survived failed Podman stop")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
            process.stdout.close()

    def test_unreaped_transport_retains_evidence_after_worker_cleanup(self):
        stop_event = threading.Event()
        coordinator = broker._SessionSlotCoordinator(stop_event)
        worker = "e" * 64
        child = Mock(spec=("poll", "wait", "terminate", "kill"))
        child.poll.return_value = None
        child.wait.side_effect = subprocess.TimeoutExpired("attached transport", broker._ATTACH_REAP_SECONDS)

        def spawn(*_args, **_kwargs):
            stop_event.set()
            return child

        rejected_stop = subprocess.CompletedProcess(("podman",), 125, b"", b"")
        with (
            patch.object(coordinator, "any_active", return_value=True),
            patch.object(broker.subprocess, "Popen", side_effect=spawn),
            patch.object(broker, "podman", return_value=rejected_stop),
            self.assertRaisesRegex(broker._AgentTransportUnverified, "Could not reap"),
        ):
            broker._attach_session_worker(worker, coordinator, stop_event, self.state, {}, None)
        child.terminate.assert_called_once()
        child.kill.assert_called_once()
        self.assertEqual(child.wait.call_count, 2)
        self.assertTrue(all(call.kwargs["timeout"] > 0 for call in child.wait.call_args_list))

        cleanup_state = {"clean": False}
        with patch.object(broker, "_remove_container_verified") as remove:
            self.assertFalse(
                broker._finalize_session_teardown(
                    coordinator, worker, None, None, cleanup_state, self.state, self.terminal,
                )
            )
        remove.assert_called_once_with(worker)
        self.assertFalse(cleanup_state["clean"])
        self.assertIn("cleanup needs verification", self.terminal.errors.getvalue())

    def _guarded_create_receipt_case(self, *, is_relay, cancel_as_create_returns):
        spec = {**valid_spec(self.sandbox), "_prepared_pod": POD_ID}
        cid = "e" * 64
        result = subprocess.CompletedProcess(("podman",), 0, cid.encode("ascii"), b"")
        name = "oc-relay-0" if is_relay else spec["agent"]
        labels = {"oc.sandbox": "1", "oc.instance": "default"}
        if is_relay:
            labels["oc.role"] = "provider-relay"
        inspect = {
            "Name": name, "Id": cid, "Pod": POD_ID,
            "Image": spec["relay_image"] if is_relay else spec["agent_image"],
            "State": {"Status": "created"}, "Config": {"Labels": labels},
        }
        cancel = threading.Event()
        coordinator = broker._SessionSlotCoordinator(cancel)
        coordinator.guarded_creation = True
        handle = SimpleNamespace(
            slot_index=0, build_relay_args=lambda _: ["create", "--name", name, "--pod", POD_ID],
            mark_relay_created=Mock(), confirm_relay_removed=Mock(), lease_release_confirmed=None,
            broker=Mock(), job=Mock(),
        )
        if is_relay:
            coordinator._slots[0] = broker._SlotState(nullcontext(), handle, self.state)
        plan = SimpleNamespace(admitted=(SimpleNamespace(spec=SimpleNamespace(kind="openai")),), ui_mode="mini")

        def host_create(*args, **_):
            if cancel_as_create_returns:
                # Simulate an actual verified create completing after owner cancellation.
                labels["oc.session.create"] = next(
                    arg.removeprefix("oc.session.create=") for arg in args if arg.startswith("oc.session.create=")
                )
                cancel.set()
            return result

        calls = []

        def host_inspect(*args):
            calls.append(args)
            _, cancelled = runtime._HOST_OPERATION_BUDGET.get()
            if cancelled is not None and cancelled.is_set():
                raise runtime.JobRuntimeError("Cancelled create-phase inspection")
            return inspect

        needle = "Cancelled create-phase inspection" if cancel_as_create_returns else "failed placement and ownership"
        start = (
            partial(broker._start_slot_relay_deferred, spec, POD_ID, handle, coordinator, [], [], cancel)
            if is_relay else partial(broker._start_session_agent, spec, plan, self.state / "config", coordinator, None)
        )
        with (
            patch.object(broker, "podman", side_effect=host_create) as podman,
            patch.object(broker, "inspected", side_effect=host_inspect),
            patch.object(broker, "_filtered_container_exists", return_value=True),
            patch.object(broker, "_remove_filtered_container") as remove,
        ):
            with runtime.host_operation_budget(time.monotonic() + 5, cancel):
                with self.assertRaisesRegex(RuntimeError, needle):
                    start()
            self.assertEqual(coordinator._created_containers, [])
            with runtime.host_operation_budget(time.monotonic() + 5):
                cleanup_error = coordinator.teardown_all(None)
        self.assertEqual(calls, [("container", "inspect", cid)] * (3 if cancel_as_create_returns else 2))
        self.assertEqual(podman.call_count, 1)
        self.assertEqual(podman.call_args.args[0], "create")
        if cancel_as_create_returns:
            self.assertIsNone(cleanup_error)
            remove.assert_called_once_with(cid, coordinator.verified_receipt(cid).selector, force=True)
        else:
            self.assertIsInstance(cleanup_error, RuntimeError)
            remove.assert_not_called()

    def test_create_reply_cannot_authorize_start_or_removal_without_ownership(self):
        for is_relay in (False, True):
            with self.subTest(is_relay=is_relay):
                self._guarded_create_receipt_case(is_relay=is_relay, cancel_as_create_returns=False)

    def test_verified_cleanup_uses_only_full_id_filters_and_confirms_absence(self):
        cid = "e" * 64
        receipt = broker._PreparedCreateReceipt(cid, "default", POD_ID, "oc-agent", None, "c" * 64, "marker")
        expected = subprocess.CompletedProcess((), 0, b"", b"")
        still_present = subprocess.CompletedProcess((), 0, cid.encode("ascii") + b"\n", b"")
        with patch.object(broker, "podman", side_effect=(expected, still_present, expected, expected)) as pm:
            with self.assertRaisesRegex(RuntimeError, "exact container selector"):
                broker._remove_filtered_container(cid, receipt.selector, force=True)
            broker._remove_filtered_container(cid, receipt.selector, force=True)
        self.assertEqual(pm.call_args_list[0].args, ("rm", "-f", *receipt.selector))
        self.assertEqual(pm.call_args_list[1].args, ("ps", "-a", "--no-trunc", "--filter", f"id=^{cid}$",
                                                    "--format", "{{.ID}}"))
        self.assertNotIn(cid, receipt.selector)
        self.assertIn("label=oc.session.create=marker", receipt.selector)

    def test_attach_requires_a_positive_exact_id_event_at_the_pinned_inode(self):
        def observed_stat(*args):
            return session_attach._identity(Path(args[-1]).lstat())

        cid = "e" * 64
        for case in ("empty", "other id", "verified", "replaced"):
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir=self.state) as directory:
                root = Path(directory)
                with patch.object(session_attach, "host_output", side_effect=observed_stat):
                    with session_attach.filtered_attach_evidence(root, cid) as evidence:
                        event = root / "worker-attach.events"
                        if case == "replaced":
                            event.rename(event.with_suffix(".old"))
                            event.touch(mode=0o600)
                        if case != "empty":
                            use_id = "f" * 64 if case == "other id" else cid
                            event.write_text(json.dumps({"ID": use_id, "Type": "container", "Status": "attach"}) + "\n")
                        if case == "verified":
                            evidence.verify()
                        else:
                            with self.assertRaises(runtime.JobRuntimeError):
                                evidence.verify()

    def test_relay_readiness_is_bound_to_label_lease_and_port(self):
        for case in ("verified", "wrong label", "too long", "duplicate", "replaced"):
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir=self.state) as directory:
                job = broker._SessionJob(Path(directory), "test-slot")
                job.prepare()
                self.addCleanup(job.revoke)
                expected = b"system_u:system_r:container_t:s0:c1,c2"
                observed = b"system_u:system_r:container_t:s0:c3,c4" if case == "wrong label" else expected
                digest = broker.readiness_mac(job.relay_proof, job.lease.active_record, 8401, observed).hex()
                packet = f"2026-01-01T00:00:00Z stdout F OC_RELAY_READY {digest}\n".encode("ascii")
                with patch.object(session_attach, "host_output",
                                  side_effect=lambda *args: session_attach._identity(Path(args[-1]).lstat())):
                    with job.relay_ready_log():
                        if case == "replaced":
                            job.ready_path.rename(job.ready_path.with_suffix(".old"))
                            job.ready_path.touch(mode=0o600)
                            job.ready_path.with_suffix(".old").write_bytes(packet)
                        else:
                            self._write_ready_fixture(job.ready_path, case, packet)
                        cancelled = threading.Event()
                        if case == "verified":
                            broker._wait_prepared_relay_bound(job, expected, 8401, cancelled)
                        else:
                            with self.assertRaises(RuntimeError):
                                broker._wait_prepared_relay_bound(job, expected, 8401, cancelled)
                        self.assertEqual(job.lease.status(), "pending")
                        job.revoke()

    @staticmethod
    def _write_ready_fixture(path, case, packet):
        if case == "too long":
            path.write_bytes(b"x" * 300 + packet)
        elif case == "duplicate":
            path.write_bytes(packet * 2)
        else:
            path.write_bytes(packet)

    def test_cancelled_create_receipt_is_verified_with_fresh_cleanup_budget(self):
        for is_relay in (False, True):
            with self.subTest(is_relay=is_relay):
                self._guarded_create_receipt_case(is_relay=is_relay, cancel_as_create_returns=True)

    def test_stopped_container_after_pod_name_replacement_is_not_removed(self):
        details = {
            "Id": "d" * 64, "Name": "oc-agent", "Pod": "e" * 64, "State": {"Status": "exited"},
            "Config": {"Labels": {"oc.sandbox": "1", "oc.instance": "default"}},
        }
        with (
            patch.object(broker, "_inspect_existing_container", return_value=details),
            patch.object(broker, "_remove_filtered_container") as remove,
        ):
            with self.assertRaisesRegex(RuntimeError, "unowned stopped"):
                broker._ensure_single_container_idle("oc-agent", "default", (None,), expected_pod=POD_ID)
            remove.assert_not_called()
            broker._ensure_single_container_idle("oc-agent", "default", (None,), expected_pod=details["Pod"])
            selector = broker._owned_container_selector(details["Id"], "default", "oc-agent")
            remove.assert_called_once_with(details["Id"], selector)

    def test_workspace_checked_after_relays_and_before_ack_or_attach(self):
        spec = valid_spec(self.sandbox)
        provider = ProviderInstanceSpec("openai", "personal", True, "subscription")
        ready = InstancePreflight(provider, ReadinessState.READY, ("choice",), None, "subscription", "v1")
        plan = ResolvedLaunchPlan((ready,), (), {}, provider.scoped_id, "choice", "mini", "--mini")
        expected = admission._expected_workspace(self.intent, self.sandbox)
        for replacement_phase in ("relays", "worker"):
            with self.subTest(replacement_phase=replacement_phase):
                workspace = self.sandbox / "construct"
                selected = admission._verify_workspace(spec, self.intent, self.sandbox, expected)

                def replace_workspace(*_):
                    workspace.rename(self.sandbox / replacement_phase)
                    workspace.mkdir()
                    return "e" * 64

                def checkpoint():
                    if admission._verify_workspace(spec, self.intent, self.sandbox, expected) != selected:
                        raise ValueError("Workspace replaced")

                def created():
                    checkpoint()
                    self.fail("Replacement should prevent creation acknowledgment")

                with (
                    patch.object(broker, "_verify_pod_with_containers", return_value=(POD_ID, [])),
                    patch.object(broker, "build_multi_provider_opencode_config", return_value={}),
                    patch.object(broker, "_write_session_opencode_config"),
                    patch.object(broker, "_ensure_containers_idle"),
                    patch.object(broker, "_SessionSlotCoordinator"),
                    patch.object(broker, "_finalize_session_teardown", return_value=True) as cleanup,
                    patch.object(broker, "_open_single_admitted_slot") as relays,
                    patch.object(broker, "_start_session_agent", return_value="e" * 64) as worker,
                    patch.object(broker, "_verify_prepared_create"),
                    patch.object(broker, "filtered_attach_evidence", return_value=nullcontext(Mock())),
                    patch.object(broker, "_launch_agent_tty") as attach,
                ):
                    (relays if replacement_phase == "relays" else worker).side_effect = replace_workspace
                    with self.assertRaisesRegex(ValueError, "Workspace replaced"):
                        broker._run_multi_slot_session(
                            spec, plan, {}, self.state, threading.Event(), self.terminal,
                            {"prepared_pod": POD_ID, "checkpoint": checkpoint, "created": created},
                        )
                self.assertEqual(worker.call_count, int(replacement_phase == "worker"))
                attach.assert_not_called()
                cleanup.assert_called_once()
