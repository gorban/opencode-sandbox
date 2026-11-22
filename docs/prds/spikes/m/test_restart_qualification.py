"""PRD M Joint Restart Qualification Suite & Combined-Pass SQLite Evidence Verifier.

Provides:
- CombinedPassExpectations and verify_combined_pass_evidence() for read-only
  SQLite outbox, tombstone, receipt, stream provenance, unconfirmed-binding,
  and audit-chain verification on both fake and real local OpenCode runs.
- Full Gate 1/Gate 2 qualification fixtures covering the 5 joint checkpoints,
  separate clean-restart & successor-at-same-address fixtures, substituted
  transport / double-failure / failed-logical-retirement recovery, post-receipt
  Phase-3 barrier, minimal-transport late-handoff settlement, permanent
  pre-write refusals with hostile detail sanitization, and operator-only /
  prompt-only / sole-grant enforcement.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import math
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
from typing import Any
import unittest
from unittest import mock

_SPIKE_M_DIR = Path(__file__).resolve().parent
_SPIKE_L_DIR = _SPIKE_M_DIR.parent / "l"
for _p in (str(_SPIKE_M_DIR), str(_SPIKE_L_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from oc_broker_common import BrokerLease  # noqa: E402
from oc_coord_contract import (  # noqa: E402
    CoordPolicyError,
    CoordRole,
    CoordValidationError,
    DispatchOutcome,
    DispatchResult,
    ExternallyFencedTransport,
    PrincipalCtx,
    ProvenanceBadge,
    RevokedError,
    TrustClass,
)
from oc_fake_worker import (  # noqa: E402
    ExternallyFencedFakeTransport,
    FakeWorkerTransport,
    TurnScript,
)
from oc_hub import CoordHub  # noqa: E402
from oc_registry import CoordRegistry  # noqa: E402

_OP = PrincipalCtx(role=CoordRole.OPERATOR, actor_id="op-qual")
_ORCH = PrincipalCtx(role=CoordRole.ORCHESTRATOR, actor_id="orch-qual")
_TRUST_RANK: dict[str, int] = {
    TrustClass.UNTRUSTED_PEER_DATA.value: 0,
    TrustClass.SYSTEM_ALERT.value: 0,
    TrustClass.PARENT_TASK.value: 1,
    TrustClass.OPERATOR_DIRECTIVE.value: 2,
}
_BADGE_RANK: dict[str, int] = {
    ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED.value: 0,
    ProvenanceBadge.TUI_INPUT.value: 0,
    ProvenanceBadge.PEER.value: 0,
    ProvenanceBadge.ORCHESTRATOR.value: 1,
    ProvenanceBadge.OPERATOR.value: 2,
}
_STATUS_ALL = (
    "pending",
    "dispatch_started",
    "handed_off",
    "uncertain",
    "completed",
    "aborted",
    "cancelled",
)
_PROJ_ID = "proj-qual"
_PROJ_NAME = "Qual"
_BRANCH = "main"
_BRIEF = "Joint restart qualification job"
_ADDR_JOB_A = "sb-job-a"
_ADDR_JOB_B = "sb-job-b"
_ADDR_SUCC = "sb-succ"
_OWNER_A = "local-relay:run-job-a"
_OWNER_B = "local-relay:run-job-b"
_OWNER_C = "local-relay:run-job-c"
_OWNER_D = "local-relay:run-job-d"


@dataclass(frozen=True, slots=True)
class CombinedPassExpectations:
    """Declarative SQLite evidence assertions for the combined hub + worker pass."""

    completed_msg_ids: tuple[str, ...] = ()
    cancelled_msg_ids: tuple[str, ...] = ()
    uncertain_msg_ids: tuple[str, ...] = ()
    aborted_msg_ids: tuple[str, ...] = ()
    expected_attempts: Mapping[str, int] = field(default_factory=dict)
    tombstoned_grants: tuple[tuple[str, int], ...] = ()
    expected_stream_substrings: Mapping[str, str] = field(default_factory=dict)
    expected_revoked_sandboxes: tuple[str, ...] = ()
    expected_unconfirmed_bindings: tuple[tuple[str, str], ...] = ()


def _verify_single_outbox_row(
    outbox_by_id: Mapping[str, Mapping[str, Any]], mid: str, expected_status: str
) -> None:
    row = outbox_by_id.get(mid)
    if row is None:
        raise AssertionError(f"Expected outbox row missing: {mid}")
    if row["status"] != expected_status:
        raise AssertionError(
            f"Outbox {mid} expected status={expected_status!r}, got {row['status']!r}"
        )
    if expected_status == "completed" and int(row["attempts"]) < 1:
        raise AssertionError(f"Completed outbox {mid} has attempts < 1")
    if expected_status == "uncertain" and int(row["attempts"]) != 1:
        raise AssertionError(
            f"Uncertain outbox {mid} expected attempts=1, got {row['attempts']}"
        )


def _verify_outbox_statuses_and_attempts(
    outbox_by_id: Mapping[str, Mapping[str, Any]],
    expectations: CombinedPassExpectations,
) -> None:
    expected_groups = (
        ("completed", expectations.completed_msg_ids),
        ("cancelled", expectations.cancelled_msg_ids),
        ("uncertain", expectations.uncertain_msg_ids),
        ("aborted", expectations.aborted_msg_ids),
    )
    for status, msg_ids in expected_groups:
        for mid in msg_ids:
            _verify_single_outbox_row(outbox_by_id, mid, status)
    for mid, want_attempts in expectations.expected_attempts.items():
        row = outbox_by_id.get(mid)
        if row is None:
            raise AssertionError(f"Expected attempt row missing: {mid}")
        if int(row["attempts"]) != want_attempts:
            raise AssertionError(
                f"Outbox {mid} expected attempts={want_attempts}, got {row['attempts']}"
            )


def _verify_unconsumed_receipts_absent(
    registry: CoordRegistry, expectations: CombinedPassExpectations
) -> None:
    terminated = (*expectations.cancelled_msg_ids, *expectations.aborted_msg_ids)
    if not terminated:
        return
    placeholders = ",".join("?" for _ in terminated)
    with registry._lock:
        rows = registry._conn.execute(
            f"""
            SELECT message_id FROM dispatch_receipts
            WHERE consumed_at IS NULL AND message_id IN ({placeholders})
            """,
            terminated,
        ).fetchall()
    if rows:
        leaked = [r["message_id"] for r in rows]
        raise AssertionError(f"Unconsumed dispatch_receipts remain for terminated rows: {leaked}")


_UNVERIFIED_USER_BADGES: frozenset[str] = frozenset(
    {
        ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED.value,
        ProvenanceBadge.TUI_INPUT.value,
    }
)


def _verify_single_event_badge(row: Mapping[str, Any]) -> None:
    badge = row["badge"]
    if row["event_type"] != "user_message":
        if badge is not None:
            raise AssertionError(
                f"Non-user stream event seq={row['seq']} has non-null badge={badge!r}"
            )
        return
    if badge is None:
        raise AssertionError(f"user_message event seq={row['seq']} missing provenance badge")
    if row["env_trust_class"] is None:
        if badge not in _UNVERIFIED_USER_BADGES:
            raise AssertionError(
                f"Forged or elevated badge on unlinked user_message seq={row['seq']}: {badge!r}"
            )
        return
    if badge not in _BADGE_RANK or _BADGE_RANK[badge] > _TRUST_RANK.get(row["env_trust_class"], -1):
        raise AssertionError(
            f"Provenance elevation detected on seq={row['seq']}: {badge!r}"
        )


def _verify_stream_substrings(
    ev_rows: list[Mapping[str, Any]], expected_substrings: Mapping[str, str]
) -> None:
    for mid, needle in expected_substrings.items():
        terminals = [
            int(r["seq"])
            for r in ev_rows
            if r["dispatch_msg_id"] == mid and r["event_type"] == "turn_completed"
        ]
        if not terminals:
            raise AssertionError(f"Missing turn_completed event for {mid}")
        term_seq = min(terminals)
        combined = "".join(
            str(r["text"])
            for r in ev_rows
            if r["dispatch_msg_id"] == mid
            and r["event_type"] == "text_delta"
            and int(r["seq"]) < term_seq
        )
        if needle not in combined:
            raise AssertionError(
                f"Expected text_delta substring {needle!r} before turn_completed for {mid}"
            )


def _verify_stream_provenance_and_order(
    registry: CoordRegistry, expectations: CombinedPassExpectations
) -> None:
    with registry._lock:
        ev_rows = registry._conn.execute(
            """
            SELECT s.seq, s.event_type, s.dispatch_msg_id, s.text, s.badge,
                   e.trust_class AS env_trust_class
            FROM stream_events s
            LEFT JOIN event_log e ON e.msg_id = s.dispatch_msg_id
            ORDER BY s.seq ASC
            """
        ).fetchall()
    for row in ev_rows:
        _verify_single_event_badge(row)
    _verify_stream_substrings(ev_rows, expectations.expected_stream_substrings)


def verify_combined_pass_evidence(
    registry: CoordRegistry,
    expectations: CombinedPassExpectations,
) -> dict[str, Any]:
    """Read-only SQLite evidence verifier for both fake and real local OpenCode passes."""
    outbox_rows = registry.list_outbox(statuses=_STATUS_ALL)
    outbox_by_id = {str(r["msg_id"]): r for r in outbox_rows}
    _verify_outbox_statuses_and_attempts(outbox_by_id, expectations)
    for edge_id, grant_gen in expectations.tombstoned_grants:
        if not registry.is_grant_tombstoned(edge_id, grant_gen):
            raise AssertionError(f"Expected grant tombstone missing: ({edge_id!r}, {grant_gen})")
    _verify_unconsumed_receipts_absent(registry, expectations)
    _verify_stream_provenance_and_order(registry, expectations)
    for sb_addr in expectations.expected_revoked_sandboxes:
        sb = registry.get_sandbox(sb_addr)
        if sb is None or sb.status != "revoked":
            raise AssertionError(f"Expected sandbox {sb_addr!r} status='revoked', got {sb!r}")
    actual_unconfirmed = sorted(
        (str(b["sandbox_addr"]), str(b["incarnation_id"]))
        for b in registry.list_unconfirmed_transport_bindings()
    )
    if actual_unconfirmed != sorted(expectations.expected_unconfirmed_bindings):
        raise AssertionError(
            f"Unconfirmed bindings mismatch: got {actual_unconfirmed}, "
            f"expected {sorted(expectations.expected_unconfirmed_bindings)}"
        )
    ok, audit_count = registry.verify_audit_chain()
    if ok is not True or audit_count <= 0:
        raise AssertionError(f"Audit hash chain invalid: ok={ok!r}, count={audit_count!r}")
    return {
        "outbox_count": len(outbox_rows),
        "audit_count": audit_count,
        "unconfirmed_bindings": actual_unconfirmed,
    }


def _wait_until(predicate: Any, *, timeout_s: float = 1.5, step_s: float = 0.005) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(step_s)
    return bool(predicate())


class TestRestartQualification(unittest.TestCase):
    """Joint PRD M restart qualification & adversarial external-fence fixtures."""

    def setUp(self) -> None:
        self._tmp = Path(tempfile.mkdtemp(prefix="oc-m-qual-"))
        self.state_dir = self._tmp / "state"
        self.sandbox_root = self._tmp / "sandbox"
        self.sandbox_root.mkdir(mode=0o700)

    def tearDown(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _open_hub(
        self,
        transport: Any,
        *,
        state_dir: Path | None = None,
    ) -> tuple[CoordRegistry, CoordHub]:
        target_dir = state_dir if state_dir is not None else self.state_dir
        reg = CoordRegistry(target_dir, sandbox_root=self.sandbox_root)
        hub = CoordHub(reg, transport, target_dir, sandbox_root=self.sandbox_root)
        return reg, hub

    @staticmethod
    def _abandon_hub_for_crash(hub: CoordHub, reg: CoordRegistry) -> None:
        """Simulate an abrupt host crash without clean close, releasing only test fds/threads."""
        from oc_hub import _release_state_dir_lock

        hub._stop_cleanup_retry_worker(time.monotonic() + 1.0)
        os_lock = hub._state_lock_fd
        hub._state_lock_fd = -1
        if os_lock >= 0:
            _release_state_dir_lock(os_lock)
        reg.close()

    @staticmethod
    def _reg_and_grant(
        hub: CoordHub, name: str, inc_id: str, *, grant_gen: int = 1
    ) -> str:
        hub.register_sandbox(
            _OP,
            name=name,
            incarnation_id=inc_id,
            project_id=_PROJ_ID,
            project_name=_PROJ_NAME,
            branch=_BRANCH,
            task_brief=_BRIEF,
        )
        edge = hub.grant_edge(
            _OP,
            src_actor=_OP.canonical_sender,
            dst_addr=name,
            allowed_threads=("main",),
            allowed_msg_kinds=("prompt",),
            grant_generation=grant_gen,
        )
        return edge.edge_id

    def test_checkpoints_1_2a_3_shared_job_held_revoke_and_reopen_same_terminal_owner(
        self,
    ) -> None:
        owner1 = ExternallyFencedFakeTransport({(_ADDR_JOB_A, "inc_a1"): _OWNER_A})
        self.assertIsInstance(owner1, ExternallyFencedTransport)
        held_started = threading.Event()
        held_release = threading.Event()
        self.addCleanup(held_release.set)
        owner1.inner.queue_script(
            _ADDR_JOB_A,
            TurnScript(
                echo_user_message=False,
                text_chunks=("ALPHA_PROOF_DELTA",),
                file_edits=("proof.txt",),
            ),
        )
        owner1.inner.queue_script(
            _ADDR_JOB_A,
            TurnScript(
                echo_user_message=False,
                text_chunks=("HELD_SHOULD_NOT_COMPLETE",),
                on_stream_started=held_started,
                block_event=held_release,
            ),
        )

        reg1, hub1 = self._open_hub(owner1)
        try:
            edge1 = self._reg_and_grant(hub1, _ADDR_JOB_A, "inc_a1", grant_gen=1)
            binding_before = reg1.get_transport_binding(_ADDR_JOB_A, "inc_a1")
            self.assertIsNotNone(binding_before)
            self.assertEqual(binding_before["owner_id"], _OWNER_A)
            self.assertFalse(binding_before["terminal_confirmed"])

            # Checkpoint 1: authorized operator turn completes with delta before terminal
            msg_ok = hub1.send(_OP, target=_ADDR_JOB_A, body_text="Write proof.txt")["msg_id"]
            self.assertEqual(hub1.dispatch_once(async_stream=False), 1)

            # Checkpoint 2A: held turn + queued turn without dispatching
            msg_held = hub1.send(_OP, target=_ADDR_JOB_A, body_text="Hold response")["msg_id"]
            self.assertEqual(hub1.dispatch_once(async_stream=True), 1)
            self.assertTrue(held_started.wait(timeout=1.0))
            msg_queued = hub1.send(_OP, target=_ADDR_JOB_A, body_text="Queued old turn")["msg_id"]

            rev_status = hub1.revoke(_OP, target=_ADDR_JOB_A, reason="checkpoint_2a_revoke")
            self.assertTrue(rev_status.aborted_streams)
            self.assertTrue(
                _wait_until(
                    lambda: msg_held in {r["msg_id"] for r in reg1.list_outbox(statuses=("aborted",))}
                )
            )
            binding_after = reg1.get_transport_binding(_ADDR_JOB_A, "inc_a1")
            self.assertTrue(binding_after["abort_requested"])
            self.assertTrue(binding_after["terminal_confirmed"])
        finally:
            hub1.close()
            reg1.close()

        # Checkpoint 3: reopen persisted DB while exact same terminal owner stays present
        before_calls = len(owner1.dispatch_calls)
        reg2, hub2 = self._open_hub(owner1)
        self.addCleanup(reg2.close)
        self.addCleanup(hub2.close)
        self.assertFalse(hub2.is_degraded)
        self.assertEqual(hub2.dispatch_once(async_stream=False), 0)
        self.assertEqual(len(owner1.dispatch_calls), before_calls)
        with self.assertRaises(RevokedError):
            hub2.register_sandbox(
                _OP,
                name=_ADDR_JOB_A,
                incarnation_id="inc_a1",
                project_id=_PROJ_ID,
                project_name=_PROJ_NAME,
                branch=_BRANCH,
                task_brief=_BRIEF,
            )
        summary = verify_combined_pass_evidence(
            reg2,
            CombinedPassExpectations(
                completed_msg_ids=(msg_ok,),
                cancelled_msg_ids=(msg_queued,),
                aborted_msg_ids=(msg_held,),
                expected_attempts={msg_ok: 1, msg_queued: 0, msg_held: 1},
                tombstoned_grants=((edge1, 1),),
                expected_stream_substrings={msg_ok: "ALPHA_PROOF_DELTA"},
                expected_revoked_sandboxes=(_ADDR_JOB_A,),
            ),
        )
        self.assertGreater(summary["audit_count"], 0)

    def test_checkpoint_2b_separate_fresh_job_paused_first_write_race(self) -> None:
        owner_b = ExternallyFencedFakeTransport({(_ADDR_JOB_B, "inc_b1"): _OWNER_B})
        paused_ack = threading.Event()
        release_pause = threading.Event()
        self.addCleanup(release_pause.set)
        owner_b.inner.queue_script(
            _ADDR_JOB_B,
            TurnScript(
                echo_user_message=False,
                text_chunks=("MUST_NEVER_WRITE",),
                on_pre_write_paused=paused_ack,
                pre_write_pause=release_pause,
            ),
        )
        reg, hub = self._open_hub(owner_b)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        edge_b = self._reg_and_grant(hub, _ADDR_JOB_B, "inc_b1")
        msg_paused = hub.send(_OP, target=_ADDR_JOB_B, body_text="Paused write race")["msg_id"]

        disp_thread = threading.Thread(
            target=lambda: hub.dispatch_once(async_stream=False), daemon=True
        )
        disp_thread.start()
        self.assertTrue(paused_ack.wait(timeout=1.0))

        # Revoke must complete promptly without blocking behind the paused relay write
        t0 = time.monotonic()
        hub.revoke(_OP, target=_ADDR_JOB_B, reason="paused_write_revoke")
        self.assertLess(time.monotonic() - t0, 0.5)

        release_pause.set()
        disp_thread.join(timeout=1.5)
        self.assertFalse(disp_thread.is_alive())
        self.assertEqual(owner_b.inner.dispatched_turns(_ADDR_JOB_B), [])
        verify_combined_pass_evidence(
            reg,
            CombinedPassExpectations(
                cancelled_msg_ids=(msg_paused,),
                expected_attempts={msg_paused: 1},
                tombstoned_grants=((edge_b, 1),),
                expected_revoked_sandboxes=(_ADDR_JOB_B,),
            ),
        )

    def test_checkpoint_4_uncertain_handoff_never_replayed_across_restart_and_recovery(
        self,
    ) -> None:
        owner_c = ExternallyFencedFakeTransport({("sb-unc", "inc_c1"): _OWNER_C})
        owner_c.inner.queue_script(
            "sb-unc",
            TurnScript(outcome=DispatchOutcome.UNCERTAIN, detail="lost_relay_receipt"),
        )
        reg1, hub1 = self._open_hub(owner_c)
        try:
            self._reg_and_grant(hub1, "sb-unc", "inc_c1")
            msg_unc = hub1.send(_OP, target="sb-unc", body_text="Lost receipt turn")["msg_id"]
            self.assertEqual(hub1.dispatch_once(async_stream=False), 1)
            self.assertEqual(len(owner_c.dispatch_calls), 1)
        finally:
            hub1.close()
            reg1.close()

        # Clean reopen: never replayed
        reg2, hub2 = self._open_hub(owner_c)
        try:
            self.assertFalse(hub2.is_degraded)
            self.assertEqual(hub2.dispatch_once(async_stream=False), 0)
            self.assertEqual(len(owner_c.dispatch_calls), 1)
            # Simulate degraded crash recovery: still never replayed
            hub2._mark_degraded("simulated_crash_after_uncertain")
            hub2.confirm_recovery(_OP, reason="verify_uncertain_preserved")
            self.assertEqual(hub2.dispatch_once(async_stream=False), 0)
            self.assertEqual(len(owner_c.dispatch_calls), 1)
            verify_combined_pass_evidence(
                reg2,
                CombinedPassExpectations(
                    uncertain_msg_ids=(msg_unc,),
                    expected_attempts={msg_unc: 1},
                    expected_revoked_sandboxes=("sb-unc",),
                ),
            )
        finally:
            hub2.close()
            reg2.close()

    def test_checkpoint_5_and_successor_only_same_address_clean_restart(self) -> None:
        # Phase 1: retire inc_1 with Owner 1 (leaving historical terminal_confirmed=1 + cancelled row)
        owner1 = ExternallyFencedFakeTransport({(_ADDR_SUCC, "inc_s1"): _OWNER_A})
        reg1, hub1 = self._open_hub(owner1)
        try:
            edge1 = self._reg_and_grant(hub1, _ADDR_SUCC, "inc_s1", grant_gen=1)
            msg_old = hub1.send(_OP, target=_ADDR_SUCC, body_text="Old inc_1 queued")["msg_id"]
            hub1.revoke(_OP, target=_ADDR_SUCC, reason="retire_inc_1")
            b1 = reg1.get_transport_binding(_ADDR_SUCC, "inc_s1")
            self.assertTrue(b1["terminal_confirmed"])
        finally:
            hub1.close()
            reg1.close()

        # Phase 2: reopen with a SUCCESSOR-ONLY transport that does NOT know or contain inc_s1
        owner2 = ExternallyFencedFakeTransport({(_ADDR_SUCC, "inc_s2"): _OWNER_D})
        owner2.inner.queue_script(
            _ADDR_SUCC, TurnScript(echo_user_message=False, text_chunks=("SUCCESSOR_OK",))
        )
        reg2, hub2 = self._open_hub(owner2)
        try:
            self.assertFalse(hub2.is_degraded)
            # Register inc_s2 at exact same address: must NOT call abort_incarnation(inc_s1)
            self._reg_and_grant(hub2, _ADDR_SUCC, "inc_s2", grant_gen=1)
            msg_new = hub2.send(_OP, target=_ADDR_SUCC, body_text="Fresh inc_2 queued")["msg_id"]
        finally:
            hub2.close()
            reg2.close()

        # Phase 3: clean reopen with inc_s2's owner -> healthy startup, 1 dispatch new, 0 old
        reg3, hub3 = self._open_hub(owner2)
        try:
            self.assertFalse(hub3.is_degraded)
            self.assertEqual(hub3.dispatch_once(async_stream=False), 1)
            self.assertEqual([t.msg_id for t in owner2.dispatch_calls], [msg_new])
            verify_combined_pass_evidence(
                reg3,
                CombinedPassExpectations(
                    completed_msg_ids=(msg_new,),
                    cancelled_msg_ids=(msg_old,),
                    expected_attempts={msg_new: 1, msg_old: 0},
                    tombstoned_grants=((edge1, 1),),
                    expected_stream_substrings={msg_new: "SUCCESSOR_OK"},
                    expected_unconfirmed_bindings=((_ADDR_SUCC, "inc_s2"),),
                ),
            )
            # Degraded crash recovery on hub3 with historical settled inc_s1 must ALSO succeed cleanly
            hub3._mark_degraded("verify_settled_predecessor_recovery")
            hub3.confirm_recovery(_OP, reason="retire_inc_s2")
            self.assertFalse(hub3.is_degraded)
        finally:
            hub3.close()
            reg3.close()

    def test_clean_restart_unrevoked_eligible_row_authority(self) -> None:
        owner = ExternallyFencedFakeTransport({("sb-elig", "inc_e1"): _OWNER_A})
        owner.inner.queue_script(
            "sb-elig", TurnScript(echo_user_message=False, text_chunks=("ELIG_OK",))
        )
        reg1, hub1 = self._open_hub(owner)
        try:
            self._reg_and_grant(hub1, "sb-elig", "inc_e1")
            msg_elig = hub1.send(_OP, target="sb-elig", body_text="Eligible across clean close")[
                "msg_id"
            ]
        finally:
            hub1.close()
            reg1.close()

        reg2, hub2 = self._open_hub(owner)
        self.addCleanup(reg2.close)
        self.addCleanup(hub2.close)
        self.assertFalse(hub2.is_degraded)
        sb = reg2.get_sandbox("sb-elig")
        self.assertEqual(sb.status, "running")
        self.assertEqual(hub2.dispatch_once(async_stream=False), 1)
        verify_combined_pass_evidence(
            reg2,
            CombinedPassExpectations(
                completed_msg_ids=(msg_elig,),
                expected_attempts={msg_elig: 1},
                expected_stream_substrings={msg_elig: "ELIG_OK"},
                expected_unconfirmed_bindings=(("sb-elig", "inc_e1"),),
            ),
        )

    def test_substituted_transport_and_wrong_owner_cannot_clear_external_obligation(
        self,
    ) -> None:
        owner1 = ExternallyFencedFakeTransport({("sb-sub", "inc_sub1"): _OWNER_A})
        owner1.fail_confirm_keys.add(("sb-sub", "inc_sub1"))
        reg1, hub1 = self._open_hub(owner1)
        try:
            self._reg_and_grant(hub1, "sb-sub", "inc_sub1")
            with self.assertRaises(CoordPolicyError):
                hub1.revoke(_OP, target="sb-sub", reason="relay_fence_failed")
            self.assertTrue(hub1.is_degraded)
            # Replacement blocked while unconfirmed
            with self.assertRaises(CoordPolicyError):
                hub1.register_sandbox(
                    _OP,
                    name="sb-sub",
                    incarnation_id="inc_sub2",
                    project_id=_PROJ_ID,
                    project_name=_PROJ_NAME,
                    branch=_BRANCH,
                    task_brief=_BRIEF,
                )
        finally:
            self._abandon_hub_for_crash(hub1, reg1)

        # (a) Reopen with plain FakeWorkerTransport: boots degraded, CANNOT clear external obligation
        reg2, hub2 = self._open_hub(FakeWorkerTransport())
        try:
            self.assertTrue(hub2.is_degraded)
            with self.assertRaises(CoordPolicyError):
                hub2.confirm_recovery(_OP, reason="legacy_must_fail")
            self.assertTrue(hub2.is_degraded)
            self.assertFalse(reg2.get_transport_binding("sb-sub", "inc_sub1")["terminal_confirmed"])
        finally:
            self._abandon_hub_for_crash(hub2, reg2)

        # (b) Reopen with wrong-owner ExternallyFencedFakeTransport: CANNOT clear obligation
        wrong_owner = ExternallyFencedFakeTransport({("sb-sub", "inc_sub1"): "local-relay:wrong"})
        reg3, hub3 = self._open_hub(wrong_owner)
        try:
            self.assertTrue(hub3.is_degraded)
            with self.assertRaises(CoordPolicyError):
                hub3.confirm_recovery(_OP, reason="wrong_owner_must_fail")
            self.assertTrue(hub3.is_degraded)
        finally:
            self._abandon_hub_for_crash(hub3, reg3)

        # (c) Reopen with exact owner1 once fault clears -> confirms terminal, reopens, allows inc_sub2
        owner1.fail_confirm_keys.discard(("sb-sub", "inc_sub1"))
        owner1.register_owner("sb-sub", "inc_sub2", _OWNER_D)
        reg4, hub4 = self._open_hub(owner1)
        self.addCleanup(reg4.close)
        self.addCleanup(hub4.close)
        self.assertTrue(hub4.is_degraded)
        hub4.confirm_recovery(_OP, reason="exact_owner_confirmed")
        self.assertFalse(hub4.is_degraded)
        self.assertTrue(reg4.get_transport_binding("sb-sub", "inc_sub1")["terminal_confirmed"])
        self._reg_and_grant(hub4, "sb-sub", "inc_sub2")

    def test_double_failure_db_and_teardown_preserves_owner_and_blocks_replacement(self) -> None:
        owner1 = ExternallyFencedFakeTransport({("sb-dbl", "inc_d1"): _OWNER_A})
        owner1.fail_confirm_keys.add(("sb-dbl", "inc_d1"))
        reg1, hub1 = self._open_hub(owner1)
        orig_mark = reg1.mark_transport_abort_requested

        def _fail_mark(sb_addr: str, inc_id: str, *, reason: str) -> bool:
            raise RuntimeError("db_mark_failed")

        reg1.mark_transport_abort_requested = _fail_mark  # type: ignore[method-assign]
        try:
            self._reg_and_grant(hub1, "sb-dbl", "inc_d1")
            with self.assertRaises(CoordPolicyError):
                hub1.revoke(_OP, target="sb-dbl", reason="double_failure_revoke")
            # Physical teardown was still attempted despite DB mark error
            self.assertEqual(len(owner1.confirm_calls), 1)
            self.assertTrue(hub1.is_degraded)
            # Even after sandboxes.status='revoked' persisted, pre-registered binding stays unconfirmed
            self.assertEqual(reg1.get_sandbox("sb-dbl").status, "revoked")
            b = reg1.get_transport_binding("sb-dbl", "inc_d1")
            self.assertEqual(b["owner_id"], _OWNER_A)
            self.assertFalse(b["terminal_confirmed"])
        finally:
            reg1.mark_transport_abort_requested = orig_mark  # type: ignore[method-assign]
            self._abandon_hub_for_crash(hub1, reg1)

        # Reopen after simulated crash: replacement blocked until exact owner confirms terminal
        reg2, hub2 = self._open_hub(owner1)
        self.addCleanup(reg2.close)
        self.addCleanup(hub2.close)
        self.assertTrue(hub2.is_degraded)
        with self.assertRaises(CoordPolicyError):
            hub2.confirm_recovery(_OP, reason="still_failing")
        owner1.fail_confirm_keys.discard(("sb-dbl", "inc_d1"))
        owner1.register_owner("sb-dbl", "inc_d2", _OWNER_D)
        hub2.confirm_recovery(_OP, reason="exact_owner_recovered")
        self.assertFalse(hub2.is_degraded)
        self.assertTrue(reg2.get_transport_binding("sb-dbl", "inc_d1")["terminal_confirmed"])
        self._reg_and_grant(hub2, "sb-dbl", "inc_d2")

    def test_failed_logical_retirement_after_physical_confirm_rolls_back_and_blocks_legacy_reopen(
        self,
    ) -> None:
        owner1 = ExternallyFencedFakeTransport({("sb-lr", "inc_lr1"): _OWNER_A})
        reg1, hub1 = self._open_hub(owner1)
        orig_commit = reg1.commit_external_revoke

        def _fail_commit(**kwargs: Any) -> list[str]:
            raise RuntimeError("commit_external_revoke_failed")

        try:
            edge1 = self._reg_and_grant(hub1, "sb-lr", "inc_lr1")
            msg_q = hub1.send(_OP, target="sb-lr", body_text="Pending before failed commit")[
                "msg_id"
            ]
            reg1.commit_external_revoke = _fail_commit  # type: ignore[method-assign]
            with self.assertRaises(CoordPolicyError):
                hub1.revoke(_OP, target="sb-lr", reason="commit_fails_after_confirm")
            self.assertTrue(hub1.is_degraded)
            b = reg1.get_transport_binding("sb-lr", "inc_lr1")
            self.assertFalse(b["terminal_confirmed"])
            self.assertTrue(b["abort_requested"])
        finally:
            reg1.commit_external_revoke = orig_commit  # type: ignore[method-assign]
            self._abandon_hub_for_crash(hub1, reg1)

        # Reopen with legacy transport -> stays degraded, zero dispatch, refuses recovery
        reg2, hub2 = self._open_hub(FakeWorkerTransport())
        try:
            self.assertTrue(hub2.is_degraded)
            self.assertEqual(hub2.dispatch_once(async_stream=False), 0)
            with self.assertRaises(CoordPolicyError):
                hub2.confirm_recovery(_OP, reason="legacy_cannot_clear")
        finally:
            self._abandon_hub_for_crash(hub2, reg2)

        # Reopen with exact owner1 -> confirm_recovery finishes logical retirement & terminal_confirmed=1
        reg3, hub3 = self._open_hub(owner1)
        self.addCleanup(reg3.close)
        self.addCleanup(hub3.close)
        hub3.confirm_recovery(_OP, reason="finish_logical_retirement")
        self.assertFalse(hub3.is_degraded)
        self.assertTrue(reg3.get_transport_binding("sb-lr", "inc_lr1")["terminal_confirmed"])
        verify_combined_pass_evidence(
            reg3,
            CombinedPassExpectations(
                cancelled_msg_ids=(msg_q,),
                expected_attempts={msg_q: 0},
                tombstoned_grants=((edge1, 1),),
                expected_revoked_sandboxes=("sb-lr",),
            ),
        )

    def test_post_receipt_phase3_pause_barrier_holds_recovery_closed_until_settled(self) -> None:
        owner = ExternallyFencedFakeTransport({("sb-p3", "inc_p3"): _OWNER_A})
        owner.inner.queue_script(
            "sb-p3",
            TurnScript(echo_user_message=False, text_chunks=("LATE_DELTA_MUST_NEVER_RECORD",)),
        )
        reg, hub = self._open_hub(owner)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_and_grant(hub, "sb-p3", "inc_p3")
        msg_id = hub.send(_OP, target="sb-p3", body_text="Post receipt barrier")["msg_id"]

        at_post_receipt = threading.Event()
        release_post_receipt = threading.Event()
        self.addCleanup(release_post_receipt.set)

        def _post_receipt(mid: str, res: Any) -> None:
            if mid == msg_id:
                at_post_receipt.set()
                release_post_receipt.wait(timeout=3.0)

        hub._on_post_receipt_hook = _post_receipt  # type: ignore[attr-defined]
        disp_thread = threading.Thread(
            target=lambda: hub.dispatch_once(async_stream=False), daemon=True
        )
        disp_thread.start()
        self.assertTrue(at_post_receipt.wait(timeout=1.0))

        hub._mark_degraded("degraded_before_phase3_settles")
        rec_done = threading.Event()
        rec_err: list[Exception] = []

        def _run_rec() -> None:
            try:
                hub.confirm_recovery(_OP, reason="post_receipt_recovery", timeout_s=2.0)
            except Exception as exc:
                rec_err.append(exc)
            finally:
                rec_done.set()

        rec_thread = threading.Thread(target=_run_rec, daemon=True)
        rec_thread.start()
        # Recovery MUST stay closed while Phase 3 has not settled ownership yet
        self.assertFalse(rec_done.wait(timeout=0.08))
        self.assertTrue(hub.is_degraded)

        release_post_receipt.set()
        self.assertTrue(rec_done.wait(timeout=2.0))
        disp_thread.join(timeout=2.0)
        self.assertEqual(rec_err, [])
        self.assertFalse(hub.is_degraded)
        self.assertEqual(hub._stream_authorities, {})
        self.assertEqual(hub._pending_cleanup_streams, {})
        events = reg.list_events_since(("sb-p3",), 0)
        self.assertFalse(
            any("LATE_DELTA_MUST_NEVER_RECORD" in str(ev.get("text", "")) for ev in events)
        )
        verify_combined_pass_evidence(
            reg,
            CombinedPassExpectations(
                uncertain_msg_ids=(msg_id,),
                expected_attempts={msg_id: 1},
                expected_revoked_sandboxes=("sb-p3",),
            ),
        )

    def test_minimal_transport_late_handed_off_race_settles_synchronously(self) -> None:
        owner = ExternallyFencedFakeTransport({("sb-lh", "inc_lh1"): _OWNER_A})
        owner.inner.queue_script(
            "sb-lh",
            TurnScript(echo_user_message=False, text_chunks=("SHOULD_DROP_ON_REVOKE",)),
        )
        reg, hub = self._open_hub(owner)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_and_grant(hub, "sb-lh", "inc_lh1")
        msg_id = hub.send(_OP, target="sb-lh", body_text="Late handed off")["msg_id"]

        at_post = threading.Event()
        release_post = threading.Event()
        self.addCleanup(release_post.set)

        def _hook(mid: str, res: Any) -> None:
            if mid == msg_id:
                at_post.set()
                release_post.wait(timeout=3.0)

        hub._on_post_receipt_hook = _hook  # type: ignore[attr-defined]
        disp_thread = threading.Thread(
            target=lambda: hub.dispatch_once(async_stream=False), daemon=True
        )
        disp_thread.start()
        self.assertTrue(at_post.wait(timeout=1.0))

        # Revoke runs AFTER dispatch_turn returned HANDED_OFF but BEFORE Phase 3 settles
        hub.revoke(_OP, target="sb-lh", reason="late_handed_off_revoke")
        release_post.set()
        disp_thread.join(timeout=2.0)
        self.assertFalse(disp_thread.is_alive())
        self.assertEqual(hub._pending_cleanup_streams, {})
        events = reg.list_events_since(("sb-lh",), 0)
        self.assertFalse(any("SHOULD_DROP_ON_REVOKE" in str(ev.get("text", "")) for ev in events))
        verify_combined_pass_evidence(
            reg,
            CombinedPassExpectations(
                aborted_msg_ids=(msg_id,),
                expected_attempts={msg_id: 1},
                expected_revoked_sandboxes=("sb-lh",),
            ),
        )

    def test_permanent_pre_write_refusal_oversize_artifacts_and_hostile_detail(self) -> None:
        owner = ExternallyFencedFakeTransport(
            {("sb-ref", "inc_ref1"): _OWNER_A},
            max_wire_frame_bytes=64,
            reject_artifacts=True,
        )
        reg, hub = self._open_hub(owner)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_and_grant(hub, "sb-ref", "inc_ref1")

        # 1. Oversize encoded wire frame -> permanent ZERO_BYTES_SENT -> cancelled, zero hot-retry
        msg_big = hub.send(_OP, target="sb-ref", body_text="x" * 128)["msg_id"]
        self.assertEqual(hub.dispatch_once(async_stream=False), 1)
        self.assertEqual(hub.dispatch_once(async_stream=False), 0)

        # 2. Unsupported artifact_refs -> permanent ZERO_BYTES_SENT -> cancelled
        msg_art = hub.send(
            _OP, target="sb-ref", body_text="short", artifact_blobs=(b"diff --git a/x b/x\n",)
        )["msg_id"]
        self.assertEqual(hub.dispatch_once(async_stream=False), 1)
        self.assertEqual(hub.dispatch_once(async_stream=False), 0)

        # 3. Hostile unsanitized detail (control chars, bidi, >256 bytes) + wait() wakes promptly
        hostile = "bad\x00\x07\u202e\n" + ("Z" * 400)
        owner.inner.queue_script(
            "sb-ref",
            TurnScript(outcome=DispatchOutcome.ZERO_BYTES_SENT, detail=hostile, permanent=True),
        )
        sent_hostile = hub.send(_OP, target="sb-ref", body_text="ok")
        msg_hostile = sent_hostile["msg_id"]
        last_seq = sent_hostile["seq"]

        wait_res: list[dict[str, Any]] = []
        wait_thread = threading.Thread(
            target=lambda: wait_res.append(
                hub.wait(_OP, targets=("sb-ref",), since_seq=last_seq, timeout_s=2.0)
            ),
            daemon=True,
        )
        wait_thread.start()
        self.assertEqual(hub.dispatch_once(async_stream=False), 1)
        wait_thread.join(timeout=1.5)
        self.assertEqual(len(wait_res), 1)
        self.assertFalse(wait_res[0]["timed_out"])
        self.assertTrue(
            any(
                ev.get("event_type") == "turn_error" and ev.get("dispatch_msg_id") == msg_hostile
                for ev in wait_res[0]["events"]
            )
        )
        verify_combined_pass_evidence(
            reg,
            CombinedPassExpectations(
                cancelled_msg_ids=(msg_big, msg_art, msg_hostile),
                expected_attempts={msg_big: 1, msg_art: 1, msg_hostile: 1},
                expected_unconfirmed_bindings=(("sb-ref", "inc_ref1"),),
            ),
        )

    def test_external_fence_operator_prompt_sole_grant_and_zero_attempt_persisted_skip(
        self,
    ) -> None:
        # First seed an incompatible persisted non-prompt row + an eligible prompt row using legacy hub
        legacy_reg, legacy_hub = self._open_hub(FakeWorkerTransport())
        try:
            legacy_hub.register_sandbox(
                _OP,
                name="sb-ext",
                incarnation_id="inc_ext1",
                project_id=_PROJ_ID,
                project_name=_PROJ_NAME,
                branch=_BRANCH,
                task_brief=_BRIEF,
            )
            legacy_reg.record_transport_binding("sb-ext", "inc_ext1", _OWNER_A)
            legacy_hub.grant_edge(
                _OP,
                src_actor=_OP.canonical_sender,
                dst_addr="sb-ext",
                allowed_threads=("main",),
                allowed_msg_kinds=("prompt", "cancel"),
            )
            msg_nonprompt = legacy_hub.send(
                _OP, target="sb-ext", msg_kind="cancel", body_text="Incompatible cancel row"
            )["msg_id"]
            msg_prompt = legacy_hub.send(
                _OP, target="sb-ext", msg_kind="prompt", body_text="Eligible prompt row"
            )["msg_id"]
        finally:
            legacy_hub.close()
            legacy_reg.close()

        owner = ExternallyFencedFakeTransport({("sb-ext", "inc_ext1"): _OWNER_A})
        owner.register_owner("sb-ext2", "inc_ext2", _OWNER_B)
        owner.inner.queue_script(
            "sb-ext", TurnScript(echo_user_message=False, text_chunks=("PROMPT_ONLY_OK",))
        )
        reg, hub = self._open_hub(owner)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self.assertFalse(hub.is_degraded)

        # Persisted incompatible non-prompt row stays at attempts=0 with zero adapter calls; prompt dispatches!
        self.assertEqual(hub.dispatch_once(async_stream=False), 1)
        self.assertEqual([t.msg_id for t in owner.dispatch_calls], [msg_prompt])
        outbox = {r["msg_id"]: r for r in reg.list_outbox(statuses=_STATUS_ALL)}
        self.assertEqual(outbox[msg_nonprompt]["status"], "pending")
        self.assertEqual(outbox[msg_nonprompt]["attempts"], 0)
        self.assertEqual(outbox[msg_prompt]["status"], "completed")

        # Admission guardrails: reject lease, controller_request_id, non-prompt grant/send, second edge
        lease = BrokerLease("job_ext_denied")
        with self.assertRaises(CoordPolicyError):
            hub.register_sandbox(
                _OP,
                name="sb-ext2",
                incarnation_id="inc_ext2",
                project_id=_PROJ_ID,
                project_name=_PROJ_NAME,
                branch=_BRANCH,
                task_brief=_BRIEF,
                lease=lease,
            )
        with self.assertRaises(CoordPolicyError):
            hub.grant_edge(
                _OP,
                src_actor=_OP.canonical_sender,
                dst_addr="sb-ext",
                allowed_msg_kinds=("prompt",),
            )
        hub.register_sandbox(
            _OP,
            name="sb-ext2",
            incarnation_id="inc_ext2",
            project_id=_PROJ_ID,
            project_name=_PROJ_NAME,
            branch=_BRANCH,
            task_brief=_BRIEF,
        )
        with self.assertRaises(CoordPolicyError):
            hub.grant_edge(
                _OP,
                src_actor=_OP.canonical_sender,
                dst_addr="sb-ext2",
                allowed_msg_kinds=("prompt", "cancel"),
            )
        with self.assertRaises(CoordPolicyError):
            hub.grant_edge(
                _OP,
                src_actor=_ORCH.canonical_sender,
                dst_addr="sb-ext2",
                allowed_msg_kinds=("prompt",),
            )
        with self.assertRaises(CoordPolicyError):
            hub.send(_OP, target="sb-ext", msg_kind="cancel", body_text="Rejected upfront")

    def test_confirm_recovery_timeout_validation_wedged_phase2_and_close_interrupt(self) -> None:
        owner = ExternallyFencedFakeTransport({("sb-to", "inc_to1"): _OWNER_A})
        paused = threading.Event()
        release = threading.Event()
        self.addCleanup(release.set)
        owner.inner.queue_script(
            "sb-to",
            TurnScript(on_pre_write_paused=paused, pre_write_pause=release),
        )
        reg, hub = self._open_hub(owner)
        self.addCleanup(reg.close)

        for bad_timeout in (True, False, -0.1, math.nan, math.inf):
            with self.assertRaises(CoordValidationError):
                hub.confirm_recovery(_OP, timeout_s=bad_timeout)  # type: ignore[arg-type]

        self._reg_and_grant(hub, "sb-to", "inc_to1")
        hub.send(_OP, target="sb-to", body_text="Wedged phase 2")["msg_id"]
        disp_thread = threading.Thread(
            target=lambda: hub.dispatch_once(async_stream=False), daemon=True
        )
        disp_thread.start()
        self.assertTrue(paused.wait(timeout=1.0))

        # 1. Wedged Phase 2 -> confirm_recovery(timeout_s=0.05) fails closed and stays degraded
        hub._mark_degraded("wedged_phase2")
        with self.assertRaises(CoordPolicyError):
            hub.confirm_recovery(_OP, reason="too_slow", timeout_s=0.05)
        self.assertTrue(hub.is_degraded)

        # 2. close(timeout_s=0.05) fails closed and retains .coord_session_active while Phase 2 wedged
        with self.assertRaises(CoordPolicyError):
            hub.close(timeout_s=0.05)
        self.assertTrue(hub._session_active_marker.exists())

        release.set()
        disp_thread.join(timeout=2.0)
        hub.close(timeout_s=1.5)

    def _run_late_handed_off_after_sweep_case(self, mode: str) -> None:
        sub_dir = self._tmp / f"state-p1-1-{mode}"
        owner = ExternallyFencedFakeTransport({("sb-lr", "inc_lr"): _OWNER_A})
        reg, hub = self._open_hub(owner, state_dir=sub_dir)
        try:
            self._reg_and_grant(hub, "sb-lr", "inc_lr")
            hub.send(_OP, target="sb-lr", body_text="Late reader turn")
            at_dispatch = threading.Event()
            release_dispatch = threading.Event()
            self.addCleanup(release_dispatch.set)
            stream_state = {"closed": False}

            orig_dispatch = owner.dispatch_turn
            orig_confirm = owner.confirm_incarnation_terminal

            def _late_dispatch(turn: Any) -> DispatchResult:
                at_dispatch.set()
                release_dispatch.wait(timeout=3.0)
                stream_state["closed"] = False
                owner.inner._revoked_incarnations.discard(("sb-lr", "inc_lr"))
                return orig_dispatch(turn)

            def _tracking_confirm(
                sb_addr: str, inc_id: str, *, owner_id: str, reason: str
            ) -> bool:
                ok = orig_confirm(sb_addr, inc_id, owner_id=owner_id, reason=reason)
                if ok:
                    stream_state["closed"] = True
                return ok

            owner.dispatch_turn = _late_dispatch  # type: ignore[method-assign]
            owner.confirm_incarnation_terminal = _tracking_confirm  # type: ignore[method-assign]

            disp_thread = threading.Thread(
                target=lambda: hub.dispatch_once(async_stream=False), daemon=True
            )
            disp_thread.start()
            self.assertTrue(at_dispatch.wait(timeout=1.0))

            if mode == "revoke":
                hub.revoke(_OP, target="sb-lr", reason="sweep_before_late_stream")
                calls_after_sweep = len(owner.confirm_calls)
                release_dispatch.set()
                disp_thread.join(timeout=2.0)
            else:
                hub._mark_degraded("recovery_sweep_before_late_stream")
                rec_done = threading.Event()
                rec_err: list[Exception] = []

                def _do_rec() -> None:
                    try:
                        hub.confirm_recovery(_OP, reason="late_stream_recovery", timeout_s=2.0)
                    except Exception as exc:
                        rec_err.append(exc)
                    finally:
                        rec_done.set()

                rec_thread = threading.Thread(target=_do_rec, daemon=True)
                rec_thread.start()
                self.assertTrue(
                    _wait_until(
                        lambda: bool(
                            reg.get_transport_binding("sb-lr", "inc_lr")["terminal_confirmed"]
                        )
                    )
                )
                calls_after_sweep = len(owner.confirm_calls)
                release_dispatch.set()
                self.assertTrue(rec_done.wait(timeout=2.0))
                disp_thread.join(timeout=2.0)
                self.assertEqual(rec_err, [])

            self.assertGreater(len(owner.confirm_calls), calls_after_sweep)
            self.assertTrue(stream_state["closed"])
            self.assertEqual(hub._pending_cleanup_streams, {})
        finally:
            hub.close(timeout_s=1.5)
            reg.close()

    def test_g2_p1_1_late_handed_off_after_terminal_sweep_reconfirms_physical_close(
        self,
    ) -> None:
        # Both revoke() and confirm_recovery() races must re-invoke confirm_incarnation_terminal
        # to close a late stream reader registered after the first sweep set terminal_confirmed=1.
        self._run_late_handed_off_after_sweep_case("revoke")
        self._run_late_handed_off_after_sweep_case("recovery")

    def test_g2_p1_2_binding_lookup_sqlite_error_fails_closed_without_legacy_fallback(
        self,
    ) -> None:
        reg, hub = self._open_hub(FakeWorkerTransport())
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        orig_get = reg.get_transport_binding

        def _failing_get(sb_addr: str, inc_id: str) -> dict[str, Any] | None:
            raise RuntimeError("sqlite_io_error")

        reg.get_transport_binding = _failing_get  # type: ignore[method-assign]
        try:
            settled, aborted = hub._abort_incarnation_confirmed("sb-x", "inc_x", "revoked")
            self.assertFalse(settled)
            self.assertFalse(aborted)
        finally:
            reg.get_transport_binding = orig_get  # type: ignore[method-assign]

    def test_g2_p1_3_verifier_rejects_forged_unlinked_and_malformed_badges(self) -> None:
        owner = ExternallyFencedFakeTransport({("sb-v", "inc_v1"): _OWNER_A})
        reg, hub = self._open_hub(owner)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_and_grant(hub, "sb-v", "inc_v1")
        msg_ok = hub.send(_OP, target="sb-v", body_text="Legit turn")["msg_id"]
        self.assertEqual(hub.dispatch_once(async_stream=False), 1)

        exp = CombinedPassExpectations(
            completed_msg_ids=(msg_ok,),
            expected_unconfirmed_bindings=(("sb-v", "inc_v1"),),
        )
        # (a) Forged user_message with dispatch_msg_id IS NULL and badge='Operator' must fail
        with reg._tx() as conn:
            conn.execute(
                """
                INSERT INTO stream_events
                    (seq, event_type, sandbox_addr, incarnation_id, thread_id,
                     seq_hint, message_id, dispatch_msg_id, text, file_path,
                     detail_json, badge, created_at)
                VALUES (9001, 'user_message', 'sb-v', 'inc_v1', 'main',
                        1, NULL, NULL, 'forged', NULL, '{}', 'Operator', 1.0)
                """
            )
        with self.assertRaises(AssertionError):
            verify_combined_pass_evidence(reg, exp)

        # (b) Null badge on user_message must fail
        with reg._tx() as conn:
            conn.execute("UPDATE stream_events SET badge = NULL WHERE seq = 9001")
        with self.assertRaises(AssertionError):
            verify_combined_pass_evidence(reg, exp)

        # (c) Non-null badge on text_delta must fail
        with reg._tx() as conn:
            conn.execute(
                "UPDATE stream_events SET event_type = 'text_delta', badge = 'Operator' WHERE seq = 9001"
            )
        with self.assertRaises(AssertionError):
            verify_combined_pass_evidence(reg, exp)

    def test_g2_p2_1_startup_reconciliation_fences_all_unconfirmed_bindings_symmetrically(
        self,
    ) -> None:
        owner = ExternallyFencedFakeTransport(
            {("sb-early", "inc_e1"): _OWNER_A, ("sb-late", "inc_l1"): _OWNER_B}
        )
        reg1, hub1 = self._open_hub(owner)
        try:
            self._reg_and_grant(hub1, "sb-early", "inc_e1")
            self._reg_and_grant(hub1, "sb-late", "inc_l1")
            # Mark ONLY the later binding abort_requested=1; earlier binding stays healthy
            reg1.mark_transport_abort_requested("sb-late", "inc_l1", reason="late_abort_req")
        finally:
            hub1.close()
            reg1.close()

        reg2, hub2 = self._open_hub(owner)
        self.addCleanup(reg2.close)
        self.addCleanup(hub2.close)
        self.assertTrue(hub2.is_degraded)
        self.assertIn(("sb-early", "inc_e1"), hub2._fenced_targets)
        self.assertIn(("sb-late", "inc_l1"), hub2._fenced_targets)
        self.assertIn(("sb-early", "inc_e1"), hub2._pending_cleanup_incarnations)
        self.assertIn(("sb-late", "inc_l1"), hub2._pending_cleanup_incarnations)
        hub2.confirm_recovery(_OP, reason="settle_both")
        self.assertFalse(hub2.is_degraded)

    def test_g2_p2_2_idempotent_second_revoke_and_settled_known_incarnation_pruning(
        self,
    ) -> None:
        owner1 = ExternallyFencedFakeTransport({("sb-idem", "inc_i1"): _OWNER_A})
        reg1, hub1 = self._open_hub(owner1)
        try:
            self._reg_and_grant(hub1, "sb-idem", "inc_i1")
            hub1.revoke(_OP, target="sb-idem", reason="first_revoke")
            # Direct idempotent commit_external_revoke returns [] without adding duplicate audit
            _ok_before, count_before = reg1.verify_audit_chain()
            self.assertEqual(
                reg1.commit_external_revoke(
                    target_addr="sb-idem",
                    incarnation_id="inc_i1",
                    owner_id=_OWNER_A,
                    actor=_OP.canonical_sender,
                    reason="dup_commit",
                ),
                [],
            )
            _ok_after, count_after = reg1.verify_audit_chain()
            self.assertEqual(count_after, count_before)
        finally:
            hub1.close()
            reg1.close()

        # Reopen with successor-only transport (does NOT know inc_i1): second revoke must succeed cleanly
        owner2 = ExternallyFencedFakeTransport({("sb-idem", "inc_i2"): _OWNER_B})
        reg2, hub2 = self._open_hub(owner2)
        self.addCleanup(reg2.close)
        self.addCleanup(hub2.close)
        hub2.revoke(_OP, target="sb-idem", reason="second_idempotent_revoke")
        self.assertEqual(hub2._pending_cleanup_incarnations, {})

    def test_g2_p2_3_uncertain_and_dispatch_exception_details_sanitized(self) -> None:
        owner = ExternallyFencedFakeTransport({("sb-san", "inc_s1"): _OWNER_A})
        bad_detail = "bad\ud800\x00\u202e\n" + ("X" * 1024)
        owner.inner.queue_script(
            "sb-san", TurnScript(outcome=DispatchOutcome.UNCERTAIN, detail=bad_detail)
        )
        reg, hub = self._open_hub(owner)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_and_grant(hub, "sb-san", "inc_s1")

        msg_unc = hub.send(_OP, target="sb-san", body_text="Uncertain hostile detail")["msg_id"]
        self.assertEqual(hub.dispatch_once(async_stream=False), 1)

        def _raising_dispatch(turn: Any) -> DispatchResult:
            raise RuntimeError("boom\ud800\x07\u202e\n" + ("Y" * 1024))

        owner.dispatch_turn = _raising_dispatch  # type: ignore[method-assign]
        msg_exc = hub.send(_OP, target="sb-san", body_text="Exception hostile detail")["msg_id"]
        self.assertEqual(hub.dispatch_once(async_stream=False), 1)

        outbox = {r["msg_id"]: r for r in reg.list_outbox(statuses=_STATUS_ALL)}
        for mid in (msg_unc, msg_exc):
            self.assertEqual(outbox[mid]["status"], "uncertain")
            self.assertLessEqual(len(outbox[mid]["detail"].encode("utf-8")), 256)
            self.assertNotIn("\x00", outbox[mid]["detail"])
            self.assertNotIn("\u202e", outbox[mid]["detail"])
        ok, count = reg.verify_audit_chain()
        self.assertTrue(ok)
        self.assertGreater(count, 0)

    def test_oc_p1_1_stale_dispatcher_cannot_cancel_another_dispatchers_inflight_write(
        self,
    ) -> None:
        owner = ExternallyFencedFakeTransport({("sb-race", "inc_r1"): _OWNER_A})
        reg, hub = self._open_hub(owner)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_and_grant(hub, "sb-race", "inc_r1")
        msg_id = hub.send(_OP, target="sb-race", body_text="Held across revoke")["msg_id"]
        stale_row = reg.list_outbox(statuses=("pending",))[0]

        in_transport = threading.Event()
        release_transport = threading.Event()
        self.addCleanup(release_transport.set)

        def _held_uncertain_dispatch(turn: Any) -> DispatchResult:
            in_transport.set()
            release_transport.wait(timeout=3.0)
            return DispatchResult(outcome=DispatchOutcome.UNCERTAIN, detail="held_lost_receipt")

        owner.dispatch_turn = _held_uncertain_dispatch  # type: ignore[method-assign]
        t1 = threading.Thread(target=lambda: hub.dispatch_once(async_stream=False), daemon=True)
        t1.start()
        self.assertTrue(in_transport.wait(timeout=1.0))

        # Revoke while Dispatcher 1 holds dispatch_started in Phase 2
        hub.revoke(_OP, target="sb-race", reason="revoke_while_inflight")

        # Stale Dispatcher 2 snapshots the old pending row and enters Phase 1 -> MUST NOT cancel dispatch_started!
        self.assertFalse(hub._dispatch_single_row(stale_row, async_stream=False))
        row_mid = {r["msg_id"]: r for r in reg.list_outbox(statuses=_STATUS_ALL)}[msg_id]
        self.assertEqual(row_mid["status"], "dispatch_started")

        # Release Dispatcher 1 -> true UNCERTAIN outcome is recorded without being clobbered by cancelled
        release_transport.set()
        t1.join(timeout=2.0)
        row_end = {r["msg_id"]: r for r in reg.list_outbox(statuses=_STATUS_ALL)}[msg_id]
        self.assertEqual(row_end["status"], "uncertain")

    def test_oc_p1_2_completed_attempt_cannot_erase_retry_settlement_owner(self) -> None:
        owner = ExternallyFencedFakeTransport({("sb-rtry", "inc_rt1"): _OWNER_A})
        reg, hub = self._open_hub(owner)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_and_grant(hub, "sb-rtry", "inc_rt1")
        msg_id = hub.send(_OP, target="sb-rtry", body_text="Retry owner race")["msg_id"]

        attempt2_paused = threading.Event()
        attempt2_release = threading.Event()
        self.addCleanup(attempt2_release.set)
        attempt1_after_fence = threading.Event()
        attempt1_allow_finally = threading.Event()
        self.addCleanup(attempt1_allow_finally.set)
        calls = {"n": 0}

        def _scripted_dispatch(turn: Any) -> DispatchResult:
            calls["n"] += 1
            if calls["n"] == 1:
                return DispatchResult(
                    outcome=DispatchOutcome.ZERO_BYTES_SENT, detail="busy_retry", permanent=False
                )
            attempt2_paused.set()
            attempt2_release.wait(timeout=3.0)
            return DispatchResult(outcome=DispatchOutcome.UNCERTAIN, detail="attempt2_uncertain")

        owner.dispatch_turn = _scripted_dispatch  # type: ignore[method-assign]
        orig_release = hub._release_inflight_owner

        def _delayed_release(
            env: Any, inflight: Any, *, settled: bool, returned_stream_id: str | None
        ) -> None:
            if not attempt1_after_fence.is_set():
                attempt1_after_fence.set()
                attempt1_allow_finally.wait(timeout=3.0)
            orig_release(env, inflight, settled=settled, returned_stream_id=returned_stream_id)

        hub._release_inflight_owner = _delayed_release  # type: ignore[method-assign]

        t1 = threading.Thread(target=lambda: hub.dispatch_once(async_stream=False), daemon=True)
        t1.start()
        self.assertTrue(attempt1_after_fence.wait(timeout=1.0))

        # Attempt 2 claims the requeued pending row and pauses in Phase 2
        t2 = threading.Thread(target=lambda: hub.dispatch_once(async_stream=False), daemon=True)
        t2.start()
        self.assertTrue(attempt2_paused.wait(timeout=1.0))

        # Now let Attempt 1 run its finally: it MUST NOT erase Attempt 2's settlement owner!
        attempt1_allow_finally.set()
        t1.join(timeout=2.0)
        self.assertIn(msg_id, hub._inflight_handoffs)

        # Recovery MUST stay closed while Attempt 2 is still paused!
        hub._mark_degraded("recovery_during_retry_attempt2")
        rec_done = threading.Event()
        rec_err: list[Exception] = []

        def _do_rec() -> None:
            try:
                hub.confirm_recovery(_OP, reason="wait_for_retry_attempt2", timeout_s=2.0)
            except Exception as exc:
                rec_err.append(exc)
            finally:
                rec_done.set()

        rec_thread = threading.Thread(target=_do_rec, daemon=True)
        rec_thread.start()
        self.assertFalse(rec_done.wait(timeout=0.08))
        self.assertTrue(hub.is_degraded)

        attempt2_release.set()
        self.assertTrue(rec_done.wait(timeout=2.0))
        t2.join(timeout=2.0)
        self.assertEqual(rec_err, [])
        self.assertFalse(hub.is_degraded)

    def test_oc_p1_3_cold_cache_unreadable_binding_during_revoke_fails_closed(self) -> None:
        owner = ExternallyFencedFakeTransport({("sb-cold", "inc_c1"): _OWNER_A})
        reg1, hub1 = self._open_hub(owner)
        try:
            self._reg_and_grant(hub1, "sb-cold", "inc_c1")
        finally:
            hub1.close()
            reg1.close()

        reg2, hub2 = self._open_hub(owner)
        self.addCleanup(reg2.close)
        # Clear in-memory owner cache (cold cache) and fail get_transport_binding() while sandbox/edges stay readable
        with hub2._meta_lock:
            hub2._external_owners.clear()
        orig_get = reg2.get_transport_binding

        def _fail_binding(sb_addr: str, inc_id: str) -> dict[str, Any] | None:
            raise RuntimeError("binding_read_io_error")

        reg2.get_transport_binding = _fail_binding  # type: ignore[method-assign]
        _ok_b, audit_before = reg2.verify_audit_chain()
        try:
            with self.assertRaises(CoordPolicyError):
                hub2.revoke(_OP, target="sb-cold", reason="cold_cache_binding_err")
            self.assertTrue(hub2.is_degraded)
            self.assertIn(("sb-cold", "inc_c1"), hub2._pending_cleanup_incarnations)
            self.assertEqual(owner.confirm_calls, [])
            # Must NOT have emitted a legacy "ok" revoke audit
            _ok_a, audit_after = reg2.verify_audit_chain()
            self.assertEqual(audit_after, audit_before)
        finally:
            reg2.get_transport_binding = orig_get  # type: ignore[method-assign]
        hub2.confirm_recovery(_OP, reason="recovered_after_binding_read")
        hub2.close()

    def test_oc_p1_4_legacy_registration_cannot_reuse_terminal_external_identity(self) -> None:
        owner1 = ExternallyFencedFakeTransport({(_ADDR_SUCC, "inc_term1"): _OWNER_A})
        reg1, hub1 = self._open_hub(owner1)
        try:
            self._reg_and_grant(hub1, _ADDR_SUCC, "inc_term1")
            hub1.revoke(_OP, target=_ADDR_SUCC, reason="retire_term1")
        finally:
            hub1.close()
            reg1.close()

        # Occupy address with successor inc_term2 and close cleanly
        owner2 = ExternallyFencedFakeTransport({(_ADDR_SUCC, "inc_term2"): _OWNER_B})
        reg2, hub2 = self._open_hub(owner2)
        try:
            self._reg_and_grant(hub2, _ADDR_SUCC, "inc_term2")
            hub2.revoke(_OP, target=_ADDR_SUCC, reason="retire_term2")
        finally:
            hub2.close()
            reg2.close()

        # Reopen with a legacy FakeWorkerTransport, run a healthy live successor with an active grant
        # and a queued turn, and attempt to reuse retired inc_term1 -> MUST raise RevokedError
        # WITHOUT stopping or invalidating the healthy live successor!
        legacy_transport = FakeWorkerTransport()
        abort_calls: list[tuple[str, str]] = []
        orig_abort_inc = legacy_transport.abort_incarnation

        def _spy_abort_inc(sb_addr: str, inc_id: str, *, reason: str) -> bool:
            abort_calls.append((sb_addr, inc_id))
            return orig_abort_inc(sb_addr, inc_id, reason=reason)

        legacy_transport.abort_incarnation = _spy_abort_inc  # type: ignore[method-assign]
        reg3, hub3 = self._open_hub(legacy_transport)
        self.addCleanup(reg3.close)
        self.addCleanup(hub3.close)
        self._reg_and_grant(hub3, _ADDR_SUCC, "inc_leg_live")
        msg_live = hub3.send(_OP, target=_ADDR_SUCC, body_text="Keep successor alive")["msg_id"]
        with self.assertRaises(RevokedError):
            hub3.register_sandbox(
                _OP,
                name=_ADDR_SUCC,
                incarnation_id="inc_term1",
                project_id=_PROJ_ID,
                project_name=_PROJ_NAME,
                branch=_BRANCH,
                task_brief=_BRIEF,
            )
        self.assertEqual(abort_calls, [])
        sb_live = reg3.get_sandbox(_ADDR_SUCC)
        self.assertIsNotNone(sb_live)
        assert sb_live is not None
        self.assertEqual(sb_live.incarnation_id, "inc_leg_live")
        self.assertEqual(sb_live.status, "running")
        self.assertTrue(reg3.list_edges(dst_addr=_ADDR_SUCC, active_only=True))
        live_row_before = {r["msg_id"]: r for r in reg3.list_outbox(statuses=_STATUS_ALL)}[msg_live]
        self.assertEqual(live_row_before["status"], "pending")
        self.assertEqual(hub3.dispatch_once(async_stream=False), 1)
        live_row_after = {r["msg_id"]: r for r in reg3.list_outbox(statuses=_STATUS_ALL)}[msg_live]
        self.assertEqual(live_row_after["status"], "completed")

    def test_oc_p2_1_crash_after_durable_handoff_settles_orphaned_row_on_recovery(self) -> None:
        owner = ExternallyFencedFakeTransport({("sb-ho", "inc_ho1"): _OWNER_A})
        started = threading.Event()
        never_done = threading.Event()
        self.addCleanup(never_done.set)
        owner.inner.queue_script(
            "sb-ho", TurnScript(on_stream_started=started, block_event=never_done)
        )
        reg1, hub1 = self._open_hub(owner)
        try:
            self._reg_and_grant(hub1, "sb-ho", "inc_ho1")
            msg_ho = hub1.send(_OP, target="sb-ho", body_text="Crash after handed_off")["msg_id"]
            self.assertEqual(hub1.dispatch_once(async_stream=True), 1)
            self.assertTrue(started.wait(timeout=1.0))
            ho_row = {r["msg_id"]: r for r in reg1.list_outbox(statuses=_STATUS_ALL)}[msg_ho]
            self.assertEqual(ho_row["status"], "handed_off")
            orig_stream_id = ho_row["stream_id"]
            self.assertTrue(orig_stream_id)
        finally:
            # Simulate abrupt host crash BEFORE stream finalization touches SQLite
            reg1.abort_handed_off_outbox_row_if_open = lambda *a, **k: False  # type: ignore[method-assign]
            reg1.mark_outbox_aborted = lambda *a, **k: None  # type: ignore[method-assign]
            reg1.mark_outbox_completed = lambda *a, **k: None  # type: ignore[method-assign]
            never_done.set()
            owner.inner.abort_incarnation("sb-ho", "inc_ho1", reason="simulated_reader_exit")
            hub1.dispatcher.join_streams(time.monotonic() + 1.0)
            self._abandon_hub_for_crash(hub1, reg1)

        # Reopen Hub 2 -> row is genuinely orphaned as handed_off; confirm_recovery settles it to aborted
        reg2, hub2 = self._open_hub(owner)
        self.addCleanup(reg2.close)
        self.addCleanup(hub2.close)
        self.assertTrue(hub2.is_degraded)
        orphan_before = {r["msg_id"]: r for r in reg2.list_outbox(statuses=_STATUS_ALL)}[msg_ho]
        self.assertEqual(orphan_before["status"], "handed_off")
        before_calls = len(owner.dispatch_calls)
        hub2.confirm_recovery(_OP, reason="settle_orphaned_handoff")
        self.assertFalse(hub2.is_degraded)
        self.assertEqual(hub2.dispatch_once(async_stream=False), 0)
        self.assertEqual(len(owner.dispatch_calls), before_calls)

        settled_row = {r["msg_id"]: r for r in reg2.list_outbox(statuses=_STATUS_ALL)}[msg_ho]
        self.assertEqual(settled_row["status"], "aborted")
        self.assertEqual(settled_row["stream_id"], orig_stream_id)
        self.assertEqual(settled_row["attempts"], 1)
        verify_combined_pass_evidence(
            reg2,
            CombinedPassExpectations(
                aborted_msg_ids=(msg_ho,),
                expected_attempts={msg_ho: 1},
                expected_revoked_sandboxes=("sb-ho",),
            ),
        )

    def test_oc_p2_2_failed_handoff_persist_with_abort_stream_still_retires_external_incarnation(
        self,
    ) -> None:
        class _ExternalWithAbortStream(ExternallyFencedFakeTransport):
            def abort_stream(self, stream_id: str, *, reason: str) -> bool:
                return self._inner.abort_stream(stream_id, reason=reason)

        owner = _ExternalWithAbortStream({("sb-hp", "inc_hp1"): _OWNER_A})
        reg, hub = self._open_hub(owner)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_and_grant(hub, "sb-hp", "inc_hp1")
        msg_id = hub.send(_OP, target="sb-hp", body_text="Handoff persist failure")["msg_id"]

        orig_mark_ho = reg.mark_outbox_handed_off

        def _fail_mark_ho(mid: str, *, stream_id: str) -> None:
            raise RuntimeError("sqlite_handoff_persist_failed")

        reg.mark_outbox_handed_off = _fail_mark_ho  # type: ignore[method-assign]
        try:
            self.assertEqual(hub.dispatch_once(async_stream=False), 1)
        finally:
            reg.mark_outbox_handed_off = orig_mark_ho  # type: ignore[method-assign]

        # Even though abort_stream() succeeded, the external incarnation MUST be retired via exact owner!
        self.assertTrue(
            any(c[0] == "sb-hp" and c[1] == "inc_hp1" and c[2] == _OWNER_A for c in owner.confirm_calls)
        )
        binding = reg.get_transport_binding("sb-hp", "inc_hp1")
        self.assertTrue(binding["terminal_confirmed"])
        verify_combined_pass_evidence(
            reg,
            CombinedPassExpectations(
                uncertain_msg_ids=(msg_id,),
                expected_attempts={msg_id: 1},
                expected_revoked_sandboxes=("sb-hp",),
            ),
        )

    def test_oc2_p1_1_cleanup_sweep_does_not_discard_late_handoff_registered_after_physical_confirm(
        self,
    ) -> None:
        owner = ExternallyFencedFakeTransport({("sb-sw", "inc_sw1"): _OWNER_A})
        reg, hub = self._open_hub(owner)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_and_grant(hub, "sb-sw", "inc_sw1")

        # Seed an incarnation cleanup obligation and inject a late stream AFTER the first
        # physical confirm returns, BEFORE _drain_pending_cleanup_incarnations reacquires _meta_lock.
        with hub._meta_lock:
            hub._pending_cleanup_incarnations[("sb-sw", "inc_sw1")] = "recovery_retired"
        injected = {"done": False}
        orig_confirm = owner.confirm_incarnation_terminal

        def _confirm_with_late_arrival(
            sb_addr: str, inc_id: str, *, owner_id: str, reason: str
        ) -> bool:
            ok = orig_confirm(sb_addr, inc_id, owner_id=owner_id, reason=reason)
            if ok and not injected["done"]:
                injected["done"] = True
                with hub._meta_lock:
                    hub._pending_cleanup_streams["str-late-after-confirm"] = (
                        "sb-sw",
                        "inc_sw1",
                        "recovery_retired",
                    )
                    hub._pending_cleanup_incarnations.setdefault(
                        ("sb-sw", "inc_sw1"), "recovery_retired"
                    )
            return ok

        owner.confirm_incarnation_terminal = _confirm_with_late_arrival  # type: ignore[method-assign]
        try:
            hub._drain_pending_cleanup_incarnations()
            # Late stream MUST NOT have been discarded, and cached owner MUST remain retained.
            self.assertIn("str-late-after-confirm", hub._pending_cleanup_streams)
            self.assertIn(("sb-sw", "inc_sw1"), hub._pending_cleanup_incarnations)
            self.assertIn(("sb-sw", "inc_sw1"), hub._external_owners)
            self.assertEqual(len(owner.confirm_calls), 1)
            # Even during a subsequent DB binding-read outage, cached owner physically confirms late stream.
            orig_get = reg.get_transport_binding

            def _binding_outage(sb_addr: str, inc_id: str) -> dict[str, Any] | None:
                raise sqlite3.OperationalError("binding_read_outage_after_late_arrival")

            reg.get_transport_binding = _binding_outage  # type: ignore[method-assign]
            try:
                self.assertFalse(hub._drain_pending_cleanups())
                self.assertGreaterEqual(len(owner.confirm_calls), 2)
                self.assertIn(("sb-sw", "inc_sw1"), hub._external_owners)
            finally:
                reg.get_transport_binding = orig_get  # type: ignore[method-assign]
            # Once DB recovers, sweep clears the last obligation AND evicts the cached owner.
            self.assertTrue(hub._drain_pending_cleanups())
            self.assertNotIn("str-late-after-confirm", hub._pending_cleanup_streams)
            self.assertNotIn(("sb-sw", "inc_sw1"), hub._pending_cleanup_incarnations)
            self.assertNotIn(("sb-sw", "inc_sw1"), hub._external_owners)
        finally:
            owner.confirm_incarnation_terminal = orig_confirm  # type: ignore[method-assign]

        # Register a same-address successor; if metadata lookup fails during revoke,
        # address-level revoke MUST fail closed and never report success for a retired/ambiguous owner.
        owner.register_owner("sb-sw", "inc_sw2", _OWNER_B)
        self._reg_and_grant(hub, "sb-sw", "inc_sw2")
        orig_get_sb = reg.get_sandbox

        def _meta_outage(sb_addr: str) -> Any:
            raise sqlite3.OperationalError("sandbox_meta_outage")

        reg.get_sandbox = _meta_outage  # type: ignore[method-assign]
        try:
            with self.assertRaises(CoordPolicyError):
                hub.revoke(_OP, target="sb-sw", reason="meta_outage_revoke")
            self.assertTrue(hub.is_degraded)
        finally:
            reg.get_sandbox = orig_get_sb  # type: ignore[method-assign]
        hub.confirm_recovery(_OP, reason="after_meta_outage")

    def test_oc2_p1_2_cleanup_retry_stops_held_stream_with_cached_owner_during_db_outage(
        self,
    ) -> None:
        owner = ExternallyFencedFakeTransport({("sb-out", "inc_out1"): _OWNER_A})
        started = threading.Event()
        never_done = threading.Event()
        self.addCleanup(never_done.set)
        owner.inner.queue_script(
            "sb-out", TurnScript(on_stream_started=started, block_event=never_done)
        )
        reg, hub = self._open_hub(owner)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_and_grant(hub, "sb-out", "inc_out1")
        hub.send(_OP, target="sb-out", body_text="Hold stream across outage")
        self.assertEqual(hub.dispatch_once(async_stream=True), 1)
        self.assertTrue(started.wait(timeout=1.0))

        # First physical confirm fails -> revoke fails closed, keeping cached owner + held stream.
        owner.fail_confirm_keys.add(("sb-out", "inc_out1"))
        with self.assertRaises(CoordPolicyError):
            hub.revoke(_OP, target="sb-out", reason="initial_revoke")
        self.assertTrue(hub.is_degraded)
        self.assertIn(("sb-out", "inc_out1"), hub._external_owners)
        self.assertIn(("sb-out", "inc_out1"), hub._pending_cleanup_incarnations)

        # Transport recovers, but SQLite binding reads now suffer an outage.
        owner.fail_confirm_keys.discard(("sb-out", "inc_out1"))
        calls_before_outage = len(owner.confirm_calls)
        orig_get = reg.get_transport_binding

        def _db_outage(sb_addr: str, inc_id: str) -> dict[str, Any] | None:
            raise sqlite3.OperationalError("binding_read_outage")

        reg.get_transport_binding = _db_outage  # type: ignore[method-assign]
        try:
            drained = hub._drain_pending_cleanups()
            self.assertFalse(drained)
            self.assertIn(("sb-out", "inc_out1"), hub._pending_cleanup_incarnations)
            self.assertGreater(len(owner.confirm_calls), calls_before_outage)
            self.assertEqual(owner.confirm_calls[-1][:3], ("sb-out", "inc_out1", _OWNER_A))
            # Recovery must remain closed until SQLite confirms durable retirement.
            with self.assertRaises(CoordPolicyError):
                hub.confirm_recovery(_OP, reason="during_db_outage")
            # Cold-cache hub must still refuse without calling transport during DB outage.
            owner_cold = ExternallyFencedFakeTransport({("sb-out", "inc_out1"): _OWNER_A})
            cold_dir = self.state_dir.parent / "cold_state"
            cold_dir.mkdir(mode=0o700, exist_ok=True)
            hub_cold = CoordHub(reg, owner_cold, cold_dir, sandbox_root=self.sandbox_root)
            self.addCleanup(hub_cold.close)
            with hub_cold._meta_lock:
                hub_cold._external_owners.clear()
                hub_cold._pending_cleanup_incarnations[("sb-out", "inc_out1")] = "cold_outage"
            self.assertFalse(hub_cold._drain_pending_cleanups())
            self.assertEqual(owner_cold.confirm_calls, [])
        finally:
            reg.get_transport_binding = orig_get  # type: ignore[method-assign]

        # Once SQLite recovers, confirm_recovery commits durable retirement and reopens.
        hub.confirm_recovery(_OP, reason="after_db_outage")
        self.assertFalse(hub.is_degraded)
        binding = reg.get_transport_binding("sb-out", "inc_out1")
        self.assertTrue(binding["terminal_confirmed"])

    def test_oc2_p2_1_orphan_handed_off_settlement_preserves_raced_terminal_and_propagates_storage_error(
        self,
    ) -> None:
        owner = ExternallyFencedFakeTransport({("sb-rc", "inc_rc1"): _OWNER_A})
        started = threading.Event()
        never_done = threading.Event()
        self.addCleanup(never_done.set)
        owner.inner.queue_script(
            "sb-rc", TurnScript(on_stream_started=started, block_event=never_done)
        )
        reg1, hub1 = self._open_hub(owner)
        try:
            self._reg_and_grant(hub1, "sb-rc", "inc_rc1")
            msg_raced = hub1.send(_OP, target="sb-rc", body_text="Race finalizer")["msg_id"]
            self.assertEqual(hub1.dispatch_once(async_stream=True), 1)
            self.assertTrue(started.wait(timeout=1.0))
        finally:
            reg1.abort_handed_off_outbox_row_if_open = lambda *a, **k: False  # type: ignore[method-assign]
            reg1.mark_outbox_aborted = lambda *a, **k: None  # type: ignore[method-assign]
            reg1.mark_outbox_completed = lambda *a, **k: None  # type: ignore[method-assign]
            never_done.set()
            owner.inner.abort_incarnation("sb-rc", "inc_rc1", reason="sim_crash")
            hub1.dispatcher.join_streams(time.monotonic() + 1.0)
            self._abandon_hub_for_crash(hub1, reg1)

        # Part A: live stream finalizer completes the row between list_outbox and orphan abort.
        reg2, hub2 = self._open_hub(owner)
        self.addCleanup(reg2.close)
        self.addCleanup(hub2.close)
        orig_list = reg2.list_outbox
        raced_once = {"done": False}

        def _list_and_finalize(statuses: tuple[str, ...] | None = None, **kwargs: Any) -> list[dict[str, Any]]:
            rows = orig_list(statuses=statuses, **kwargs)
            if statuses == ("handed_off",) and rows and not raced_once["done"]:
                raced_once["done"] = True
                reg2.mark_outbox_completed(msg_raced)
            return rows

        reg2.list_outbox = _list_and_finalize  # type: ignore[method-assign]
        try:
            hub2.confirm_recovery(_OP, reason="raced_finalizer")
        finally:
            reg2.list_outbox = orig_list  # type: ignore[method-assign]
        self.assertFalse(hub2.is_degraded)
        row_a = {r["msg_id"]: r for r in reg2.list_outbox(statuses=_STATUS_ALL)}[msg_raced]
        self.assertEqual(row_a["status"], "completed")
        hub2.close()
        reg2.close()

        # Part B: genuine SQLite storage error during orphan settlement MUST propagate and keep recovery closed.
        owner_b = ExternallyFencedFakeTransport({("sb-rc2", "inc_rc2"): _OWNER_B})
        started_b = threading.Event()
        never_b = threading.Event()
        self.addCleanup(never_b.set)
        owner_b.inner.queue_script(
            "sb-rc2", TurnScript(on_stream_started=started_b, block_event=never_b)
        )
        reg3, hub3 = self._open_hub(owner_b)
        try:
            self._reg_and_grant(hub3, "sb-rc2", "inc_rc2")
            hub3.send(_OP, target="sb-rc2", body_text="Storage failure during orphan abort")
            self.assertEqual(hub3.dispatch_once(async_stream=True), 1)
            self.assertTrue(started_b.wait(timeout=1.0))
        finally:
            reg3.abort_handed_off_outbox_row_if_open = lambda *a, **k: False  # type: ignore[method-assign]
            reg3.mark_outbox_aborted = lambda *a, **k: None  # type: ignore[method-assign]
            reg3.mark_outbox_completed = lambda *a, **k: None  # type: ignore[method-assign]
            never_b.set()
            owner_b.inner.abort_incarnation("sb-rc2", "inc_rc2", reason="sim_crash_b")
            hub3.dispatcher.join_streams(time.monotonic() + 1.0)
            self._abandon_hub_for_crash(hub3, reg3)

        reg4, hub4 = self._open_hub(owner_b)
        self.addCleanup(reg4.close)
        self.addCleanup(hub4.close)

        def _raise_storage_error(msg_id: str, *, reason: str = "x") -> bool:
            raise sqlite3.OperationalError("disk_io_error")

        orig_abort_open = reg4.abort_handed_off_outbox_row_if_open
        orig_mark_aborted = reg4.mark_outbox_aborted
        reg4.abort_handed_off_outbox_row_if_open = _raise_storage_error  # type: ignore[method-assign]
        reg4.mark_outbox_aborted = _raise_storage_error  # type: ignore[method-assign]
        try:
            with self.assertRaises(sqlite3.OperationalError):
                hub4.confirm_recovery(_OP, reason="storage_err_recovery")
            self.assertTrue(hub4.is_degraded)
        finally:
            reg4.abort_handed_off_outbox_row_if_open = orig_abort_open  # type: ignore[method-assign]
            reg4.mark_outbox_aborted = orig_mark_aborted  # type: ignore[method-assign]
        hub4.confirm_recovery(_OP, reason="storage_err_cleared")

    def test_oc2_p2_2_pending_only_cancel_enforced_for_in_memory_and_minimal_stores(self) -> None:
        from test_hub import InMemoryRegistryStore

        mem = InMemoryRegistryStore()
        transport = FakeWorkerTransport()
        mem_dir = self.state_dir.parent / "mem_state"
        mem_dir.mkdir(mode=0o700, exist_ok=True)
        hub = CoordHub(mem, transport, mem_dir, sandbox_root=self.sandbox_root)
        self.addCleanup(hub.close)
        edge_id = self._reg_and_grant(hub, "sb-mem", "inc_mem1")
        msg_id = hub.send(_OP, target="sb-mem", body_text="Protect dispatch_started")["msg_id"]
        self.assertTrue(
            mem.mark_outbox_dispatch_started(
                msg_id,
                edge_id=edge_id,
                grant_generation=mem.edges[edge_id].grant_generation,
                dst_incarnation="inc_mem1",
            )
        )
        self.assertFalse(mem.cancel_pending_outbox_row(msg_id, reason="stale_dispatcher"))
        self.assertEqual(mem.outbox[msg_id]["status"], "dispatch_started")

        # Minimal store omitting cancel_pending_outbox_row must NOT fall back to cancel_outbox_row.
        cancel_fallback_calls: list[str] = []

        class _MinimalStore:
            def __getattr__(self, name: str) -> Any:
                if name == "cancel_pending_outbox_row":
                    raise AttributeError(name)
                return getattr(mem, name)

            def cancel_outbox_row(self, mid: str, *, reason: str) -> None:
                cancel_fallback_calls.append(mid)
                mem.cancel_outbox_row(mid, reason=reason)

        min_dir = self.state_dir.parent / "min_state"
        min_dir.mkdir(mode=0o700, exist_ok=True)
        hub_min = CoordHub(_MinimalStore(), transport, min_dir, sandbox_root=self.sandbox_root)  # type: ignore[arg-type]
        self.addCleanup(hub_min.close)
        hub_min._cancel_if_still_pending(msg_id, reason="stale_minimal")
        self.assertEqual(cancel_fallback_calls, [])
        self.assertEqual(mem.outbox[msg_id]["status"], "dispatch_started")

    def test_oc3_p1_2_stream_reader_start_failure_fences_and_cleans_up_handed_off_turn(
        self,
    ) -> None:
        owner = ExternallyFencedFakeTransport({("sb-st", "inc_st1"): _OWNER_A})
        reg, hub = self._open_hub(owner)
        self._reg_and_grant(hub, "sb-st", "inc_st1")
        msg_id = hub.send(_OP, target="sb-st", body_text="Reader thread start fails")["msg_id"]

        # Fail physical confirm once so cleanup obligation stays retained until explicit drain,
        # and fail threading.Thread.start once for the async stream reader.
        owner.fail_confirm_keys.add(("sb-st", "inc_st1"))
        orig_start = threading.Thread.start
        failed_once = {"done": False}

        def _fail_first_thread_start(thread_self: threading.Thread) -> None:
            if not failed_once["done"]:
                failed_once["done"] = True
                raise RuntimeError("cannot_start_reader_thread")
            orig_start(thread_self)

        with mock.patch.object(threading.Thread, "start", _fail_first_thread_start):
            self.assertEqual(hub.dispatch_once(async_stream=True), 1)

        self.assertTrue(hub.is_degraded)
        self.assertIn(("sb-st", "inc_st1"), hub._fenced_targets)
        self.assertIn(("sb-st", "inc_st1"), hub._pending_cleanup_incarnations)
        self.assertEqual(len(hub.dispatcher._stream_threads), 0)
        row_before = {r["msg_id"]: r for r in reg.list_outbox(statuses=_STATUS_ALL)}[msg_id]
        self.assertEqual(row_before["status"], "handed_off")
        self.assertEqual(row_before["attempts"], 1)

        # Allow physical confirm before shutdown, close cleanly, reopen degraded, and recover without replay.
        owner.fail_confirm_keys.discard(("sb-st", "inc_st1"))
        hub.close()
        reg.close()
        self.assertTrue(
            any(c[0] == "sb-st" and c[1] == "inc_st1" and c[2] == _OWNER_A for c in owner.confirm_calls)
        )
        reg2, hub2 = self._open_hub(owner)
        self.addCleanup(reg2.close)
        self.addCleanup(hub2.close)
        self.assertTrue(hub2.is_degraded)
        calls_before = len(owner.dispatch_calls)
        hub2.confirm_recovery(_OP, reason="recover_stream_start_failure")
        self.assertEqual(hub2.dispatch_once(async_stream=False), 0)
        self.assertEqual(len(owner.dispatch_calls), calls_before)
        row_after = {r["msg_id"]: r for r in reg2.list_outbox(statuses=_STATUS_ALL)}[msg_id]
        self.assertEqual(row_after["status"], "aborted")
        self.assertEqual(row_after["attempts"], 1)

    def test_oc3_p2_1_failed_terminal_outbox_write_marks_degraded_and_recovers_on_reopen(
        self,
    ) -> None:
        owner = ExternallyFencedFakeTransport({("sb-fw", "inc_fw1"): _OWNER_A})
        reg, hub = self._open_hub(owner)
        self._reg_and_grant(hub, "sb-fw", "inc_fw1")
        msg_id = hub.send(_OP, target="sb-fw", body_text="Terminal write fails")["msg_id"]

        orig_complete = reg.mark_outbox_completed

        def _fail_complete(mid: str) -> None:
            raise sqlite3.OperationalError("transient_terminal_write_failure")

        reg.mark_outbox_completed = _fail_complete  # type: ignore[method-assign]
        try:
            self.assertEqual(hub.dispatch_once(async_stream=False), 1)
        finally:
            reg.mark_outbox_completed = orig_complete  # type: ignore[method-assign]

        self.assertTrue(hub.is_degraded)
        row_mid = {r["msg_id"]: r for r in reg.list_outbox(statuses=_STATUS_ALL)}[msg_id]
        self.assertEqual(row_mid["status"], "handed_off")
        hub.close()
        reg.close()

        # Reopen MUST detect the retained session seal, enter recovery, and settle the orphan.
        reg2, hub2 = self._open_hub(owner)
        self.addCleanup(reg2.close)
        self.addCleanup(hub2.close)
        self.assertTrue(hub2.is_degraded)
        hub2.confirm_recovery(_OP, reason="settle_failed_terminal_write")
        self.assertFalse(hub2.is_degraded)
        row_after = {r["msg_id"]: r for r in reg2.list_outbox(statuses=_STATUS_ALL)}[msg_id]
        self.assertEqual(row_after["status"], "aborted")
        self.assertEqual(row_after["attempts"], 1)

    def test_oc3_p2_2_recovery_fails_closed_when_minimal_store_cannot_settle_open_handoff(
        self,
    ) -> None:
        from test_hub import InMemoryRegistryStore

        # Case A: minimal store omitting both abort_handed_off_outbox_row_if_open and mark_outbox_aborted.
        mem_a = InMemoryRegistryStore()
        transport = FakeWorkerTransport()

        class _NoAbortStore:
            def __getattr__(self, name: str) -> Any:
                if name in ("abort_handed_off_outbox_row_if_open", "mark_outbox_aborted"):
                    raise AttributeError(name)
                return getattr(mem_a, name)

        dir_a = self.state_dir.parent / "min_rec_a"
        dir_a.mkdir(mode=0o700, exist_ok=True)
        hub_a = CoordHub(_NoAbortStore(), transport, dir_a, sandbox_root=self.sandbox_root)  # type: ignore[arg-type]
        self.addCleanup(hub_a.close)
        edge_a = self._reg_and_grant(hub_a, "sb-ma", "inc_ma1")
        msg_a = hub_a.send(_OP, target="sb-ma", body_text="Open handoff no abort")["msg_id"]
        mem_a.mark_outbox_dispatch_started(
            msg_a, edge_id=edge_a, grant_generation=mem_a.edges[edge_a].grant_generation, dst_incarnation="inc_ma1"
        )
        mem_a.mark_outbox_handed_off(msg_a, stream_id="str-ma-1")
        hub_a._mark_degraded("sim_crash_a")
        with self.assertRaises(CoordPolicyError):
            hub_a.confirm_recovery(_OP, reason="recover_no_abort")
        self.assertTrue(hub_a.is_degraded)

        # Case B: legacy store raising CoordValidationError without transitioning the row out of handed_off.
        mem_b = InMemoryRegistryStore()

        class _SpuriousRejectStore:
            def __getattr__(self, name: str) -> Any:
                if name == "abort_handed_off_outbox_row_if_open":
                    raise AttributeError(name)
                return getattr(mem_b, name)

            def mark_outbox_aborted(self, mid: str, *, reason: str = "x") -> None:
                raise CoordValidationError("spurious_reject_leaves_handed_off")

        dir_b = self.state_dir.parent / "min_rec_b"
        dir_b.mkdir(mode=0o700, exist_ok=True)
        hub_b = CoordHub(_SpuriousRejectStore(), transport, dir_b, sandbox_root=self.sandbox_root)  # type: ignore[arg-type]
        self.addCleanup(hub_b.close)
        edge_b = self._reg_and_grant(hub_b, "sb-mb", "inc_mb1")
        msg_b = hub_b.send(_OP, target="sb-mb", body_text="Open handoff spurious reject")["msg_id"]
        mem_b.mark_outbox_dispatch_started(
            msg_b, edge_id=edge_b, grant_generation=mem_b.edges[edge_b].grant_generation, dst_incarnation="inc_mb1"
        )
        mem_b.mark_outbox_handed_off(msg_b, stream_id="str-mb-1")
        hub_b._mark_degraded("sim_crash_b")
        with self.assertRaises(CoordPolicyError):
            hub_b.confirm_recovery(_OP, reason="recover_spurious_reject")
        self.assertTrue(hub_b.is_degraded)

    def test_oc4_p1_1_inflight_handoff_retains_owner_cache_across_revoke_and_binding_outage(
        self,
    ) -> None:
        owner = ExternallyFencedFakeTransport({("sb-inf", "inc_inf1"): _OWNER_A})
        reg, hub = self._open_hub(owner)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_and_grant(hub, "sb-inf", "inc_inf1")
        hub.send(_OP, target="sb-inf", body_text="Inflight handoff across revoke + outage")

        entered_p2 = threading.Event()
        release_p2 = threading.Event()
        self.addCleanup(release_p2.set)

        def _pause_p2(_mid: str, _res: Any) -> None:
            entered_p2.set()
            release_p2.wait(timeout=2.0)

        hub._on_post_receipt_hook = _pause_p2
        t = threading.Thread(target=hub.dispatch_once, kwargs={"async_stream": False})
        t.start()
        self.assertTrue(entered_p2.wait(timeout=1.0))

        # Revoke completes while dispatch is still paused in Phase 2 (no pending stream yet).
        hub.revoke(_OP, target="sb-inf", reason="revoke_while_inflight")
        self.assertEqual(len(owner.confirm_calls), 1)
        self.assertIn(("sb-inf", "inc_inf1"), hub._external_owners)

        # Now binding reads fail with a DB outage when the late HANDED_OFF receipt settles.
        orig_get = reg.get_transport_binding

        def _binding_outage(sb_addr: str, inc_id: str) -> dict[str, Any] | None:
            raise sqlite3.OperationalError("binding_read_outage_post_revoke")

        reg.get_transport_binding = _binding_outage  # type: ignore[method-assign]
        try:
            release_p2.set()
            t.join(timeout=2.0)
            self.assertFalse(t.is_alive())
            self.assertGreaterEqual(len(owner.confirm_calls), 2)
            self.assertEqual(owner.confirm_calls[-1][:3], ("sb-inf", "inc_inf1", _OWNER_A))
        finally:
            reg.get_transport_binding = orig_get  # type: ignore[method-assign]
            hub._on_post_receipt_hook = None

        self.assertTrue(hub._drain_pending_cleanups())
        self.assertNotIn(("sb-inf", "inc_inf1"), hub._external_owners)

    def test_oc4_p2_1_async_dispatch_applies_immediate_abort_before_reader_enters(self) -> None:
        owner = ExternallyFencedFakeTransport({("sb-ord", "inc_ord1"): _OWNER_A})
        reg, hub = self._open_hub(owner)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_and_grant(hub, "sb-ord", "inc_ord1")
        msg_id = hub.send(_OP, target="sb-ord", body_text="Abort before async reader")["msg_id"]

        entered_p2 = threading.Event()
        release_p2 = threading.Event()
        self.addCleanup(release_p2.set)
        order: list[str] = []
        orig_confirm = owner.confirm_incarnation_terminal
        orig_stream = owner.stream_events

        def _trace_confirm(
            sb_addr: str, inc_id: str, *, owner_id: str, reason: str
        ) -> bool:
            order.append("abort")
            return orig_confirm(sb_addr, inc_id, owner_id=owner_id, reason=reason)

        def _trace_stream(stream_id: str) -> Any:
            order.append("stream_events")
            return orig_stream(stream_id)

        def _pause_p2(_mid: str, _res: Any) -> None:
            entered_p2.set()
            release_p2.wait(timeout=2.0)

        owner.confirm_incarnation_terminal = _trace_confirm  # type: ignore[method-assign]
        owner.stream_events = _trace_stream  # type: ignore[method-assign]
        hub._on_post_receipt_hook = _pause_p2
        t = threading.Thread(target=hub.dispatch_once, kwargs={"async_stream": True})
        t.start()
        self.assertTrue(entered_p2.wait(timeout=1.0))
        hub.revoke(_OP, target="sb-ord", reason="revoke_before_async_reader")
        order.clear()
        # Hold the immediate post-receipt abort unconfirmed so the stream enters _pending_cleanup_streams;
        # the fenced async reader MUST STILL NOT enter stream_events(), while cleanup retries settle it.
        owner.fail_confirm_keys.add(("sb-ord", "inc_ord1"))
        release_p2.set()
        t.join(timeout=2.0)
        self.assertFalse(t.is_alive())
        hub._on_post_receipt_hook = None
        hub.dispatcher.join_streams(time.monotonic() + 2.0)

        self.assertIn("abort", order)
        self.assertNotIn("stream_events", order)
        self.assertTrue(hub._has_pending_cleanups())
        row = {r["msg_id"]: r for r in reg.list_outbox(statuses=_STATUS_ALL)}[msg_id]
        self.assertEqual(row["status"], "aborted")

        # Release physical confirmation and verify the background cleanup worker settles the obligation.
        owner.fail_confirm_keys.discard(("sb-ord", "inc_ord1"))
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and hub._has_pending_cleanups():
            time.sleep(0.02)
        self.assertFalse(hub._has_pending_cleanups())
        self.assertNotIn("stream_events", order)

    def test_oc4_p2_2_phase3_exception_schedules_cleanup_worker_before_recovery_or_close(
        self,
    ) -> None:
        owner = ExternallyFencedFakeTransport({("sb-p3", "inc_p3_1"): _OWNER_A})
        reg, hub = self._open_hub(owner)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_and_grant(hub, "sb-p3", "inc_p3_1")
        hub.send(_OP, target="sb-p3", body_text="Phase 3 persistence exception")

        orig_dispatch = owner.dispatch_turn
        orig_uncertain = reg.mark_outbox_uncertain

        def _raise_dispatch(turn: Any) -> Any:
            raise RuntimeError("phase2_transport_boom")

        def _raise_uncertain(msg_id: str, *, detail: str) -> None:
            raise sqlite3.OperationalError("phase3_uncertain_persist_boom")

        owner.dispatch_turn = _raise_dispatch  # type: ignore[method-assign]
        reg.mark_outbox_uncertain = _raise_uncertain  # type: ignore[method-assign]
        try:
            with self.assertRaises(sqlite3.OperationalError):
                hub.dispatch_once(async_stream=False)
        finally:
            owner.dispatch_turn = orig_dispatch  # type: ignore[method-assign]
            reg.mark_outbox_uncertain = orig_uncertain  # type: ignore[method-assign]

        # Background cleanup retry worker MUST be scheduled and perform exact-owner confirmation
        # BEFORE any explicit confirm_recovery() or close() call.
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and not owner.confirm_calls:
            time.sleep(0.02)
        self.assertTrue(
            any(c[0] == "sb-p3" and c[1] == "inc_p3_1" and c[2] == _OWNER_A for c in owner.confirm_calls)
        )


if __name__ == "__main__":
    unittest.main()
