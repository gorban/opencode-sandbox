"""Exercise the offline controller against a bounded, synthetic effect journal."""
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, asdict, replace
from enum import Enum, auto
from hashlib import sha256
import json
from threading import Barrier
import unittest

from oc_controller import (
    Attempt, Capability, CapacityExceeded, Conflict, Controller, Decision, Denied,
    Intent, InvalidRequest, Job, Operation, Outcome, Principal, ProbeResult,
    Proposal, Reason, Reference, Role, State, Subject, Worker,
)


OPERATOR = Principal(Role.OPERATOR, "operator-session")
OTHER_OPERATOR = Principal(Role.OPERATOR, "other-session")
SAME_NAME_OPERATOR = Principal(Role.OPERATOR, "channel-one")
ORCHESTRATOR = Principal(Role.ORCHESTRATOR, "orchestrator-one")
OTHER_ORCHESTRATOR = Principal(Role.ORCHESTRATOR, "orchestrator-two")
WORKER_HOST = Principal(Role.WORKER_HOST, "worker-one")
SUBJECT = Subject("worker-one", "job-one", "channel-one")
SIBLING = Subject("worker-one", "job-two", "channel-two")
REENROLLED = Subject("worker-two", "job-one", "channel-three")
JOB = Principal(Role.JOB, SUBJECT.channel)
SIBLING_JOB = Principal(Role.JOB, SIBLING.channel)
REENROLLED_JOB = Principal(Role.JOB, REENROLLED.channel)

PROBE = Proposal(Intent.PROBE_GRANT, "alias-one", "probe-ref")
APPLY = Proposal(Intent.APPLY_ONCE, "alias-one", "apply-ref")
EQUIVALENT = replace(APPLY, alias="alias-two")


class Fault(Enum):
    LOST_APPLIED_REPLY = auto()
    LOST_ABSENT_REPLY = auto()
    TIMEOUT_UNKNOWN = auto()


class Clock:
    def __init__(self):
        self.ticks = 10
        self.failures = deque()

    def __call__(self):
        if self.failures and self.failures.popleft():
            raise RuntimeError("synthetic private clock diagnostic")
        return self.ticks


class Adapter:
    """A journal entry is the synthetic effect or definitive proof of absence."""

    def __init__(self):
        self.revisions = {"target-one": "rev-one"}
        self.reads = 0
        self.attempts = []
        self.journal = {}
        self.reconciliations = []
        self.outcomes = deque()
        self.lookup_failures = deque()
        self.fail_reconciliation = False

    def target_revision(self, target):
        self.reads += 1
        if self.lookup_failures and self.lookup_failures.popleft():
            raise RuntimeError("synthetic private target diagnostic")
        return self.revisions.get(target)

    def set_target_revision(self, target, revision):
        self.revisions[target] = revision

    def dispatch(self, attempt, payload):
        self.attempts.append((attempt, payload.pin))
        if self.revisions.get(payload.pin.target) != payload.pin.revision:
            return Outcome.DEFINITE_FAILURE
        if type(payload.operation) is not Operation:
            return Outcome.DEFINITE_FAILURE
        if payload.operation is Operation.APPLY and attempt in self.journal:
            recorded_payload, outcome = self.journal[attempt]
            return outcome if recorded_payload == payload else Outcome.UNKNOWN
        outcome = self.outcomes.popleft() if self.outcomes else Outcome.SUCCEEDED
        if outcome is Fault.TIMEOUT_UNKNOWN:
            raise TimeoutError("synthetic private diagnostic")
        if outcome in (Fault.LOST_APPLIED_REPLY, Fault.LOST_ABSENT_REPLY):
            recorded = (
                Outcome.SUCCEEDED
                if outcome is Fault.LOST_APPLIED_REPLY
                else Outcome.DEFINITE_FAILURE
            )
            if payload.operation is Operation.APPLY:
                self.journal[attempt] = (payload, recorded)
            raise TimeoutError("synthetic private diagnostic")
        if payload.operation is Operation.APPLY and outcome in (
            Outcome.SUCCEEDED, Outcome.DEFINITE_FAILURE
        ):
            self.journal[attempt] = (payload, outcome)
        return outcome

    def reconcile(self, attempt, payload):
        self.reconciliations.append(attempt)
        if self.fail_reconciliation:
            raise ValueError("synthetic private diagnostic")
        recorded_payload, outcome = self.journal.get(attempt, (None, Outcome.UNKNOWN))
        return outcome if recorded_payload == payload else Outcome.UNKNOWN

    def effects(self):
        return {attempt for attempt, (_, result) in self.journal.items()
                if result is Outcome.SUCCEEDED}


class ControllerTest(unittest.TestCase):
    def make_controller(self, *, incarnation="a" * 32, budget=12, jobs=None, workers=None):
        self.clock = Clock()
        self.adapter = Adapter()
        defaults = (
            Job(SUBJECT, ORCHESTRATOR, budget),
            Job(SIBLING, OTHER_ORCHESTRATOR, budget),
            Job(REENROLLED, OTHER_ORCHESTRATOR, budget),
        )
        controller = Controller(
            incarnation=incarnation,
            clock=self.clock,
            lifetime=5,
            workers=(
                Worker(SUBJECT.worker_enrollment, OPERATOR),
                Worker(REENROLLED.worker_enrollment, OTHER_OPERATOR),
            ) if workers is None else workers,
            jobs=defaults if jobs is None else jobs,
            capabilities=(
                Capability("probe-cap", Operation.PROBE, "target-one"),
                Capability("apply-cap", Operation.APPLY, "target-one"),
            ),
            references=(Reference("probe-ref", "probe-cap"), Reference("apply-ref", "apply-cap")),
            adapter=self.adapter,
        )
        controller._set_alias("alias-one", "target-one")
        controller._set_alias("alias-two", "target-one")
        controller._set_alias("alias-two", "target-one")
        return controller

    def setUp(self):
        self.core = self.make_controller()

    def propose(self, proposal=PROBE, actor=JOB):
        return self.core.propose(actor, proposal).request_id

    def decision_args(self, request_id, operator=OPERATOR):
        view = self.core.view(operator, request_id)
        return request_id, view.payload.revision, view.digest

    def approve(self, request_id, operator=OPERATOR):
        return self.core.decide(operator, *self.decision_args(request_id, operator), Decision.APPROVE)

    def test_exact_authority_matrix(self):
        request_id = self.propose()
        decision_args = self.decision_args(request_id)
        aliases = (
            Principal(Role.JOB, "worker-one"),
            Principal(Role.WORKER_HOST, SUBJECT.channel),
            Principal(Role.OPERATOR, "operator-session-copy"),
            SAME_NAME_OPERATOR,
            Principal("operator", OPERATOR.identifier),
            Principal(Role.JOB, ["channel-one"]),
        )
        for actor in (ORCHESTRATOR, OTHER_ORCHESTRATOR, WORKER_HOST, OPERATOR,
                      OTHER_OPERATOR, *aliases):
            with self.subTest(actor=actor), self.assertRaises(Denied):
                self.core.propose(actor, PROBE)

        owned_operator_ops = (
            lambda actor: self.core.view(actor, request_id),
            lambda actor: self.core.decide(actor, *decision_args, Decision.APPROVE),
            lambda actor: self.core.revoke(actor, request_id),
            lambda actor: self.core.revoke_worker(actor, SUBJECT.worker_enrollment),
        )
        for actor in (ORCHESTRATOR, OTHER_ORCHESTRATOR, WORKER_HOST, JOB, SIBLING_JOB,
                      REENROLLED_JOB, OTHER_OPERATOR, *aliases):
            for operation in owned_operator_ops:
                with self.subTest(actor=actor), self.assertRaises(Denied):
                    operation(actor)

        for actor in (ORCHESTRATOR, OTHER_ORCHESTRATOR, WORKER_HOST, OPERATOR, OTHER_OPERATOR,
                      SIBLING_JOB, REENROLLED_JOB, *aliases):
            with self.subTest(actor=actor), self.assertRaises(Denied):
                self.core.invoke(actor, request_id)

        for actor in (OTHER_ORCHESTRATOR, WORKER_HOST, OTHER_OPERATOR, SIBLING_JOB,
                      REENROLLED_JOB, *aliases):
            with self.subTest(actor=actor), self.assertRaises(Denied):
                self.core.status(actor, request_id)
            with self.subTest(actor=actor), self.assertRaises(Denied):
                self.core.events(actor, SUBJECT)

        for actor in (OPERATOR, ORCHESTRATOR, JOB):
            self.assertEqual(self.core.status(actor, request_id).state, State.PENDING)
            self.assertEqual(len(self.core.events(actor, SUBJECT)), 1)
        self.assertEqual(self.core.events(SIBLING_JOB, SIBLING), ())
        self.assertEqual(self.adapter.attempts, [])

    def test_fixture_rejects_ambiguous_ownership(self):
        with self.assertRaises(ValueError):
            self.make_controller(workers=(
                Worker(SUBJECT.worker_enrollment, OPERATOR),
                Worker(SUBJECT.worker_enrollment, OTHER_OPERATOR),
            ))
        with self.assertRaises(ValueError):
            self.make_controller(jobs=(
                Job(SUBJECT, ORCHESTRATOR, 1),
                Job(replace(SIBLING, channel=SUBJECT.channel), OTHER_ORCHESTRATOR, 1),
            ))
        with self.assertRaises(ValueError):
            self.make_controller(jobs=(
                Job(SUBJECT, ORCHESTRATOR, 1),
                Job(replace(SUBJECT, channel=SIBLING.channel), OTHER_ORCHESTRATOR, 1),
            ))
        for job in (Job(SUBJECT, WORKER_HOST, 1), Job(SUBJECT, ORCHESTRATOR, True)):
            with self.subTest(job=job), self.assertRaises(ValueError):
                self.make_controller(jobs=(job,))

    def test_canonical_payload_and_projection(self):
        request_id = self.propose()
        view = self.core.view(OPERATOR, request_id)
        self.assertEqual(
            asdict(view.payload), {
                "format_version": 1, "incarnation": "a" * 32, "request_id": request_id,
                "revision": 1, "subject": asdict(SUBJECT), "operator_session": OPERATOR.identifier,
                "intent": Intent.PROBE_GRANT, "operation": Operation.PROBE, "alias": PROBE.alias,
                "pin": {"target": "target-one", "revision": "rev-one", "alias_generation": 1},
                "scope": "fixture:probe", "reference": "probe-ref", "capability": "probe-cap",
                "expires_at": 15,
            },
        )
        encoded = json.dumps(asdict(view.payload), sort_keys=True, separators=(",", ":"))
        self.assertEqual(view.digest, sha256(encoded.encode()).hexdigest())
        with self.assertRaises(FrozenInstanceError):
            view.payload.pin.revision = "different"
        newer = self.core.view(OPERATOR, request_id)
        self.assertIsNot(newer.payload, view.payload)
        self.assertIsNot(newer.payload.pin, view.payload.pin)
        self.assertIsNot(newer.payload.subject, view.payload.subject)

        self.assertTrue(self.approve(request_id).eligible)
        result = self.core.invoke(JOB, request_id)
        self.assertEqual((result.state, result.probe_result), (State.SUCCEEDED, ProbeResult.OK))
        self.assertFalse(result.eligible)
        audit = self.core.events(ORCHESTRATOR, SUBJECT)
        self.assertEqual([e.status.reason for e in audit],
                         [Reason.APPROVAL_NEEDED, Reason.APPROVED, Reason.SUCCEEDED])
        self.assertEqual([e.status.eligible for e in audit], [False, True, False])
        for private in (view.digest, PROBE.alias, "probe-ref", "probe-cap", "channel-one"):
            self.assertNotIn(private, repr(audit))
        self.assertTrue(all(e.status.probe_result is None for e in audit))
        with self.assertRaises(FrozenInstanceError):
            audit[0].status.state = State.FAILED
        with self.assertRaises(Conflict):
            self.core.invoke(JOB, request_id)

    def test_closed_proposal_and_decision_inputs(self):
        for invalid in (
            {"intent": Intent.PROBE_GRANT, "alias": "alias-one", "reference": "probe-ref"},
            replace(PROBE, intent="probe_grant"), replace(PROBE, alias="/etc/no"),
            replace(PROBE, alias="x" * 65), replace(PROBE, reference=["probe-ref"]),
            replace(PROBE, alias="missing"), replace(PROBE, reference="missing"),
            replace(PROBE, reference="apply-ref"),
        ):
            with self.subTest(invalid=invalid), self.assertRaises(InvalidRequest):
                self.core.propose(JOB, invalid)
        self.assertEqual(self.core.events(JOB, SUBJECT), ())
        request_id = self.propose()
        _, revision, digest = self.decision_args(request_id)
        self.clock.ticks = 15
        for bad_revision, bad_digest, bad_decision in (
            (True, digest, Decision.APPROVE), (2, digest, Decision.APPROVE),
            (10**200, digest, Decision.APPROVE), (revision, digest.upper(), Decision.APPROVE),
            (revision, ["a" * 64], Decision.APPROVE), (revision, "0" * 64, Decision.REJECT),
            (revision, "x" * 1000, Decision.REJECT), (revision, digest, "approve"),
        ):
            with self.subTest(bad_revision=bad_revision, bad_decision=bad_decision):
                with self.assertRaises(InvalidRequest):
                    self.core.decide(OPERATOR, request_id, bad_revision, bad_digest, bad_decision)
        for bad_id in ([request_id], request_id + "0", 1, "0" * 64):
            with self.subTest(bad_id=bad_id), self.assertRaises(Denied):
                self.core.status(JOB, bad_id)
        self.assertEqual(self.core.status(JOB, request_id).state, State.PENDING)
        self.assertEqual(len(self.core.events(JOB, SUBJECT)), 1)
        self.assertEqual(self.approve(request_id).state, State.EXPIRED)

    def test_rejection_and_repeat_decision(self):
        request_id = self.propose(APPLY)
        args = self.decision_args(request_id)
        result = self.core.decide(OPERATOR, *args, Decision.REJECT)
        self.assertEqual((result.state, result.eligible), (State.REJECTED, False))
        for decision in (Decision.REJECT, Decision.APPROVE):
            with self.assertRaises(Conflict):
                self.core.decide(OPERATOR, *args, decision)
        with self.assertRaises(Conflict):
            self.core.invoke(JOB, request_id)
        self.assertEqual(len(self.core.events(JOB, SUBJECT)), 2)
        self.assertEqual(self.adapter.attempts, [])

    def test_exclusive_expiry_and_read_only_projection(self):
        approved = self.propose()
        pending = self.propose()
        self.approve(approved)
        self.clock.ticks = 15
        for request_id, state in ((approved, State.APPROVED), (pending, State.PENDING)):
            status = self.core.status(ORCHESTRATOR, request_id)
            self.assertEqual((status.state, status.reason, status.eligible),
                             (state, Reason.EXPIRED, False))
        self.assertEqual(len(self.core.events(JOB, SUBJECT)), 3)
        self.assertEqual(self.core.invoke(JOB, approved).state, State.EXPIRED)
        self.assertEqual(self.approve(pending).state, State.EXPIRED)
        self.assertEqual(self.adapter.attempts, [])

    def test_alias_generation_and_pin_rechecked(self):
        before_decision = self.propose(APPLY)
        args = self.decision_args(before_decision)
        self.core._set_alias("alias-one", None)
        self.core._set_alias("alias-one", "target-one")
        self.assertEqual(self.core.decide(OPERATOR, *args, Decision.APPROVE).state, State.STALE)

        before_dispatch = self.propose(APPLY)
        self.approve(before_dispatch)
        self.core._set_alias("alias-one", "target-one")
        self.assertEqual(self.core.invoke(JOB, before_dispatch).state, State.STALE)

        for revision in ("rev-two", None):
            request_id = self.propose(APPLY)
            self.approve(request_id)
            self.core._set_target_revision("target-one", revision)
            self.assertEqual(self.core.status(JOB, request_id).reason, Reason.STALE)
            self.assertEqual(self.core.invoke(JOB, request_id).state, State.STALE)
            self.core._set_target_revision("target-one", "rev-one")
        restored = self.propose(APPLY)
        self.approve(restored)
        self.core._set_target_revision("target-one", "rev-two")
        self.core._set_target_revision("target-one", "rev-one")
        self.assertEqual(self.core.invoke(JOB, restored).state, State.STALE)
        self.assertEqual(self.adapter.attempts, [])

    def test_withdrawn_binding_and_new_incarnation(self):
        approved = self.propose(APPLY)
        pending = self.propose(APPLY)
        stale_args = self.decision_args(pending)
        self.approve(approved)
        self.core._withdraw_capability("apply-cap")
        self.core._withdraw_capability("apply-cap")
        self.assertEqual(self.core.invoke(JOB, approved).state, State.STALE)
        self.assertEqual(self.approve(pending).state, State.STALE)
        with self.assertRaises(InvalidRequest):
            self.propose(APPLY)
        self.assertEqual(self.adapter.attempts, [])

        self.core = self.make_controller(incarnation="b" * 32)
        fresh = self.propose(APPLY)
        self.assertNotEqual(fresh, approved)
        with self.assertRaises(Denied):
            self.core.invoke(JOB, approved)
        with self.assertRaises(Denied):
            self.core.decide(OPERATOR, *stale_args, Decision.APPROVE)
        _, prior_revision, prior_digest = stale_args
        with self.assertRaises(InvalidRequest):
            self.core.decide(OPERATOR, fresh, prior_revision, prior_digest, Decision.APPROVE)
        self.assertEqual(self.approve(fresh).state, State.APPROVED)

    def test_revocation_is_exact_and_idempotent(self):
        active = self.propose()
        pending = self.propose(actor=SIBLING_JOB)
        new_enrollment = self.propose(actor=REENROLLED_JOB)
        self.approve(active)
        self.approve(new_enrollment, OTHER_OPERATOR)
        self.core.revoke(OPERATOR, pending)
        self.core.revoke(OPERATOR, pending)
        self.assertEqual(len(self.core.events(SIBLING_JOB, SIBLING)), 2)
        self.core.revoke_worker(OPERATOR, SUBJECT.worker_enrollment)
        self.core.revoke_worker(OPERATOR, SUBJECT.worker_enrollment)
        self.assertEqual(len(self.core.events(SIBLING_JOB, SIBLING)), 2)
        self.assertEqual(len(self.core.events(JOB, SUBJECT)), 3)
        self.assertEqual(self.core.status(JOB, active).state, State.APPROVED)
        self.assertTrue(self.core.status(JOB, active).revoked)
        self.assertEqual(self.core.events(JOB, SUBJECT)[-1].status.reason, Reason.REVOKED)
        with self.assertRaises(Conflict):
            self.approve(pending)
        with self.assertRaises(Conflict):
            self.core.invoke(JOB, active)
        self.assertTrue(self.core.status(REENROLLED_JOB, new_enrollment).eligible)
        self.assertEqual(self.core.invoke(REENROLLED_JOB, new_enrollment).state, State.SUCCEEDED)

    def test_unavailable_liveness_keeps_decision_pending_and_scoped(self):
        for source in ("clock", "target"):
            with self.subTest(source=source):
                self.core = self.make_controller()
                request_id = self.propose()
                args = self.decision_args(request_id)
                failures = (self.clock.failures if source == "clock"
                            else self.adapter.lookup_failures)
                failures.extend((True, True))
                result = self.core.decide(OPERATOR, *args, Decision.APPROVE)
                self.assertEqual((result.state, result.reason, result.eligible),
                                 (State.PENDING, Reason.UNAVAILABLE, False))
                with self.assertRaises(Denied):
                    self.core.status(SIBLING_JOB, request_id)
                self.assertEqual(self.core.status(ORCHESTRATOR, request_id).reason,
                                 Reason.UNAVAILABLE)
                self.assertEqual(len(self.core.events(JOB, SUBJECT)), 1)
                self.assertEqual(self.core.events(SIBLING_JOB, SIBLING), ())
                with self.assertRaises(Conflict):
                    self.core.invoke(JOB, request_id)
                self.assertEqual(self.adapter.attempts, [])
                self.assertTrue(self.core.decide(OPERATOR, *args, Decision.APPROVE).eligible)

    def test_approval_audit_reuses_checked_liveness(self):
        for source in ("clock", "target"):
            with self.subTest(source=source):
                self.core = self.make_controller()
                request_id = self.propose()
                args = self.decision_args(request_id)
                failures = (self.clock.failures if source == "clock"
                            else self.adapter.lookup_failures)
                failures.extend((False, True))
                result = self.core.decide(OPERATOR, *args, Decision.APPROVE)
                self.assertTrue(result.eligible)
                audit = self.core.events(JOB, SUBJECT)
                self.assertEqual([event.status.reason for event in audit],
                                 [Reason.APPROVAL_NEEDED, Reason.APPROVED])
                self.assertTrue(audit[-1].status.eligible)
                # The next read fails independently without changing the audited decision.
                status = self.core.status(ORCHESTRATOR, request_id)
                self.assertEqual((status.state, status.reason, status.eligible),
                                 (State.APPROVED, Reason.UNAVAILABLE, False))
                self.assertEqual(self.core.events(JOB, SUBJECT), audit)

    def test_unavailable_post_attempt_check_audits_terminal_result(self):
        for source in ("clock", "target"):
            with self.subTest(source=source):
                self.core = self.make_controller()
                request_id = self.propose()
                self.approve(request_id)
                failures = (self.clock.failures if source == "clock"
                            else self.adapter.lookup_failures)
                failures.extend((False, True))
                self.adapter.outcomes.append(Outcome.TRANSIENT_FAILURE)
                result = self.core.invoke(JOB, request_id)
                self.assertEqual((result.state, result.reason, result.eligible),
                                 (State.FAILED, Reason.UNAVAILABLE, False))
                audit = self.core.events(ORCHESTRATOR, SUBJECT)
                self.assertEqual(audit[-1].status, result)
                self.assertNotIn("private", repr(audit))
                with self.assertRaises(Conflict):
                    self.core.invoke(JOB, request_id)
                self.assertEqual([attempt.number for attempt, _ in self.adapter.attempts], [1])

    def test_revoke_blocks_dispatch_when_clock_is_unavailable(self):
        request_id = self.propose(APPLY)
        self.approve(request_id)
        self.clock.failures.append(True)
        self.core.revoke_worker(OPERATOR, SUBJECT.worker_enrollment)
        result = self.core.status(JOB, request_id)
        self.assertEqual((result.state, result.revoked, result.eligible),
                         (State.APPROVED, True, False))
        self.assertEqual(self.core.events(JOB, SUBJECT)[-1].status.reason, Reason.REVOKED)
        with self.assertRaises(Conflict):
            self.core.invoke(JOB, request_id)
        self.assertEqual(self.adapter.attempts, [])

    def test_probe_reply_faults_leave_effect_journal_empty(self):
        for fault in Fault:
            with self.subTest(fault=fault):
                self.core = self.make_controller()
                request_id = self.propose()
                self.approve(request_id)
                self.adapter.outcomes.append(fault)
                self.assertEqual(self.core.invoke(JOB, request_id).state, State.ELIGIBLE_RETRY)
                self.assertEqual(self.adapter.journal, {})
                self.assertEqual(self.core.invoke(JOB, request_id).probe_result, ProbeResult.OK)
                self.assertEqual(self.adapter.journal, {})

    def test_probe_retry_budget_and_expiry(self):
        request_id = self.propose()
        self.approve(request_id)
        self.adapter.outcomes.extend(
            (Outcome.TRANSIENT_FAILURE, Fault.TIMEOUT_UNKNOWN, Outcome.UNKNOWN)
        )
        self.assertEqual(self.core.invoke(JOB, request_id).state, State.ELIGIBLE_RETRY)
        self.assertTrue(self.core.invoke(JOB, request_id).eligible)
        result = self.core.invoke(JOB, request_id)
        self.assertEqual((result.state, result.reason, result.eligible),
                         (State.FAILED, Reason.ATTEMPTS_EXHAUSTED, False))
        self.assertFalse(self.core.events(JOB, SUBJECT)[-1].status.eligible)
        self.assertNotIn("private diagnostic", repr(self.core.events(JOB, SUBJECT)))
        self.assertEqual([attempt.number for attempt, _ in self.adapter.attempts], [1, 2, 3])
        with self.assertRaises(Conflict):
            self.core.invoke(JOB, request_id)

        expiring = self.propose()
        self.approve(expiring)
        self.adapter.outcomes.append(Outcome.TRANSIENT_FAILURE)
        self.core.invoke(JOB, expiring)
        self.clock.ticks = 15
        self.assertFalse(self.core.status(JOB, expiring).eligible)
        self.assertEqual(self.core.invoke(JOB, expiring).state, State.EXPIRED)
        self.assertEqual(len(self.adapter.attempts), 4)

    def test_uncertain_effect_fences_equivalent_jobs_aliases_and_revisions(self):
        for revoke_all, fault, terminal in (
            (False, Fault.LOST_APPLIED_REPLY, State.SUCCEEDED),
            (True, Fault.LOST_ABSENT_REPLY, State.FAILED),
        ):
            with self.subTest(revoke_all=revoke_all):
                self.core = self.make_controller()
                original = self.propose(APPLY)
                preapproved = self.propose(EQUIVALENT, SIBLING_JOB)
                self.approve(original)
                self.approve(preapproved)
                self.adapter.outcomes.append(fault)
                result = self.core.invoke(JOB, original)
                self.assertEqual((result.state, result.consumed), (State.UNCERTAIN, True))
                blocked = self.core.invoke(SIBLING_JOB, preapproved)
                self.assertEqual((blocked.reason, blocked.eligible), (Reason.UNAVAILABLE, False))
                self.assertNotIn(original, repr(blocked))
                with self.assertRaises(Denied):
                    self.core.status(SIBLING_JOB, original)
                if revoke_all:
                    self.core.revoke_worker(OPERATOR, SUBJECT.worker_enrollment)
                else:
                    self.core.revoke(OPERATOR, original)
                self.core._set_target_revision("target-one", "rev-two")
                newer = self.propose(EQUIVALENT, actor=REENROLLED_JOB)
                self.assertFalse(self.approve(newer, OTHER_OPERATOR).eligible)
                self.assertEqual(self.core.invoke(REENROLLED_JOB, newer).reason, Reason.UNAVAILABLE)
                self.assertEqual(len(self.adapter.attempts), 1)
                self.adapter.fail_reconciliation = True
                result = self.core._reconcile(original)
                self.assertEqual((result.state, result.revoked), (State.UNCERTAIN, True))
                self.adapter.fail_reconciliation = False
                result = self.core._reconcile(original)
                self.assertEqual((result.state, result.revoked, result.consumed), (terminal, True, True))
                self.assertEqual(self.adapter.reconciliations, [Attempt(original, 1)] * 2)
                with self.assertRaises(Conflict):
                    self.core._reconcile(original)
                with self.assertRaises(Conflict):
                    self.core.invoke(JOB, original)
                self.assertEqual(len(self.adapter.attempts), 1)
                self.assertTrue(self.core.status(REENROLLED_JOB, newer).eligible)
                self.assertEqual(self.core.invoke(REENROLLED_JOB, newer).state, State.SUCCEEDED)
                self.assertEqual(len(self.adapter.effects()), 2 if terminal is State.SUCCEEDED else 1)

    def test_missing_journal_entry_cannot_settle_ambiguous_mutation(self):
        request_id = self.propose(APPLY)
        self.approve(request_id)
        self.adapter.outcomes.append(Fault.TIMEOUT_UNKNOWN)
        self.assertEqual(self.core.invoke(JOB, request_id).state, State.UNCERTAIN)
        self.assertEqual(self.adapter.effects(), set())
        before = self.core.events(JOB, SUBJECT)
        self.assertEqual(self.core._reconcile(request_id).state, State.UNCERTAIN)
        self.assertEqual(self.core.events(JOB, SUBJECT), before)
        another = self.propose(EQUIVALENT)
        self.assertFalse(self.approve(another).eligible)
        self.assertEqual(self.core.invoke(JOB, another).reason, Reason.UNAVAILABLE)
        self.assertEqual(len(self.adapter.attempts), 1)

    def test_subject_capacity_preserves_other_allocations_and_outcomes(self):
        self.core = self.make_controller(budget=1)
        request_id = self.propose(APPLY)
        self.approve(request_id)
        self.adapter.outcomes.append(Fault.LOST_APPLIED_REPLY)
        self.assertEqual(self.core.invoke(JOB, request_id).state, State.UNCERTAIN)
        attempts_before = len(self.adapter.attempts)
        reads_before = self.adapter.reads
        for _ in range(3):
            with self.assertRaises(CapacityExceeded):
                self.propose()
        self.assertEqual(len(self.adapter.attempts), attempts_before)
        self.assertEqual(self.adapter.reads, reads_before)

        self.propose(actor=SIBLING_JOB)
        self.propose(actor=REENROLLED_JOB)
        self.core.revoke_worker(OPERATOR, SUBJECT.worker_enrollment)
        result = self.core._reconcile(request_id)
        self.assertEqual((result.state, result.revoked), (State.SUCCEEDED, True))
        self.assertEqual([e.status.reason for e in self.core.events(JOB, SUBJECT)], [
            Reason.APPROVAL_NEEDED, Reason.APPROVED, Reason.UNCERTAIN,
            Reason.REVOKED, Reason.SUCCEEDED,
        ])

    def test_definite_failure_releases_fence_without_reusing_approval(self):
        rejected = self.propose(APPLY)
        self.approve(rejected)
        self.adapter.outcomes.append(Outcome.DEFINITE_FAILURE)
        result = self.core.invoke(JOB, rejected)
        self.assertEqual((result.state, result.consumed), (State.FAILED, True))
        with self.assertRaises(Conflict):
            self.core.invoke(JOB, rejected)
        fresh = self.propose(APPLY)
        self.assertTrue(self.approve(fresh).eligible)
        self.assertEqual(self.core.invoke(JOB, fresh).state, State.SUCCEEDED)
        self.assertEqual(self.adapter.effects(), {Attempt(fresh, 1)})

    def race(self, *actions):
        start = Barrier(len(actions))

        def run(action):
            start.wait(timeout=5)
            try:
                return action()
            except Conflict:
                return None

        with ThreadPoolExecutor(max_workers=len(actions)) as pool:
            futures = [pool.submit(run, action) for action in actions]
            return [future.result(timeout=5) for future in futures]

    def test_concurrent_repeat_decision_and_invoke(self):
        request_id = self.propose(APPLY)
        args = self.decision_args(request_id)
        decide = lambda: self.core.decide(OPERATOR, *args, Decision.APPROVE)
        invoke = lambda: self.core.invoke(JOB, request_id)
        self.assertEqual(sum(result is not None for result in self.race(decide, decide)), 1)
        self.assertEqual(sum(result is not None for result in self.race(invoke, invoke)), 1)
        self.assertEqual(self.adapter.effects(), {Attempt(request_id, 1)})
        self.assertEqual(len(self.adapter.attempts), 1)
        self.assertEqual([event.status.reason for event in self.core.events(JOB, SUBJECT)],
                         [Reason.APPROVAL_NEEDED, Reason.APPROVED, Reason.SUCCEEDED])

    def test_concurrent_revoke_and_invoke(self):
        request_id = self.propose(APPLY)
        self.approve(request_id)
        self.race(lambda: self.core.revoke(OPERATOR, request_id),
                  lambda: self.core.invoke(JOB, request_id))
        status = self.core.status(JOB, request_id)
        audit = self.core.events(JOB, SUBJECT)
        self.assertEqual(len(audit), 3)
        if status.revoked:
            self.assertEqual(status.state, State.APPROVED)
            self.assertEqual(audit[-1].status.reason, Reason.REVOKED)
            self.assertEqual(self.adapter.attempts, [])
        else:
            self.assertEqual(status.state, State.SUCCEEDED)
            self.assertEqual(audit[-1].status.reason, Reason.SUCCEEDED)
            self.assertEqual(self.adapter.effects(), {Attempt(request_id, 1)})
        self.assertFalse(status.eligible)

    def test_adapter_refuses_outside_pinned_revision_and_operation(self):
        request_id = self.propose(APPLY)
        payload = self.core.view(OPERATOR, request_id).payload
        wrong_pin = replace(payload, pin=replace(payload.pin, revision="different"))
        self.assertIs(self.adapter.dispatch(Attempt(request_id, 1), wrong_pin),
                      Outcome.DEFINITE_FAILURE)
        for operation in ("custom", "apply"):
            unsupported = replace(payload, operation=operation)
            self.assertIs(self.adapter.dispatch(Attempt(request_id, 2), unsupported),
                          Outcome.DEFINITE_FAILURE)
        self.assertEqual(self.adapter.effects(), set())


if __name__ == "__main__":
    unittest.main()
