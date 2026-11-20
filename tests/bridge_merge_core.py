import unittest
from dataclasses import replace
from threading import Lock

from oc_bridge_merge import (
    MAX_TEXT_BYTES,
    AdapterFixture,
    DestinationFixture,
    ExportOutcome,
    ExportReceipt,
    Inputs,
    MergeError,
    MergeMode,
    MergeOutcome,
    MergeReceipt,
    MergeSession,
    Phase,
    PreferenceError,
    PreferenceSource,
    RepositoryStatus,
    Revision,
    ScopedPreferences,
    ToolName,
    ToolPolicy,
    merge_preferences,
    select_tool,
)


def revision(data):
    return Revision(object(), data)


class FakeExport:
    def __init__(self):
        self.parent = object()
        self.files = {}
        self.receipts = {}
        self._lock = Lock()

    def destination(self, leaf="reviewed.txt"):
        return DestinationFixture(self.parent, leaf, True)

    def create(self, operation):
        # Each receipt keeps its operation alive, so this identity cannot be reused.
        key = id(operation)
        with self._lock:
            previous = self.receipts.get(key)
            if previous is not None:
                return previous
            destination = operation.approved.destination
            if destination.parent_identity is not self.parent:
                receipt = ExportReceipt(operation, ExportOutcome.UNCERTAIN, destination)
            else:
                new = revision(operation.output)
                observed = self.files.setdefault(destination.leaf, new)
                if observed is new:
                    receipt = ExportReceipt(
                        operation, ExportOutcome.VERIFIED_CREATED, destination, observed, new.identity
                    )
                else:
                    receipt = ExportReceipt(operation, ExportOutcome.EXISTS, destination)
            self.receipts[key] = receipt
            return receipt


class MergeCoreTest(unittest.TestCase):
    def setUp(self):
        self.owner = object()
        self.inputs = Inputs(revision(b"one\ntwo\n"), revision(b"ONE\ntwo\n"), revision(b"one\nTWO\n"))
        self.preferences = ScopedPreferences(self.inputs.agent.identity, RepositoryStatus.VERIFIED)
        self.adapter = AdapterFixture(object(), True)
        self.exporter = FakeExport()
        self.session = self.make_session()

    def make_session(self, inputs=None):
        return MergeSession(self.owner, "projects/example.txt", inputs or self.inputs)

    def selection(self, preferences=None, adapter=None):
        return select_tool(merge_preferences(), preferences or self.preferences, adapter or self.adapter)

    def open_merge(self):
        prompt = self.session.offer_merge(self.owner, self.preferences, self.adapter)
        return self.session.open_merge(self.owner, prompt, self.inputs.agent, self.adapter)

    def merge_receipt(self, operation, output):
        return MergeReceipt(operation, MergeOutcome.COMPLETED, self.adapter.identity, self.inputs, output, output.identity)

    def ready_output(self, data=b"ONE\nTWO\n"):
        operation = self.open_merge()
        output = revision(data)
        finish = self.session.complete_merge(self.owner, self.merge_receipt(operation, output))
        self.session.finish_merge(self.owner, finish, output)
        return output

    def begin_export(self, output, leaf="reviewed.txt"):
        prompt = self.session.offer_export(self.owner, self.exporter.destination(leaf))
        return self.session.begin_export(self.owner, prompt, self.inputs.agent, output)

    def test_typed_stub_and_preference_sources(self):
        settings = merge_preferences()
        self.assertIs(settings.mode, MergeMode.THREE_WAY)
        self.assertIs(settings.tool_policy, ToolPolicy.GIT_PREFERENCE)
        for preferences, source in (
            ({"local": b"vimdiff", "global_home": PreferenceError.UNAVAILABLE}, PreferenceSource.LOCAL),
            ({"global_xdg": b"vimdiff"}, PreferenceSource.GLOBAL_XDG),
            ({"global_xdg": b"other", "global_home": b"vimdiff"}, PreferenceSource.GLOBAL_HOME),
            ({"repository": RepositoryStatus.ABSENT, "global_home": b"vimdiff"}, PreferenceSource.GLOBAL_HOME),
            ({}, PreferenceSource.FALLBACK),
        ):
            with self.subTest(preferences=preferences):
                selected = self.selection(replace(self.preferences, **preferences))
                self.assertIs(selected.name, ToolName.VIMDIFF)
                self.assertIs(selected.source, source)
                self.assertIs(selected.adapter_identity, self.adapter.identity)
        with self.assertRaisesRegex(MergeError, "Unsupported merge mode"):
            select_tool(replace(settings, mode=MergeMode.TWO_WAY), self.preferences, self.adapter)

    def test_unsafe_or_missing_preference_does_not_fall_back(self):
        for preference in (
            b"", b"v" * 65, b"Vimdiff", b"vimdiff\0", b"vimdiff\n", b"vimdiff --flag",
            b"/bin/vimdiff", b"[include]\npath=x", PreferenceError.UNAVAILABLE,
        ):
            with self.subTest(preference=preference), self.assertRaises(MergeError):
                self.selection(replace(self.preferences, local=preference, global_home=b"vimdiff"))
        for preferences in (
            replace(self.preferences, repository=RepositoryStatus.UNCERTAIN),
            replace(self.preferences, repository=RepositoryStatus.ABSENT, local=b"vimdiff"),
            replace(self.preferences, global_xdg=PreferenceError.UNAVAILABLE, global_home=b"vimdiff"),
            replace(self.preferences, global_xdg=b"vimdiff", global_home=b"unknown"),
        ):
            with self.subTest(preferences=preferences), self.assertRaises(MergeError):
                self.selection(preferences)
        with self.assertRaisesRegex(MergeError, "unavailable"):
            self.selection(adapter=AdapterFixture(None, True))
        with self.assertRaisesRegex(MergeError, "attended terminal"):
            self.selection(adapter=replace(self.adapter, attended_terminal=False))

    def test_terminal_attestation_must_be_literal_true(self):
        truthy = replace(self.adapter, attended_terminal=1)
        with self.assertRaisesRegex(MergeError, "attended terminal"):
            self.selection(adapter=truthy)
        prompt = self.session.offer_merge(self.owner, self.preferences, self.adapter)
        with self.assertRaisesRegex(MergeError, "no longer available"):
            self.session.open_merge(self.owner, prompt, self.inputs.agent, truthy)

    def test_original_file_owns_preference_fixture(self):
        staged = replace(self.preferences, agent_identity=object())
        with self.assertRaisesRegex(MergeError, "original file"):
            self.session.offer_merge(self.owner, staged, self.adapter)
        self.assertEqual(self.session.recovery(self.owner).inputs, self.inputs)

    def test_no_host_change_has_no_export(self):
        self.session = self.make_session(replace(self.inputs, host=revision(self.inputs.base.contents)))
        self.assertIs(self.session.phase, Phase.NO_HOST_CHANGE)
        with self.assertRaises(MergeError):
            self.session.offer_export(self.owner, self.exporter.destination())
        self.session.discard(self.owner)
        self.assertIs(self.session.phase, Phase.CLOSED)

    def test_agent_unchanged_stages_host_but_waits_for_confirmation(self):
        self.inputs = replace(self.inputs, agent=revision(self.inputs.base.contents))
        self.session = self.make_session()
        self.assertIs(self.session.phase, Phase.READY)
        output = self.session.recovery(self.owner).output
        self.assertEqual(output.contents, self.inputs.host.contents)
        operation = self.begin_export(output)
        self.assertEqual(self.exporter.files, {})
        self.session.complete_export(self.owner, self.exporter.create(operation))
        self.assertEqual(self.exporter.files["reviewed.txt"].contents, self.inputs.host.contents)
        self.assertIs(self.session.phase, Phase.CLOSED)

    def test_missing_or_unsupported_inputs_keep_host_recovery(self):
        for name, inputs in (
            ("missing base", replace(self.inputs, base=None)),
            ("missing agent", replace(self.inputs, agent=None)),
            ("binary", replace(self.inputs, agent=revision(b"contains\0binary"))),
            ("non-UTF-8", replace(self.inputs, agent=revision(b"\xff"))),
            ("oversized", replace(self.inputs, agent=revision(b"a" * (MAX_TEXT_BYTES + 1)))),
        ):
            with self.subTest(input_problem=name):
                session = self.make_session(inputs)
                self.assertIs(session.phase, Phase.RECOVERY)
                recovery = session.recovery(self.owner)
                self.assertIs(recovery.inputs.host, self.inputs.host)
                self.assertTrue(recovery.preparation_error)
                with self.assertRaises(MergeError):
                    session.offer_merge(self.owner, self.preferences, self.adapter)

    def test_recovery_filters_each_input_even_when_another_is_missing(self):
        oversized = revision(b"a" * (MAX_TEXT_BYTES + 1))
        binary = revision(b"invalid\0text")
        for candidate, expected in (
            (Inputs(None, self.inputs.host, oversized), Inputs(None, self.inputs.host, None)),
            (Inputs(oversized, self.inputs.host, binary), Inputs(None, self.inputs.host, None)),
            (Inputs(self.inputs.base, oversized, None), Inputs(self.inputs.base, None, None)),
            (Inputs(None, Revision(None, b"edit"), None), Inputs(None, None, None)),
            (Inputs(None, Revision(object(), bytearray(b"edit")), None), Inputs(None, None, None)),
        ):
            with self.subTest(expected=expected):
                session = self.make_session(candidate)
                self.assertIs(session.phase, Phase.RECOVERY)
                recovery = session.recovery(self.owner)
                for role in ("base", "host", "agent"):
                    self.assertTrue(
                        getattr(recovery.inputs, role) is getattr(expected, role),
                        f"Incorrect recovery retention for {role}",
                    )
                self.assertTrue(recovery.preparation_error)

    def test_recovery_keeps_exact_bounded_host_bytes_when_text_is_ineligible(self):
        for contents in (b"unsaved\0binary edit", b"unsaved\xffedit"):
            with self.subTest(contents=contents):
                host = revision(contents)
                session = self.make_session(replace(self.inputs, host=host))
                self.assertIs(session.phase, Phase.RECOVERY)
                recovery = session.recovery(self.owner)
                self.assertIs(recovery.inputs.host, host)
                self.assertIn("Host", recovery.preparation_error)
                with self.assertRaises(MergeError):
                    session.offer_merge(self.owner, self.preferences, self.adapter)
                with self.assertRaises(MergeError):
                    session.offer_export(self.owner, self.exporter.destination())

    def test_exact_confirmation_is_owned_current_and_single_use(self):
        first = self.session.offer_merge(self.owner, self.preferences, self.adapter)
        prompt = self.session.offer_merge(self.owner, self.preferences, self.adapter)
        foreign = self.make_session().offer_merge(self.owner, self.preferences, self.adapter)
        for invalid in (first, foreign, replace(prompt)):
            with self.subTest(prompt=invalid), self.assertRaisesRegex(MergeError, "Confirmation"):
                self.session.open_merge(self.owner, invalid, self.inputs.agent, self.adapter)
        with self.assertRaisesRegex(MergeError, "owner"):
            self.session.open_merge(object(), prompt, self.inputs.agent, self.adapter)
        with self.assertRaisesRegex(MergeError, "no longer available"):
            self.session.open_merge(self.owner, prompt, self.inputs.agent, AdapterFixture(object(), True))
        with self.assertRaisesRegex(MergeError, "Confirmation"):
            self.session.open_merge(self.owner, prompt, self.inputs.agent, self.adapter)
        self.open_merge()
        self.assertIs(self.session.phase, Phase.EDITING)

    def test_changed_agent_bytes_or_identity_invalidate_review(self):
        for observed in (revision(self.inputs.agent.contents), replace(self.inputs.agent, contents=b"new"), None):
            with self.subTest(observed=observed):
                self.session = self.make_session()
                prompt = self.session.offer_merge(self.owner, self.preferences, self.adapter)
                with self.assertRaisesRegex(MergeError, "revision"):
                    self.session.open_merge(self.owner, prompt, observed, self.adapter)
                self.assertIs(self.session.phase, Phase.RECOVERY)
                self.assertEqual(self.session.recovery(self.owner).inputs, self.inputs)

    def test_merge_result_needs_verified_completion_and_finish_confirmation(self):
        # The fake tool can intentionally keep one side verbatim, or supply a resolved edit.
        for data in (b"ONE\nTWO\n", self.inputs.agent.contents, self.inputs.host.contents, b""):
            with self.subTest(data=data):
                self.session = self.make_session()
                operation = self.open_merge()
                with self.assertRaises(MergeError):
                    self.session.offer_export(self.owner, self.exporter.destination())
                output = revision(data)
                receipt = self.merge_receipt(operation, output)
                with self.assertRaisesRegex(MergeError, "current merge operation"):
                    self.session.complete_merge(self.owner, replace(receipt, operation=replace(operation)))
                finish = self.session.complete_merge(self.owner, receipt)
                self.assertEqual(finish.output_digest, output.digest())
                self.assertIs(finish.binding, operation.approved.binding)
                with self.assertRaises(MergeError):
                    self.session.offer_export(self.owner, self.exporter.destination())
                with self.assertRaisesRegex(MergeError, "Confirmation"):
                    self.session.finish_merge(self.owner, replace(finish), output)
                self.session.finish_merge(self.owner, finish, output)
                self.assertIs(self.session.phase, Phase.READY)

    def test_export_requires_the_exact_prompt(self):
        output = self.ready_output()
        prompt = self.session.offer_export(self.owner, self.exporter.destination())

        with self.assertRaisesRegex(MergeError, "Confirmation"):
            self.session.begin_export(self.owner, replace(prompt), self.inputs.agent, output)
        self.assertIs(self.session.phase, Phase.READY)
        self.assertEqual(self.exporter.files, {})
        self.assertEqual(self.exporter.receipts, {})

        operation = self.session.begin_export(self.owner, prompt, self.inputs.agent, output)
        self.assertIs(operation.approved, prompt)
        self.assertIs(self.session.phase, Phase.EXPORTING)

    def test_cancel_retains_recovery_and_unknown_outcome_holds_lease(self):
        output = revision(b"possible result")
        for outcome in (MergeOutcome.CANCELLED, MergeOutcome.UNCERTAIN):
            with self.subTest(outcome=outcome):
                self.session = self.make_session()
                operation = self.open_merge()
                receipt = replace(self.merge_receipt(operation, output), outcome=outcome)
                if outcome is MergeOutcome.CANCELLED:
                    self.assertIsNone(self.session.complete_merge(self.owner, receipt))
                else:
                    with self.assertRaisesRegex(MergeError, "completion"):
                        self.session.complete_merge(self.owner, receipt)
                self.assertIs(self.session.phase, Phase.RECOVERY)
                self.assertIs(self.session.recovery(self.owner).output, output)
                with self.assertRaises(MergeError):
                    self.session.offer_export(self.owner, self.exporter.destination())
                if outcome is MergeOutcome.CANCELLED:
                    self.session.discard(self.owner)
                else:
                    with self.assertRaisesRegex(MergeError, "still owns"):
                        self.session.discard(self.owner)

    def test_cancel_releases_lease_even_when_output_is_ineligible(self):
        for data in (b"a" * (MAX_TEXT_BYTES + 1), b"invalid\0text"):
            with self.subTest(size=len(data)):
                self.session = self.make_session()
                operation = self.open_merge()
                receipt = replace(self.merge_receipt(operation, revision(data)), outcome=MergeOutcome.CANCELLED)
                self.assertIsNone(self.session.complete_merge(self.owner, receipt))
                recovery = self.session.recovery(self.owner)
                self.assertEqual(recovery.inputs, self.inputs)
                self.assertIsNone(recovery.output)
                self.session.discard(self.owner)
                self.assertIs(self.session.phase, Phase.CLOSED)

    def test_result_needs_new_identity_even_when_reusing_source_bytes(self):
        for source in (self.inputs.base, self.inputs.host, self.inputs.agent):
            with self.subTest(source=source):
                self.session = self.make_session()
                operation = self.open_merge()
                with self.assertRaisesRegex(MergeError, "verified output"):
                    self.session.complete_merge(self.owner, self.merge_receipt(operation, source))
                recovery = self.session.recovery(self.owner)
                self.assertEqual(recovery.inputs, self.inputs)
                self.assertIsNone(recovery.output)
                self.session = self.make_session()
                self.ready_output(source.contents)
                self.assertIs(self.session.phase, Phase.READY)

    def test_changed_source_or_unverified_adapter_cannot_complete(self):
        for changes in (
            {"observed_inputs": replace(self.inputs, host=revision(self.inputs.host.contents))},
            {"adapter_identity": object()},
            {"output": None},
            {"saved_identity": object()},
        ):
            with self.subTest(changes=changes):
                self.session = self.make_session()
                operation = self.open_merge()
                receipt = replace(self.merge_receipt(operation, revision(b"merged")), **changes)
                with self.assertRaises(MergeError):
                    self.session.complete_merge(self.owner, receipt)
                self.assertIs(self.session.phase, Phase.RECOVERY)
                self.assertIs(self.session.recovery(self.owner).inputs.host, self.inputs.host)

    def test_finish_detects_replaced_output(self):
        operation = self.open_merge()
        output = revision(b"merged")
        finish = self.session.complete_merge(self.owner, self.merge_receipt(operation, output))
        with self.assertRaisesRegex(MergeError, "revision"):
            self.session.finish_merge(self.owner, finish, revision(output.contents))
        self.assertIs(self.session.phase, Phase.RECOVERY)
        self.assertIs(self.session.recovery(self.owner).output, output)

    def test_unverified_destinations_do_not_authorize_export(self):
        self.ready_output()
        for destination in (
            DestinationFixture(object(), "safe.txt", False),
            DestinationFixture(None, "safe.txt", True),
            self.exporter.destination("../overwrite"),
            self.exporter.destination("\x1b[1mname"),
        ):
            with self.subTest(destination=destination), self.assertRaisesRegex(MergeError, "trusted destination"):
                self.session.offer_export(self.owner, destination)
        self.assertEqual(self.exporter.files, {})
        self.assertIs(self.session.phase, Phase.READY)

    def test_destination_leaf_is_character_bounded_before_encoding(self):
        class LongLeaf(str):
            def encode(self, *args, **kwargs):
                raise AssertionError("Oversized leaf was encoded")

        self.ready_output()
        for leaf in (LongLeaf("x" * 256), "x" * 256, "é" * 128):
            with self.assertRaisesRegex(MergeError, "trusted destination"):
                self.session.offer_export(self.owner, self.exporter.destination(leaf))

    def test_export_is_create_only_and_conflict_keeps_review(self):
        output = self.ready_output()
        self.exporter.files["reviewed.txt"] = existing = revision(b"existing")
        operation = self.begin_export(output)
        self.session.complete_export(self.owner, self.exporter.create(operation))
        self.assertIs(self.exporter.files["reviewed.txt"], existing)
        self.assertIs(self.session.phase, Phase.READY)
        self.assertIs(self.session.recovery(self.owner).output, output)
        next_operation = self.begin_export(output, "reviewed-new.txt")
        with self.assertRaisesRegex(MergeError, "current export operation"):
            self.session.complete_export(self.owner, self.exporter.create(operation))
        self.session.complete_export(self.owner, self.exporter.create(next_operation))
        self.assertIs(self.session.phase, Phase.CLOSED)
        with self.assertRaises(MergeError):
            self.session.recovery(self.owner)

    def test_export_detects_stale_agent_or_output_before_create(self):
        for changed in ("agent", "output"):
            with self.subTest(changed=changed):
                self.session = self.make_session()
                output = self.ready_output()
                prompt = self.session.offer_export(self.owner, self.exporter.destination())
                observed = {"agent": self.inputs.agent, "output": output}
                observed[changed] = replace(observed[changed], contents=b"unexpected")
                with self.assertRaisesRegex(MergeError, "revision"):
                    self.session.begin_export(self.owner, prompt, **observed)
                self.assertIs(self.session.phase, Phase.RECOVERY)
                self.assertIs(self.session.recovery(self.owner).output, output)
                self.assertEqual(self.exporter.files, {})

    def test_export_retry_after_lost_receipt_replays_verified_creation(self):
        output = self.ready_output()
        operation = self.begin_export(output)
        lost_receipt = self.exporter.create(operation)
        retry_receipt = self.exporter.create(operation)
        self.assertIs(retry_receipt, lost_receipt)
        self.session.complete_export(self.owner, retry_receipt)
        self.assertEqual(self.exporter.files, {"reviewed.txt": lost_receipt.observed_output})
        self.assertIs(self.session.phase, Phase.CLOSED)

    def test_created_export_identity_must_be_distinct_from_private_recovery(self):
        for name, source in (
            ("staged", None),
            ("base", self.inputs.base),
            ("host", self.inputs.host),
            ("agent", self.inputs.agent),
        ):
            with self.subTest(alias=name):
                self.session = self.make_session()
                output = self.ready_output(source.contents if source is not None else b"merged")
                operation = self.begin_export(output)
                alias = output if source is None else source
                receipt = ExportReceipt(
                    operation, ExportOutcome.VERIFIED_CREATED, operation.approved.destination,
                    alias, alias.identity,
                )
                with self.assertRaisesRegex(MergeError, "publication could not be verified"):
                    self.session.complete_export(self.owner, receipt)
                self.assertIs(self.session.phase, Phase.RECOVERY)
                self.assertIs(self.session.recovery(self.owner).output, output)
                self.assertEqual(self.session.recovery(self.owner).inputs, self.inputs)
                with self.assertRaisesRegex(MergeError, "still owns"):
                    self.session.discard(self.owner)

    def test_ambiguous_publication_retains_inputs_output_and_lease(self):
        for problem in ("uncertain", "parent", "identity", "digest", "conflicting-status"):
            with self.subTest(problem=problem):
                self.session = self.make_session()
                output = self.ready_output()
                operation = self.begin_export(output, f"{problem}.txt")
                receipt = self.exporter.create(operation)
                if problem == "uncertain":
                    receipt = replace(receipt, outcome=ExportOutcome.UNCERTAIN)
                elif problem == "parent":
                    receipt = replace(receipt, destination=replace(receipt.destination, parent_identity=object()))
                elif problem == "identity":
                    receipt = replace(receipt, observed_output=revision(output.contents))
                elif problem == "conflicting-status":
                    receipt = replace(receipt, outcome=ExportOutcome.EXISTS)
                else:
                    receipt = replace(receipt, observed_output=replace(receipt.observed_output, contents=b"invalid"))
                with self.assertRaises(MergeError):
                    self.session.complete_export(self.owner, receipt)
                self.assertEqual(self.exporter.files[f"{problem}.txt"].contents, output.contents)
                self.assertIs(self.session.phase, Phase.RECOVERY)
                self.assertIs(self.session.recovery(self.owner).output, output)
                self.assertEqual(self.session.recovery(self.owner).inputs, self.inputs)
                with self.assertRaisesRegex(MergeError, "still owns"):
                    self.session.discard(self.owner)

    def test_abandoned_operation_preserves_session_and_owner_boundary(self):
        self.open_merge()
        with self.assertRaisesRegex(MergeError, "owner"):
            self.session.recovery(object())
        with self.assertRaisesRegex(MergeError, "owner"):
            self.session.discard(object())
        with self.assertRaises(MergeError):
            self.session.discard(self.owner)
        self.assertIs(self.session.phase, Phase.EDITING)
        self.assertEqual(self.session.recovery(self.owner).inputs, self.inputs)


    def test_late_verified_merge_requires_separate_finish_after_uncertainty(self):
        operation = self.open_merge()
        retained = revision(b"provisional merge")
        uncertain = replace(self.merge_receipt(operation, retained), outcome=MergeOutcome.UNCERTAIN)
        with self.assertRaisesRegex(MergeError, "completion"):
            self.session.complete_merge(self.owner, uncertain)
        self.assertIs(self.session.recovery(self.owner).output, retained)
        with self.assertRaisesRegex(MergeError, "still owns"):
            self.session.discard(self.owner)
        with self.assertRaises(MergeError):
            self.session.open_merge(self.owner, operation.approved, self.inputs.agent, self.adapter)

        output = revision(b"verified merge")
        receipt = self.merge_receipt(operation, output)
        prompt = self.session.complete_merge(self.owner, receipt)
        self.assertEqual(prompt.output_digest, output.digest())
        self.assertIs(prompt.binding, operation.approved.binding)
        self.assertIs(self.session.recovery(self.owner).output, output)
        self.assertIs(self.session.phase, Phase.FINISH_REQUIRED)
        with self.assertRaises(MergeError):
            self.session.complete_merge(self.owner, receipt)
        with self.assertRaises(MergeError):
            self.session.offer_export(self.owner, self.exporter.destination())
        self.session.finish_merge(self.owner, prompt, output)
        self.assertIs(self.session.phase, Phase.READY)

    def test_late_merge_rechecks_owner_operation_kind_and_output(self):
        operation = self.open_merge()
        retained = revision(b"provisional merge")
        uncertain = replace(self.merge_receipt(operation, retained), outcome=MergeOutcome.UNCERTAIN)
        with self.assertRaisesRegex(MergeError, "completion"):
            self.session.complete_merge(self.owner, uncertain)

        candidate = revision(b"different result")
        receipt = self.merge_receipt(operation, candidate)
        destination = self.exporter.destination()
        forged_export = ExportReceipt(operation, ExportOutcome.EXISTS, destination)
        with self.assertRaisesRegex(MergeError, "owner"):
            self.session.complete_merge(object(), receipt)
        other = self.make_session()
        other_prompt = other.offer_merge(self.owner, self.preferences, self.adapter)
        other_operation = other.open_merge(self.owner, other_prompt, self.inputs.agent, self.adapter)
        for bad in (
            replace(receipt, operation=replace(operation)),
            replace(receipt, operation=other_operation),
            forged_export,
        ):
            with self.subTest(bad=type(bad)), self.assertRaisesRegex(MergeError, "current merge operation"):
                self.session.complete_merge(self.owner, bad)
        with self.assertRaisesRegex(MergeError, "current export operation"):
            self.session.complete_export(self.owner, forged_export)
        for bad, diagnostic in (
            (replace(receipt, adapter_identity=object()), "different adapter"),
            (replace(receipt, saved_identity=object()), "verified output"),
            (self.merge_receipt(operation, revision(b"x" * (MAX_TEXT_BYTES + 1))), "verified output"),
            (replace(receipt, observed_inputs=replace(self.inputs, host=revision(b"changed"))), "revision"),
            (replace(receipt, observed_inputs=replace(self.inputs, agent=None)), "revision"),
            (replace(receipt, outcome=MergeOutcome.UNCERTAIN), "completion"),
        ):
            with self.subTest(diagnostic=diagnostic), self.assertRaisesRegex(MergeError, diagnostic):
                self.session.complete_merge(self.owner, bad)
            self.assertIs(self.session.recovery(self.owner).output, retained)
            self.assertIs(self.session.phase, Phase.RECOVERY)
        with self.assertRaisesRegex(MergeError, "still owns"):
            self.session.discard(self.owner)

    def test_late_cancel_settles_merge_lease_and_rejects_replay_or_none(self):
        operation = self.open_merge()
        output = revision(b"provisional merge")
        receipt = self.merge_receipt(operation, output)
        with self.assertRaisesRegex(MergeError, "completion"):
            self.session.complete_merge(self.owner, replace(receipt, outcome=MergeOutcome.UNCERTAIN))
        cancelled = replace(
            self.merge_receipt(operation, revision(b"later unverified candidate")),
            outcome=MergeOutcome.CANCELLED,
        )
        self.assertIsNone(self.session.complete_merge(self.owner, cancelled))

        for bad in (cancelled, replace(receipt, operation=None)):
            with self.subTest(bad=bad.operation), self.assertRaisesRegex(MergeError, "current merge operation"):
                self.session.complete_merge(self.owner, bad)
        forged = ExportReceipt(None, ExportOutcome.EXISTS, self.exporter.destination())
        with self.assertRaisesRegex(MergeError, "current export operation"):
            self.session.complete_export(self.owner, forged)
        self.assertIs(self.session.recovery(self.owner).output, output)
        self.session.discard(self.owner)
        self.assertIs(self.session.phase, Phase.CLOSED)

    def test_late_verified_export_settles_the_same_single_creation(self):
        output = self.ready_output()
        operation = self.begin_export(output)
        verified = self.exporter.create(operation)
        uncertain = ExportReceipt(operation, ExportOutcome.UNCERTAIN, verified.destination)
        with self.assertRaisesRegex(MergeError, "publication could not be verified"):
            self.session.complete_export(self.owner, uncertain)
        self.assertIs(self.session.phase, Phase.RECOVERY)
        self.assertIs(self.session.recovery(self.owner).output, output)
        with self.assertRaisesRegex(MergeError, "still owns"):
            self.session.discard(self.owner)

        self.session.complete_export(self.owner, verified)
        self.assertIs(self.session.phase, Phase.CLOSED)
        self.assertEqual(self.exporter.files, {"reviewed.txt": verified.observed_output})
        self.assertEqual(len(self.exporter.receipts), 1)
        with self.assertRaises(MergeError):
            self.session.complete_export(self.owner, verified)

    def test_late_verified_export_conflict_releases_lease_without_publication(self):
        output = self.ready_output()
        existing = revision(b"preexisting file")
        self.exporter.files["reviewed.txt"] = existing
        operation = self.begin_export(output)
        conflict = self.exporter.create(operation)
        self.assertIs(conflict.outcome, ExportOutcome.EXISTS)
        uncertain = ExportReceipt(operation, ExportOutcome.UNCERTAIN, conflict.destination)
        with self.assertRaisesRegex(MergeError, "publication could not be verified"):
            self.session.complete_export(self.owner, uncertain)
        self.assertIs(self.session.phase, Phase.RECOVERY)
        with self.assertRaisesRegex(MergeError, "still owns"):
            self.session.discard(self.owner)

        self.session.complete_export(self.owner, conflict)
        self.assertIs(self.session.phase, Phase.READY)
        self.assertIs(self.session.recovery(self.owner).output, output)
        self.assertEqual(self.exporter.files, {"reviewed.txt": existing})
        self.assertEqual(len(self.exporter.receipts), 1)
        with self.assertRaises(MergeError):
            self.session.complete_export(self.owner, conflict)

    def test_late_export_rechecks_owner_operation_kind_and_publication(self):
        output = self.ready_output()
        operation = self.begin_export(output)
        verified = self.exporter.create(operation)
        with self.assertRaisesRegex(MergeError, "publication could not be verified"):
            self.session.complete_export(self.owner, ExportReceipt(operation, ExportOutcome.UNCERTAIN, verified.destination))

        forged_merge = self.merge_receipt(operation, output)
        with self.assertRaisesRegex(MergeError, "owner"):
            self.session.complete_export(object(), verified)
        for bad in (replace(verified, operation=replace(operation)), forged_merge):
            with self.subTest(bad=type(bad)), self.assertRaisesRegex(MergeError, "current export operation"):
                self.session.complete_export(self.owner, bad)
        with self.assertRaisesRegex(MergeError, "current merge operation"):
            self.session.complete_merge(self.owner, forged_merge)
        for bad, diagnostic in (
            (replace(verified, destination=replace(verified.destination, parent_identity=object())), "destination"),
            (replace(verified, destination=replace(verified.destination, trusted_new_file=False)), "destination"),
            (replace(verified, observed_output=replace(verified.observed_output, contents=b"changed")), "publication"),
            (replace(verified, created_identity=object()), "publication"),
            (replace(verified, observed_output=output, created_identity=output.identity), "publication"),
        ):
            with self.subTest(diagnostic=diagnostic), self.assertRaisesRegex(MergeError, diagnostic):
                self.session.complete_export(self.owner, bad)
            self.assertIs(self.session.phase, Phase.RECOVERY)
            self.assertIs(self.session.recovery(self.owner).output, output)
        with self.assertRaisesRegex(MergeError, "still owns"):
            self.session.discard(self.owner)

    def test_malformed_merge_receipt_keeps_phase_and_preview_unchanged(self):
        for phase in (Phase.EDITING, Phase.RECOVERY):
            for invalid in (
                {"outcome": "completed"},
                {"observed_inputs": object()},
                {"observed_inputs": replace(self.inputs, base=object())},
                {"observed_inputs": replace(self.inputs, host=object())},
                {"observed_inputs": replace(self.inputs, agent=object())},
                {"output": object(), "outcome": MergeOutcome.CANCELLED},
            ):
                with self.subTest(phase=phase, fields=invalid.keys()):
                    self.session = self.make_session()
                    operation = self.open_merge()
                    output = revision(b"verified merge")
                    receipt = self.merge_receipt(operation, output)
                    if phase is Phase.RECOVERY:
                        uncertain = replace(
                            receipt, outcome=MergeOutcome.UNCERTAIN, output=None, saved_identity=None
                        )
                        with self.assertRaisesRegex(MergeError, "completion"):
                            self.session.complete_merge(self.owner, uncertain)
                    with self.assertRaisesRegex(MergeError, "Malformed merge receipt"):
                        self.session.complete_merge(self.owner, replace(receipt, **invalid))
                    self.assertIs(self.session.phase, phase)
                    self.assertIsNone(self.session.recovery(self.owner).output)
                    prompt = self.session.complete_merge(self.owner, receipt)
                    self.session.finish_merge(self.owner, prompt, output)
                    self.assertIs(self.session.phase, Phase.READY)

    def test_malformed_export_receipt_keeps_active_operation_unchanged(self):
        for field in ("outcome", "destination", "leaf", "attestation", "output"):
            with self.subTest(field=field):
                self.session = self.make_session()
                output = self.ready_output()
                operation = self.begin_export(output, f"{field}.txt")
                verified = self.exporter.create(operation)
                invalid = {
                    "outcome": {"outcome": "verified-created"},
                    "destination": {"destination": object()},
                    "leaf": {"destination": replace(verified.destination, leaf=object())},
                    "attestation": {"destination": replace(verified.destination, trusted_new_file=1)},
                    "output": {"observed_output": object()},
                }[field]
                with self.assertRaisesRegex(MergeError, "Malformed export receipt"):
                    self.session.complete_export(self.owner, replace(verified, **invalid))
                self.assertIs(self.session.phase, Phase.EXPORTING)
                self.assertIs(self.session.recovery(self.owner).output, output)
                self.session.complete_export(self.owner, verified)
                self.assertIs(self.session.phase, Phase.CLOSED)
