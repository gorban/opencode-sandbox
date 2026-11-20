"""Offline model of bridge merge decisions. Inputs and receipts are synthetic fixtures.

The caller supplies all provenance, adapter and destination attestations. This module
keeps recovery in memory and never accesses a path, starts a tool, or publishes a file.
"""

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from threading import Lock


MAX_TEXT_BYTES = 1024 * 1024
MAX_TOOL_BYTES = 64


class MergeError(ValueError):
    pass


class MergeMode(Enum):
    THREE_WAY = "three-way"
    TWO_WAY = "two-way"


class ToolPolicy(Enum):
    GIT_PREFERENCE = "git-preference"


@dataclass(frozen=True)
class MergePreferences:
    mode: MergeMode
    tool_policy: ToolPolicy


def merge_preferences() -> MergePreferences:
    return MergePreferences(MergeMode.THREE_WAY, ToolPolicy.GIT_PREFERENCE)


class RepositoryStatus(Enum):
    VERIFIED = "verified"
    ABSENT = "absent"
    UNCERTAIN = "uncertain"


class PreferenceError(Enum):
    UNAVAILABLE = "unavailable"


# The scoped boundary exports one direct scalar, a verified absence, or an error.
Preference = bytes | None | PreferenceError


@dataclass(frozen=True)
class ScopedPreferences:
    agent_identity: object
    repository: RepositoryStatus
    local: Preference = None
    global_xdg: Preference = None
    global_home: Preference = None


class PreferenceSource(Enum):
    LOCAL = "repository"
    GLOBAL_XDG = "global XDG"
    GLOBAL_HOME = "global home"
    FALLBACK = "fallback"


class ToolName(Enum):
    VIMDIFF = "vimdiff"


@dataclass(frozen=True)
class AdapterFixture:
    identity: object | None
    attended_terminal: bool


@dataclass(frozen=True)
class ToolSelection:
    mode: MergeMode
    name: ToolName
    source: PreferenceSource
    adapter_identity: object


def _tool_name(scalar: Preference) -> ToolName:
    if scalar is PreferenceError.UNAVAILABLE:
        raise MergeError("Merge tool preference is unavailable")
    if type(scalar) is not bytes or not 0 < len(scalar) <= MAX_TOOL_BYTES:
        raise MergeError("Invalid merge tool preference")
    if scalar != b"vimdiff":
        raise MergeError("Unsupported merge tool preference")
    return ToolName.VIMDIFF


def select_tool(
    settings: MergePreferences, preferences: ScopedPreferences, adapter: AdapterFixture
) -> ToolSelection:
    if (
        settings.mode is not MergeMode.THREE_WAY
        or settings.tool_policy is not ToolPolicy.GIT_PREFERENCE
    ):
        raise MergeError("Unsupported merge mode or tool policy")
    if preferences.repository is RepositoryStatus.ABSENT:
        if preferences.local is not None:
            raise MergeError("Repository preference has no verified source")
    elif preferences.repository is not RepositoryStatus.VERIFIED:
        raise MergeError("Repository identity is uncertain")

    if preferences.local is not None:
        name = _tool_name(preferences.local)
        source = PreferenceSource.LOCAL
    else:
        if PreferenceError.UNAVAILABLE in (preferences.global_xdg, preferences.global_home):
            raise MergeError("Global merge tool preference is unavailable")
        if preferences.global_home is not None:
            name = _tool_name(preferences.global_home)
            source = PreferenceSource.GLOBAL_HOME
        elif preferences.global_xdg is not None:
            name = _tool_name(preferences.global_xdg)
            source = PreferenceSource.GLOBAL_XDG
        else:
            name = ToolName.VIMDIFF
            source = PreferenceSource.FALLBACK

    if adapter.identity is None:
        raise MergeError("vimdiff adapter is unavailable")
    if adapter.attended_terminal is not True:
        raise MergeError("vimdiff requires an attended terminal")
    return ToolSelection(settings.mode, name, source, adapter.identity)


@dataclass(frozen=True)
class Revision:
    identity: object
    contents: bytes

    def _has_bounded_bytes(self) -> bool:
        return (
            self.identity is not None
            and type(self.contents) is bytes
            and len(self.contents) <= MAX_TEXT_BYTES
        )

    def digest(self) -> str:
        if not self._has_bounded_bytes():
            raise MergeError("Invalid or oversized merge input")
        if b"\0" in self.contents:
            raise MergeError("Merge input is not text")
        try:
            self.contents.decode("utf-8")
        except UnicodeDecodeError:
            raise MergeError("Merge input is not UTF-8") from None
        return sha256(self.contents).hexdigest()


@dataclass(frozen=True)
class Inputs:
    base: Revision | None
    host: Revision | None
    agent: Revision | None


@dataclass(frozen=True)
class SessionBinding:
    session: object
    target: str
    agent_identity: object
    input_digests: tuple[str, str, str]


@dataclass(frozen=True)
class MergePrompt:
    binding: SessionBinding
    selection: ToolSelection


@dataclass(frozen=True)
class MergeOperation:
    approved: MergePrompt
    inputs: Inputs


class MergeOutcome(Enum):
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    UNCERTAIN = "uncertain"


@dataclass(frozen=True)
class MergeReceipt:
    operation: MergeOperation
    outcome: MergeOutcome
    adapter_identity: object
    observed_inputs: Inputs
    output: Revision | None = None
    saved_identity: object | None = None


@dataclass(frozen=True)
class FinishPrompt:
    binding: SessionBinding
    output_digest: str


@dataclass(frozen=True)
class DestinationFixture:
    parent_identity: object
    leaf: str
    trusted_new_file: bool


@dataclass(frozen=True)
class ExportPrompt:
    binding: SessionBinding
    output_digest: str
    destination: DestinationFixture


@dataclass(frozen=True)
class ExportOperation:
    approved: ExportPrompt
    output: bytes


class ExportOutcome(Enum):
    VERIFIED_CREATED = "verified-created"
    EXISTS = "exists"
    UNCERTAIN = "uncertain"


@dataclass(frozen=True)
class ExportReceipt:
    operation: ExportOperation
    outcome: ExportOutcome
    destination: DestinationFixture
    observed_output: Revision | None = None
    created_identity: object | None = None


class Phase(Enum):
    NO_HOST_CHANGE = "no-host-change"
    MERGE_REQUIRED = "merge-required"
    EDITING = "editing"
    FINISH_REQUIRED = "finish-required"
    READY = "ready"
    EXPORTING = "exporting"
    RECOVERY = "recovery"
    CLOSED = "closed"


@dataclass(frozen=True)
class Recovery:
    inputs: Inputs
    output: Revision | None
    preparation_error: str | None


def _is_optional_revision(value: object) -> bool:
    return value is None or type(value) is Revision


def _same_revision(expected: Revision | None, observed: Revision | None) -> bool:
    return (
        expected is not None
        and observed is not None
        and expected.identity is observed.identity
        and expected.digest() == observed.digest()
    )


class MergeSession:
    def __init__(self, owner: object, target: str, inputs: Inputs):
        if owner is None:
            raise MergeError("Session owner is required")
        self._lock = Lock()
        self._owner = owner
        self._output: Revision | None = None
        self._prompt: MergePrompt | FinishPrompt | ExportPrompt | None = None
        self._operation: MergeOperation | ExportOperation | None = None
        retained_inputs: list[Revision | None] = []
        digests: list[str] = []
        errors: list[str] = []
        for role, revision, keep_non_text in (
            ("Base", inputs.base, False),
            ("Host", inputs.host, True),
            ("Agent", inputs.agent, False),
        ):
            retained = None
            try:
                if revision is None:
                    raise MergeError("Missing merge input")
                if type(revision) is not Revision or not revision._has_bounded_bytes():
                    raise MergeError("Invalid or oversized merge input")
                if keep_non_text:
                    retained = revision
                digests.append(revision.digest())
                retained = revision
            except MergeError as exc:
                errors.append(f"{role} revision could not be used for merge. {exc}")
            retained_inputs.append(retained)
        self._inputs: Inputs | None = Inputs(*retained_inputs)
        self._preparation_error = ". ".join(errors) if errors else None
        if errors:
            self._phase = Phase.RECOVERY
            return
        base, host, agent = digests
        self._binding = SessionBinding(object(), target, inputs.agent.identity, (base, host, agent))
        if host == base:
            self._phase = Phase.NO_HOST_CHANGE
        elif agent == base:
            self._output = Revision(object(), inputs.host.contents)
            self._phase = Phase.READY
        else:
            self._phase = Phase.MERGE_REQUIRED

    @property
    def phase(self) -> Phase:
        with self._lock:
            return self._phase

    def _require(self, owner: object, *phases: Phase) -> None:
        if owner is not self._owner:
            raise MergeError("Session owner could not be verified")
        if self._phase not in phases:
            raise MergeError("Action is unavailable in this session phase")

    def _confirm(self, prompt: MergePrompt | FinishPrompt | ExportPrompt) -> None:
        if prompt is None or prompt is not self._prompt:
            raise MergeError("Confirmation does not match the current prompt")
        self._prompt = None

    def _verify_revision(self, expected: Revision | None, observed: Revision | None) -> None:
        try:
            if _same_revision(expected, observed):
                return
        except MergeError:
            pass
        self._phase = Phase.RECOVERY
        raise MergeError("Reviewed revision could not be verified")

    def recovery(self, owner: object) -> Recovery:
        with self._lock:
            self._require(owner, *(phase for phase in Phase if phase is not Phase.CLOSED))
            return Recovery(self._inputs, self._output, self._preparation_error)

    def offer_merge(
        self, owner: object, preferences: ScopedPreferences, adapter: AdapterFixture
    ) -> MergePrompt:
        with self._lock:
            self._require(owner, Phase.MERGE_REQUIRED)
            self._prompt = None
            if preferences.agent_identity is not self._binding.agent_identity:
                raise MergeError("Merge preferences do not match the original file")
            selected = select_tool(merge_preferences(), preferences, adapter)
            prompt = MergePrompt(self._binding, selected)
            self._prompt = prompt
            return prompt

    def open_merge(
        self, owner: object, prompt: MergePrompt, agent: Revision | None, adapter: AdapterFixture
    ) -> MergeOperation:
        with self._lock:
            self._require(owner, Phase.MERGE_REQUIRED)
            self._confirm(prompt)
            self._verify_revision(self._inputs.agent, agent)
            if (
                adapter.identity is not prompt.selection.adapter_identity
                or adapter.attended_terminal is not True
            ):
                raise MergeError("Reviewed adapter is no longer available")
            operation = MergeOperation(prompt, self._inputs)
            self._operation = operation
            self._phase = Phase.EDITING
            return operation

    def complete_merge(self, owner: object, receipt: MergeReceipt) -> FinishPrompt | None:
        with self._lock:
            self._require(owner, Phase.EDITING, Phase.RECOVERY)
            operation = self._operation
            if (
                type(receipt) is not MergeReceipt
                or type(operation) is not MergeOperation
                or receipt.operation is not operation
            ):
                raise MergeError("Completion does not match the current merge operation")
            inputs = receipt.observed_inputs
            output = receipt.output
            if type(receipt.outcome) is not MergeOutcome or type(inputs) is not Inputs:
                raise MergeError("Malformed merge receipt")
            observed_sources = (inputs.base, inputs.host, inputs.agent)
            if not all(_is_optional_revision(value) for value in (*observed_sources, output)):
                raise MergeError("Malformed merge receipt")

            self._phase = Phase.RECOVERY
            if receipt.adapter_identity is not operation.approved.selection.adapter_identity:
                raise MergeError("Completion came from a different adapter")
            sources = (self._inputs.base, self._inputs.host, self._inputs.agent)
            digest = None
            if output is not None and all(
                output.identity is not source.identity for source in sources
            ):
                try:
                    digest = output.digest()
                except MergeError:
                    pass
                else:
                    # Preserve the first usable recovery copy until a result is verified.
                    if self._output is None:
                        self._output = output
            # Terminal cancellation settles the lease even if there is no usable output.
            if receipt.outcome is MergeOutcome.CANCELLED:
                self._operation = None
                return None
            if receipt.outcome is not MergeOutcome.COMPLETED:
                raise MergeError("Merge completion could not be verified")
            for expected, observed in zip(sources, observed_sources):
                self._verify_revision(expected, observed)
            if digest is None or output.identity is not receipt.saved_identity:
                raise MergeError("Completed merge has no verified output")
            self._output = output
            self._operation = None
            prompt = FinishPrompt(self._binding, digest)
            self._prompt = prompt
            self._phase = Phase.FINISH_REQUIRED
            return prompt

    def finish_merge(self, owner: object, prompt: FinishPrompt, observed_output: Revision | None) -> None:
        with self._lock:
            self._require(owner, Phase.FINISH_REQUIRED)
            self._confirm(prompt)
            self._verify_revision(self._output, observed_output)
            self._phase = Phase.READY

    def offer_export(self, owner: object, destination: DestinationFixture) -> ExportPrompt:
        with self._lock:
            self._require(owner, Phase.READY)
            self._prompt = None
            leaf = destination.leaf
            if (
                destination.trusted_new_file is not True
                or destination.parent_identity is None
                or type(leaf) is not str
                or len(leaf) > 255
                or leaf in {"", ".", ".."}
                or not leaf.isprintable()
                or len(leaf.encode("utf-8")) > 255
                or any(char in leaf for char in ("/", "\\"))
            ):
                raise MergeError("Export requires a new file in a trusted destination")
            prompt = ExportPrompt(self._binding, self._output.digest(), destination)
            self._prompt = prompt
            return prompt

    def begin_export(
        self, owner: object, prompt: ExportPrompt, agent: Revision | None, output: Revision | None
    ) -> ExportOperation:
        with self._lock:
            self._require(owner, Phase.READY)
            self._confirm(prompt)
            self._verify_revision(self._inputs.agent, agent)
            self._verify_revision(self._output, output)
            operation = ExportOperation(prompt, self._output.contents)
            self._operation = operation
            self._phase = Phase.EXPORTING
            return operation

    def complete_export(self, owner: object, receipt: ExportReceipt) -> None:
        with self._lock:
            self._require(owner, Phase.EXPORTING, Phase.RECOVERY)
            operation = self._operation
            if (
                type(receipt) is not ExportReceipt
                or type(operation) is not ExportOperation
                or receipt.operation is not operation
            ):
                raise MergeError("Publication does not match the current export operation")
            observed_destination = receipt.destination
            observed_output = receipt.observed_output
            if (
                type(receipt.outcome) is not ExportOutcome
                or type(observed_destination) is not DestinationFixture
                or type(observed_destination.leaf) is not str
                or type(observed_destination.trusted_new_file) is not bool
                or not _is_optional_revision(observed_output)
            ):
                raise MergeError("Malformed export receipt")

            self._phase = Phase.RECOVERY
            destination = operation.approved.destination
            if (
                observed_destination.parent_identity is not destination.parent_identity
                or observed_destination.leaf != destination.leaf
                or observed_destination.trusted_new_file is not True
            ):
                raise MergeError("Export destination could not be verified")
            if receipt.outcome is ExportOutcome.EXISTS:
                if receipt.created_identity is not None or observed_output is not None:
                    raise MergeError("Export conflict receipt reports a publication")
                self._operation = None
                self._phase = Phase.READY
                return
            private_revisions = (self._output, self._inputs.base, self._inputs.host, self._inputs.agent)
            if (
                receipt.outcome is not ExportOutcome.VERIFIED_CREATED
                or observed_output is None
                or observed_output.identity is not receipt.created_identity
                or any(receipt.created_identity is revision.identity for revision in private_revisions)
                or observed_output.digest() != operation.approved.output_digest
            ):
                raise MergeError("Export publication could not be verified")
            self._close()

    def discard(self, owner: object) -> None:
        with self._lock:
            self._require(
                owner,
                Phase.NO_HOST_CHANGE,
                Phase.MERGE_REQUIRED,
                Phase.FINISH_REQUIRED,
                Phase.READY,
                Phase.RECOVERY,
            )
            if self._operation is not None:
                raise MergeError("An operation still owns this recovery session")
            self._close()

    def _close(self) -> None:
        self._inputs = None
        self._output = None
        self._prompt = None
        self._operation = None
        self._preparation_error = None
        self._phase = Phase.CLOSED
