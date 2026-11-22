"""Host-trusted ConfigStore, persistent-inode flock, durable proposals, and real oc_controller integration.

Integrates directly with production `oc_controller.Controller` (without modifying it!)
using `_ID`-compliant identifiers, Role.JOB propose/invoke, operator view()/decide(),
non-terminal State.UNCERTAIN handling (and "applying" crash recovery), and monotonic revisions.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import time
from typing import Any, Iterator

# Import production oc_controller.py from repository root (read-only)
_REPO_ROOT = Path(__file__).resolve().parents[4]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import oc_controller as occ  # noqa: E402

from oc_plan import (  # noqa: E402
    CompiledPlanResult,
    PlanOverrides,
    compile_plan,
    compute_closed_security_delta,
)
from oc_schema import (  # noqa: E402
    MAX_CONFIG_FILE_BYTES,
    MUTABLE_ORCHESTRATOR_KINDS,
    PROPOSAL_ACTIONS,
    PROPOSAL_ID_RE,
    READABLE_ORCHESTRATOR_KINDS,
    PolicyError,
    SchemaError,
    assert_trusted_dir,
    canonical_json,
    check_not_in_sandbox,
    is_builtin_id,
    parse_toml_strict,
    read_regular_no_follow,
    sha256_canonical_json,
    validate_doc_by_kind,
    validate_opaque_id,
)

KIND_DIRS = {
    "service": "services",
    "bundle": "bundles",
    "sandbox-type": "sandbox-types",
    "worker": "workers",
    "host-provider": "host-providers",
    "transport": "transports",
}

MAX_PENDING_PROPOSALS = 32
DEFAULT_PROPOSAL_TTL_SECONDS = 900
DEFAULT_BUILTIN_DIR = Path(__file__).resolve().parent / "builtin"


class StoreError(RuntimeError):
    """ConfigStore / proposal / publish error."""


class ConflictError(StoreError):
    """State or dependency conflict."""


class StaleProposalError(StoreError):
    """Stale store revision, transitive closure mismatch, or prior incarnation."""


class DigestMismatchError(StoreError):
    """Operator approval digest mismatch."""


class ExpiredProposalError(StoreError):
    """Proposal TTL expired."""


class PublishUncertainError(StoreError):
    """Controller invocation returned State.UNCERTAIN; reconcile required."""


def _atomic_write_0600(target: Path, data: bytes) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(target.parent, 0o700)
    tmp = target.parent / f".{target.name}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(tmp, flags, 0o600)
    try:
        view = memoryview(data)
        written = 0
        while written < len(view):
            written += os.write(fd, view[written:])
        os.fsync(fd)
    except Exception:
        os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.close(fd)
    os.replace(tmp, target)
    dir_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _append_journal_0600(journal_path: Path, entry: dict[str, Any]) -> None:
    line = (canonical_json(entry) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW
    fd = os.open(journal_path, flags, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PolicyError(f"Non-regular journal file rejected: {journal_path}")
        if st.st_nlink != 1:
            raise PolicyError(f"Hardlinked journal file rejected: {journal_path}")
        if st.st_uid != os.geteuid():
            raise PolicyError(f"Journal file not owned by current user: {journal_path}")
        if st.st_mode & 0o077:
            raise PolicyError(f"Journal file permissions too open (require 0600): {journal_path}")
        view = memoryview(line)
        written = 0
        while written < len(view):
            written += os.write(fd, view[written:])
        os.fsync(fd)
    finally:
        os.close(fd)


class _OverlayStoreView:
    """In-memory read-only overlay used for plan_preview and dry-run proposal validation."""

    def __init__(
        self,
        base: "HostConfigStore",
        overrides: dict[tuple[str, str], dict[str, Any] | None],
        archived_overrides: dict[tuple[str, str], bool],
    ):
        self._base = base
        self._overrides = overrides
        self._archived = archived_overrides

    def get(self, kind: str, obj_id: str, *, include_archived: bool = False) -> dict[str, Any]:
        key = (kind, obj_id)
        if not include_archived and self._archived.get(key, False):
            raise KeyError(f"{kind}/{obj_id} is archived")
        if key in self._overrides:
            doc = self._overrides[key]
            if doc is None:
                raise KeyError(f"{kind}/{obj_id} not found")
            return doc
        return self._base.get(kind, obj_id, include_archived=include_archived)

    def list_ids(self, kind: str, *, include_archived: bool = False) -> list[str]:
        ids = set(self._base.list_ids(kind, include_archived=True))
        for (k, oid), doc in self._overrides.items():
            if k == kind and doc is not None:
                ids.add(oid)
        result = []
        for oid in sorted(ids):
            key = (kind, oid)
            is_arch = self._archived[key] if key in self._archived else self._base.is_archived(kind, oid)
            if include_archived or not is_arch:
                result.append(oid)
        return result

    def get_revision(self, kind: str, obj_id: str) -> int:
        if (kind, obj_id) in self._overrides or (kind, obj_id) in self._archived:
            return self._base.get_revision(kind, obj_id) + 1
        return self._base.get_revision(kind, obj_id)

    def bundle_asset_root(self, bundle_id: str) -> Path | None:
        return self._base.bundle_asset_root(bundle_id)


class ConfigPublishAdapter:
    """Implements oc_controller.FixtureAdapter for atomic config publishing + journal reconciliation."""

    def __init__(self, store: "HostConfigStore"):
        self._store = store
        self._pending_exec: dict[str, dict[str, Any]] = {}
        self.inject_uncertain_once: bool = False
        self.inject_crash_after_write_once: bool = False

    def target_revision(self, target: str) -> str | None:
        if target != "config_store_target":
            return None
        return hashlib.sha256(f"store-rev:{self._store.store_revision}".encode("utf-8")).hexdigest()

    def set_target_revision(self, target: str, revision: str | None) -> None:
        _ = (target, revision)

    def stage_for_request(self, request_id: str, proposal: dict[str, Any]) -> None:
        self._pending_exec[request_id] = proposal

    def dispatch(self, attempt: occ.Attempt, payload: occ.Payload) -> occ.Outcome:
        proposal = self._pending_exec.get(attempt.request_id)
        if proposal is None:
            return occ.Outcome.DEFINITE_FAILURE
        expected_rev = self.target_revision(payload.pin.target)
        if expected_rev != payload.pin.revision:
            return occ.Outcome.DEFINITE_FAILURE
        if self.inject_uncertain_once:
            self.inject_uncertain_once = False
            # Simulate uncertain network/disk outcome where nothing was journaled yet
            return occ.Outcome.UNKNOWN
        self._store._commit_proposal_effect_unlocked(proposal, attempt.request_id)
        if self.inject_crash_after_write_once:
            self.inject_crash_after_write_once = False
            # Simulate crash after atomic publish + journal commit (outcome appears UNKNOWN to caller)
            return occ.Outcome.UNKNOWN
        return occ.Outcome.SUCCEEDED

    def reconcile(self, attempt: occ.Attempt, payload: occ.Payload) -> occ.Outcome:
        _ = payload
        if self._store.journal_has_request_id(attempt.request_id):
            return occ.Outcome.SUCCEEDED
        return occ.Outcome.DEFINITE_FAILURE


@dataclass(frozen=True, slots=True)
class ApprovalPrincipals:
    operator: occ.Principal
    orchestrator: occ.Principal
    config_job: occ.Principal
    subject: occ.Subject


class HostConfigStore:
    """Host-trusted config store under explicit config_dir + immutable builtin catalog."""

    def __init__(
        self,
        config_dir: Path,
        *,
        builtin_dir: Path = DEFAULT_BUILTIN_DIR,
        clock: Any = None,
        incarnation: str | None = None,
        sandbox_root: Path | None = None,
    ):
        self.sandbox_root = sandbox_root
        raw_config_dir = Path(config_dir)
        check_not_in_sandbox(raw_config_dir, sandbox_root)
        if raw_config_dir.is_symlink():
            raise PolicyError(f"Expected non-symlink config_dir: {raw_config_dir}")
        raw_config_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(raw_config_dir, 0o700)
        self.config_dir = assert_trusted_dir(raw_config_dir, sandbox_root=sandbox_root)
        self.builtin_dir = builtin_dir.resolve()
        self._clock = clock or (lambda: int(time.monotonic()))
        self._ensure_layout()
        self._builtins: dict[tuple[str, str], dict[str, Any]] = {}
        self._builtin_paths: dict[tuple[str, str], Path] = {}
        self._load_builtins()

        self.incarnation = incarnation or secrets.token_hex(16)
        self.principals = ApprovalPrincipals(
            operator=occ.Principal(occ.Role.OPERATOR, "host_operator"),
            orchestrator=occ.Principal(occ.Role.ORCHESTRATOR, "oc_orchestrator"),
            config_job=occ.Principal(occ.Role.JOB, "config_publisher"),
            subject=occ.Subject("host_controller", f"cfg_{self.incarnation[:12]}", "config_publisher"),
        )
        self.adapter = ConfigPublishAdapter(self)
        self.controller = occ.Controller(
            incarnation=self.incarnation,
            clock=self._clock,
            lifetime=DEFAULT_PROPOSAL_TTL_SECONDS,
            workers=[occ.Worker("host_controller", self.principals.operator)],
            jobs=[occ.Job(self.principals.subject, self.principals.orchestrator, 256)],
            capabilities=[occ.Capability("cap_config_apply", occ.Operation.APPLY, "config_store_target")],
            references=[occ.Reference("config_store_apply", "cap_config_apply")],
            adapter=self.adapter,
        )
        self.controller._set_alias("config_store", "config_store_target")

    def _ensure_layout(self) -> None:
        assert_trusted_dir(self.config_dir, sandbox_root=self.sandbox_root)
        for sub in ("objects", "proposals", "revisions"):
            d = self.config_dir / sub
            if d.is_symlink():
                raise PolicyError(f"Expected non-symlink store subdirectory: {d}")
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o700)
            assert_trusted_dir(d, sandbox_root=self.sandbox_root)
        self._lock_path = self.config_dir / "store.lock"
        # Create persistent-inode lock file without ever unlinking it
        fd = os.open(self._lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_nlink != 1:
                raise PolicyError(f"Untrusted lock file: {self._lock_path}")
            if stat.S_IMODE(st.st_mode) != 0o600:
                os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        self._state_path = self.config_dir / "state.json"
        self._journal_path = self.config_dir / "journal.jsonl"
        if not self._state_path.exists():
            _atomic_write_0600(
                self._state_path,
                canonical_json({"store_revision": 0, "objects": {}}).encode("utf-8"),
            )

    @contextmanager
    def persistent_flock(self) -> Iterator[None]:
        """Persistent-inode exclusive flock (O_NOFOLLOW, 0o600, fstat + inode verified, never unlinked)."""
        fd = os.open(self._lock_path, os.O_RDWR | os.O_NOFOLLOW)
        locked = False
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise PolicyError(f"Non-regular lock file rejected: {self._lock_path}")
            if st.st_uid != os.geteuid():
                raise PolicyError(f"Lock file not owned by current user: {self._lock_path}")
            if stat.S_IMODE(st.st_mode) != 0o600:
                raise PolicyError(f"Lock file mode must be 0600: {self._lock_path}")
            if st.st_nlink != 1:
                raise PolicyError(f"Hardlinked lock file rejected: {self._lock_path}")
            fcntl.flock(fd, fcntl.LOCK_EX)
            locked = True
            lst = os.lstat(self._lock_path)
            if (lst.st_dev, lst.st_ino) != (st.st_dev, st.st_ino):
                raise PolicyError(f"Lock file inode replaced during flock: {self._lock_path}")
            yield
        finally:
            try:
                if locked:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _load_builtins(self) -> None:
        for kind, dirname in KIND_DIRS.items():
            kdir = self.builtin_dir / dirname
            if not kdir.exists():
                continue
            for path in sorted(kdir.glob("*.toml")):
                raw = read_regular_no_follow(path, max_bytes=MAX_CONFIG_FILE_BYTES, confined_root=self.builtin_dir)
                parsed = parse_toml_strict(raw.decode("utf-8"), context=str(path.name))
                doc = validate_doc_by_kind(kind, parsed, for_orchestrator=False)
                if not is_builtin_id(doc["id"]):
                    raise SchemaError(f"Builtin file {path} must declare builtin/* id")
                self._builtins[(kind, doc["id"])] = doc
                self._builtin_paths[(kind, doc["id"])] = path.parent

    def _read_state(self) -> dict[str, Any]:
        raw = read_regular_no_follow(
            self._state_path,
            max_bytes=1_048_576,
            require_owner_only=True,
            confined_root=self.config_dir,
            sandbox_root=self.sandbox_root,
        )
        return json.loads(raw.decode("utf-8"))

    def _write_state(self, state: dict[str, Any]) -> None:
        _atomic_write_0600(self._state_path, canonical_json(state).encode("utf-8"))

    @property
    def store_revision(self) -> int:
        return int(self._read_state()["store_revision"])

    def _obj_key(self, kind: str, obj_id: str) -> str:
        return f"{kind}:{obj_id}"

    @staticmethod
    def _encode_id(obj_id: str) -> str:
        # Injective: '@' is forbidden by OPAQUE_ID_RE, so "team/foo" -> "team@foo" never collides with "team__foo".
        validate_opaque_id(obj_id, label="id")
        return obj_id.replace("/", "@")

    def _obj_file(self, kind: str, obj_id: str) -> Path:
        if kind not in READABLE_ORCHESTRATOR_KINDS:
            raise SchemaError(f"Unknown kind: {kind!r}")
        safe = self._encode_id(obj_id)
        return self.config_dir / "objects" / f"{kind}__{safe}.toml"

    def _rev_file(self, kind: str, obj_id: str, rev: int) -> Path:
        if kind not in READABLE_ORCHESTRATOR_KINDS:
            raise SchemaError(f"Unknown kind: {kind!r}")
        if type(rev) is not int or rev < 1:
            raise SchemaError(f"Invalid revision: {rev!r}")
        safe = self._encode_id(obj_id)
        return self.config_dir / "revisions" / f"{kind}__{safe}.r{rev}.toml"

    def _proposal_file(self, proposal_id: str) -> Path:
        if type(proposal_id) is not str or PROPOSAL_ID_RE.fullmatch(proposal_id) is None:
            raise SchemaError("Invalid proposal_id")
        return self.config_dir / "proposals" / f"{proposal_id}.json"

    def bundle_asset_root(self, bundle_id: str) -> Path | None:
        validate_opaque_id(bundle_id, label="bundle_id")
        if ("bundle", bundle_id) in self._builtin_paths:
            return self._builtin_paths[("bundle", bundle_id)]
        asset_dir = self.config_dir / "assets" / self._encode_id(bundle_id)
        return asset_dir if asset_dir.is_dir() else None

    def is_archived(self, kind: str, obj_id: str) -> bool:
        if (kind, obj_id) in self._builtins:
            return False
        st = self._read_state()["objects"].get(self._obj_key(kind, obj_id))
        return bool(st and st.get("archived", False))

    def get_revision(self, kind: str, obj_id: str) -> int:
        if (kind, obj_id) in self._builtins:
            return 1
        st = self._read_state()["objects"].get(self._obj_key(kind, obj_id))
        return int(st["revision"]) if st else 0

    def get_raw_toml(self, kind: str, obj_id: str, *, include_archived: bool = False) -> str:
        if kind not in READABLE_ORCHESTRATOR_KINDS:
            raise SchemaError(f"Unknown kind: {kind!r}")
        validate_opaque_id(obj_id, label="id")
        if (kind, obj_id) in self._builtins:
            name = obj_id.split("/", 1)[1] + ".toml"
            p = self.builtin_dir / KIND_DIRS[kind] / name
            return read_regular_no_follow(p, confined_root=self.builtin_dir).decode("utf-8")
        if not include_archived and self.is_archived(kind, obj_id):
            raise KeyError(f"{kind}/{obj_id} is archived")
        p = self._obj_file(kind, obj_id)
        if not p.exists():
            raise KeyError(f"{kind}/{obj_id} not found")
        return read_regular_no_follow(
            p,
            require_owner_only=True,
            confined_root=self.config_dir / "objects",
            sandbox_root=self.sandbox_root,
        ).decode("utf-8")

    def get(self, kind: str, obj_id: str, *, include_archived: bool = False) -> dict[str, Any]:
        if kind not in READABLE_ORCHESTRATOR_KINDS:
            raise SchemaError(f"Unknown kind: {kind!r}")
        validate_opaque_id(obj_id, label="id")
        if (kind, obj_id) in self._builtins:
            return self._builtins[(kind, obj_id)]
        if not include_archived and self.is_archived(kind, obj_id):
            raise KeyError(f"{kind}/{obj_id} is archived")
        raw = self.get_raw_toml(kind, obj_id, include_archived=include_archived)
        return validate_doc_by_kind(
            kind, parse_toml_strict(raw, context=f"{kind}/{obj_id}"), expected_id=obj_id, for_orchestrator=False
        )

    def list_ids(self, kind: str, *, include_archived: bool = False) -> list[str]:
        if kind not in READABLE_ORCHESTRATOR_KINDS:
            raise SchemaError(f"Unknown kind: {kind!r}")
        ids = {oid for (k, oid) in self._builtins if k == kind}
        state = self._read_state()["objects"]
        prefix = f"{kind}:"
        for key, meta in state.items():
            if not key.startswith(prefix):
                continue
            if not include_archived and meta.get("archived", False):
                continue
            ids.add(key[len(prefix) :])
        return sorted(ids)

    def get_history(self, kind: str, obj_id: str) -> list[dict[str, Any]]:
        if kind not in READABLE_ORCHESTRATOR_KINDS:
            raise SchemaError(f"Unknown kind: {kind!r}")
        validate_opaque_id(obj_id, label="id")
        if not self._journal_path.exists():
            return []
        raw = read_regular_no_follow(
            self._journal_path,
            max_bytes=4_194_304,
            require_owner_only=True,
            confined_root=self.config_dir,
            sandbox_root=self.sandbox_root,
        ).decode("utf-8")
        entries = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("kind") == kind and rec.get("obj_id") == obj_id:
                entries.append(rec)
        return entries

    def get_revision_toml(self, kind: str, obj_id: str, rev: int) -> str:
        if kind not in READABLE_ORCHESTRATOR_KINDS:
            raise SchemaError(f"Unknown kind: {kind!r}")
        validate_opaque_id(obj_id, label="id")
        if type(rev) is not int or rev < 1:
            raise SchemaError("Revision must be a positive integer")
        p = self._rev_file(kind, obj_id, rev)
        if not p.exists():
            raise KeyError(f"Revision {rev} not found for {kind}/{obj_id}")
        return read_regular_no_follow(
            p,
            require_owner_only=True,
            confined_root=self.config_dir / "revisions",
            sandbox_root=self.sandbox_root,
        ).decode("utf-8")

    def get_revision_doc(self, kind: str, obj_id: str, rev: int) -> dict[str, Any]:
        raw = self.get_revision_toml(kind, obj_id, rev)
        return validate_doc_by_kind(
            kind, parse_toml_strict(raw, context=f"{kind}/{obj_id}@r{rev}"), expected_id=obj_id, for_orchestrator=False
        )

    def with_in_memory_overlay(
        self,
        entries: dict[tuple[str, str], tuple[str, dict[str, Any] | None]],
    ) -> _OverlayStoreView:
        overrides: dict[tuple[str, str], dict[str, Any] | None] = {}
        archived: dict[tuple[str, str], bool] = {}
        for key, (action, doc) in entries.items():
            if action == "archive":
                archived[key] = True
            elif action == "unarchive":
                archived[key] = False
                if doc is not None:
                    overrides[key] = doc
            else:
                archived[key] = False
                overrides[key] = doc
        return _OverlayStoreView(self, overrides, archived)

    def has_active_dependents(self, kind: str, obj_id: str) -> list[str]:
        """Return active objects referencing (kind, obj_id)."""
        refs: list[str] = []
        if kind == "bundle":
            for st_id in self.list_ids("sandbox-type", include_archived=False):
                if obj_id in self.get("sandbox-type", st_id)["bundles"]:
                    refs.append(f"sandbox-type:{st_id}")
            for b_id in self.list_ids("bundle", include_archived=False):
                if b_id != obj_id and obj_id in self.get("bundle", b_id)["includes"]:
                    refs.append(f"bundle:{b_id}")
        elif kind == "service":
            for b_id in self.list_ids("bundle", include_archived=False):
                b = self.get("bundle", b_id)
                targets = (
                    [r["target"] for r in b["requires_services"]]
                    + [r["provider"] for r in b["requires_services"] if r["provider"]]
                    + [ls["service"] for ls in b["local_services"]]
                    + [m["local"]["service"] for m in b["mcp"].values() if m["local"]]
                )
                if obj_id in targets:
                    refs.append(f"bundle:{b_id}")
            for s_id in self.list_ids("service", include_archived=False):
                if s_id == obj_id:
                    continue
                s = self.get("service", s_id)
                targets = (
                    [r["target"] for r in s["requires"]]
                    + [r["provider"] for r in s["requires"] if r["provider"]]
                    + ([s["fallback_service"]] if s["fallback_service"] else [])
                )
                if obj_id in targets:
                    refs.append(f"service:{s_id}")
        return sorted(refs)

    def _list_proposals_unlocked(self) -> list[dict[str, Any]]:
        pdir = self.config_dir / "proposals"
        out = []
        for p in sorted(pdir.glob("*.json")):
            raw = read_regular_no_follow(
                p, require_owner_only=True, confined_root=pdir, sandbox_root=self.sandbox_root
            )
            out.append(json.loads(raw.decode("utf-8")))
        return out

    def load_proposal(self, proposal_id: str) -> dict[str, Any]:
        if type(proposal_id) is not str or PROPOSAL_ID_RE.fullmatch(proposal_id) is None:
            raise SchemaError("Invalid proposal_id")
        p = self._proposal_file(proposal_id)
        if not p.exists():
            raise KeyError(f"Proposal not found: {proposal_id}")
        return json.loads(
            read_regular_no_follow(
                p,
                require_owner_only=True,
                confined_root=self.config_dir / "proposals",
                sandbox_root=self.sandbox_root,
            ).decode("utf-8")
        )

    def _save_proposal_unlocked(self, proposal: dict[str, Any]) -> None:
        _atomic_write_0600(
            self._proposal_file(proposal["id"]),
            canonical_json(proposal).encode("utf-8"),
        )

    def assert_no_unresolved_uncertain_proposals(self) -> None:
        """Block new proposals/publishes if any proposal is in 'applying' or 'uncertain'."""
        for prop in self._list_proposals_unlocked():
            if prop["status"] in ("applying", "uncertain"):
                raise ConflictError(
                    f"Unresolved {prop['status']} proposal {prop['id']}; run config reconcile first"
                )

    def journal_has_request_id(self, request_id: str) -> bool:
        if not self._journal_path.exists():
            return False
        raw = read_regular_no_follow(
            self._journal_path,
            max_bytes=4_194_304,
            require_owner_only=True,
            confined_root=self.config_dir,
            sandbox_root=self.sandbox_root,
        ).decode("utf-8")
        for line in raw.splitlines():
            if not line.strip():
                continue
            if json.loads(line).get("controller_request_id") == request_id:
                return True
        return False

    def _dry_run_affected_plans(
        self,
        kind: str,
        obj_id: str,
        action: str,
        validated_doc: dict[str, Any] | None,
    ) -> tuple[dict[str, CompiledPlanResult], dict[str, CompiledPlanResult], str]:
        draft_view = self.with_in_memory_overlay({(kind, obj_id): (action, validated_doc)})
        old_st_ids = set(self.list_ids("sandbox-type", include_archived=False))
        new_st_ids = set(draft_view.list_ids("sandbox-type", include_archived=False))
        old_plans: dict[str, CompiledPlanResult] = {}
        new_plans: dict[str, CompiledPlanResult] = {}
        closure_items: list[Any] = [(kind, obj_id, self.get_revision(kind, obj_id))]

        for st_id in sorted(old_st_ids):
            old_plans[st_id] = compile_plan(self, st_id)
            closure_items.append(("old_plan", st_id, old_plans[st_id].closure_digest))
        for st_id in sorted(new_st_ids):
            new_plans[st_id] = compile_plan(draft_view, st_id)
            closure_items.append(("new_plan", st_id, new_plans[st_id].closure_digest))

        return old_plans, new_plans, sha256_canonical_json(closure_items)

    def create_proposal(
        self,
        *,
        kind: str,
        obj_id: str,
        action: str,
        proposed_toml: str | None,
        ttl_seconds: int = DEFAULT_PROPOSAL_TTL_SECONDS,
    ) -> dict[str, Any]:
        if kind not in MUTABLE_ORCHESTRATOR_KINDS:
            raise PolicyError(f"Kind {kind!r} is not mutable via proposals")
        validate_opaque_id(obj_id, label="id")
        if is_builtin_id(obj_id):
            raise PolicyError("builtin/* namespace is strictly immutable")
        if action not in PROPOSAL_ACTIONS:
            raise SchemaError(f"Invalid proposal action: {action!r}")
        if type(ttl_seconds) is not int or not (1 <= ttl_seconds <= DEFAULT_PROPOSAL_TTL_SECONDS):
            raise SchemaError(
                f"ttl_seconds must be an integer in 1..{DEFAULT_PROPOSAL_TTL_SECONDS}"
            )

        validated_doc: dict[str, Any] | None = None
        if action == "upsert":
            if type(proposed_toml) is not str or not proposed_toml.strip():
                raise SchemaError("upsert requires non-empty proposed_toml")
            if len(proposed_toml.encode("utf-8")) > MAX_CONFIG_FILE_BYTES:
                raise SchemaError("proposed_toml exceeds byte limit")
            validated_doc = validate_doc_by_kind(
                kind,
                parse_toml_strict(proposed_toml, context=f"proposed_toml({kind}/{obj_id})"),
                expected_id=obj_id,
                for_orchestrator=True,
            )
        else:
            if proposed_toml is not None:
                raise SchemaError(f"action={action!r} requires proposed_toml=None")

        with self.persistent_flock():
            self.assert_no_unresolved_uncertain_proposals()
            if action == "archive":
                if self.get_revision(kind, obj_id) == 0:
                    raise KeyError(f"{kind}/{obj_id} does not exist")
                deps = self.has_active_dependents(kind, obj_id)
                if deps:
                    raise ConflictError(f"Cannot archive {kind}/{obj_id}; referenced by: {', '.join(deps)}")
            elif action == "unarchive":
                if not self.is_archived(kind, obj_id):
                    raise ConflictError(f"{kind}/{obj_id} is not archived")
                # Gate 2 note #3: re-validate archived TOML against current schema/orchestrator rules
                archived_raw = self.get_raw_toml(kind, obj_id, include_archived=True)
                validated_doc = validate_doc_by_kind(
                    kind,
                    parse_toml_strict(archived_raw, context=f"archived({kind}/{obj_id})"),
                    expected_id=obj_id,
                    for_orchestrator=True,
                )

            now = self._clock()
            active_pending = 0
            for existing in self._list_proposals_unlocked():
                if existing["status"] == "pending":
                    if now >= existing["expires_at"]:
                        existing["status"] = "expired"
                        self._save_proposal_unlocked(existing)
                    elif existing["incarnation"] == self.incarnation:
                        active_pending += 1
            if active_pending >= MAX_PENDING_PROPOSALS:
                raise ConflictError(f"Pending proposal quota exceeded (max {MAX_PENDING_PROPOSALS})")

            base_store_rev = self.store_revision
            old_plans, new_plans, closure_digest = self._dry_run_affected_plans(
                kind, obj_id, action, validated_doc
            )
            security_delta = compute_closed_security_delta(old_plans, new_plans)

            proposal_id = f"prop_{secrets.token_hex(8)}"
            canonical_body = {
                "id": proposal_id,
                "incarnation": self.incarnation,
                "kind": kind,
                "obj_id": obj_id,
                "action": action,
                "proposed_toml": proposed_toml,
                "base_store_revision": base_store_rev,
                "closure_digest": closure_digest,
                "security_delta_digest": security_delta["digest"],
                "created_at": now,
                "expires_at": now + ttl_seconds,
            }
            proposal_digest = sha256_canonical_json(canonical_body)

            # Submit through real oc_controller.Controller API (Role.JOB + _ID-compliant names)
            try:
                ctrl_status = self.controller.propose(
                    self.principals.config_job,
                    occ.Proposal(occ.Intent.APPLY_ONCE, "config_store", "config_store_apply"),
                )
            except occ.CapacityExceeded as exc:
                raise ConflictError("Controller pending proposal capacity exceeded") from exc
            ctrl_view = self.controller.view(self.principals.operator, ctrl_status.request_id)

            proposal = {
                **canonical_body,
                "digest": proposal_digest,
                "security_delta": security_delta,
                "status": "pending",
                "controller_request_id": ctrl_status.request_id,
                "controller_rev": ctrl_view.payload.revision,
                "controller_digest": ctrl_view.digest,
            }
            self._save_proposal_unlocked(proposal)
            return proposal

    def _commit_proposal_effect_unlocked(self, proposal: dict[str, Any], request_id: str) -> int:
        state = self._read_state()
        kind, obj_id, action = proposal["kind"], proposal["obj_id"], proposal["action"]
        okey = self._obj_key(kind, obj_id)
        prev_meta = state["objects"].get(okey, {"revision": 0, "archived": False})
        new_rev = int(prev_meta["revision"]) + 1
        new_store_rev = int(state["store_revision"]) + 1

        if action == "upsert":
            raw = proposal["proposed_toml"].encode("utf-8")
            _atomic_write_0600(self._obj_file(kind, obj_id), raw)
            _atomic_write_0600(self._rev_file(kind, obj_id, new_rev), raw)
            archived = False
        elif action == "archive":
            archived = True
        else:  # unarchive
            raw = self.get_raw_toml(kind, obj_id, include_archived=True).encode("utf-8")
            _atomic_write_0600(self._rev_file(kind, obj_id, new_rev), raw)
            archived = False

        state["store_revision"] = new_store_rev
        state["objects"][okey] = {"revision": new_rev, "archived": archived}
        self._write_state(state)
        _append_journal_0600(
            self._journal_path,
            {
                "store_revision": new_store_rev,
                "kind": kind,
                "obj_id": obj_id,
                "revision": new_rev,
                "action": action,
                "proposal_id": proposal["id"],
                "proposal_digest": proposal["digest"],
                "controller_request_id": request_id,
            },
        )
        return new_rev

    def approve_proposal(self, proposal_id: str, expected_digest: str) -> int:
        with self.persistent_flock():
            self.assert_no_unresolved_uncertain_proposals()
            proposal = self.load_proposal(proposal_id)
            if proposal["incarnation"] != self.incarnation:
                raise StaleProposalError("Proposal belongs to a prior helper incarnation; re-propose")
            if proposal["status"] != "pending":
                raise ConflictError(f"Proposal {proposal_id} is not pending (status={proposal['status']})")
            if self._clock() >= proposal["expires_at"]:
                proposal["status"] = "expired"
                self._save_proposal_unlocked(proposal)
                raise ExpiredProposalError("Proposal expired")
            if not hmac.compare_digest(proposal["digest"], expected_digest):
                raise DigestMismatchError("Approval digest mismatch")
            if self.store_revision != proposal["base_store_revision"]:
                raise StaleProposalError("Store revision changed since proposal; re-propose")

            kind, obj_id, action = proposal["kind"], proposal["obj_id"], proposal["action"]
            validated_doc: dict[str, Any] | None = None
            if action == "archive":
                deps = self.has_active_dependents(kind, obj_id)
                if deps:
                    raise ConflictError(f"Target {kind}/{obj_id} now referenced by: {', '.join(deps)}")
            elif action == "unarchive":
                archived_raw = self.get_raw_toml(kind, obj_id, include_archived=True)
                validated_doc = validate_doc_by_kind(
                    kind,
                    parse_toml_strict(archived_raw, context=f"archived({kind}/{obj_id})"),
                    expected_id=obj_id,
                    for_orchestrator=True,
                )
            else:
                validated_doc = validate_doc_by_kind(
                    kind,
                    parse_toml_strict(proposal["proposed_toml"], context=f"proposed_toml({kind}/{obj_id})"),
                    expected_id=obj_id,
                    for_orchestrator=True,
                )

            old_plans, new_plans, cur_closure = self._dry_run_affected_plans(
                kind, obj_id, action, validated_doc
            )
            cur_delta = compute_closed_security_delta(old_plans, new_plans)
            if (
                cur_closure != proposal["closure_digest"]
                or cur_delta["digest"] != proposal["security_delta_digest"]
            ):
                raise StaleProposalError("Transitive dependencies or security delta changed")

            proposal["status"] = "applying"
            self._save_proposal_unlocked(proposal)
            self.adapter.stage_for_request(proposal["controller_request_id"], proposal)

            # Gate 2 note #2: check Status returned by controller.decide() BEFORE invoke()
            decide_status = self.controller.decide(
                self.principals.operator,
                proposal["controller_request_id"],
                proposal["controller_rev"],
                proposal["controller_digest"],
                occ.Decision.APPROVE,
            )
            if decide_status.state is occ.State.EXPIRED:
                proposal["status"] = "expired"
                self._save_proposal_unlocked(proposal)
                raise ExpiredProposalError("Controller approval expired")
            if decide_status.state is occ.State.STALE:
                proposal["status"] = "failed"
                self._save_proposal_unlocked(proposal)
                raise StaleProposalError("Controller marked approval stale")
            if decide_status.state is not occ.State.APPROVED:
                proposal["status"] = "failed"
                self._save_proposal_unlocked(proposal)
                raise StoreError(f"Unexpected controller decide state: {decide_status.state}")

            inv_status = self.controller.invoke(
                self.principals.config_job, proposal["controller_request_id"]
            )
            if inv_status.state is occ.State.SUCCEEDED:
                proposal["status"] = "applied"
                self._save_proposal_unlocked(proposal)
                return self.get_revision(kind, obj_id)
            if inv_status.state is occ.State.UNCERTAIN:
                proposal["status"] = "uncertain"
                self._save_proposal_unlocked(proposal)
                raise PublishUncertainError(
                    f"Publish outcome uncertain for {proposal_id}; run config reconcile"
                )
            if inv_status.state is occ.State.EXPIRED:
                proposal["status"] = "expired"
                self._save_proposal_unlocked(proposal)
                raise ExpiredProposalError("Controller approval expired during invoke")
            proposal["status"] = "failed"
            self._save_proposal_unlocked(proposal)
            raise StoreError(f"Publish failed: {inv_status.reason}")

    def reject_proposal(self, proposal_id: str) -> dict[str, Any]:
        with self.persistent_flock():
            proposal = self.load_proposal(proposal_id)
            if proposal["status"] != "pending":
                raise ConflictError(f"Proposal {proposal_id} is not pending")
            if proposal["incarnation"] == self.incarnation:
                self.controller.decide(
                    self.principals.operator,
                    proposal["controller_request_id"],
                    proposal["controller_rev"],
                    proposal["controller_digest"],
                    occ.Decision.REJECT,
                )
            proposal["status"] = "rejected"
            self._save_proposal_unlocked(proposal)
            return proposal

    def reconcile_proposal(self, proposal_id: str) -> str:
        """Reconcile 'applying' or 'uncertain' proposals (in-process or across restarts)."""
        with self.persistent_flock():
            proposal = self.load_proposal(proposal_id)
            if proposal["status"] not in ("applying", "uncertain"):
                raise ConflictError(f"Proposal {proposal_id} is not applying/uncertain")
            if (
                proposal["incarnation"] == self.incarnation
                and proposal["status"] == "uncertain"
            ):
                status = self.controller._reconcile(proposal["controller_request_id"])
                if status.state is occ.State.SUCCEEDED:
                    proposal["status"] = "applied"
                    self._save_proposal_unlocked(proposal)
                    return "applied"
                if status.state is occ.State.FAILED:
                    proposal["status"] = "failed"
                    self._save_proposal_unlocked(proposal)
                    return "failed"
                return "uncertain"
            # Cross-restart or 'applying' crash recovery: settle strictly from durable journal
            settled = (
                "applied"
                if self.journal_has_request_id(proposal["controller_request_id"])
                else "failed"
            )
            proposal["status"] = settled
            self._save_proposal_unlocked(proposal)
            return settled

    def _operator_direct_upsert_unlocked(self, kind: str, obj_id: str, raw_toml: str) -> int:
        if kind not in READABLE_ORCHESTRATOR_KINDS:
            raise SchemaError(f"Unknown kind: {kind!r}")
        validate_opaque_id(obj_id, label="id")
        if is_builtin_id(obj_id):
            raise PolicyError("builtin/* namespace is strictly immutable")
        validate_doc_by_kind(
            kind,
            parse_toml_strict(raw_toml, context=f"operator_upsert({kind}/{obj_id})"),
            expected_id=obj_id,
            for_orchestrator=False,
        )
        self.assert_no_unresolved_uncertain_proposals()
        fake_prop = {
            "id": f"op_{secrets.token_hex(6)}",
            "kind": kind,
            "obj_id": obj_id,
            "action": "upsert",
            "proposed_toml": raw_toml,
            "digest": hashlib.sha256(raw_toml.encode("utf-8")).hexdigest(),
        }
        return self._commit_proposal_effect_unlocked(fake_prop, f"operator_{secrets.token_hex(8)}")

    def operator_direct_upsert(self, kind: str, obj_id: str, raw_toml: str) -> int:
        """Host-operator direct publish (for non-orchestrator kinds or operator CLI restore)."""
        with self.persistent_flock():
            return self._operator_direct_upsert_unlocked(kind, obj_id, raw_toml)

    def operator_restore_revision(self, kind: str, obj_id: str, target_rev: int) -> int:
        """Restore a prior revision by publishing it as a NEW monotonic revision N+1 under one lock."""
        with self.persistent_flock():
            raw_toml = self.get_revision_toml(kind, obj_id, target_rev)
            return self._operator_direct_upsert_unlocked(kind, obj_id, raw_toml)
