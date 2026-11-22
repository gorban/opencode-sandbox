"""Pure workflow@1 schema validation, bounded predicate AST, templates, and digests."""

from __future__ import annotations

import ast
import hashlib
import json
import math
import re
import tomllib
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping

SPEC_DIGEST_DOMAIN = "oc-wf-spec-v1:"
PLAN_DIGEST_DOMAIN = "oc-wf-plan-v1:"
RUBRIC_DIGEST_DOMAIN = "oc-wf-rubric-v1:"

MAX_STATES = 32
MAX_TRANSITIONS = 64
MIN_TICK_INTERVAL_S = 10
MAX_RUBRIC_BYTES = 2048
MAX_TEMPLATE_BYTES = 1024
MAX_TEMPLATES = 32
MAX_PREDICATE_BYTES = 512
MAX_AST_NODES = 64
MAX_AST_DEPTH = 8
MAX_IN_ITEMS = 16
MAX_PREDICATE_STR_BYTES = 128
MAX_EXCERPT_BYTES_CAP = 512
MAX_SPEND_MICROUSD = 1_000_000_000  # $1,000.00 upper bound per workflow run

ALLOWED_MODES = frozenset({"statechart", "fleet_supervisor"})
AUTONOMY_ORDER: Mapping[str, int] = {
    "observe_only": 0,
    "nudge_bounded": 1,
    "orchestrator_signal": 2,
}
TARGET_SELECTOR_ORDER: Mapping[str, int] = {
    "bound_targets": 0,
    "project_scope": 1,
    "all_running_sandboxes": 2,
}
ALLOWED_DECISION_TYPES = frozenset({"noul", "choice", "score"})
ALLOWED_EXCERPT_SOURCES = frozenset({"sanitized_last_error_excerpt"})
ALLOWED_EXCERPT_USES = frozenset({"live", "replay"})
ALLOWED_TEMPLATE_VARS = frozenset({"target_addr", "stall_seconds", "workflow_id"})
ALLOWED_PREDICATE_NAMESPACES = frozenset({"metric", "event", "lane", "state", "limits"})
ALLOWED_WIDGET_TYPES = frozenset(
    {
        "status_card",
        "metric_kpi",
        "kv_table",
        "lane_health_matrix",
        "timeline_log",
        "checklist_progress",
        "sparkline_series",
        "action_chips",
    }
)
ALLOWED_STATE_SHAPES = frozenset(
    {
        "observe",
        "deterministic",
        "ship_lane",
        "scout_lane",
        "parallel_lanes",
        "wait_signal",
        "human_gate_async",
        "human_gate_blocking",
    }
)
ALLOWED_EFFECTS = frozenset(
    {
        "read_metrics",
        "update_health_projection",
        "post_advisory_inbox",
        "launch_sandbox",
        "stage_patch",
        "spawn_lane",
        "nudge_sandbox",
        "pause_lane_gate",
        "blocking_gate",
        "call_decisions_model",
        "call_blind_check_model",
        "invoke_factory",
        "acquire_lane_lease",
    }
)
SECURITY_DELTA_TRIGGERS: tuple[str, ...] = (
    "workflow_added",
    "workflow_autonomy_widened",
    "workflow_decisions_route_added",
    "workflow_blocking_gate_changed",
    "workflow_skill_changed",
    "workflow_template_changed",
    "workflow_rubric_or_predicate_changed",
    "workflow_default_surface_changed",
    "workflow_factory_changed",
    "workflow_excerpt_disclosure_changed",
)

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_NAMESPACED_ID_RE = re.compile(r"^(builtin|user)/([a-z0-9][a-z0-9_-]{0,63})$")
_FIELD_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SAFE_IDENT_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,127}$")
_TEMPLATE_TOKEN_RE = re.compile(r"\{([a-z_][a-z0-9_]*)\}")

_BIDI_CODEPOINTS = frozenset(
    {
        0x061C,
        0x200E,
        0x200F,
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,
        0x2066,
        0x2067,
        0x2068,
        0x2069,
    }
)


class WorkflowSchemaError(ValueError):
    """Raised when a workflow@1 document violates schema or security constraints."""


class PredicateValidationError(WorkflowSchemaError):
    """Raised when a workflow predicate violates bounded AST constraints."""


class TemplateValidationError(WorkflowSchemaError):
    """Raised when a workflow template violates single-pass placeholder constraints."""


def _validate_char(ch: str, field: str, *, allow_multiline: bool) -> None:
    code = ord(ch)
    if code == 0 or code in _BIDI_CODEPOINTS:
        raise WorkflowSchemaError(f"{field}: forbidden NUL or BiDi control character")
    if allow_multiline and ch in ("\n", "\t"):
        return
    if code < 0x20 or code == 0x7F or (0x80 <= code <= 0x9F):
        raise WorkflowSchemaError(f"{field}: forbidden control character 0x{code:02x}")


def validate_clean_str(
    value: Any,
    field: str,
    *,
    allow_multiline: bool = False,
    max_bytes: int | None = None,
    allow_empty: bool = False,
) -> str:
    """Validate string type, size, and absence of NUL, control, and BiDi chars."""
    if not isinstance(value, str):
        raise WorkflowSchemaError(f"{field}: expected str")
    if not allow_empty and not value:
        raise WorkflowSchemaError(f"{field}: must not be empty")
    try:
        raw = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise WorkflowSchemaError(f"{field}: invalid UTF-8 surrogate sequence") from exc
    if max_bytes is not None and len(raw) > max_bytes:
        raise WorkflowSchemaError(f"{field}: exceeds {max_bytes} bytes")
    for ch in value:
        _validate_char(ch, field, allow_multiline=allow_multiline)
    return value


def parse_strict_int(
    value: Any,
    field: str,
    *,
    min_val: int = 0,
    max_val: int | None = None,
) -> int:
    """Parse an integer while rejecting booleans and floats."""
    if type(value) is not int:
        raise WorkflowSchemaError(f"{field}: expected int")
    if value < min_val:
        raise WorkflowSchemaError(f"{field}: must be >= {min_val}")
    if max_val is not None and value > max_val:
        raise WorkflowSchemaError(f"{field}: must be <= {max_val}")
    return value


def parse_strict_bool(value: Any, field: str) -> bool:
    """Parse a boolean strictly."""
    if type(value) is not bool:
        raise WorkflowSchemaError(f"{field}: expected bool")
    return value


def _to_finite_decimal(value: Any, field: str) -> Decimal:
    if type(value) is bool or not isinstance(value, (int, float, Decimal)):
        raise WorkflowSchemaError(f"{field}: expected finite number")
    if isinstance(value, float) and not math.isfinite(value):
        raise WorkflowSchemaError(f"{field}: non-finite float rejected")
    try:
        dec = value if isinstance(value, Decimal) else Decimal(str(value))
    except InvalidOperation as exc:
        raise WorkflowSchemaError(f"{field}: invalid decimal") from exc
    if not dec.is_finite():
        raise WorkflowSchemaError(f"{field}: non-finite decimal rejected")
    return dec


def _scale_exact_decimal(
    dec: Decimal,
    *,
    max_decimals: int,
    max_scaled: int,
    field: str,
) -> int:
    """Scale a non-negative Decimal using exact (sign, digits, exp) with zero context rounding."""
    sign, digits, exp = dec.as_tuple()
    if not isinstance(exp, int):
        raise WorkflowSchemaError(f"{field}: non-finite decimal rejected")
    if sign != 0 and any(d != 0 for d in digits):
        raise WorkflowSchemaError(f"{field}: must be >= 0")
    if not any(d != 0 for d in digits):
        return 0
    # Strip trailing zeros so e.g. 0.2500000 -> (25, -2) without touching Decimal context.
    trimmed = list(digits)
    while trimmed and trimmed[-1] == 0:
        trimmed.pop()
        exp += 1
    if exp < -max_decimals:
        raise WorkflowSchemaError(f"{field}: exceeds {max_decimals} decimal places")
    # Check digit magnitude BEFORE computing giant integer powers (e.g. 1e100000).
    shift = max_decimals + exp
    max_digits = len(str(max_scaled))
    if len(trimmed) + shift > max_digits:
        raise WorkflowSchemaError(f"{field}: exceeds maximum allowed ceiling")
    coeff = 0
    for d in trimmed:
        coeff = coeff * 10 + d
    scaled = coeff * (10 ** shift)
    if scaled > max_scaled:
        raise WorkflowSchemaError(f"{field}: exceeds maximum allowed ceiling")
    return scaled


def parse_microdollars(value: Any, field: str) -> int:
    """Parse non-negative USD amount (<= 6 decimal places, <= $1,000) to exact integer microdollars."""
    dec = _to_finite_decimal(value, field)
    return _scale_exact_decimal(dec, max_decimals=6, max_scaled=MAX_SPEND_MICROUSD, field=field)


def parse_basis_points(value: Any, field: str) -> int:
    """Parse [0, 1] ratio (<= 4 decimal places) to exact integer basis points (0..10_000)."""
    dec = _to_finite_decimal(value, field)
    return _scale_exact_decimal(dec, max_decimals=4, max_scaled=10_000, field=field)


def parse_namespaced_id(value: Any, field: str) -> tuple[str, str, str]:
    """Parse '<namespace>/<slug>' returning (full_id, namespace, slug)."""
    text = validate_clean_str(value, field, max_bytes=128)
    match = _NAMESPACED_ID_RE.match(text)
    if not match:
        raise WorkflowSchemaError(
            f"{field}: must match '(builtin|user)/<slug>' with lowercase slug"
        )
    return text, match.group(1), match.group(2)


def _reject_unknown_keys(mapping: Mapping[str, Any], allowed: frozenset[str], section: str) -> None:
    if not isinstance(mapping, Mapping):
        raise WorkflowSchemaError(f"{section}: expected table")
    unknown = sorted(set(mapping.keys()) - allowed)
    if unknown:
        raise WorkflowSchemaError(f"{section}: unknown keys {unknown}")


def canonical_json_bytes(obj: Any) -> bytes:
    """Serialize obj to deterministic UTF-8 canonical JSON rejecting NaN/Inf."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def domain_sha256(domain: str, obj: Any) -> str:
    """Compute domain-separated SHA-256 hex digest over canonical JSON."""
    payload = domain.encode("utf-8") + canonical_json_bytes(obj)
    return hashlib.sha256(payload).hexdigest()


# --- Literal single-pass templates ---


def validate_template(name: str, text: str) -> None:
    """Validate template name and single-pass placeholder syntax."""
    try:
        clean_name = validate_clean_str(name, "templates.key", max_bytes=64)
        if not _FIELD_RE.match(clean_name):
            raise TemplateValidationError(f"template key {clean_name!r} is invalid")
        validate_clean_str(text, f"templates.{clean_name}", allow_multiline=True, max_bytes=MAX_TEMPLATE_BYTES)
    except WorkflowSchemaError as exc:
        if isinstance(exc, TemplateValidationError):
            raise
        raise TemplateValidationError(str(exc)) from exc
    pos = 0
    for match in _TEMPLATE_TOKEN_RE.finditer(text):
        segment = text[pos : match.start()]
        if "{" in segment or "}" in segment:
            raise TemplateValidationError(f"templates.{clean_name}: invalid brace syntax")
        var_name = match.group(1)
        if var_name not in ALLOWED_TEMPLATE_VARS:
            raise TemplateValidationError(
                f"templates.{clean_name}: placeholder {{{var_name}}} is not allowlisted"
            )
        pos = match.end()
    tail = text[pos:]
    if "{" in tail or "}" in tail:
        raise TemplateValidationError(f"templates.{clean_name}: invalid brace syntax")


def render_template(text: str, values: Mapping[str, Any]) -> str:
    """Render a validated template in a single pass with zero re-expansion."""
    validate_template("render_check", text)
    unknown_keys = set(values.keys()) - ALLOWED_TEMPLATE_VARS
    if unknown_keys:
        raise TemplateValidationError(f"unallowlisted render vars: {sorted(unknown_keys)}")

    rendered_values: dict[str, str] = {}
    for key, val in values.items():
        if type(val) is bool or not isinstance(val, (str, int)):
            raise TemplateValidationError(f"render var {key!r}: expected str or int")
        rendered_values[key] = validate_clean_str(str(val), f"render.{key}", max_bytes=256)

    def _replace(match: re.Match[str]) -> str:
        var_name = match.group(1)
        if var_name not in rendered_values:
            raise TemplateValidationError(f"missing render var {var_name!r}")
        return rendered_values[var_name]

    return _TEMPLATE_TOKEN_RE.sub(_replace, text)


# --- Bounded predicate AST ---

_ScalarValue = bool | int | Decimal | str


@dataclass(frozen=True)
class CompiledPredicate:
    """Validated bounded predicate AST."""

    source: str
    tree: ast.expr
    referenced_fields: frozenset[tuple[str, str]]


def _scalar_type_tag(val: _ScalarValue) -> str:
    if type(val) is bool:
        return "bool"
    if isinstance(val, (int, Decimal)):
        return "num"
    if isinstance(val, str):
        return "str"
    raise PredicateValidationError(f"unsupported scalar type {type(val).__name__}")


def _extract_constant_scalar(val: Any) -> _ScalarValue:
    if type(val) is bool or type(val) is int:
        return val
    if isinstance(val, float):
        if not math.isfinite(val):
            raise PredicateValidationError("non-finite float in predicate")
        return Decimal(str(val))
    if isinstance(val, str):
        try:
            return validate_clean_str(val, "predicate.literal", max_bytes=MAX_PREDICATE_STR_BYTES, allow_empty=True)
        except WorkflowSchemaError as exc:
            raise PredicateValidationError(str(exc)) from exc
    raise PredicateValidationError(f"unsupported literal type {type(val).__name__}")


def _extract_literal_scalar(node: ast.AST, *, allow_usub: bool = True) -> _ScalarValue:
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        if not allow_usub or not isinstance(node.operand, ast.Constant):
            raise PredicateValidationError("unary '-' permitted only once directly on a numeric literal")
        inner = _extract_constant_scalar(node.operand.value)
        if _scalar_type_tag(inner) != "num":
            raise PredicateValidationError("unary '-' permitted only on numeric literals")
        return -inner  # type: ignore[operator]
    if not isinstance(node, ast.Constant):
        raise PredicateValidationError("expected scalar literal")
    return _extract_constant_scalar(node.value)


class _PredicateValidator:
    def __init__(self) -> None:
        self.nodes = 0
        self.fields: set[tuple[str, str]] = set()

    def _bump(self, depth: int) -> None:
        self.nodes += 1
        if self.nodes > MAX_AST_NODES:
            raise PredicateValidationError(f"predicate exceeds {MAX_AST_NODES} AST nodes")
        if depth > MAX_AST_DEPTH:
            raise PredicateValidationError(f"predicate exceeds AST depth {MAX_AST_DEPTH}")

    def validate(self, node: ast.AST, depth: int = 1) -> str:
        """Validate AST node and return coarse type tag ('bool'|'num'|'str'|'any')."""
        self._bump(depth)
        if isinstance(node, ast.BoolOp):
            return self._validate_boolop(node, depth)
        if isinstance(node, ast.UnaryOp):
            return self._validate_unary(node, depth)
        if isinstance(node, ast.Compare):
            return self._validate_compare(node, depth)
        if isinstance(node, ast.Attribute):
            return self._validate_attribute(node)
        if isinstance(node, ast.Constant):
            return _scalar_type_tag(_extract_literal_scalar(node))
        raise PredicateValidationError(f"disallowed AST node {type(node).__name__}")

    def _validate_boolop(self, node: ast.BoolOp, depth: int) -> str:
        if not isinstance(node.op, (ast.And, ast.Or)):
            raise PredicateValidationError("unsupported boolean operator")
        for val in node.values:
            tag = self.validate(val, depth + 1)
            if tag not in ("bool", "any"):
                raise PredicateValidationError("boolean operator requires boolean operands")
        return "bool"

    def _validate_unary(self, node: ast.UnaryOp, depth: int) -> str:
        if isinstance(node.op, ast.Not):
            tag = self.validate(node.operand, depth + 1)
            if tag not in ("bool", "any"):
                raise PredicateValidationError("'not' requires boolean operand")
            return "bool"
        if isinstance(node.op, ast.USub):
            self._bump(depth + 1)
            val = _extract_literal_scalar(node)
            return _scalar_type_tag(val)
        raise PredicateValidationError(f"disallowed unary operator {type(node.op).__name__}")

    def _validate_compare(self, node: ast.Compare, depth: int) -> str:
        if len(node.ops) != 1 or len(node.comparators) != 1:
            raise PredicateValidationError("chained comparisons are not allowed")
        op = node.ops[0]
        left_tag = self.validate(node.left, depth + 1)
        right = node.comparators[0]
        if isinstance(op, ast.In):
            self._validate_in_rhs(right, left_tag, depth + 1)
            return "bool"
        if not isinstance(op, (ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE)):
            raise PredicateValidationError(f"disallowed comparison operator {type(op).__name__}")
        right_tag = self.validate(right, depth + 1)
        self._check_cmp_types(op, left_tag, right_tag)
        return "bool"

    def _validate_in_rhs(self, node: ast.AST, left_tag: str, depth: int) -> None:
        self._bump(depth)
        if not isinstance(node, (ast.List, ast.Tuple)):
            raise PredicateValidationError("RHS of 'in' must be a literal list or tuple")
        if not node.elts or len(node.elts) > MAX_IN_ITEMS:
            raise PredicateValidationError(f"RHS of 'in' must contain 1..{MAX_IN_ITEMS} items")
        item_tags: set[str] = set()
        for elt in node.elts:
            self._bump(depth + 1)
            item_tags.add(_scalar_type_tag(_extract_literal_scalar(elt)))
        if len(item_tags) != 1:
            raise PredicateValidationError("RHS of 'in' must contain homogeneous scalar types")
        rhs_tag = next(iter(item_tags))
        if left_tag != "any" and left_tag != rhs_tag:
            raise PredicateValidationError(f"incompatible 'in' types: {left_tag} vs {rhs_tag}")

    def _check_cmp_types(self, op: ast.cmpop, left_tag: str, right_tag: str) -> None:
        if left_tag != "any" and right_tag != "any" and left_tag != right_tag:
            raise PredicateValidationError(f"incompatible comparison types: {left_tag} vs {right_tag}")
        if isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)):
            if left_tag == "bool" or right_tag == "bool":
                raise PredicateValidationError("ordering comparison not permitted on bool")

    def _validate_attribute(self, node: ast.Attribute) -> str:
        if not isinstance(node.value, ast.Name):
            raise PredicateValidationError("nested attribute access is not allowed")
        ns = node.value.id
        if ns not in ALLOWED_PREDICATE_NAMESPACES:
            raise PredicateValidationError(f"disallowed predicate namespace {ns!r}")
        if not _FIELD_RE.match(node.attr):
            raise PredicateValidationError(f"invalid predicate field {node.attr!r}")
        self.fields.add((ns, node.attr))
        return "any"


def compile_predicate(source: str) -> CompiledPredicate:
    """Parse and validate a bounded predicate expression without eval()."""
    try:
        clean = validate_clean_str(source, "predicate", max_bytes=MAX_PREDICATE_BYTES)
    except WorkflowSchemaError as exc:
        raise PredicateValidationError(str(exc)) from exc
    try:
        parsed = ast.parse(clean, mode="eval")
    except SyntaxError as exc:
        raise PredicateValidationError(f"invalid predicate syntax: {exc.msg}") from exc
    validator = _PredicateValidator()
    top_tag = validator.validate(parsed.body, depth=1)
    if top_tag not in ("bool", "any"):
        raise PredicateValidationError("predicate root must evaluate to bool")
    return CompiledPredicate(
        source=clean,
        tree=parsed.body,
        referenced_fields=frozenset(validator.fields),
    )


def _normalize_runtime_scalar(val: Any) -> _ScalarValue:
    if type(val) is bool or type(val) is int:
        return val
    if isinstance(val, Decimal) and val.is_finite():
        return val
    if isinstance(val, float) and math.isfinite(val):
        return Decimal(str(val))
    if isinstance(val, str):
        return val
    raise PredicateValidationError(f"unsupported runtime value type {type(val).__name__}")


def _eval_node(node: ast.AST, context: Mapping[str, Mapping[str, Any]]) -> Any:
    if isinstance(node, ast.BoolOp):
        return _eval_boolop(node, context)
    if isinstance(node, ast.UnaryOp):
        if isinstance(node.op, ast.Not):
            val = _eval_node(node.operand, context)
            if type(val) is not bool:
                raise PredicateValidationError("runtime 'not' operand must be bool")
            return not val
        return _extract_literal_scalar(node)
    if isinstance(node, ast.Compare):
        return _eval_compare(node, context)
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        ns_map = context.get(node.value.id)
        if ns_map is None or node.attr not in ns_map:
            raise PredicateValidationError(f"missing context field {node.value.id}.{node.attr}")
        return _normalize_runtime_scalar(ns_map[node.attr])
    if isinstance(node, ast.Constant):
        return _extract_literal_scalar(node)
    raise PredicateValidationError(f"cannot evaluate node {type(node).__name__}")


def _eval_boolop(node: ast.BoolOp, context: Mapping[str, Mapping[str, Any]]) -> bool:
    is_and = isinstance(node.op, ast.And)
    for item in node.values:
        val = _eval_node(item, context)
        if type(val) is not bool:
            raise PredicateValidationError("runtime boolean operand must be bool")
        if is_and and not val:
            return False
        if not is_and and val:
            return True
    return is_and


def _eval_compare(node: ast.Compare, context: Mapping[str, Mapping[str, Any]]) -> bool:
    left = _eval_node(node.left, context)
    op = node.ops[0]
    right_node = node.comparators[0]
    left_tag = _scalar_type_tag(left)
    if isinstance(op, ast.In):
        if not isinstance(right_node, (ast.List, ast.Tuple)):
            raise PredicateValidationError("RHS of 'in' must be a literal container")
        items = [_extract_literal_scalar(elt) for elt in right_node.elts]
        if _scalar_type_tag(items[0]) != left_tag:
            raise PredicateValidationError("runtime type mismatch in 'in' comparison")
        return any(left == item for item in items)
    right = _eval_node(right_node, context)
    right_tag = _scalar_type_tag(right)
    if left_tag != right_tag:
        raise PredicateValidationError("runtime type mismatch in comparison")
    if isinstance(op, ast.Eq):
        return bool(left == right)
    if isinstance(op, ast.NotEq):
        return bool(left != right)
    if left_tag == "bool":
        raise PredicateValidationError("ordering comparison not permitted on bool")
    if isinstance(op, ast.Lt):
        return bool(left < right)
    if isinstance(op, ast.LtE):
        return bool(left <= right)
    if isinstance(op, ast.Gt):
        return bool(left > right)
    if isinstance(op, ast.GtE):
        return bool(left >= right)
    raise PredicateValidationError("unsupported comparison operator")


def evaluate_predicate(
    pred: CompiledPredicate,
    context: Mapping[str, Mapping[str, Any]],
) -> tuple[bool, str | None]:
    """Evaluate compiled predicate safely; fails closed (False, fault) on missing/bad fields."""
    try:
        result = _eval_node(pred.tree, context)
    except PredicateValidationError as exc:
        return False, str(exc)
    if type(result) is not bool:
        return False, "predicate did not evaluate to bool"
    return result, None


# --- workflow@1 dataclasses & parser ---


@dataclass(frozen=True)
class ScopeSpec:
    target_selector: str
    bound_targets: tuple[str, ...]
    allow_remote_workers: bool

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "allow_remote_workers": self.allow_remote_workers,
            "bound_targets": list(self.bound_targets),
            "target_selector": self.target_selector,
        }


@dataclass(frozen=True)
class LimitsSpec:
    tick_interval_s: int
    throttle_period_s: int
    fleet_max_concurrent_checks: int
    fleet_max_checks_per_hour: int
    fleet_audit_checks_per_hour: int
    max_nudges_per_target_per_hour: int
    min_nudge_interval_s: int
    max_total_nudges_per_run: int
    max_decisions_calls_per_hour: int
    max_decisions_spend_microusd: int
    max_blind_check_spend_microusd: int
    max_open_inbox_items: int
    defer_nudge_during_human_lease: bool
    wake_grace_after_host_sleep_s: int

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "defer_nudge_during_human_lease": self.defer_nudge_during_human_lease,
            "fleet_audit_checks_per_hour": self.fleet_audit_checks_per_hour,
            "fleet_max_checks_per_hour": self.fleet_max_checks_per_hour,
            "fleet_max_concurrent_checks": self.fleet_max_concurrent_checks,
            "max_blind_check_spend_microusd": self.max_blind_check_spend_microusd,
            "max_decisions_calls_per_hour": self.max_decisions_calls_per_hour,
            "max_decisions_spend_microusd": self.max_decisions_spend_microusd,
            "max_nudges_per_target_per_hour": self.max_nudges_per_target_per_hour,
            "max_open_inbox_items": self.max_open_inbox_items,
            "max_total_nudges_per_run": self.max_total_nudges_per_run,
            "min_nudge_interval_s": self.min_nudge_interval_s,
            "throttle_period_s": self.throttle_period_s,
            "tick_interval_s": self.tick_interval_s,
            "wake_grace_after_host_sleep_s": self.wake_grace_after_host_sleep_s,
        }


@dataclass(frozen=True)
class ExcerptDisclosureSpec:
    mode: str  # "none" | "opt_in"
    source: str | None = None
    max_bytes: int = 0
    allowed_routes: tuple[str, ...] = ()
    permitted_uses: tuple[str, ...] = ()

    def to_canonical_dict(self) -> dict[str, Any]:
        if self.mode == "none":
            return {"mode": "none"}
        return {
            "allowed_routes": list(self.allowed_routes),
            "max_bytes": self.max_bytes,
            "mode": "opt_in",
            "permitted_uses": list(self.permitted_uses),
            "source": self.source,
        }


@dataclass(frozen=True)
class System1Spec:
    route: str
    model: str
    authority: str
    decision_type: str
    rubric: str
    choices: tuple[str, ...]
    abstain_default: str
    canary_injection_question: bool

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "abstain_default": self.abstain_default,
            "authority": self.authority,
            "canary_injection_question": self.canary_injection_question,
            "choices": list(self.choices),
            "decision_type": self.decision_type,
            "model": self.model,
            "route": self.route,
            "rubric": self.rubric,
        }

    def rubric_payload(self) -> dict[str, Any]:
        return {
            "abstain_default": self.abstain_default,
            "canary_injection_question": self.canary_injection_question,
            "choices": list(self.choices),
            "decision_type": self.decision_type,
            "rubric": self.rubric,
        }


@dataclass(frozen=True)
class BlindCheckSpec:
    model_profile: str
    scheduled_audit_interval_s: int
    min_calibration_samples: int
    fp_drift_warn_threshold_bps: int
    fn_drift_warn_count_24h: int

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "fn_drift_warn_count_24h": self.fn_drift_warn_count_24h,
            "fp_drift_warn_threshold_bps": self.fp_drift_warn_threshold_bps,
            "min_calibration_samples": self.min_calibration_samples,
            "model_profile": self.model_profile,
            "scheduled_audit_interval_s": self.scheduled_audit_interval_s,
        }


@dataclass(frozen=True)
class WidgetSpec:
    id: str
    widget_type: str
    metrics: tuple[str, ...]
    columns: tuple[str, ...]
    chips: tuple[str, ...]

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "chips": list(self.chips),
            "columns": list(self.columns),
            "id": self.id,
            "metrics": list(self.metrics),
            "type": self.widget_type,
        }


@dataclass(frozen=True)
class DashboardSurfaceSpec:
    title: str
    priority: int
    widgets: tuple[WidgetSpec, ...]

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "priority": self.priority,
            "title": self.title,
            "widgets": [w.to_canonical_dict() for w in self.widgets],
        }


@dataclass(frozen=True)
class StateSpec:
    name: str
    shape: str
    effects: tuple[str, ...]
    factory_id: str | None = None

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "effects": list(self.effects),
            "factory_id": self.factory_id,
            "name": self.name,
            "shape": self.shape,
        }


@dataclass(frozen=True)
class TransitionSpec:
    src: str
    dst: str
    predicate: CompiledPredicate | None
    effects: tuple[str, ...]

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "dst": self.dst,
            "effects": list(self.effects),
            "predicate": self.predicate.source if self.predicate is not None else None,
            "src": self.src,
        }


@dataclass(frozen=True)
class TimerSpec:
    name: str
    interval_s: int
    effects: tuple[str, ...]

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "effects": list(self.effects),
            "interval_s": self.interval_s,
            "name": self.name,
        }


@dataclass(frozen=True)
class SignalHandlerSpec:
    signal: str
    effects: tuple[str, ...]

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "effects": list(self.effects),
            "signal": self.signal,
        }


@dataclass(frozen=True)
class WorkflowSpec:
    schema_version: int
    kind: str
    id: str
    id_namespace: str
    id_slug: str
    mode: str
    description: str
    autonomy: str
    orchestrator_skill: str
    skill_namespace: str
    skill_slug: str
    survives_restart: bool
    scope: ScopeSpec
    limits: LimitsSpec
    excerpt_disclosure: ExcerptDisclosureSpec
    system1: System1Spec | None
    blind_check: BlindCheckSpec | None
    templates: tuple[tuple[str, str], ...]
    default_surface: DashboardSurfaceSpec | None
    states: tuple[StateSpec, ...]
    transitions: tuple[TransitionSpec, ...]
    timers: tuple[TimerSpec, ...]
    signal_handlers: tuple[SignalHandlerSpec, ...]
    spec_digest: str
    candidate_rubric_digest: str | None

    @property
    def templates_map(self) -> dict[str, str]:
        return dict(self.templates)

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "autonomy": self.autonomy,
            "blind_check": self.blind_check.to_canonical_dict() if self.blind_check else None,
            "default_surface": self.default_surface.to_canonical_dict() if self.default_surface else None,
            "description": self.description,
            "excerpt_disclosure": self.excerpt_disclosure.to_canonical_dict(),
            "id": self.id,
            "kind": self.kind,
            "limits": self.limits.to_canonical_dict(),
            "mode": self.mode,
            "orchestrator_skill": self.orchestrator_skill,
            "schema_version": self.schema_version,
            "scope": self.scope.to_canonical_dict(),
            "signal_handlers": [h.to_canonical_dict() for h in self.signal_handlers],
            "states": [s.to_canonical_dict() for s in self.states],
            "survives_restart": self.survives_restart,
            "system1": self.system1.to_canonical_dict() if self.system1 else None,
            "templates": dict(self.templates),
            "timers": [t.to_canonical_dict() for t in self.timers],
            "transitions": [tr.to_canonical_dict() for tr in self.transitions],
        }


_TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "id",
        "mode",
        "description",
        "autonomy",
        "orchestrator_skill",
        "survives_restart",
        "scope",
        "limits",
        "supervision",
        "templates",
        "dashboard",
        "states",
        "transitions",
        "timers",
        "signal_handlers",
    }
)


def _parse_scope(raw: Mapping[str, Any]) -> ScopeSpec:
    _reject_unknown_keys(raw, frozenset({"target_selector", "bound_targets", "allow_remote_workers"}), "scope")
    selector = validate_clean_str(raw.get("target_selector"), "scope.target_selector", max_bytes=64)
    if selector not in TARGET_SELECTOR_ORDER:
        raise WorkflowSchemaError(f"scope.target_selector: unsupported value {selector!r}")
    raw_targets = raw.get("bound_targets", [])
    if not isinstance(raw_targets, list):
        raise WorkflowSchemaError("scope.bound_targets: expected list")
    targets: list[str] = []
    for item in raw_targets:
        t = validate_clean_str(item, "scope.bound_targets[]", max_bytes=128)
        if not _SAFE_IDENT_RE.match(t):
            raise WorkflowSchemaError(f"scope.bound_targets: invalid target {t!r}")
        targets.append(t)
    if len(set(targets)) != len(targets):
        raise WorkflowSchemaError("scope.bound_targets: duplicate targets not allowed")
    if selector == "bound_targets" and not targets:
        raise WorkflowSchemaError("scope.bound_targets: must be non-empty when target_selector == 'bound_targets'")
    allow_remote = parse_strict_bool(raw.get("allow_remote_workers", False), "scope.allow_remote_workers")
    return ScopeSpec(
        target_selector=selector,
        bound_targets=tuple(sorted(targets)),
        allow_remote_workers=allow_remote,
    )


def _parse_limits(raw: Mapping[str, Any]) -> LimitsSpec:
    allowed = frozenset(
        {
            "tick_interval_s",
            "throttle_period_s",
            "fleet_max_concurrent_checks",
            "fleet_max_checks_per_hour",
            "fleet_audit_checks_per_hour",
            "max_nudges_per_target_per_hour",
            "min_nudge_interval_s",
            "max_total_nudges_per_run",
            "max_decisions_calls_per_hour",
            "max_decisions_spend_usd",
            "max_blind_check_spend_usd",
            "max_open_inbox_items",
            "defer_nudge_during_human_lease",
            "wake_grace_after_host_sleep_s",
        }
    )
    _reject_unknown_keys(raw, allowed, "limits")
    fleet_max_hr = parse_strict_int(raw.get("fleet_max_checks_per_hour", 0), "limits.fleet_max_checks_per_hour")
    fleet_audit_hr = parse_strict_int(raw.get("fleet_audit_checks_per_hour", 0), "limits.fleet_audit_checks_per_hour")
    if fleet_audit_hr > fleet_max_hr:
        raise WorkflowSchemaError("limits.fleet_audit_checks_per_hour cannot exceed fleet_max_checks_per_hour")
    return LimitsSpec(
        tick_interval_s=parse_strict_int(raw.get("tick_interval_s", 60), "limits.tick_interval_s", min_val=MIN_TICK_INTERVAL_S),
        throttle_period_s=parse_strict_int(raw.get("throttle_period_s", 300), "limits.throttle_period_s", min_val=10),
        fleet_max_concurrent_checks=parse_strict_int(raw.get("fleet_max_concurrent_checks", 0), "limits.fleet_max_concurrent_checks"),
        fleet_max_checks_per_hour=fleet_max_hr,
        fleet_audit_checks_per_hour=fleet_audit_hr,
        max_nudges_per_target_per_hour=parse_strict_int(raw.get("max_nudges_per_target_per_hour", 0), "limits.max_nudges_per_target_per_hour"),
        min_nudge_interval_s=parse_strict_int(raw.get("min_nudge_interval_s", 300), "limits.min_nudge_interval_s", min_val=1),
        max_total_nudges_per_run=parse_strict_int(raw.get("max_total_nudges_per_run", 0), "limits.max_total_nudges_per_run"),
        max_decisions_calls_per_hour=parse_strict_int(raw.get("max_decisions_calls_per_hour", 0), "limits.max_decisions_calls_per_hour"),
        max_decisions_spend_microusd=parse_microdollars(raw.get("max_decisions_spend_usd", 0), "limits.max_decisions_spend_usd"),
        max_blind_check_spend_microusd=parse_microdollars(raw.get("max_blind_check_spend_usd", 0), "limits.max_blind_check_spend_usd"),
        max_open_inbox_items=parse_strict_int(raw.get("max_open_inbox_items", 16), "limits.max_open_inbox_items", min_val=1),
        defer_nudge_during_human_lease=parse_strict_bool(raw.get("defer_nudge_during_human_lease", True), "limits.defer_nudge_during_human_lease"),
        wake_grace_after_host_sleep_s=parse_strict_int(raw.get("wake_grace_after_host_sleep_s", 120), "limits.wake_grace_after_host_sleep_s", min_val=0),
    )


def _parse_excerpt_disclosure(raw_sup: Mapping[str, Any], sys1_mode: str | None) -> ExcerptDisclosureSpec:
    block = raw_sup.get("excerpt_disclosure")
    if block is None:
        if sys1_mode is not None and sys1_mode != "none":
            raise WorkflowSchemaError("supervision.system1.excerpt_disclosure requires [supervision.excerpt_disclosure] block")
        return ExcerptDisclosureSpec(mode="none")
    if not isinstance(block, Mapping):
        raise WorkflowSchemaError("supervision.excerpt_disclosure: expected table")
    if sys1_mode == "none":
        raise WorkflowSchemaError("supervision.excerpt_disclosure block conflicts with excerpt_disclosure = 'none'")
    _reject_unknown_keys(block, frozenset({"source", "max_bytes", "allowed_routes", "permitted_uses"}), "supervision.excerpt_disclosure")
    source = validate_clean_str(block.get("source"), "supervision.excerpt_disclosure.source", max_bytes=64)
    if source not in ALLOWED_EXCERPT_SOURCES:
        raise WorkflowSchemaError(f"supervision.excerpt_disclosure.source: unsupported {source!r}")
    max_bytes = parse_strict_int(block.get("max_bytes"), "supervision.excerpt_disclosure.max_bytes", min_val=1, max_val=MAX_EXCERPT_BYTES_CAP)
    routes = _parse_str_list(block.get("allowed_routes"), "supervision.excerpt_disclosure.allowed_routes", min_items=1)
    uses = _parse_str_list(block.get("permitted_uses"), "supervision.excerpt_disclosure.permitted_uses", min_items=1)
    for use in uses:
        if use not in ALLOWED_EXCERPT_USES:
            raise WorkflowSchemaError(f"supervision.excerpt_disclosure.permitted_uses: invalid {use!r}")
    return ExcerptDisclosureSpec(
        mode="opt_in",
        source=source,
        max_bytes=max_bytes,
        allowed_routes=tuple(sorted(set(routes))),
        permitted_uses=tuple(sorted(set(uses))),
    )


def _parse_str_list(raw: Any, field: str, *, min_items: int = 0, max_items: int = 64) -> tuple[str, ...]:
    if not isinstance(raw, list):
        raise WorkflowSchemaError(f"{field}: expected list")
    if len(raw) < min_items or len(raw) > max_items:
        raise WorkflowSchemaError(f"{field}: must contain {min_items}..{max_items} items")
    out = [validate_clean_str(item, f"{field}[]", max_bytes=128) for item in raw]
    return tuple(out)


def _parse_supervision(
    raw_sup: Mapping[str, Any] | None,
) -> tuple[System1Spec | None, BlindCheckSpec | None, ExcerptDisclosureSpec]:
    if raw_sup is None:
        return None, None, ExcerptDisclosureSpec(mode="none")
    _reject_unknown_keys(raw_sup, frozenset({"system1", "blind_check", "excerpt_disclosure"}), "supervision")
    sys1_spec: System1Spec | None = None
    sys1_disclosure_mode: str | None = None
    if "system1" in raw_sup:
        sys1_spec, sys1_disclosure_mode = _parse_system1(raw_sup["system1"])
    blind_spec = _parse_blind_check(raw_sup["blind_check"]) if "blind_check" in raw_sup else None
    disclosure = _parse_excerpt_disclosure(raw_sup, sys1_disclosure_mode)
    return sys1_spec, blind_spec, disclosure


def _parse_system1(raw: Mapping[str, Any]) -> tuple[System1Spec, str]:
    allowed = frozenset(
        {
            "route",
            "model",
            "authority",
            "decision_type",
            "rubric",
            "choices",
            "abstain_default",
            "canary_injection_question",
            "excerpt_disclosure",
        }
    )
    _reject_unknown_keys(raw, allowed, "supervision.system1")
    authority = validate_clean_str(raw.get("authority", "trigger_only"), "supervision.system1.authority", max_bytes=32)
    if authority != "trigger_only":
        raise WorkflowSchemaError("supervision.system1.authority must be 'trigger_only'")
    decision_type = validate_clean_str(raw.get("decision_type"), "supervision.system1.decision_type", max_bytes=32)
    if decision_type not in ALLOWED_DECISION_TYPES:
        raise WorkflowSchemaError(f"supervision.system1.decision_type: invalid {decision_type!r}")
    choices = _parse_str_list(raw.get("choices"), "supervision.system1.choices", min_items=2, max_items=32)
    if len(set(choices)) != len(choices):
        raise WorkflowSchemaError("supervision.system1.choices: duplicates not allowed")
    abstain = validate_clean_str(raw.get("abstain_default"), "supervision.system1.abstain_default", max_bytes=128)
    if abstain not in choices:
        raise WorkflowSchemaError("supervision.system1.abstain_default must be in choices")
    disc_mode = validate_clean_str(raw.get("excerpt_disclosure", "none"), "supervision.system1.excerpt_disclosure", max_bytes=16)
    if disc_mode not in ("none", "opt_in"):
        raise WorkflowSchemaError("supervision.system1.excerpt_disclosure must be 'none' or 'opt_in'")
    spec = System1Spec(
        route=validate_clean_str(raw.get("route"), "supervision.system1.route", max_bytes=128),
        model=validate_clean_str(raw.get("model"), "supervision.system1.model", max_bytes=128),
        authority=authority,
        decision_type=decision_type,
        rubric=validate_clean_str(raw.get("rubric"), "supervision.system1.rubric", allow_multiline=True, max_bytes=MAX_RUBRIC_BYTES),
        choices=choices,
        abstain_default=abstain,
        canary_injection_question=parse_strict_bool(raw.get("canary_injection_question", True), "supervision.system1.canary_injection_question"),
    )
    return spec, disc_mode


def _parse_blind_check(raw: Mapping[str, Any]) -> BlindCheckSpec:
    allowed = frozenset(
        {
            "model_profile",
            "scheduled_audit_interval_s",
            "min_calibration_samples",
            "fp_drift_warn_threshold",
            "fn_drift_warn_count_24h",
        }
    )
    _reject_unknown_keys(raw, allowed, "supervision.blind_check")
    return BlindCheckSpec(
        model_profile=validate_clean_str(raw.get("model_profile"), "supervision.blind_check.model_profile", max_bytes=128),
        scheduled_audit_interval_s=parse_strict_int(raw.get("scheduled_audit_interval_s", 900), "supervision.blind_check.scheduled_audit_interval_s", min_val=60),
        min_calibration_samples=parse_strict_int(raw.get("min_calibration_samples", 10), "supervision.blind_check.min_calibration_samples", min_val=1),
        fp_drift_warn_threshold_bps=parse_basis_points(raw.get("fp_drift_warn_threshold", Decimal("0.25")), "supervision.blind_check.fp_drift_warn_threshold"),
        fn_drift_warn_count_24h=parse_strict_int(raw.get("fn_drift_warn_count_24h", 2), "supervision.blind_check.fn_drift_warn_count_24h", min_val=1),
    )


def _parse_templates(raw: Mapping[str, Any] | None) -> tuple[tuple[str, str], ...]:
    if raw is None:
        return ()
    if not isinstance(raw, Mapping):
        raise WorkflowSchemaError("templates: expected table")
    if len(raw) > MAX_TEMPLATES:
        raise WorkflowSchemaError(f"templates: exceeds {MAX_TEMPLATES} entries")
    items: list[tuple[str, str]] = []
    for key in sorted(raw.keys()):
        val = raw[key]
        validate_template(key, val)
        items.append((key, val))
    return tuple(items)


def _parse_dashboard(raw: Mapping[str, Any] | None) -> DashboardSurfaceSpec | None:
    if raw is None:
        return None
    _reject_unknown_keys(raw, frozenset({"default_surface"}), "dashboard")
    surf = raw.get("default_surface")
    if surf is None:
        return None
    _reject_unknown_keys(surf, frozenset({"title", "priority", "widgets"}), "dashboard.default_surface")
    raw_widgets = surf.get("widgets", [])
    if not isinstance(raw_widgets, list) or len(raw_widgets) > 16:
        raise WorkflowSchemaError("dashboard.default_surface.widgets: expected list of <= 16 widgets")
    widgets: list[WidgetSpec] = []
    for idx, w in enumerate(raw_widgets):
        _reject_unknown_keys(w, frozenset({"id", "type", "metrics", "columns", "chips"}), f"widgets[{idx}]")
        wtype = validate_clean_str(w.get("type"), f"widgets[{idx}].type", max_bytes=64)
        if wtype not in ALLOWED_WIDGET_TYPES:
            raise WorkflowSchemaError(f"widgets[{idx}].type: unsupported widget {wtype!r}")
        widgets.append(
            WidgetSpec(
                id=validate_clean_str(w.get("id"), f"widgets[{idx}].id", max_bytes=64),
                widget_type=wtype,
                metrics=_parse_str_list(w.get("metrics", []), f"widgets[{idx}].metrics", max_items=32),
                columns=_parse_str_list(w.get("columns", []), f"widgets[{idx}].columns", max_items=16),
                chips=_parse_str_list(w.get("chips", []), f"widgets[{idx}].chips", max_items=8),
            )
        )
    return DashboardSurfaceSpec(
        title=validate_clean_str(surf.get("title"), "dashboard.default_surface.title", max_bytes=128),
        priority=parse_strict_int(surf.get("priority", 10), "dashboard.default_surface.priority", min_val=0, max_val=1000),
        widgets=tuple(widgets),
    )


def _parse_effects(raw: Any, field: str) -> tuple[str, ...]:
    items = _parse_str_list(raw if raw is not None else [], field, max_items=32)
    for eff in items:
        if eff not in ALLOWED_EFFECTS:
            raise WorkflowSchemaError(f"{field}: unknown effect {eff!r}")
    return tuple(sorted(set(items)))


def _parse_single_state(
    idx: int,
    item: Any,
    seen: set[str],
    *,
    is_builtin: bool,
    allowlisted_factories: frozenset[str],
) -> StateSpec:
    _reject_unknown_keys(item, frozenset({"name", "shape", "effects", "factory_id"}), f"states[{idx}]")
    name = validate_clean_str(item.get("name"), f"states[{idx}].name", max_bytes=64)
    if not _FIELD_RE.match(name) or name in seen:
        raise WorkflowSchemaError(f"states[{idx}].name: invalid or duplicate {name!r}")
    seen.add(name)
    shape = validate_clean_str(item.get("shape", "observe"), f"states[{idx}].shape", max_bytes=32)
    if shape not in ALLOWED_STATE_SHAPES:
        raise WorkflowSchemaError(f"states[{idx}].shape: unsupported {shape!r}")
    factory_id: str | None = None
    raw_factory = item.get("factory_id")
    if raw_factory is not None:
        factory_id = validate_clean_str(raw_factory, f"states[{idx}].factory_id", max_bytes=64)
        if not is_builtin and factory_id not in allowlisted_factories:
            raise WorkflowSchemaError(
                f"states[{idx}].factory_id: mutable workflow cannot reference non-allowlisted factory {factory_id!r}"
            )
    return StateSpec(
        name=name,
        shape=shape,
        effects=_parse_effects(item.get("effects"), f"states[{idx}].effects"),
        factory_id=factory_id,
    )


def _parse_states(
    raw_states: Any,
    *,
    is_builtin: bool,
    allowlisted_factories: frozenset[str],
) -> tuple[StateSpec, ...]:
    if raw_states is None:
        return ()
    if not isinstance(raw_states, list):
        raise WorkflowSchemaError("states: expected array of tables")
    if len(raw_states) > MAX_STATES:
        raise WorkflowSchemaError(f"states: exceeds maximum of {MAX_STATES}")
    seen: set[str] = set()
    return tuple(
        _parse_single_state(
            idx, item, seen, is_builtin=is_builtin, allowlisted_factories=allowlisted_factories
        )
        for idx, item in enumerate(raw_states)
    )


def _parse_transitions(raw_transitions: Any, state_names: frozenset[str]) -> tuple[TransitionSpec, ...]:
    if raw_transitions is None:
        return ()
    if not isinstance(raw_transitions, list):
        raise WorkflowSchemaError("transitions: expected array of tables")
    if len(raw_transitions) > MAX_TRANSITIONS:
        raise WorkflowSchemaError(f"transitions: exceeds maximum of {MAX_TRANSITIONS}")
    parsed: list[TransitionSpec] = []
    for idx, item in enumerate(raw_transitions):
        _reject_unknown_keys(item, frozenset({"src", "dst", "predicate", "effects"}), f"transitions[{idx}]")
        src = validate_clean_str(item.get("src"), f"transitions[{idx}].src", max_bytes=64)
        dst = validate_clean_str(item.get("dst"), f"transitions[{idx}].dst", max_bytes=64)
        if state_names and (src not in state_names or dst not in state_names):
            raise WorkflowSchemaError(f"transitions[{idx}]: unknown state reference {src!r} -> {dst!r}")
        pred = compile_predicate(item["predicate"]) if "predicate" in item and item["predicate"] is not None else None
        parsed.append(
            TransitionSpec(
                src=src,
                dst=dst,
                predicate=pred,
                effects=_parse_effects(item.get("effects"), f"transitions[{idx}].effects"),
            )
        )
    return tuple(parsed)


def _parse_timers(raw_timers: Any) -> tuple[TimerSpec, ...]:
    if raw_timers is None:
        return ()
    if not isinstance(raw_timers, list) or len(raw_timers) > 32:
        raise WorkflowSchemaError("timers: expected list of <= 32 timers")
    out: list[TimerSpec] = []
    for idx, item in enumerate(raw_timers):
        _reject_unknown_keys(item, frozenset({"name", "interval_s", "effects"}), f"timers[{idx}]")
        out.append(
            TimerSpec(
                name=validate_clean_str(item.get("name"), f"timers[{idx}].name", max_bytes=64),
                interval_s=parse_strict_int(item.get("interval_s"), f"timers[{idx}].interval_s", min_val=MIN_TICK_INTERVAL_S),
                effects=_parse_effects(item.get("effects"), f"timers[{idx}].effects"),
            )
        )
    return tuple(out)


def _parse_signal_handlers(raw_signals: Any) -> tuple[SignalHandlerSpec, ...]:
    if raw_signals is None:
        return ()
    if not isinstance(raw_signals, list) or len(raw_signals) > 32:
        raise WorkflowSchemaError("signal_handlers: expected list of <= 32 handlers")
    out: list[SignalHandlerSpec] = []
    for idx, item in enumerate(raw_signals):
        _reject_unknown_keys(item, frozenset({"signal", "effects"}), f"signal_handlers[{idx}]")
        out.append(
            SignalHandlerSpec(
                signal=validate_clean_str(item.get("signal"), f"signal_handlers[{idx}].signal", max_bytes=64),
                effects=_parse_effects(item.get("effects"), f"signal_handlers[{idx}].effects"),
            )
        )
    return tuple(out)


def _parse_workflow_header(doc: Mapping[str, Any], *, is_builtin: bool) -> dict[str, Any]:
    schema_version = parse_strict_int(doc.get("schema_version"), "schema_version", min_val=1, max_val=1)
    kind = validate_clean_str(doc.get("kind"), "kind", max_bytes=32)
    if kind != "workflow@1":
        raise WorkflowSchemaError("kind must be 'workflow@1'")
    wf_id, id_ns, id_slug = parse_namespaced_id(doc.get("id"), "id")
    if is_builtin != (id_ns == "builtin"):
        raise WorkflowSchemaError("workflow id namespace must match builtin/mutable origin")
    mode = validate_clean_str(doc.get("mode"), "mode", max_bytes=32)
    if mode not in ALLOWED_MODES:
        raise WorkflowSchemaError(f"mode: unsupported {mode!r}")
    autonomy = validate_clean_str(doc.get("autonomy"), "autonomy", max_bytes=32)
    if autonomy not in AUTONOMY_ORDER:
        raise WorkflowSchemaError(f"autonomy: unsupported {autonomy!r}")
    skill_id, skill_ns, skill_slug = parse_namespaced_id(doc.get("orchestrator_skill"), "orchestrator_skill")
    return {
        "autonomy": autonomy,
        "description": validate_clean_str(doc.get("description", ""), "description", allow_multiline=True, max_bytes=1024, allow_empty=True),
        "id": wf_id,
        "id_namespace": id_ns,
        "id_slug": id_slug,
        "kind": kind,
        "mode": mode,
        "orchestrator_skill": skill_id,
        "schema_version": schema_version,
        "skill_namespace": skill_ns,
        "skill_slug": skill_slug,
        "survives_restart": parse_strict_bool(doc.get("survives_restart", True), "survives_restart"),
    }


def parse_and_validate_workflow_toml(
    raw_toml: str,
    *,
    is_builtin: bool,
    allowlisted_factories: frozenset[str] = frozenset(),
) -> WorkflowSpec:
    """Parse and validate a workflow@1 TOML document into an immutable WorkflowSpec."""
    if not isinstance(raw_toml, str) or not raw_toml.strip():
        raise WorkflowSchemaError("workflow TOML must be a non-empty string")
    try:
        doc = tomllib.loads(raw_toml, parse_float=Decimal)
    except tomllib.TOMLDecodeError as exc:
        raise WorkflowSchemaError(f"invalid TOML: {exc}") from exc

    _reject_unknown_keys(doc, _TOP_LEVEL_KEYS, "workflow")
    header = _parse_workflow_header(doc, is_builtin=is_builtin)
    if "scope" not in doc or "limits" not in doc:
        raise WorkflowSchemaError("workflow requires [scope] and [limits] tables")

    scope = _parse_scope(doc["scope"])
    limits = _parse_limits(doc["limits"])
    sys1, blind, disclosure = _parse_supervision(doc.get("supervision"))
    templates = _parse_templates(doc.get("templates"))
    surface = _parse_dashboard(doc.get("dashboard"))
    states = _parse_states(doc.get("states"), is_builtin=is_builtin, allowlisted_factories=allowlisted_factories)
    transitions = _parse_transitions(doc.get("transitions"), frozenset(s.name for s in states))
    timers = _parse_timers(doc.get("timers"))
    signal_handlers = _parse_signal_handlers(doc.get("signal_handlers"))

    if header["mode"] == "statechart" and not states:
        raise WorkflowSchemaError("statechart mode requires at least one state")

    rubric_digest = domain_sha256(RUBRIC_DIGEST_DOMAIN, sys1.rubric_payload()) if sys1 is not None else None
    provisional = WorkflowSpec(
        **header,
        scope=scope,
        limits=limits,
        excerpt_disclosure=disclosure,
        system1=sys1,
        blind_check=blind,
        templates=templates,
        default_surface=surface,
        states=states,
        transitions=transitions,
        timers=timers,
        signal_handlers=signal_handlers,
        spec_digest="",
        candidate_rubric_digest=rubric_digest,
    )
    spec_digest = domain_sha256(SPEC_DIGEST_DOMAIN, provisional.to_canonical_dict())
    return WorkflowSpec(**{**provisional.__dict__, "spec_digest": spec_digest})


# --- Directional compute_security_delta() ---


def _has_blocking_or_pausing_gate(spec: WorkflowSpec) -> bool:
    return any(
        s.shape in ("human_gate_async", "human_gate_blocking")
        or "pause_lane_gate" in s.effects
        or "blocking_gate" in s.effects
        for s in spec.states
    )


def _blocking_gate_signature(spec: WorkflowSpec) -> tuple[Any, ...]:
    return tuple(
        (s.name, s.shape, s.effects)
        for s in spec.states
        if s.shape in ("human_gate_async", "human_gate_blocking")
        or "pause_lane_gate" in s.effects
        or "blocking_gate" in s.effects
    )


def _factories_signature(spec: WorkflowSpec) -> tuple[tuple[str, str], ...]:
    return tuple((s.name, s.factory_id) for s in spec.states if s.factory_id is not None)


def _predicates_signature(spec: WorkflowSpec) -> tuple[tuple[str, str, str | None], ...]:
    return tuple((t.src, t.dst, t.predicate.source if t.predicate else None) for t in spec.transitions)


def _limits_autonomy_widened(old_lim: LimitsSpec, new_lim: LimitsSpec) -> bool:
    cap_widened = (
        new_lim.max_nudges_per_target_per_hour > old_lim.max_nudges_per_target_per_hour
        or new_lim.max_total_nudges_per_run > old_lim.max_total_nudges_per_run
        or new_lim.fleet_max_concurrent_checks > old_lim.fleet_max_concurrent_checks
        or new_lim.fleet_max_checks_per_hour > old_lim.fleet_max_checks_per_hour
        or new_lim.max_open_inbox_items > old_lim.max_open_inbox_items
    )
    interval_shortened = (
        new_lim.min_nudge_interval_s < old_lim.min_nudge_interval_s
        or new_lim.throttle_period_s < old_lim.throttle_period_s
        or new_lim.tick_interval_s < old_lim.tick_interval_s
        or new_lim.wake_grace_after_host_sleep_s < old_lim.wake_grace_after_host_sleep_s
    )
    return cap_widened or interval_shortened


def _autonomy_widened(old: WorkflowSpec, new: WorkflowSpec) -> bool:
    scope_or_role_widened = (
        AUTONOMY_ORDER[new.autonomy] > AUTONOMY_ORDER[old.autonomy]
        or TARGET_SELECTOR_ORDER[new.scope.target_selector] > TARGET_SELECTOR_ORDER[old.scope.target_selector]
        or not set(new.scope.bound_targets).issubset(set(old.scope.bound_targets))
        or (not old.scope.allow_remote_workers and new.scope.allow_remote_workers)
        or (old.limits.defer_nudge_during_human_lease and not new.limits.defer_nudge_during_human_lease)
    )
    return scope_or_role_widened or _limits_autonomy_widened(old.limits, new.limits)


def _decisions_route_or_audit_weakened(old: WorkflowSpec, new: WorkflowSpec) -> bool:
    old_route = (old.system1.route, old.system1.model) if old.system1 else None
    new_route = (new.system1.route, new.system1.model) if new.system1 else None
    old_blind = old.blind_check.model_profile if old.blind_check else None
    new_blind = new.blind_check.model_profile if new.blind_check else None
    if old_route != new_route or old_blind != new_blind:
        return True
    if (
        new.limits.max_decisions_calls_per_hour > old.limits.max_decisions_calls_per_hour
        or new.limits.max_decisions_spend_microusd > old.limits.max_decisions_spend_microusd
        or new.limits.max_blind_check_spend_microusd > old.limits.max_blind_check_spend_microusd
        or new.limits.fleet_audit_checks_per_hour < old.limits.fleet_audit_checks_per_hour
    ):
        return True
    if old.blind_check and new.blind_check:
        if new.blind_check.scheduled_audit_interval_s > old.blind_check.scheduled_audit_interval_s:
            return True
    return False


def _excerpt_disclosure_widened(old: ExcerptDisclosureSpec, new: ExcerptDisclosureSpec) -> bool:
    if new.mode == "none":
        return False
    if old.mode == "none":
        return True
    return (
        new.source != old.source
        or new.max_bytes > old.max_bytes
        or not set(new.allowed_routes).issubset(set(old.allowed_routes))
        or not set(new.permitted_uses).issubset(set(old.permitted_uses))
    )


def _creation_security_delta(new: WorkflowSpec) -> set[str]:
    triggers = {"workflow_added"}
    if (
        new.autonomy != "observe_only"
        or new.scope.allow_remote_workers
        or not new.limits.defer_nudge_during_human_lease
    ):
        triggers.add("workflow_autonomy_widened")
    if (
        new.system1 is not None
        or new.blind_check is not None
        or new.limits.max_decisions_spend_microusd > 0
        or new.limits.max_blind_check_spend_microusd > 0
    ):
        triggers.add("workflow_decisions_route_added")
    if _has_blocking_or_pausing_gate(new):
        triggers.add("workflow_blocking_gate_changed")
    if _factories_signature(new):
        triggers.add("workflow_factory_changed")
    if new.excerpt_disclosure.mode != "none":
        triggers.add("workflow_excerpt_disclosure_changed")
    return triggers


def compute_security_delta(
    old_spec: WorkflowSpec | None,
    new_spec: WorkflowSpec,
    *,
    old_skill_sha256: str | None = None,
    new_skill_sha256: str | None = None,
) -> tuple[str, ...]:
    """Compute directional security-delta triggers across the 10 closed workflow triggers."""
    if old_spec is None:
        triggers = _creation_security_delta(new_spec)
        return tuple(t for t in SECURITY_DELTA_TRIGGERS if t in triggers)

    skill_hash_changed = (
        old_skill_sha256 is not None
        and new_skill_sha256 is not None
        and old_skill_sha256 != new_skill_sha256
    )
    checks: tuple[tuple[str, bool], ...] = (
        ("workflow_autonomy_widened", _autonomy_widened(old_spec, new_spec)),
        ("workflow_decisions_route_added", _decisions_route_or_audit_weakened(old_spec, new_spec)),
        ("workflow_blocking_gate_changed", _blocking_gate_signature(old_spec) != _blocking_gate_signature(new_spec)),
        ("workflow_skill_changed", old_spec.orchestrator_skill != new_spec.orchestrator_skill or skill_hash_changed),
        ("workflow_template_changed", old_spec.templates != new_spec.templates),
        (
            "workflow_rubric_or_predicate_changed",
            old_spec.candidate_rubric_digest != new_spec.candidate_rubric_digest
            or _predicates_signature(old_spec) != _predicates_signature(new_spec),
        ),
        ("workflow_default_surface_changed", old_spec.default_surface != new_spec.default_surface),
        ("workflow_factory_changed", _factories_signature(old_spec) != _factories_signature(new_spec)),
        ("workflow_excerpt_disclosure_changed", _excerpt_disclosure_widened(old_spec.excerpt_disclosure, new_spec.excerpt_disclosure)),
    )
    return tuple(name for name, fired in checks if fired)
