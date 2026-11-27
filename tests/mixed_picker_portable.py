"""Copied-bootstrap fixture for mixed-provider model projection and simulated placement."""

from contextlib import contextmanager, nullcontext
from dataclasses import asdict, dataclass, field
from hashlib import sha256
from hmac import compare_digest
import json
from pathlib import Path
import secrets
import socket
import sys
from threading import Lock
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlsplit

from oc_openai import session_broker as broker
from oc_openai.cli import StreamTerminal
from oc_openai.proof_gate import (
    ClosedProofSlotGate, ProofApproval, ProofGate, ProofGateError, canonical_proof_body,
    compute_exposure_history_digest,
)
from oc_providers import config as provider_config
from oc_providers.contracts import InstancePreflight, ReadinessState, SlotHandle

SCOPES = ("google--personal", "openai--personal", "openai--work")
MODEL = "opal-v2"
CWD = "fixture-work"
MODELS = (MODEL, "opal-v1")
POLICY = "fixture subscription"
POD_ID = "a" * 64
INSTRUCTIONS = (
    "Synthetic instructions\n"
    "Today's date: Wed Nov 25 2026\n"
    f"  Working directory: /sandbox/{CWD}\n"
    f"  Workspace root folder: /sandbox/{CWD}\n"
)
INSTRUCTIONS_DIGEST = sha256(INSTRUCTIONS.replace("Wed Nov 25 2026", "[date]").replace(f"/{CWD}", "").encode()).hexdigest()


def require(condition, message):
    if not condition:
        raise ProofGateError(message)


class FakePlacement:
    """Return opaque container IDs and assert start, verification and removal order."""

    def __init__(self, root, spec):
        self.root = root
        self.spec = spec
        self.containers = {}
        self.events = []
        self.config_path = None
        self.worker_id = None
        self.worker_args = None
        self.pod = None

    def podman(self, *argv, **_options):
        status, stdout = 0, b""
        match argv:
            case ("create", *args):
                ident = f"{len(self.events) + 1:064x}"
                self.containers[ident] = "created"
                self.events.append(("create", ident))
                if "-it" in args:
                    self.record_worker(ident, args)
                else:
                    self.events.append(("relay", ident, "--defer-bind" in args))
                stdout = ident.encode()
            case ("start", ident):
                require(self.containers.get(ident) == "created", "unexpected relay start")
                self.containers[ident] = "started"
                self.events.append(("start", ident))
            case ("rm", "-f", ident):
                require(ident in self.containers, "unexpected container removal")
                del self.containers[ident]
                self.events.append(("remove", ident))
            case ("container", "exists", ident):
                status = int(ident not in self.containers)
            case _:
                raise AssertionError(f"Unexpected hardware operation: {argv!r}")
        return SimpleNamespace(returncode=status, stdout=stdout)

    def record_worker(self, ident, args):
        spec = self.spec
        mounts = [args[index + 1] for index, arg in enumerate(args[:-1]) if arg == "-v"]
        require(len(mounts) == 3, "unexpected worker mounts")
        config_mount = mounts[2]
        file, separator, options = config_mount.partition(":/etc/opencode/opencode.json:")
        path = Path(file)
        require(separator and options == "ro,Z,nosuid,nodev,noexec"
                and path.is_relative_to(self.root / "jobs") and path.stat().st_mode & 0o222 == 0,
                "unexpected projected config path or permissions")
        mode = "mini" if spec["cli_ui_mode"] == "mini" else "full"
        expected = [
            "-it", "--rm", "--pull=never", "--name", spec["agent"], "--pod", spec["pod"],
            "--label", "oc.sandbox=1", "--label", f"oc.instance={spec['instance']}",
            "--label", "oc.provider=multi", "--label", f"oc.ui_mode={mode}",
            "--http-proxy=false", "--image-volume=ignore", "--restart=no",
            "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--security-opt", f"label=level:{spec['level']}", "--pids-limit=512", "--memory", spec["agent_mem"],
            "-v", f"{spec['sandbox']}:/sandbox", "-v", f"{spec['home_vol']}:/root:Z", "-v", config_mount,
            "-w", f"/sandbox/{spec['cwd']}",
            "-e", f"OC_INSTANCE={spec['instance']}",
            "-e", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "-e", "OPENCODE_CONFIG=/etc/opencode/opencode.json",
            "-e", "OPENCODE_CONFIG_PROJECT_DISABLE=true", "-e", "OPENCODE_DISABLE_MODELS_FETCH=true",
            "-e", "OPENCODE_DISABLE_FREE_MODELS=true", "-e", "OPENCODE_DISABLE_AUTOUPDATE=true",
            "-e", "OPENCODE_DISABLE_CLAUDE_CODE=true", spec["agent_image"],
        ]
        if mode == "mini":
            expected.append("mini")
        require(self.worker_id is None and self.pod == POD_ID and args == expected,
                "unexpected portable worker create arguments")
        self.worker_id = ident
        self.worker_args = args
        self.config_path = path

    def verify_pod(self, spec):
        require(spec == self.spec, "unexpected placement")
        self.pod = POD_ID
        return self.pod, []

    @staticmethod
    def idle(*_args, **kwargs):
        require(not kwargs["pod_containers"], "unexpected existing containers")

    def verify_relay(self, ident, _image, pod, _level, job, _siblings):
        require(pod == POD_ID and self.containers.get(ident) == "started"
                and job.lease.status() == "pending", "unexpected relay verification")
        self.events.append(("verify", ident, job.incarnation))

    def wait_bound(self, ident, *, port):
        require(any(event[:2] == ("verify", ident) for event in self.events),
                "relay bound before verification")
        self.events.append(("bound", ident, port))


@dataclass(frozen=True)
class Binding:
    scope: str
    registration_id: str
    generation: int
    epoch: str
    incarnation: str
    launch_id: str
    pod: str
    placement: str
    auth_mode: str
    route_policy: str


class Recorder:
    """Independent per-route transport observations taken after the write fence."""

    def __init__(self):
        self.lock = Lock()
        self.writes = []

    def record(self, scope, binding, body):
        with self.lock:
            self.writes.append((scope, asdict(binding), json.loads(json.dumps(body))))


class Transport:
    def __init__(self, scope, binding, recorder):
        self.scope = scope
        self.binding = binding
        self.recorder = recorder

    def require_active(self, binding):
        require(binding == self.binding, "wrong fixture transport binding")

    @contextmanager
    def interactive_responses(self, binding, body, before_write, *, authorization, write_fence, **_):
        self.require_active(binding)
        with (authorization or nullcontext)(), write_fence():
            before_write()
            self.recorder.record(self.scope, binding, body)
        yield response_events(body["model"])


def response_events(model):
    response = {"id": "resp_fixture", "object": "response", "model": model}
    item = {"id": "msg_fixture", "type": "message", "role": "assistant"}
    part = {"type": "output_text", "text": "ok", "annotations": []}
    position = {"item_id": item["id"], "output_index": 0, "content_index": 0}
    yield {"type": "response.created", "response": dict(response, status="in_progress", output=[])}
    yield {"type": "response.output_item.added", "output_index": 0,
           "item": dict(item, status="in_progress", content=[])}
    yield {"type": "response.content_part.added", **position, "part": dict(part, text="")}
    yield {"type": "response.output_text.delta", **position, "delta": "ok"}
    yield {"type": "response.output_text.done", **position, "text": "ok"}
    yield {"type": "response.content_part.done", **position, "part": part}
    completed = dict(item, status="completed", content=[part])
    yield {"type": "response.output_item.done", "output_index": 0, "item": completed}
    yield {"type": "response.completed", "response": dict(
        response, status="completed", output=[completed],
        usage={"input_tokens": 10, "output_tokens": 1, "total_tokens": 11},
    )}


class ProjectionGate(ProofGate):
    def __init__(self, approval, **kwargs):
        super().__init__(approval, **kwargs)
        self.raw_route = None
        self.projected = False

    def harden_opencode_config(self, payload):
        expected = f"{self.approval.scoped_provider_id}/{self.approval.approved_model}"
        self.raw_route = payload.get("model")
        require(self.raw_route == expected, "raw projected route differs from fixture approval")
        self.projected = True
        return super().harden_opencode_config(payload)

    def verify_ready_for_arm(self):
        require(self.projected, "raw projected route was never checked")
        return super().verify_ready_for_arm()


class FixtureAdapter:
    def __init__(self, kind, owner):
        self.kind = kind
        self.owner = owner

    def is_qualified(self, auth_mode, placement):
        return auth_mode == "subscription" and placement == "sandbox"

    def preflight_instance(self, spec):
        require(spec.kind == self.kind and spec.scoped_id in SCOPES, "unexpected fixture instance")
        return InstancePreflight(spec=spec, readiness=ReadinessState.READY, models=MODELS, route_policy=POLICY)

    def provider_config_entry(self, preflight, *, port, worker_token):
        scope = preflight.spec.scoped_id
        if self.owner.scenario == "wrong-bearer" and scope == self.owner.approval.scoped_provider_id:
            worker_token = "wrong-projected-fixture-bearer"
        label = preflight.spec.qualified_name if scope.endswith("--personal") else preflight.spec.label
        return {
            "name": label,
            "package": "@opencode/ai/providers/openai-compatible/responses",
            "settings": {"baseURL": f"http://127.0.0.1:{port}/v1", "apiKey": worker_token, "store": False},
            "models": {
                slug: {"name": f"Opal {slug[-2:]} - {label} [subscription]"}
                for slug in preflight.models
            },
        }

    def open_slot(self, preflight, **params):
        return self._open(preflight, discovery=False, **params)

    def open_discovery_slot(self, preflight, **params):
        return self._open(preflight, discovery=True, **params)

    @contextmanager
    def _open(self, preflight, *, slot_index, slot_root, port, worker_token,
              acknowledged_exposure_digest, on_revoke, discovery):
        owner = self.owner
        scope = preflight.spec.scoped_id
        turn = not discovery and scope == owner.approval.scoped_provider_id
        if turn:
            owner.consume_permit(preflight)
        job = broker._SessionJob(slot_root, "inc_" + secrets.token_hex(16))
        closed = ClosedProofSlotGate(scope)
        job.prepare()
        try:
            binding = Binding(
                scope=scope, registration_id=owner.registrations[scope],
                generation=owner.approval.credential_generation, epoch=owner.approval.selection_epoch,
                incarnation=job.incarnation, launch_id=owner.approval.run_id,
                pod=owner.placement.pod, placement="sandbox",
                auth_mode=preflight.spec.auth_mode, route_policy=preflight.route_policy,
            )
            if turn:
                owner.gate.bind_incarnation(job.incarnation, job.generation)
            session = broker.SessionBroker(
                socket_path=job.provider_socket,
                relay_proof=job.relay_proof,
                worker_token=worker_token,
                lease=job.lease,
                connection=Transport(scope, binding, owner.recorder),
                binding=binding,
                models=preflight.models,
                profile_label=preflight.spec.label,
                expected_port=port,
                policy=broker.SessionPolicy(
                    exposure_dir=owner.exposure,
                    acknowledged_exposure_digest=acknowledged_exposure_digest,
                    authorization=(lambda: owner.authorize(binding, job)) if turn else None,
                    on_revoke=lambda: on_revoke(slot_index),
                    proof_gate=owner.gate if turn else closed,
                    job_incarnation=job.incarnation,
                ),
            )
            session.start()
            record = SimpleNamespace(
                job=job, port=port, token=worker_token, closed=not turn, released=False,
            )
            owner.slots[scope] = record
            try:
                yield SlotHandle(
                    slot_index=slot_index, scoped_id=scope, provider_label=preflight.spec.qualified_name,
                    port=port, job=job, broker=session, lease=job.lease,
                    build_relay_args=lambda spec: broker._build_relay_args(
                        spec, job, slot_index=slot_index, port=port,
                        provider_label=preflight.spec.qualified_name,
                        relay_name_override=f"{spec['pod']}-relay-disc-{slot_index}" if discovery else None,
                        defer_bind=turn,
                    ),
                    lease_release_confirmed=lambda: record.released,
                )
            finally:
                session.close()
                record.released = record.job.lease.status() == "terminal" and not job.provider_socket.exists()
        finally:
            job.revoke()


@dataclass(frozen=True)
class ProjectedRoute:
    endpoint: str
    bearer: str = field(repr=False)


class ProjectedWorker:
    """Use mounted settings for requests, mapping the fake loopback ports to Unix relays."""

    def __init__(self, config_path, slots):
        self.slots = slots
        self.projection = json.loads(config_path.read_bytes())
        self.routes = {}
        for scope, entry in self.projection["providers"].items():
            settings = entry["settings"]
            self.routes[scope] = ProjectedRoute(settings["baseURL"], settings["apiKey"])

    def check_bearers(self):
        require(self.routes.keys() == self.slots.keys(), "unexpected worker provider projection")
        for scope, route in self.routes.items():
            slot = self.slots[scope]
            require(route.endpoint == f"http://127.0.0.1:{slot.port}/v1",
                    "projected endpoint does not belong to its fixture route")
            require(type(route.bearer) is str and route.bearer.isascii()
                    and compare_digest(route.bearer, slot.token),
                    "projected bearer does not belong to its fixture route")

    def request(self, scope, *, bearer_scope=None, model=MODEL, extra=None):
        endpoint = urlsplit(self.routes[scope].endpoint)
        bearer = self.routes[scope if bearer_scope is None else bearer_scope].bearer
        slot, = (slot for slot in self.slots.values() if slot.port == endpoint.port)
        body = dict(canonical_proof_body(model), instructions=INSTRUCTIONS)
        body.update(extra or {})
        data = json.dumps(body).encode("ascii")
        raw = (
            f"POST {endpoint.path}/responses HTTP/1.1\r\n"
            f"Host: {endpoint.netloc}\r\n"
            f"Authorization: Bearer {bearer}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(data)}\r\n\r\n"
        ).encode("ascii") + data
        frame = broker.relay_mod.PROOF_PREFIX + slot.job.relay_proof + broker.REQUEST_LENGTH.pack(len(raw)) + raw
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(5)
            peer.connect(str(slot.job.provider_socket))
            peer.sendall(frame)
            with peer.makefile("rb") as stream:
                return stream.read()


def status(reply):
    return int(reply.split(b" ", 2)[1])


def chunk_payload(reply):
    header, separator, wire = reply.partition(b"\r\n\r\n")
    headers = header.split(b"\r\n")
    require(separator and headers[0] == b"HTTP/1.1 200 OK"
            and b"Content-Type: text/event-stream" in headers
            and b"Transfer-Encoding: chunked" in headers, "unexpected fixture stream headers")
    payload = bytearray()
    while wire:
        size, separator, body = wire.partition(b"\r\n")
        require(separator and size and all(char in b"0123456789abcdef" for char in size),
                "invalid fixture response chunk size")
        length = int(size, 16)
        require(len(body) >= length + 2 and body[length:length + 2] == b"\r\n",
                "truncated fixture response chunk")
        wire = body[length + 2:]
        if not length:
            require(not wire, "unexpected bytes after terminal fixture chunk")
            return bytes(payload)
        payload.extend(body[:length])
    raise ProofGateError("missing terminal fixture response chunk")


TEXT_EVENTS = (
    "response.created", "response.output_item.added", "response.content_part.added",
    "response.output_text.delta", "response.output_text.done", "response.content_part.done",
    "response.output_item.done", "response.completed",
)


def read_assistant_sse(reply, model):
    payload = chunk_payload(reply)
    require(payload.endswith(b"\n\n"), "truncated fixture SSE")
    events = []
    for frame in payload[:-2].split(b"\n\n"):
        event, separator, data = frame.partition(b"\ndata: ")
        require(separator and event.startswith(b"event: "), "invalid fixture SSE frame")
        item = json.loads(data)
        require(item["type"] == event[len(b"event: "):].decode("ascii"),
                "fixture SSE types disagree")
        events.append(item)
    require(tuple(event["type"] for event in events) == TEXT_EVENTS, "unexpected fixture SSE event sequence")
    created, added, part_added, delta, text_done, part_done, done, completed = events
    require(created["response"]["model"] == model and created["response"]["output"] == [],
            "unexpected fixture response start")
    for event in (added, done):
        item = event["item"]
        require(item["type"] == "message" and item["role"] == "assistant",
                "non-assistant fixture response item")
    for event in (part_added, part_done):
        require(event["part"]["type"] == "output_text", "non-text fixture response part")
    require(added["item"]["content"] == [] and part_added["part"]["text"] == "",
            "nonempty initial fixture response content")
    response = completed["response"]
    require(response["status"] == "completed" and response["model"] == model
            and response["output"] == [done["item"]] and done["item"]["content"] == [part_done["part"]]
            and delta["delta"] == text_done["text"] == part_done["part"]["text"] == "ok",
            "unexpected completed fixture assistant text or content")
    return {"text": delta["delta"], "completed": True, "tool_parts": 0, "events": len(events)}


class Owner:
    def __init__(self, root, spec, target, scenario):
        self.spec = spec
        self.scenario = scenario
        self.root = root
        self.home = root / "home"
        self.config_dir = self.home / ".config" / "oc-sandbox"
        self.exposure = root / "exposure"
        self.placement = FakePlacement(root, spec)
        self.recorder = Recorder()
        self.slots = {}
        self.registrations = {scope: secrets.token_hex(16) for scope in SCOPES}
        self.confirmed = False
        self.alive = True
        self.permit = None
        self.observations = {}
        self.approval = ProofApproval(
            run_id=secrets.token_hex(16), instance_label=target.split("--")[1],
            scoped_provider_id=target, approved_model=MODEL,
            ui_mode="mini" if spec["cli_ui_mode"] == "mini" else "full", cwd=spec["cwd"],
            selection_epoch=secrets.token_hex(16), credential_generation=1,
            history_digest_all_12_files=compute_exposure_history_digest(self.exposure),
            route_policy=POLICY,
            providers_config_digest=self.config_digest(),
        )
        self.gate = ProjectionGate(
            self.approval, evidence_dir=root / "evidence", exposure_dir=self.exposure,
            check_owner_alive=self.require_owner,
            check_binding_intact=self.check_binding,
            expected_instructions_sha256=INSTRUCTIONS_DIGEST,
        )

    def config_digest(self):
        return provider_config.load_provider_config_with_digest(
            config_dir=self.config_dir, sandbox_dir=self.home / "opencode-sandbox",
        )[1]

    def require_owner(self):
        require(self.alive and self.confirmed, "fixture foreground authority is closed")

    def check_binding(self, approval):
        require(approval is self.approval and self.config_digest() == approval.providers_config_digest,
                "fixture registration or configuration drift")

    @contextmanager
    def authorize(self, binding, job):
        approval = self.approval
        if not (
            self.alive and self.confirmed and binding.scope == approval.scoped_provider_id
            and binding.registration_id == self.registrations[binding.scope]
            and binding.generation == approval.credential_generation
            and binding.epoch == approval.selection_epoch
            and binding.incarnation == job.incarnation
            and binding.launch_id == approval.run_id
            and binding.pod == self.placement.pod == POD_ID
            and binding.placement == "sandbox"
            and binding.auth_mode == approval.auth_mode and binding.route_policy == approval.route_policy
        ):
            raise broker.ConnectionError("connection_retired")
        yield

    def confirm(self, prompt):
        require("Start interactive " in prompt, "unexpected workstation confirmation")
        self.observations["confirmation"] = prompt
        self.confirmed = self.scenario != "cancelled"
        return self.confirmed

    def consume_permit(self, item):
        self.require_owner()
        self.check_binding(self.approval)
        discovery = self.permit
        require(self.placement.pod == POD_ID and discovery is not None and discovery.released and discovery.closed
                and discovery.job.lease.status() == "terminal"
                and item.spec.scoped_id == self.approval.scoped_provider_id
                and item.spec.auth_mode == self.approval.auth_mode
                and item.route_policy == self.approval.route_policy and MODEL in item.models,
                "fixture turn prepared without exact retired discovery slot")
        self.permit = None

    def drive(self, agent_id, stop_event, arm):
        require(agent_id == self.placement.worker_id and self.placement.containers.get(agent_id) == "created"
                and self.placement.pod == POD_ID and not stop_event.is_set(), "unexpected agent attachment")
        self.observations["worker_id"] = self.placement.worker_id
        self.observations["runner_worker_id"] = agent_id
        worker = ProjectedWorker(self.placement.config_path, self.slots)
        worker.check_bearers()
        self.observations["worker_routes_checked"] = True
        projection = worker.projection
        target = self.approval.scoped_provider_id
        slots = self.slots.copy()
        self.observations["slots"] = {
            scope: {
                "port": slot.port,
                "endpoint": projection["providers"][scope]["settings"]["baseURL"],
                "models": {slug: cfg["name"] for slug, cfg in projection["providers"][scope]["models"].items()},
                "zero_tools": all(cfg["capabilities"]["tools"] is False
                                  for cfg in projection["providers"][scope]["models"].values()),
            }
            for scope, slot in slots.items()
        }
        self.observations["unique_bearers"] = len({route.bearer for route in worker.routes.values()})
        self.observations["pre_arm"] = {scope: status(worker.request(scope)) for scope in slots}
        self.observations["cross_slot"] = {
            scope: status(worker.request(scope, bearer_scope=target))
            for scope in slots if scope != target
        }
        require(self.recorder.writes == [], "discovery reached fixture transport")
        projected_model_label = projection["providers"][target]["models"][MODEL]["name"]
        if self.scenario == "wrong-model-evidence":
            projected_model_label = next(
                projection["providers"][scope]["models"][MODEL]["name"] for scope in slots if scope != target
            )
        self.require_owner()
        self.check_binding(self.approval)
        expected = f"Opal v2 - {target.replace('--', '/') if target.endswith('--personal') else 'work'} [subscription]"
        if projected_model_label != expected:
            self.observations["wrong_model_evidence_refused"] = True
            return 0
        self.permit = slots[target]
        try:
            arm(projected_model_label, sha256(projected_model_label.encode()).hexdigest())
        finally:
            self.permit = None
        turn = self.slots[target]
        self.observations["fresh_incarnation"] = turn.job.incarnation != slots[target].job.incarnation
        self.observations["retired_discovery"] = slots[target].released
        self.observations["siblings_after_arm"] = {
            scope: status(worker.request(scope)) for scope in slots if scope != target
        }
        self.observations["sibling_bearer_to_turn"] = {
            scope: status(worker.request(target, bearer_scope=scope)) for scope in slots if scope != target
        }
        require(self.recorder.writes == [], "sibling bearer reached the replacement transport")
        self.observations["wrong_model"] = status(worker.request(target, model="opal-v1"))
        self.observations["automatic_prompt"] = status(worker.request(target, extra={
            "input": [{"type": "message", "role": "user", "content": "Create a title"}],
        }))
        self.observations["tool_request"] = status(worker.request(target, extra={"tools": [{"type": "web_search"}]}))
        if self.scenario == "owner-loss":
            self.alive = False
            self.observations["owner_loss"] = status(worker.request(target))
            return 0
        if self.scenario == "config-drift":
            with (self.config_dir / "providers.toml").open("a") as stream:
                stream.write("# fixture drift\n")
            self.observations["config_drift"] = status(worker.request(target))
            return 0
        reply = worker.request(target)
        self.observations["received_sse"] = read_assistant_sse(reply, MODEL)
        self.observations["replay"] = status(worker.request(target))
        try:
            arm(projected_model_label, sha256(projected_model_label.encode()).hexdigest())
        except ProofGateError:
            self.observations["rearm_refused"] = True
        return 0


def run(supervise, spec, terminal):
    """Inject scratch options only after the copied supervisor decoded FD 3."""
    root = Path(__file__).resolve().parents[2]
    scenario = json.loads((root / "case.json").read_text())
    target = scenario["target"]
    cases = {"positive", "wrong-model-evidence", "owner-loss", "config-drift", "cancelled", "wrong-bearer"}
    require(target in SCOPES and scenario["mode"] in cases, "unexpected fixture case")
    expected_spec = {
        "instance": "fixture", "pod": "oc-fixture", "agent": "oc-fixture-agent",
        "relay": "oc-fixture-openai-relay", "relay_image": "c" * 64, "agent_image": "d" * 64,
        "agent_mem": "2g", "level": "s0:c100,c200",
        "sandbox": str(root / "home" / "opencode-sandbox"), "cwd": CWD,
        "home_vol": "oc-fixture-openai-home", "chromium": "oc-fixture-chromium",
        "postgres": "", "pg_secret": "", "dind": "", "dind_run": "",
        "provider_filter": "", "cli_ui_mode": scenario["ui_mode"],
    }
    require(scenario["ui_mode"] in {"default", "mini"} and spec == expected_spec,
            "launch spec differs from the pinned portable fixture")

    def unavailable(*_args, **_kwargs):
        raise AssertionError("portable fixture attempted to access account state or start a host command")

    def local_sockets_only(event, args):
        if event == "socket.__new__" and args[1] != socket.AF_UNIX:
            raise AssertionError("portable fixture attempted to open a network socket")

    sys.addaudithook(local_sockets_only)
    with patch.object(provider_config, "_account_home", return_value=root / "home"):
        owner = Owner(root, spec, target, scenario["mode"])
        hardware = owner.placement
        with (
            patch.multiple(broker, check_devbox=lambda: None, check_host=lambda: None,
                           _verify_pod_with_containers=hardware.verify_pod,
                           _ensure_containers_idle=hardware.idle, podman=hardware.podman,
                           _verify_relay_isolation=hardware.verify_relay, _wait_relay_bound=hardware.wait_bound,
                           make_backend=unavailable, _launch_agent_tty=unavailable, SHARED_TMP=root / "jobs"),
            patch.object(broker.subprocess, "Popen", side_effect=unavailable),
            patch.object(StreamTerminal, "attended", return_value=True),
            patch.object(StreamTerminal, "confirm", side_effect=owner.confirm),
        ):
            result = supervise(
                spec, terminal, config_dir=owner.config_dir,
                adapters={kind: FixtureAdapter(kind, owner) for kind in ("google", "openai")},
                lock_dir=root / "locks",
                proof_options=broker.ProofSessionOptions(proof_gate=owner.gate, agent_runner=owner.drive),
            )
        observations = owner.observations
        observations.update(
            target=target, writes=owner.recorder.writes, live_containers=list(hardware.containers),
            placement_events=hardware.events, remaining_jobs=list(map(str, (root / "jobs").iterdir())),
            mini_argument=bool(hardware.worker_args and hardware.worker_args[-1] == "mini"),
            gate=owner.gate.snapshot_evidence(), raw_route=owner.gate.raw_route,
        )
        (root / "observations.json").write_text(json.dumps(observations))
        return result
