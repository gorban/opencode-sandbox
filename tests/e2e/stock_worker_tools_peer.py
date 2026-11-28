"""Host-only synthetic TLS peer for the stock worker-tools guest fixture."""

from contextlib import suppress
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import stat
from urllib.parse import parse_qs

from oc_openai.connection import DIRECT_SCOPE
from oc_openai.connection_state import decode_json
from oc_openai.responses import API_HOST, AUTH_HOST, DISCOVERY, JWKS, MODELS, RESPONSES, TOKEN
from stock_worker_tools_sealed import (
    MANAGED_SHELL_SHA256, SEALED_CASES, SHELL_SCHEMA_KEYS, SHELL_SCHEMA_SHA256,
    append_row, journal_path, read_journal, scenario, verified_rows,
)
from stock_worker_tools_history import bounded_text, digest
from stock_worker_tools_protocol import (
    MODEL, PROMPT, TITLE, TITLE_PROMPT, ToolScript, encode_sse, output_text, refused_events, require, response_events,
)

PRIVATE_LEAF = ".oc-stock-tools-proof"
SHAPE_LOG = "peer-shapes.jsonl"
WORKSPACE = "/sandbox/construct"
SYNTHETIC_CIPHERTEXT = "fixture-reasoning-ciphertext"
SYNTHETIC_REASONING_ID = "rs_fixture_upstream"


def private_file(path, flags):
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        os.close(fd)
        raise RuntimeError("Untrusted offline stock-tools evidence file")
    return fd


def receipt(home, operation, *, peer_pid=None, details=None):
    append_receipt(Path(home) / PRIVATE_LEAF / "peer.jsonl", operation, peer_pid=peer_pid, details=details)


def append_receipt(path, operation, *, peer_pid=None, details=None):
    fd = private_file(path, os.O_WRONLY | os.O_APPEND)
    payload = {"op": operation, "pid": os.getpid() if peer_pid is None else peer_pid}
    if details is not None:
        payload["details"] = details
    line = json.dumps(payload, separators=(",", ":")).encode("ascii") + b"\n"
    with os.fdopen(fd, "ab", buffering=0) as stream:
        require(stream.write(line) == len(line), "Partial peer evidence write")


def read_request(stream):
    with stream.makefile("rb") as reader:
        method, path, version = reader.readline(256).decode("ascii").strip().split(" ")
        require(method in {"GET", "POST"} and version == "HTTP/1.1", "Unexpected fake-peer HTTP method")
        headers = {}
        for _ in range(32):
            line = reader.readline(4096)
            if line == b"\r\n":
                break
            name, sep, value = line.decode("ascii").rstrip("\r\n").partition(":")
            key = name.lower()
            require(sep == ":" and key and key not in headers, "Malformed fake-peer HTTP headers")
            headers[key] = value.strip()
        else:
            raise RuntimeError("Too many fake-peer HTTP headers")
        size = int(headers["content-length"])
        require(0 <= size <= 128 * 1024, "Fake-peer request exceeds its expected bound")
        body = reader.read(size)
        require(len(body) == size, "Incomplete fake-peer HTTP body")
    return method, path, headers, body


def scripted_tools(home, body):
    target = Path(home) / PRIVATE_LEAF / "tool-state.json"
    fd = private_file(target, os.O_RDWR)
    with os.fdopen(fd, "r+b") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        stored = json.loads(stream.read(1024 * 1024))
        script = ToolScript(WORKSPACE)
        for previous in stored:
            script.respond(previous)
        result = script.respond(body)
        stage = len(script.requests)
        stored.append(body)
        updated = json.dumps(stored, separators=(",", ":")).encode("ascii")
        require(len(updated) < 1024 * 1024, "Synthetic continuation history exceeded bounds")
        stream.seek(0)
        stream.write(updated)
        stream.truncate()
        stream.flush()
        return result, stage, script.outputs


def upstream_response(home, case, method, path, headers, raw):
    origin = headers.get("host"), method, path
    if origin == (API_HOST, "POST", RESPONSES):
        require(headers.get("authorization") == "Bearer test-access", "Missing synthetic workstation authorization")
        body = decode_json(raw)
        if case == "tools":
            events, stage, outputs = scripted_tools(home, body)
            is_title = events[0]["response"]["id"].endswith("_title")
            receipt(home, "title" if is_title else "generation",
                    details={"stage": stage, "result_sha256": [hashlib.sha256(item.encode()).hexdigest() for item in outputs]})
            return "text/event-stream", encode_sse(events)
        require(case in {"hosted", "undeclared", "held", "vault"}, "An unapproved case made an inference request")
        require(body.get("model") == MODEL, "Incorrect synthetic negative model")
        message = body["input"][-1]
        prompt = output_text(message["content"])
        require(message["role"] == "user", "Unexpected synthetic prompt role")
        if case in {"hosted", "undeclared"} and prompt == TITLE_PROMPT:
            require(len(body["input"]) == 1 and not body.get("tools"), "Invalid negative title request")
            receipt(home, "title")
            return "text/event-stream", encode_sse(response_events("title", reply=TITLE))
        require(prompt == PROMPT, "Incorrect synthetic negative prompt")
        if case in {"hosted", "undeclared"}:
            digest = hashlib.sha256(raw).hexdigest().encode("ascii")
            first_flow = Path(home) / PRIVATE_LEAF / f"{case}-request"
            try:
                fd = os.open(first_flow, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                with os.fdopen(private_file(first_flow, os.O_RDONLY), "rb") as stream:
                    require(stream.read(65) == digest, "Stock retry changed the initial request")
                receipt(home, "initial_retry")
                return "application/json", b'{"error":{"code":"fixture_stop_retry"}}'
            with os.fdopen(fd, "wb") as stream:
                stream.write(digest)
        receipt(home, "generation", details={"case": case})
        initial = next(response_events(0))
        if case == "vault":
            if len(body["input"]) == 1:
                item = {"type": "reasoning", "id": SYNTHETIC_REASONING_ID, "summary": [], "status": "completed",
                        "encrypted_content": SYNTHETIC_CIPHERTEXT}
                done = {"type": "response.completed", "response": {**initial["response"], "status": "completed",
                        "output": [item], "usage": {"input_tokens": 2, "output_tokens": 1, "total_tokens": 3}}}
                return "text/event-stream", encode_sse((initial,
                       {"type": "response.output_item.done", "output_index": 0, "item": item}, done))
            require(len(body["input"]) == 2, "Unexpected synthetic reasoning replay input")
            reasoning = body["input"][0]
            require(reasoning["type"] == "reasoning" and reasoning["id"] == SYNTHETIC_REASONING_ID
                    and reasoning["encrypted_content"] == SYNTHETIC_CIPHERTEXT, "Unauthentic reasoning reached upstream")
            receipt(home, "authentic_reasoning")
            return "text/event-stream", encode_sse(response_events(1))
        require(len(body["input"]) == 1, "Unexpected negative request input")
        if case == "held":
            return "text/event-stream", None
        return "text/event-stream", encode_sse(refused_events(case, body, WORKSPACE))
    if origin == (API_HOST, "GET", MODELS):
        require(headers.get("authorization") == "Bearer test-access", "Incorrect synthetic catalog authorization")
        value = {"models": [{"slug": MODEL, "visibility": "list"}]}
    elif origin == (AUTH_HOST, "POST", TOKEN):
        require(parse_qs(raw.decode()).get("grant_type") in (["authorization_code"], ["refresh_token"]),
                "Unexpected synthetic token grant")
        value = {"id_token": "test-identity", "access_token": "test-access", "refresh_token": "test-refresh",
                 "token_type": "Bearer", "expires_in": 3600, "scope": DIRECT_SCOPE}
    elif origin == (AUTH_HOST, "GET", DISCOVERY):
        value = {"issuer": f"https://{AUTH_HOST}", "revocation_endpoint": f"https://{AUTH_HOST}/fixture/revoke"}
    elif origin == (AUTH_HOST, "GET", JWKS):
        value = {"keys": ["synthetic"]}
    else:
        raise RuntimeError("Unexpected synthetic HTTPS destination")
    receipt(home, "metadata")
    return "application/json", json.dumps(value).encode("ascii")


def sealed_request_shape(body):
    # The count reflects the measured stock envelope. Report names only for
    # fixture-owned, known fields and tools. Ignore all other strings.
    from stock_worker_tools_history import _TOOL_DEFINITIONS
    from stock_worker_tools_sealed import _ENVELOPE

    fields = body.keys() if type(body) is dict else set()
    tools = body.get("tools") if type(body) is dict else None
    named = {item["name"]: item for item in tools if type(item) is dict
             and type(item.get("name")) is str and item["name"] in _TOOL_DEFINITIONS} if type(tools) is list else {}
    pins = {**_TOOL_DEFINITIONS, "shell": MANAGED_SHELL_SHA256}
    return {
        "missing_fields": sorted(_ENVELOPE - fields),
        "extra_field_count": len(fields - _ENVELOPE),
        "declaration_count": len(tools) if type(tools) is list else None,
        "missing_known_tools": sorted(_TOOL_DEFINITIONS.keys() - named.keys()),
        "changed_full_definitions": sorted(name for name in named if digest(named[name]) != pins[name]),
        "shell": sealed_shell_shape(named.get("shell")),
    }


def sealed_shell_shape(definition):
    if definition is None:
        return {"category": "missing"}
    if (definition.keys() != SHELL_SCHEMA_KEYS | {"strict", "description"}
            or definition["type"] != "function" or definition["strict"] is not False
            or type(definition["parameters"]) is not dict or not bounded_text(definition["description"])):
        return {"category": "other_shape"}
    return {
        "category": "stock_function_shape",
        "matches_managed_definition": digest(definition) == MANAGED_SHELL_SHA256,
        "matches_pinned_schema": digest({key: definition[key] for key in SHELL_SCHEMA_KEYS}) == SHELL_SCHEMA_SHA256,
    }


_INPUT_TYPES = frozenset({"message", "function_call", "function_call_output", "reasoning"})
_INPUT_ROLES = frozenset({"user", "assistant", "system", "developer", "tool"})
_MAX_SHAPE_ITEMS = 12


def input_category(item, field, allowed):
    if type(item) is not dict or field not in item:
        return "missing"
    value = item[field]
    return value if type(value) is str and value in allowed else "other"


def matching_prior_call(call, script, run, index):
    if type(call) is not dict or call.keys() != {"type", "name", "call_id", "arguments"}:
        return False
    if (call["type"] != "function_call" or call["name"] != script.tools[index]
            or call["call_id"] != script.identity(run, index) or not bounded_text(call["arguments"])):
        return False
    try:
        return decode_json(call["arguments"]) == script.arguments[index]
    except ValueError:
        return False


def sealed_chat_shape(body, script, run, rows):
    # A private diagnostic is emitted from the same locked journal snapshot
    # that the validator receives, and contributes nothing to its decision.
    claims, submissions = verified_rows(rows)
    stage = len(claims)
    items = body.get("input") if type(body) is dict else None
    input_count = len(items) if type(items) is list else None
    items = items if type(items) is list else ()
    expected_user = {"type": "message", "role": "user", "content": [{"type": "input_text", "text": script.prompt}]}
    calls = results = pairs = 0
    for index in range(min(stage, len(script.tools), max(0, (len(items) - 1) // 2))):
        call, result = items[1 + index * 2:3 + index * 2]
        call_match = matching_prior_call(call, script, run, index)
        result_match = result == {"type": "function_call_output", "call_id": script.identity(run, index),
                                  "output": script.outputs[index]}
        calls += call_match
        results += result_match
        pairs += call_match and result_match
    return {
        "stage": stage,
        "prior_submission_count": len(submissions),
        "prior_submissions_match_stage": stage == len(submissions),
        "stage_in_bounds": stage <= len(script.tools),
        "input_count": input_count,
        "input_count_matches_stage": input_count == 1 + stage * 2,
        "input_items": [{"type": input_category(item, "type", _INPUT_TYPES),
                         "role": input_category(item, "role", _INPUT_ROLES)} for item in items[:_MAX_SHAPE_ITEMS]],
        "input_items_omitted": max(0, len(items) - _MAX_SHAPE_ITEMS),
        "initial_user_matches": bool(items and items[0] == expected_user),
        "claimed_session_matches": all(row["session"] == body.get("prompt_cache_key") for row in claims)
                                   if claims and type(body) is dict else None,
        "matching_prior_call_count": calls,
        "matching_prior_result_count": results,
        "matching_prior_pair_count": pairs,
    }


def sealed_response(home, case, headers, raw, channel):
    require(headers.get("authorization") == "Bearer test-access", "Missing synthetic workstation authorization")
    body = decode_json(raw)
    # This diagnostic does not authorize or settle synthetic generation.
    # The measured validator and durable journal remain the only gate.
    with suppress(Exception):
        append_receipt(Path(home) / PRIVATE_LEAF / SHAPE_LOG, "sealed_request_shape",
                       details={"case": case, **sealed_request_shape(body)})
    script = scenario(case, home)
    target = journal_path(home, case)
    with os.fdopen(private_file(target, os.O_RDWR), "r+b", buffering=0) as ledger:
        fcntl.flock(ledger, fcntl.LOCK_EX)
        run, rows = read_journal(ledger, case)
        if case in {"sealed-skill", "sealed-skill-boundary"}:
            with suppress(Exception):
                append_receipt(Path(home) / PRIVATE_LEAF / SHAPE_LOG, "sealed_chat_shape",
                               details={"case": case, **sealed_chat_shape(body, script, run, rows)})
        stage = script.steps(body, run, rows)
        if script.missing_skill and stage == 1:
            append_row(ledger, target, {"op": "refused", "session": body["prompt_cache_key"],
                                        "prefix": digest(body["input"])})
            payload = b'{"error":{"code":"fixture_missing_skill"}}'
            status = "401 Unauthorized"
            content_type = "application/json"
        else:
            payload = encode_sse(script.response(run, stage))
            claim = {"op": "claim", "stage": stage, "session": body["prompt_cache_key"], "prefix": digest(body["input"])}
            append_row(ledger, target, claim)
            status = "200 OK"
            content_type = "text/event-stream"
        head = (f"HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {len(payload)}"
                "\r\nConnection: close\r\n\r\n").encode("ascii")
        if status == "200 OK":
            submit_sealed_stream(home, case, channel, head + payload, ledger, target, claim)
        else:
            channel.sendall(head + payload)
            # A non-stream HTTP refusal is confirmed independently in broker usage.
            with suppress(ssl.SSLEOFError, BrokenPipeError, ConnectionResetError):
                with channel.unwrap():
                    pass
            receipt(home, "sealed_refusal", details={"case": case})


def submit_sealed_stream(home, case, channel, response, ledger, target, claim):
    # Submission certifies that sendall consumed the entire response. The
    # production client verifies the server alert and then closes directly.
    # Neither a compatible EOF nor reciprocal TLS shutdown proves application
    # delivery. The driver requires separate broker usage and native evidence.
    channel.sendall(response)
    try:
        with channel.unwrap():
            pass
    except ssl.SSLEOFError:
        shutdown = "peer_eof"
    else:
        shutdown = "mutual"
    stage = claim["stage"]
    append_row(ledger, target, {"op": "submitted", "stage": stage, "claim": digest(claim), "shutdown": shutdown})
    receipt(home, "sealed_submission", details={"case": case, "stage": stage})


def openai_peer(home, case, descriptor, certificate, key):
    receipt(home, "open")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, key)
    with socket.socket(fileno=descriptor) as plain:
        plain.settimeout(10)
        with context.wrap_socket(plain, server_side=True) as channel:
            method, path, headers, data = read_request(channel)
            if case in SEALED_CASES and (headers.get("host"), method, path) == (API_HOST, "POST", RESPONSES):
                sealed_response(home, case, headers, data, channel)
                return
            content_type, body = upstream_response(home, case, method, path, headers, data)
            if body is None:
                first = encode_sse((next(response_events(0)),))
                channel.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                                b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                                + f"{len(first):x}\r\n".encode("ascii") + first + b"\r\n")
                with suppress(ssl.SSLEOFError, BrokenPipeError, ConnectionResetError):
                    require(channel.recv(1) == b"", "Unexpected write during held synthetic stream")
                receipt(home, "held_closed")
                return
            status = "401 Unauthorized" if body == b'{"error":{"code":"fixture_stop_retry"}}' else "200 OK"
            head = (f"HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {len(body)}"
                    "\r\nConnection: close\r\n\r\n").encode("ascii")
            channel.sendall(head + body)
            # The real OpenAI event iterator requires verified TLS close.
            with suppress(ssl.SSLEOFError, BrokenPipeError, ConnectionResetError):
                with channel.unwrap():
                    pass
