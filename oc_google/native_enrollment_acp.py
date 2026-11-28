"""The metadata-only ACP dialogue with the pinned standalone native process."""

import json
import os
import re
import select

from oc_orchestrator.protocol import bad_constant, unique

from .metadata_destination import _remaining


_FRAME_LIMIT = 256 * 1024
_USAGE_LIMIT = 2048
_UNEXPECTED_REPLY = "Unexpected standalone Google ACP reply"
_SESSION_ID = re.compile(r"[A-Za-z0-9._:-]{1,256}\Z", re.ASCII)
_WORKSPACE = "/run/oc-proof/empty"


class NativeAcpError(RuntimeError):
    """The standalone ACP metadata dialogue did not complete as expected."""


class NativeEnrollmentAcp:
    """Allow fixed initialization, sign-in and metadata session creation only."""

    def __init__(self, process, deadline, authorized):
        self._process = process
        self._input = process.stdin.fileno()
        self._output = process.stdout.fileno()
        os.set_blocking(self._input, False)
        os.set_blocking(self._output, False)
        self._deadline = deadline
        self._authorized = authorized
        self._phase = "new"
        self._buffer = bytearray()
        self._cold_session = None
        self._completed_sign_in = False
        self._drained_sign_in = False
        self._drained_cold_session = False

    def _require(self, phase):
        if self._phase != phase or self._authorized() is not True:
            raise NativeAcpError("Standalone Google ACP dialogue is unavailable")

    def _quiet_boundary(self):
        if self._buffer:
            raise NativeAcpError("Early standalone Google ACP data before the next request")

    def _wait(self, descriptor, event):
        poll = select.poll()
        poll.register(descriptor, event)
        while self._authorized() is True:
            ready = poll.poll(max(1, int(1000 * min(.1, _remaining(self._deadline)))))
            if ready:
                if ready[0][1] & event and self._authorized() is True:
                    return
                break
        raise NativeAcpError("Standalone Google ACP pipe retired")

    def _send(self, request, method, params):
        self._quiet_boundary()
        pending = select.poll()
        pending.register(self._output, select.POLLIN | select.POLLHUP | select.POLLERR)
        if pending.poll(0):
            raise NativeAcpError("Standalone Google ACP output was pending before the request")
        packet = json.dumps({"jsonrpc": "2.0", "id": request, "method": method, "params": params},
                            separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"
        self._wait(self._input, select.POLLOUT)
        if pending.poll(0):
            raise NativeAcpError("Standalone Google ACP output became pending before dispatch")
        try:
            if os.write(self._input, packet) != len(packet):
                raise NativeAcpError("Standalone Google ACP request did not settle")
        except OSError:
            raise NativeAcpError("Standalone Google ACP request did not settle") from None

    def _frame(self):
        try:
            while b"\n" not in self._buffer:
                self._wait(self._output, select.POLLIN)
                chunk = os.read(self._output, min(8192, _FRAME_LIMIT - len(self._buffer) + 1))
                self._buffer.extend(chunk)
                if not chunk or len(self._buffer) > _FRAME_LIMIT:
                    raise NativeAcpError("Standalone Google ACP reply exceeded its frame bound")
            frame, _, self._buffer = self._buffer.partition(b"\n")
        except (OSError, ValueError, RecursionError):
            raise NativeAcpError("Standalone Google ACP reply is invalid") from None
        if self._authorized() is not True:
            raise NativeAcpError(_UNEXPECTED_REPLY)
        return _parse_frame(frame), len(frame)

    def _reply(self, request, *, allow_usage=False):
        reply, size = self._frame()
        usage_session = None
        if allow_usage and "method" in reply:
            usage_session = _usage_session(reply, size)
            reply, _ = self._frame()
        if (type(reply.get("id")) is not int or reply["id"] != request
                or set(reply) not in ({"jsonrpc", "id", "result"}, {"jsonrpc", "id", "error"})):
            raise NativeAcpError(_UNEXPECTED_REPLY)
        if usage_session is not None:
            result = reply.get("result")
            if type(result) is not dict or result.get("sessionId") != usage_session:
                raise NativeAcpError("Standalone Google ACP usage did not match its session")
        return reply

    def initialize(self):
        self._require("new")
        self._phase = "closed"
        self._send(1, "initialize", {"protocolVersion": 1, "clientCapabilities": {}})
        result = self._reply(1).get("result")
        if type(result) is not dict or type(result.get("protocolVersion")) is not int or result["protocolVersion"] != 1:
            raise NativeAcpError("Unexpected standalone Google ACP protocol")
        info, methods = result.get("agentInfo"), result.get("authMethods")
        if (type(info) is not dict or info.get("version") != "1.5.2" or type(methods) is not list
                or sum(type(method) is dict and method.get("id") == "oauth-personal" for method in methods) != 1):
            raise NativeAcpError("Unexpected standalone Google ACP identity")
        self._quiet_boundary()
        self._phase = "initialized"

    def verify_signed_out(self):
        self._require("initialized")
        self._phase = "closed"
        self._send(2, "session/new", {"cwd": _WORKSPACE, "mcpServers": []})
        error = self._reply(2).get("error")
        if (type(error) is not dict or type(error.get("code")) is not int or error["code"] != -32000
                or error.get("message") != "Authentication required"):
            raise NativeAcpError("New standalone Google ACP profile is not signed out")
        self._quiet_boundary()
        self._phase = "signed-out"

    def start_personal_sign_in(self):
        self._require("signed-out")
        self._phase = "closed"
        self._send(3, "authenticate", {"methodId": "oauth-personal"})
        self._phase = "signing-in"

    def finish_personal_sign_in(self):
        self._require("signing-in")
        self._phase = "closed"
        if type(self._reply(3).get("result")) is not dict:
            raise NativeAcpError("Standalone Google ACP refused personal sign-in")
        self._quiet_boundary()
        self._completed_sign_in = True

    def open_metadata_session(self):
        self._require("initialized")
        self._phase = "closed"
        self._send(2, "session/new", {"cwd": _WORKSPACE, "mcpServers": [],
                                      "_meta": {"antigravity": {"enabledTools": []}}})
        self._phase = "opening"

    def finish_metadata_session(self):
        self._require("opening")
        self._phase = "closed"
        result = self._reply(2, allow_usage=True).get("result")
        if (type(result) is not dict or type(result.get("sessionId")) is not str or
                _SESSION_ID.fullmatch(result["sessionId"]) is None):
            raise NativeAcpError("Standalone Google ACP did not open an authenticated metadata session")
        self._cold_session = result["sessionId"]

    def drain_retired_metadata(self):
        """After revocation and stop, admit only the measured final catalog and EOF."""
        session = self._cold_session
        self._cold_session = None
        if session is None:
            raise NativeAcpError("Standalone Google ACP has no exact cold session")
        self._drain_pipe()
        if self._buffer:
            if self._buffer.count(b"\n") != 1 or not self._buffer.endswith(b"\n"):
                raise NativeAcpError("Incomplete or additional standby standalone Google ACP data")
            _check_catalog_notice(_parse_frame(self._buffer[:-1]), session)
            self._buffer.clear()
        self._drained_cold_session = True

    def drain_retired_enrollment(self):
        if not self._completed_sign_in or self._drained_sign_in:
            raise NativeAcpError("Standalone Google ACP has no exact completed sign-in")
        self._drain_pipe()
        if self._buffer:
            raise NativeAcpError("Unexpected standalone Google ACP output after sign-in")
        self._drained_sign_in = True

    def _drain_pipe(self):
        pending = select.poll()
        pending.register(self._output, select.POLLIN | select.POLLHUP | select.POLLERR)
        try:
            while len(self._buffer) <= _USAGE_LIMIT + 1:
                wait = max(1, int(1000 * min(.1, _remaining(self._deadline))))
                if not pending.poll(wait):
                    continue
                block = os.read(self._output, _USAGE_LIMIT + 2 - len(self._buffer))
                if not block:
                    break
                self._buffer.extend(block)
            else:
                raise NativeAcpError("Standby standalone Google ACP data exceeded its bound")
        except OSError:
            raise NativeAcpError("Standby standalone Google ACP pipe did not retire") from None

    def completed_for(self, process, *, cold):
        return process is self._process and (self._drained_cold_session if cold else self._drained_sign_in)


def _parse_frame(frame):
    if b"\r" in frame or frame.startswith(b"\xef\xbb\xbf"):
        raise NativeAcpError("Invalid standalone Google ACP frame ending")
    try:
        reply = json.loads(frame.decode("utf-8"), object_pairs_hook=unique, parse_constant=bad_constant)
    except (ValueError, RecursionError):
        raise NativeAcpError("Standalone Google ACP reply is invalid") from None
    if type(reply) is not dict or reply.get("jsonrpc") != "2.0":
        raise NativeAcpError(_UNEXPECTED_REPLY)
    return reply


def _usage_session(reply, frame_size):
    params = reply.get("params")
    if (frame_size > _USAGE_LIMIT or set(reply) != {"jsonrpc", "method", "params"}
            or reply["method"] != "session/update" or type(params) is not dict
            or set(params) != {"sessionId", "update"}):
        raise NativeAcpError("Unexpected standalone Google ACP notification")
    session, update = params["sessionId"], params["update"]
    if (type(session) is not str or _SESSION_ID.fullmatch(session) is None or type(update) is not dict
            or set(update) != {"sessionUpdate", "size", "used"} or update["sessionUpdate"] != "usage_update"
            or type(update["size"]) is not int or type(update["used"]) is not int
            or not 0 <= update["used"] <= update["size"] <= 2**31 - 1):
        raise NativeAcpError("Invalid standalone Google ACP usage notification")
    return session


def _check_catalog_notice(reply, session):
    params = reply.get("params")
    if (set(reply) != {"jsonrpc", "method", "params"} or reply["method"] != "session/update"
            or type(params) is not dict or set(params) != {"sessionId", "update"} or params["sessionId"] != session):
        raise NativeAcpError("Unexpected standby standalone Google ACP notification")
    update = params["update"]
    if (type(update) is not dict or set(update) != {"sessionUpdate", "availableCommands"}
            or update["sessionUpdate"] != "available_commands_update"
            or type(update["availableCommands"]) is not list or len(update["availableCommands"]) != 3):
        raise NativeAcpError("Invalid standby standalone Google ACP command catalog")
    names = set()
    for entry in update["availableCommands"]:
        if (type(entry) is not dict or set(entry) != {"name", "description"} or type(entry["name"]) is not str
                or type(entry["description"]) is not str or not entry["description"].isprintable()
                or len(entry["description"].encode("utf-8")) > 256):
            raise NativeAcpError("Invalid standby standalone Google ACP command catalog entry")
        names.add(entry["name"])
    if names != {"plan", "logout", "usage"}:
        raise NativeAcpError("Unexpected standby standalone Google ACP command catalog")
