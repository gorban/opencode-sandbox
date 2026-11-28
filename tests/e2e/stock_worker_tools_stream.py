"""In-memory fake upstream transport using the existing strict SSE parser and projector."""

from io import BytesIO
import time

from oc_openai.connection_state import decode_json
from oc_openai.responses import Cancellation, StreamLimits, _StreamEvidence, _StrictResponse, _events
from oc_openai.session_protocol import SessionStreamProjector, encode_chunk
from stock_worker_tools_history import digest, message_text, stock_call
from stock_worker_tools_protocol import MODEL, encode_sse, require

_STREAM_LIMITS = StreamLimits(65_536, 262_144, 32_768, 256, 5)
_END = b"0\r\n\r\n"


class SyntheticResponse:
    def __init__(self, payload, boundary=_END):
        self.stream = BytesIO(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                              b"Transfer-Encoding: chunked\r\n\r\n" + encode_chunk(payload) + boundary)

    def makefile(self, _mode):
        return self.stream


def project_stream(response, vault, allowed_tools, local_id):
    projector = SessionStreamProjector(model=MODEL, local_response_id=local_id, vault=vault,
                                       allowed_tools=frozenset(allowed_tools))
    evidence = _StreamEvidence()
    cancel = Cancellation(time.monotonic() + _STREAM_LIMITS.io_timeout)
    frames = []
    with _StrictResponse(response, keep_fp=True) as http:
        http.begin()
        require(http.status == 200 and http.chunked, "Unexpected synthetic upstream response")
        for event in _events(http, cancel, evidence, limits=_STREAM_LIMITS, strict_terminal=True):
            if event["type"] == "response.completed":
                terminal = event.get("response")
                require(type(terminal) is dict and terminal.get("model") == MODEL,
                        "Wrong synthetic terminal model")
            frames.extend(projector.feed(event))
        require(evidence.http_body_verified and http._oc_fp is not None and not http._oc_fp.read(1),
                "Unverified or trailing synthetic stream bytes")
        require(projector.metadata_checked == 1, "Missing or repeated synthetic moderation metadata")
        tail = projector.finalize()
    return (*frames, *tail), projector.usage


def terminal_output(frame, *, search=False, interaction=None):
    event = decode_json(frame.removeprefix(b"event: response.completed\ndata: "))
    require(event["type"] == "response.completed", "Missing projected terminal")
    output = event["response"]["output"]
    if output and all(item["type"] == "function_call" for item in output):
        return tuple(stock_call(item, projected=True, search=search, interaction=interaction) for item in output), None
    require(len(output) == 1 and output[0]["type"] == "message", "Unmeasured synthetic terminal output")
    source = output[0]
    require(len(source["content"]) == 1 and source["content"][0].get("annotations") == [],
            "Unmeasured synthetic terminal text")
    item = {**source, "content": [{key: value for key, value in source["content"][0].items()
                                  if key != "annotations"}]}
    message_text(item, assistant=True)
    return (), digest(item)


def scripted_response(events):
    return SyntheticResponse(encode_sse(events))
