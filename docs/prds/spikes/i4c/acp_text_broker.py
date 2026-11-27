"""Compatibility entry point for the offline ACP text broker spike."""

from oc_google import route
from oc_orchestrator import protocol


BrokerReceipt = route.BrokerReceipt
ctypes = route.ctypes
_libc_send = route._libc_send


def _send_once(client, data):
    return route._send_once(client, data, send=_libc_send)


class TextBroker(route._TextBroker):
    def _request(self, client, deadline):
        body = protocol.request_body(client, deadline, self._port)
        protocol.accept_text(body)
        return body

    def _answer(self):
        return protocol.reply_bytes(protocol.FIXTURE_EVENTS)

    def _send(self, client, data):
        return _send_once(client, data)
