"""Regression checks for the offline picker evidence harness."""

from contextlib import closing
import http.client
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

from probe import (
    APPROVED_TARGET, CLAUDE_WORK, EXPECTED_REQUEST, FIXTURE_AUTH, GOOGLE_PERSONAL, Fake, PROMPT, SAVED_ROUTE,
    SELECT, request_log_matches, seed, serving, stale_refusal,
)


def valid_payload():
    return json.dumps({
        "model": SELECT[1], "stream": True, "messages": [{"role": "user", "content": PROMPT}],
    })


def send_post(fake, payload):
    with closing(http.client.HTTPConnection("127.0.0.1", fake.server_port, timeout=3)) as client:
        client.request("POST", APPROVED_TARGET, payload, {"Authorization": FIXTURE_AUTH})
        response = client.getresponse()
        response.read()
        return response.status


class EvidenceChecks(unittest.TestCase):
    def test_extra_attempts_fail_the_whole_log(self):
        self.assertTrue(request_log_matches([EXPECTED_REQUEST]))
        self.assertFalse(request_log_matches([]))
        for phase in ("startup", "approved", "stale", "collision-opal-v1", "collision-opal-v2"):
            with self.subTest(phase=phase):
                extra = dict(EXPECTED_REQUEST, phase=phase, accepted=False)
                self.assertFalse(request_log_matches([EXPECTED_REQUEST, extra]))
                self.assertFalse(request_log_matches([extra, EXPECTED_REQUEST]))

    def test_stale_refusal_names_the_removed_route(self):
        for mode, notice in {
            "full": "Model unavailable\n" + SAVED_ROUTE + " is not available",
            "mini": "Model unavailable: " + SAVED_ROUTE,
        }.items():
            with self.subTest(mode=mode):
                self.assertTrue(stale_refusal(mode, notice))
                self.assertFalse(stale_refusal(mode, "Model unavailable"))
                self.assertFalse(stale_refusal(mode, notice.replace(GOOGLE_PERSONAL, CLAUDE_WORK)))
                self.assertFalse(stale_refusal(mode, notice.replace(SAVED_ROUTE, "other-" + SAVED_ROUTE)))
                self.assertFalse(stale_refusal(mode, notice.replace(SAVED_ROUTE, SAVED_ROUTE + "-preview")))
        self.assertTrue(stale_refusal("full", f"Model unavailable\n┃  ┃{SAVED_ROUTE} is not available"))

    def test_seed_rejects_fixture_that_grows_after_measurement(self):
        with tempfile.TemporaryDirectory() as scratch:
            source = Path(scratch) / "source"
            target = Path(scratch) / "target"
            source.write_bytes(b"abc")
            first_read = 1024 * 1024
            measure = os.fstat

            def measure_then_grow(fd):
                info = measure(fd)
                with source.open("ab") as writer:
                    writer.write(b"d" * (first_read + 1))
                return info

            with (
                patch("probe.MAX_FIXTURE_BYTES", first_read + 3),
                patch("probe.os.fstat", side_effect=measure_then_grow),
                self.assertRaisesRegex(RuntimeError, "exceeded its size bound"),
            ):
                seed(source, target)
            self.assertEqual(target.stat().st_size, first_read)

    def test_final_verdict_includes_in_flight_handler(self):
        self.assertEqual({name for _, name in socket.if_nameindex()}, {"lo"},
                         "run the regression checks inside a loopback-only network namespace")
        blocked = threading.Event()
        stopping = threading.Event()
        release = threading.Event()
        statuses = []

        class DelayedFake(Fake):
            def arrive(self, method, target):
                blocked.set()
                if not release.wait(2):
                    raise TimeoutError("test did not release the blocked handler")
                return super().arrive(method, target)

            def shutdown(self):
                stopping.set()
                super().shutdown()

        def send_extra():
            with closing(http.client.HTTPConnection("127.0.0.1", fake.server_port, timeout=3)) as client:
                client.request("POST", f"/{CLAUDE_WORK}/v1/chat/completions", "{}")
                response = client.getresponse()
                statuses.append(response.status)
                response.read()

        def release_on_shutdown():
            if stopping.wait(2):
                release.set()

        with DelayedFake() as fake, serving(fake):
            fake.events.append(EXPECTED_REQUEST)
            client = threading.Thread(target=send_extra, daemon=True)
            unblock = threading.Thread(target=release_on_shutdown, daemon=True)
            unblock.start()
            client.start()
            self.assertTrue(blocked.wait(2))
            self.assertTrue(request_log_matches(fake.snapshot()))
        client.join(timeout=3)
        unblock.join(timeout=3)
        self.assertEqual(statuses, [403])
        events = fake.snapshot()
        self.assertEqual(len(events), 2)
        self.assertFalse(events[1]["accepted"])
        self.assertFalse(request_log_matches(events))

    def test_startup_request_cannot_consume_later_approval(self):
        self.assertEqual({name for _, name in socket.if_nameindex()}, {"lo"})
        arrived = threading.Event()

        class ArrivingFake(Fake):
            def arrive(self, method, target):
                arrival = super().arrive(method, target)
                arrived.set()
                return arrival

        payload = valid_payload().encode()
        with ArrivingFake() as fake, serving(fake):
            with closing(http.client.HTTPConnection("127.0.0.1", fake.server_port, timeout=3)) as client:
                client.putrequest("POST", APPROVED_TARGET)
                client.putheader("Content-Length", str(len(payload)))
                client.putheader("Authorization", FIXTURE_AUTH)
                client.endheaders()
                self.assertTrue(arrived.wait(2))
                fake.mark("approved", SELECT)
                client.send(payload)
                response = client.getresponse()
                self.assertEqual(response.status, 403)
                response.read()
            self.assertEqual(send_post(fake, payload), 200)
        startup, approved = fake.snapshot()
        self.assertEqual(startup, dict(EXPECTED_REQUEST, phase="startup", accepted=False))
        self.assertEqual(approved, EXPECTED_REQUEST)
        self.assertFalse(request_log_matches(fake.snapshot()))

    def test_parser_recursion_leaves_extra_request_in_the_log(self):
        self.assertEqual({name for _, name in socket.if_nameindex()}, {"lo"})
        with Fake() as fake, serving(fake):
            fake.mark("approved", SELECT)
            self.assertEqual(send_post(fake, valid_payload()), 200)
            with patch("probe.json.loads", side_effect=RecursionError("fixture parser failure")):
                self.assertEqual(send_post(fake, b"[]"), 403)
        approved, malformed = fake.snapshot()
        self.assertEqual(approved, EXPECTED_REQUEST)
        self.assertEqual(malformed, dict(EXPECTED_REQUEST, model=None, fixed_prompt=False, accepted=False))
        self.assertFalse(request_log_matches(fake.snapshot()))

    def test_http_method_and_exact_raw_target(self):
        self.assertEqual({name for _, name in socket.if_nameindex()}, {"lo"},
                         "run the regression checks inside a loopback-only network namespace")
        payload = valid_payload()
        cases = [
            ("POST", APPROVED_TARGET + "?extra=yes", 403),
            ("HEAD", APPROVED_TARGET, 403),
            ("PROBE", APPROVED_TARGET, 403),
            ("POST", "/" + APPROVED_TARGET, 403),
            ("POST", APPROVED_TARGET, 200),
        ]
        with Fake() as fake:
            thread = threading.Thread(target=fake.serve_forever)
            thread.start()
            fake.mark("approved", SELECT)
            try:
                for method, target, status in cases:
                    with (
                        self.subTest(method=method, target=target),
                        closing(http.client.HTTPConnection("127.0.0.1", fake.server_port, timeout=3)) as client,
                    ):
                        client.request(method, target, payload, {"Authorization": FIXTURE_AUTH})
                        response = client.getresponse()
                        self.assertEqual(response.status, status)
                        body = response.read()
                        if status == 200:
                            first_frame = body.splitlines()[0].removeprefix(b"data: ")
                            self.assertEqual(json.loads(first_frame)["model"], SELECT[1])
            finally:
                fake.shutdown()
                thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            events = fake.snapshot()
            self.assertEqual([(entry["method"], entry["target"]) for entry in events],
                             [(method, target) for method, target, _ in cases])
            self.assertEqual([entry["accepted"] for entry in events], [False, False, False, False, True])
            self.assertEqual(events[-1], EXPECTED_REQUEST)
            self.assertFalse(request_log_matches(events))


if __name__ == "__main__":
    unittest.main()
