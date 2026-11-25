"""Regression checks for the offline picker evidence harness."""

from contextlib import closing
import http.client
import json
import socket
import threading
import unittest

from probe import (
    APPROVED_TARGET, EXPECTED_REQUEST, Fake, PROMPT, SAVED_ROUTE, SELECT, request_log_matches, serving, stale_refusal,
)


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
                self.assertFalse(stale_refusal(mode, notice.replace("google--personal", "claude--work")))
                self.assertFalse(stale_refusal(mode, notice.replace(SAVED_ROUTE, SAVED_ROUTE + "-preview")))

    def test_final_verdict_includes_in_flight_handler(self):
        self.assertEqual({name for _, name in socket.if_nameindex()}, {"lo"},
                         "run the regression checks inside a loopback-only network namespace")
        blocked = threading.Event()
        stopping = threading.Event()
        release = threading.Event()
        statuses = []

        class DelayedFake(Fake):
            def record(self, method, target, authorization, payload):
                blocked.set()
                if not release.wait(2):
                    raise TimeoutError("test did not release the blocked handler")
                return super().record(method, target, authorization, payload)

            def shutdown(self):
                stopping.set()
                super().shutdown()

        def send_extra():
            with closing(http.client.HTTPConnection("127.0.0.1", fake.server_port, timeout=3)) as client:
                client.request("POST", "/claude--work/v1/chat/completions", "{}")
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

    def test_http_method_and_exact_raw_target(self):
        self.assertEqual({name for _, name in socket.if_nameindex()}, {"lo"},
                         "run the regression checks inside a loopback-only network namespace")
        payload = json.dumps({
            "model": SELECT[1], "stream": True, "messages": [{"role": "user", "content": PROMPT}],
        })
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
                    with self.subTest(method=method, target=target):
                        with closing(http.client.HTTPConnection("127.0.0.1", fake.server_port, timeout=3)) as client:
                            client.request(method, target, payload, {"Authorization": "Bearer offline-fixture"})
                            response = client.getresponse()
                            self.assertEqual(response.status, status)
                            response.read()
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
