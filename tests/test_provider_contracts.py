"""Tests for the shared metadata-only oc_providers contract and openai verify."""

from dataclasses import FrozenInstanceError
import unittest

from oc_openai.cli import Reason, RouteUnavailable, run
from oc_providers import (
    ActiveBinding,
    ConnectionStatus,
    PROVIDERS,
    ReadinessState,
    SavedProfile,
    VerifyResult,
)


class _Terminal:
    def __init__(self, attended=True):
        self._attended = attended
        self.out = []
        self.err = []

    def attended(self):
        return self._attended

    def write(self, message):
        self.out.append(message)

    def error(self, message):
        self.err.append(message)

    def confirm(self, message):
        return False


class _VerifyBackend:
    def __init__(self, result=None, error=None):
        self._result = result
        self._error = error

    def verify(self):
        if self._error is not None:
            raise self._error
        return self._result


class ProviderContractsTests(unittest.TestCase):
    def test_canonical_provider_ids_and_frozen_dtos(self):
        self.assertEqual(PROVIDERS, frozenset({"openai", "claude", "google"}))
        profile = SavedProfile("openai", "personal", True, False, True, ReadinessState.READY)
        status = ConnectionStatus("openai", (profile,), "personal")
        binding = ActiveBinding("openai", "reg-1", "gen-1", "personal", "epoch-1")
        verified = VerifyResult("openai", "personal", ReadinessState.READY, ("gpt-6.2-sol",))
        self.assertEqual(status.active, "personal")
        self.assertEqual(binding.provider, "openai")
        self.assertEqual(verified.models, ("gpt-6.2-sol",))
        with self.assertRaises(FrozenInstanceError):
            verified.models = ()

    def test_cli_verify_prints_redacted_models_and_fails_closed_on_invalid_result(self):
        terminal = _Terminal()
        ok_backend = _VerifyBackend(
            VerifyResult("openai", "work", ReadinessState.READY, ("gpt-6.2-sol", "gpt-6.2-mini"))
        )
        rc = run(["verify"], terminal=terminal, backend_factory=lambda: ok_backend)
        self.assertEqual(rc, 0)
        self.assertEqual(terminal.err, [])
        self.assertIn("Verified ChatGPT registration work (ready): gpt-6.2-sol, gpt-6.2-mini", terminal.out[0])

        bad_terminal = _Terminal()
        bad_backend = _VerifyBackend(VerifyResult("openai", "work", ReadinessState.READY, ()))
        self.assertEqual(run(["verify"], terminal=bad_terminal, backend_factory=lambda: bad_backend), 1)
        self.assertTrue(bad_terminal.err)

        unavail_terminal = _Terminal()
        unavail_backend = _VerifyBackend(error=RouteUnavailable(Reason.CONNECTION_CHANGED))
        self.assertEqual(run(["verify"], terminal=unavail_terminal, backend_factory=lambda: unavail_backend), 1)
        self.assertTrue(unavail_terminal.err)


if __name__ == "__main__":
    unittest.main()
