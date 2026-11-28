"""Construct old synthetic journal states for focused storage tests."""

from dataclasses import replace

from oc_google.registration import (
    ColdCheck, ColdObservation, Phase, RegistrationUnavailable, _absent, _check_credential,
    _credential, _CUSTODY, _verify_binding,
)


def record_enrollment_retired(self, enrollment):
    """Record reported retirement and pin the resulting credential inode."""
    with self._exact(enrollment, Phase.ENROLLING) as (slot, record, profile, pins, key_fd):
        retired = replace(record, phase=Phase.ENROLLMENT_RETIRED,
                          credential_identity=_credential(pins, profile))
        slot.store(retired, recheck=lambda: _verify_binding(slot, retired, profile, key_fd))


def record_cold_observation(self, check, observation):
    """Record the caller's exact zero-prompt cold check and reported retirement."""
    if (type(check) is not ColdCheck or type(observation) is not ColdObservation or observation.check != check
            or observation.authenticated_metadata is not True or observation.native_retired is not True
            or type(observation.prompt_count) is not int or observation.prompt_count != 0):
        raise RegistrationUnavailable("Google cold observation is incomplete")
    with self._exact(check.enrollment, Phase.COLD_CHECKING) as (slot, record, profile, pins, key_fd):
        if record.check() != check:
            raise RegistrationUnavailable("the exact Google cold check changed")
        if not _absent(_CUSTODY, directory=slot.directory.fd):
            raise RegistrationUnavailable("Google cold custody must settle through its live owner")
        _check_credential(pins, profile, record)
        if not record.cold_subject_observed:
            raise RegistrationUnavailable("the exact Google cold check has no subject observation")
        observed = replace(record, phase=Phase.COLD_RETIREMENT_OBSERVED, check_nonce=None,
                           cold_subject_observed=False)
        slot.store(observed, recheck=lambda: _verify_binding(slot, observed, profile, key_fd))
        return observed.status()
