"""Join a verified synthetic native result to one durable worker delivery."""

from dataclasses import dataclass
from hashlib import sha256

from .generation_journal import AcpSentReceipt, Operation, Phase, SettlementEvidence, WriteEvidence, _Run
from .generation_phase import Phase as ProxyPhase, PhaseReceipt
from .native_generation_transcript import GenerationTranscript, UnitRetirementReceipt
from .native_service import NativeInvocation
from .worker_channel import AdoptedWorker, RelayRetirement, RetainedWorkerChannel, WorkerChannelError


@dataclass(frozen=True, slots=True, eq=False)
class ProxyRetirementObservation:
    """Trusted supervisor observation of the exact native run's proxy retirement."""

    sent: AcpSentReceipt
    invocation: NativeInvocation
    receipt: PhaseReceipt


def _check_proxy(observation, sent, invocation):
    if (type(observation) is not ProxyRetirementObservation or observation.sent is not sent
            or observation.invocation is not invocation):
        raise WorkerChannelError("Exact native proxy retirement is unconfirmed")
    receipt = observation.receipt
    if (type(receipt) is not PhaseReceipt or receipt.phase is not ProxyPhase.COMPLETE
            or receipt.connector_retired is not True or receipt.refusal_observed is not False
            or any(type(count) is not int or count != 1 for count in (
                receipt.helper_turn_accepts, receipt.owner_turn_accepts, receipt.fake_writes,
            ))):
        raise WorkerChannelError("Exact native proxy retirement is unconfirmed")


def deliver_worker(run, channel, *, adopted, relay_retirement, transcript, native_retirement, proxy_retirement):
    """Freeze the verified result, send once, then settle only after exact channel closure.

    The private fixture supervisor supplies the authentic transcript, independent
    proxy/unit/relay observations, and the current journal owner check. The bound
    local guard checks the exact original worker through durable settlement.
    """
    if type(run) is not _Run or type(channel) is not RetainedWorkerChannel:
        raise WorkerChannelError("Exact joined worker delivery is unavailable")
    fence = run._owner_fence()
    if channel._fence is not fence:
        raise WorkerChannelError("Joined worker delivery must share the journal owner fence")
    try:
        binding = run._control.binding
        if (type(transcript) is not GenerationTranscript or transcript._fence is not fence
                or type(native_retirement) is not UnitRetirementReceipt
                or native_retirement.invocation is not transcript._invocation
                or type(adopted) is not AdoptedWorker or adopted.placement is not channel._placement
                or type(relay_retirement) is not RelayRetirement or relay_retirement.adopted is not adopted
                or adopted.placement.run != binding.launch or adopted.placement.epoch != str(binding.epoch)
                or channel._model != binding.model):
            raise WorkerChannelError("Native transcript and retained worker do not match the journal run")
        with fence:
            run._check_phase(Phase.DESTINATION_SETTLED)
            sent = run.acp_sent()
            if sent.write.target is not native_retirement.invocation:
                raise WorkerChannelError("Native invocation differs from the durable ACP write")
        _check_proxy(proxy_retirement, sent, native_retirement.invocation)
        if transcript.finish(native_retirement) != b"ok":
            raise WorkerChannelError("Exact native response is unconfirmed")
        prepared = channel.prepare_delivery(adopted, relay_retirement, run=run)
        guard = channel.settlement_guard(prepared, run=run)
        digest = sha256(prepared.packet).hexdigest()
        with fence:
            run.verify_acp_sent(sent)
            channel.verify_prepared(prepared)
            capability = run.issue(Operation.DELIVERY)

        delivery = None

        def write(proof):
            nonlocal delivery
            delivery = channel.write_prepared(prepared, run=run, proof=proof)
            return WriteEvidence(prepared, delivery.bytes_sent, digest)

        write_receipt = run.write_once(capability, write, target=prepared, data=prepared.packet, settlement_guard=guard)
        closed = channel.close_written(prepared, delivery)
        evidence = SettlementEvidence(write_receipt, prepared, delivery.bytes_sent, digest, closure=closed)
        with fence:
            run._check_phase(Phase.DELIVERY_CLAIMED)
            channel.verify_closed_write(closed)
            run.settle(write_receipt, evidence)
        return delivery
    except BaseException:
        try:
            run.revoke()
        finally:
            channel.revoke()
        raise
