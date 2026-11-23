# Offline M1.3 quota proof

From the repository root, run the suite with Python 3.10 or newer.

```sh
python3 -B -m unittest discover -s docs/prds/spikes/m/quota-core -v
```

This spike uses a checked-in fixture, an injected test clock, and in-process
accounting. It needs only the Python standard library. The tests exercise
admission across two quota windows and reservation on a separately approved
fixture route. The reservation race checks that exactly one caller wins the
sole active slot, regardless of scheduling.

Each process starts with an empty model. The send boundary, evidence, and
charges are simulated. Route and model binding comes from the single immutable
fixture grant. Final evidence comes from the trusted harness in that grant's
request ID namespace. A contradiction of a terminal receipt suspends the
grant while preserving any other hold. The proof covers local state transitions
and keeps receipts for up to eight admitted requests. Production wiring, provider
authorization and telemetry, real grants and charges, and restart durability are
outside the scope. See the [walkthrough](WALKTHROUGH.md) for the transition rules.
