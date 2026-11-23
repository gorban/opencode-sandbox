# M1.2 offline ModelCatalog proof

Run from the repository root with Python 3.11 or later.

```sh
python3 -B -m unittest discover -s docs/prds/spikes/m/model-catalog -v
```

The fixtures use one synthetic route and model with distinct per-agent reasoning grants. The tests project a worker config with explicit variants, lower each authorized symbol to a synthetic provider body, and exercise the denial and recovery cases in the [walkthrough](WALKTHROUGH.md).

The proof assumes that trusted host code supplies each call's lease, job, agent and route. The policy accepts exact frozen host records with tuples for profile and grant entries and a frozenset for each grant's variants. Malformed records and containers yield a fixed invalid-input result. Each serialization returns a fresh dictionary. The OpenCode config and upstream body are examples. The proof uses no network, credentials, OpenCode process or production service. Actual caller identity binding, lease management and production integration require separate qualification.
