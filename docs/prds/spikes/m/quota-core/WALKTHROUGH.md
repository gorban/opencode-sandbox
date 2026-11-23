# M1.3 offline quota and admission accounting walkthrough

This [M1.3](../../../prd_m1.md#concrete-gaps-and-checkboxes) spike exercises two independent
decisions in one host-side, in-memory Python model. A synthetic account supplies 5-hour and
7-day quota observations for ordinary admission. Separately, an already selected synthetic
metered route demonstrates reservation and settlement under a fixed budget. The test harness
owns the clock, observations, route, grant, bound, and evidence. It reads checked-in fixtures
and calls the model directly. The spike has no worker interface, production state, provider
calls, credential inputs, or dependencies beyond the Python standard library.

The fixture clock accepts integer seconds from 0 through 2,147,483,647 inclusive. Reject
non-integers, out-of-range values, and regressions below the last accepted reading. A bad
reading leaves the last accepted time and evidence unchanged. While the reading is
invalid, reject observations, ordinary admission, reservation, and the send transition.
Resume those operations after a valid reading at or above the last accepted time, subject
to the usual freshness checks. Pre-send release and authoritative settlement do not
depend on the clock and remain available.

## Window admission

Use a complete snapshot for the single fixture bucket. Both windows report integer remaining
basis points from 0 to 10,000 and individual reset timestamps. The observation and reset
timestamps share the fixture clock range. The observation must be at or before the clock.
Each reset must be after the observation and at most one corresponding window duration
away. Use TTLs of 300 and 900 seconds respectively. Treat a current partial or invalid
snapshot as uncertain for the entire bucket. A strictly newer valid complete snapshot can
recover it. Reject an older or future timestamp without replacing accepted evidence.
Identical replay at the current timestamp is a no-op. Conflicting evidence at that
timestamp makes the bucket
uncertain until a strictly newer valid snapshot arrives. The fixture harness supplies the
trusted timestamp separately from the observation fields.

```text
observe(snapshot, observed_at):
    reject timestamps older than the recorded observation or later than clock()
    if observed_at equals recorded time:
        if snapshot conflicts with the recorded evidence: mark bucket uncertain
        return
    record timestamp and complete validated snapshot, or mark bucket uncertain

ordinary_admission():
    if any fresh window has zero remaining: deny quota_exhausted
    if either window is missing, uncertain, past its TTL or at/past reset: deny quota_unverified
    headroom = min(remaining basis points across both windows)
    allow with a low-headroom advisory if headroom < 1,000
```

A window is fresh only while both its TTL and reset are strictly in the future. A fresh
exhausted window takes precedence over another window's staleness. If both are freshly
exhausted, report the 5-hour window first. Elapsed reset never replenishes the fixture quota.
Admission stays closed until fresh complete evidence arrives. Provider-specific parsing,
authoritative 429 precedence, and post-reset canaries remain outside this proof.

## Reservation and settlement

Use one host-approved fixture grant for a fixed route and model, a budget of 10 integer
fixture units, a hard bound of 6 for that route and model, and one active reservation.
The host fixture provides the bound on successful route/model matching. Represent missing or
invalid bounds explicitly and deny them. An ordinary quota denial never invokes reservation.
Treat each operation as atomic under a single in-process lock.

```text
reserve(request_id, route, model):
    require exact grant route and model, a positive hard bound, and a new request ID
    deny if suspended, a reservation is active, or spent + bound exceeds budget
    deny if the admitted request ID limit has been reached
    record a held reservation bound to request, route, and model

mark_may_have_sent(request_id):
    require the matching active held reservation and an unsuspended route
    transition to may_have_sent before any simulated send

release_pre_send(request_id):
    require the matching active held reservation
    release the bound and record a terminal outcome for the ID

settle(evidence):
    require authoritative final evidence for the matching request, route, and model
    require may_have_sent and a nonnegative integer charge
    absent, partial, invalid, or mismatched evidence leaves the full bound held
    record the charge and clear the hold atomically
    if charge exceeds bound: suspend the route
    repeat identical final evidence as a no-op
    reject conflicting final evidence and suspend on an authoritative charge conflict
```

Accept request IDs of 1–64 ASCII letters, digits, underscores, or hyphens and at most
eight distinct admitted IDs over the life of the model. Count the active ID toward that
limit so its terminal receipt already has a slot. Keep every terminal receipt for replay
and conflict checks. At capacity reject new IDs and continue to process the outstanding
request and terminal replays. A stale window reading cannot release a reservation or
erase a settlement. Simulated disconnect after the send boundary keeps the full bound
and occupies the active slot.
Durable send state, restart recovery, real grant issuance, tariff calculation, and grant
expiry are deferred to the production slice.

## Offline checks

- Exercise cold start, healthy admission, low-headroom warning at 999 versus 1,000 basis
  points, either window exhausting, both exhausting, and one fresh exhausted window while the
  other is stale. Check equality at each reset and TTL boundary and reopening only when a
  newer complete observation supplies fresh evidence.
- Check older and future snapshots, identical replay, equal-time conflict, and a partial or
  malformed current snapshot. Verify that an earlier observation cannot repair uncertainty.
- Exercise invalid clock types and values, both clock range endpoints, and a clock regression.
  Verify that invalid readings block new work and leave evidence intact, settlement stays
  available, and a corrected clock restores admission only with fresh evidence.
- Verify the route/model and bound checks, exact-budget admission, over-budget rejection,
  and a two-caller race for the sole slot. Verify release before the send mark and refusal
  to release after it, including on simulated disconnect.
- Hold the full bound on missing, partial, or mismatched settlement. Verify that a valid
  settlement adjusts spent once, terminal IDs cannot be reused, duplicate settlement never
  double-charges, and an authoritative over-bound charge is recorded before suspension.
- Fill the receipt store with seven released reservations and one active reservation. Verify
  that the last request can settle, the first ID remains remembered, and a ninth ID with an
  otherwise valid budget is denied. Check request ID length and character bounds.
