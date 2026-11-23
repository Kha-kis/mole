# Fix: Approved-List Recovery

Status: applied in isolated source, with residual blocking audit below.

## Root Cause And Changes

Recovery previously chose the same pin without recording failures and overlapping
triggers could renew simultaneously. A pure opt-in policy now orders approved
names, rejects outside pins, deduplicates physical endpoints and applies monotonic
cooldowns. Provider selection refreshes resolution on each attempt; saved/manual
selection cannot bypass the list. Explicit pins remain strict when failover is off.

Renewal triggers share one owner; cancellation of a waiter does not cancel that
owner. Attempts are bounded to three distinct endpoints, followed by capped
exponential backoff/jitter. Mapping failures retain private outbound service;
three failures permit one same-endpoint recovery, then approved alternatives.
Only a valid mapping resets the mapping-recovery budget. A previously verified
eligible endpoint may be restored once; failed restoration remains blocked.
Cleanup drains recovery before disconnect and invalidates status evidence.

## Tests

Policy tests cover ordering, member pins, validation, physical cooldown/duplicates,
fresh resolution, unavailable strict pins, disabled physical servers and saved/
manual bypass. Orchestration regressions cover shared ownership, cancelled waiters,
bounded exhaustion/backoff, mapping degradation, one recovery budget, restoration,
cleanup and invalidation before failed registration. Failure-first evidence and
full suite results are recorded in the execution ledger.

## Deviations And Residual Blocking Audit

The strict-pin unavailable case previously fell back despite the intended pin;
it now refuses implicit failover, as required by the approved policy.

The legacy runtime now also uses the shared configuration validation gate.

Not repaired by NAT-PMP changes: synchronous Proton SDK refresh/authentication,
server-list/certificate calls (SDK timeout 30 seconds), latency thread-pool joins
and command helpers, wg-quick/route setup, optional hooks and PIA provider calls.
These can delay the event loop. Python executor cancellation alone cannot safely
stop an SDK call that writes session/certificate state, so a provider-wide worker
ownership/deadline change needs its own design/acceptance rather than an unsafe
fire-and-forget thread conversion. No claim of fully nonblocking recovery or live
production readiness is made. No runtime dependency or tracker policy changed.

## Independent Review Corrections

Strict pins search all configured countries before refusing alternatives.
Installed identity is separate from selected candidates. Client work no longer
holds the renewal owner or watchdog. Raw provider resolution tests cover shared
failed addresses and a logical server moving to a new physical address.

The owner approved a follow-up scope on the same date to repair the remaining
synchronous provider/setup/hook operations before deployment. This report records
the first reviewed phase, not completion of that extension.
