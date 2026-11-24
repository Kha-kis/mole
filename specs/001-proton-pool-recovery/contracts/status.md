# Recovery Status Contract

Add the RecoveryHealth fields from data-model.md to authenticated status/health
responses and corresponding low-cardinality metrics. Do not put candidate names,
exit addresses, arbitrary error text or policy digests in metric labels.

Existing connected/tunnel_ready continue to mean verified transport. Existing
healthy is not silently repurposed into tracker acceptance. New workload_ready
is the explicit aggregate for validated-mode application availability. A false
DNS/forwarding/client flag cannot be hidden by a true transport flag.

Readiness evidence remains bound to current process/generation and expiry.
Gate state requires a fresh bounded kernel verification, not just cached JSON.
Do not permit the read-only API to mutate rules. A supervisor writes evidence;
an API reader rejects expired state. Restart defaults are false/null, never the
last process's success.

next_retry_in_seconds is derived from a current monotonic deadline. Optional
next_retry_at is a display-only wall-time projection of that delay; do not load
it as an execution deadline. No eligible candidates and pool cooldown have
different recovery_reason values and candidate counts.

Keep hook_ready unchanged. Tracker registration is externally owned; the public
API must not invent mam_ready from hook exit, tunnel status or a matching ASN.
The host companion records actual registration and canary results separately.
