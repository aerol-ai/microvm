# Create Idempotency Timeline

The hardest compatibility problem on the control plane was `POST /e2b/sandboxes`.

## Why it mattered

Create is not like list or get.

If a caller retries the same create request because of a timeout, proxy retry, client reconnect, or race, a naive implementation can launch two live sandboxes for what the caller believes was one request.

That is especially dangerous for an SDK facade because the upstream SDK does not provide a caller-supplied idempotency key or request ID that AerolVM can reuse directly.

So the facade had to design its own safe replay behavior.

## Implemented design

The implemented strategy is:

1. Build a canonical fingerprint from the effective create semantics.
2. Persist that fingerprint in SQLite.
3. Treat the first matching request as the owner of a short-lived pending lock.
4. Let concurrent matching requests wait for that owner to finish.
5. Replay the same sandbox only inside a short replay window.
6. Allow the same request to create a fresh sandbox again once that replay window expires.

This is backed by the `e2b_create_requests` table.

## What goes into the fingerprint

The fingerprint is not based on raw JSON bytes.

It is built from the normalized semantics of the create request, including:

- template ID
- metadata
- env vars
- timeout seconds
- timeout behavior such as pause or kill
- secure mode
- supported network fields
- public-traffic and host-masking intent when present

That means semantically identical requests still match even if the JSON field order differs.

## The concrete timing rules

The current values are:

- pending lock TTL: 2 minutes
- wait timeout for other callers: 30 seconds
- replay window after success: 10 seconds

## Retry timeline example

Assume two identical `Sandbox.create(...)` calls happen close together.

### T0: first request arrives

- Request A hits `POST /e2b/sandboxes`.
- AerolVM computes fingerprint `F`.
- No row exists for `F`, so AerolVM inserts a `pending` record.
- The row gets `locked_until = T0 + 2m`.
- Request A is now the owner of the create attempt.

### T0 + 100 ms: duplicate retry arrives

- Request B hits `POST /e2b/sandboxes` with the same effective payload.
- AerolVM computes the same fingerprint `F`.
- It sees a `pending` row whose lock is still valid.
- Request B does not create a second sandbox.
- Instead, it waits up to 30 seconds for the original create to finish.

### T0 + 1.2 s: native create succeeds

- Request A finishes native `CreateSandbox(...)`.
- E2B metadata is persisted.
- The create record moves from `pending` to `ready`.
- The row is updated with:
  - `sandbox_id = sb_123`
  - `replay_until = T0 + 11.2s`

### T0 + 1.3 s: waiting retry wakes up

- Request B re-checks the record.
- It sees `ready` and a valid replay window.
- It returns the same sandbox `sb_123` instead of creating a duplicate.

### T0 + 5 s: another identical retry arrives

- Request C arrives with the same payload.
- The row is still `ready` and still inside the replay window.
- Request C also gets `sb_123`.

### T0 + 12 s: legitimate identical launch later

- Request D arrives with the same payload.
- The replay window has expired.
- AerolVM treats this as a new legitimate create.
- It refreshes the record back to `pending` and allows a fresh sandbox launch.

This is the key balance:

- accidental retries replay briefly
- real later launches are still allowed

## Failure handling

The failure behavior matters as much as the success behavior.

### If native create fails

- the pending reservation is deleted
- the next retry is free to try again cleanly

### If native create succeeds but E2B metadata persistence fails

- AerolVM destroys the newly created sandbox
- the pending reservation is deleted
- the client gets an error instead of a half-created compatibility record

### If the owner dies or stalls

- the pending lock has a TTL
- once it expires, the next matching request can reclaim the fingerprint and try again

## Why this was better than simpler alternatives

### Better than no dedupe

Without it, a client-side retry can create multiple real sandboxes.

### Better than permanent dedupe

Permanent dedupe would make two legitimate identical launches impossible.

### Better than in-memory locking only

In-memory locking disappears on process restart and does not survive concurrent request paths safely.

Persisting the state in SQLite makes the behavior durable and restart-safe.

## Relationship to other lifecycle endpoints

Create needed the special persisted replay design because it allocates a brand-new sandbox.

The other control-plane operations are simpler:

- `connect` is safe because it only starts or extends the sandbox when needed
- `pause` is safe because pausing an already paused sandbox is a no-op success
- `timeout` is safe because it updates lifecycle state in place
- snapshot creation uses stable external snapshot IDs so later delete calls resolve deterministically