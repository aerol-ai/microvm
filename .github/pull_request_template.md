<!--
GitHub auto-fills new PR descriptions with this template. Fill in EVERY
section below. "N/A - <one-line reason>" is a valid answer; an empty answer
is not. See pr-review.md at the repo root for what each section is asking.
-->

## Summary

<!-- 1-3 bullets: what changed and why. -->

## Code-path diagram

<!--
REQUIRED for any change to runtime behavior (see pr-review.md §8): at least
one ```mermaid``` diagram of the changed code path, annotated with what
changed on each branch (before -> after).

- sequenceDiagram for protocol / handshake / cross-process changes
- flowchart for control-flow, lifecycle, or cleanup-path changes
- every failure/cleanup branch the diff touches must appear as a branch

Reference example: PR #289 "What changed, visually".
Only valid opt-out: "N/A - docs/comment-only change."
-->

## Sandbox boot impact

<!--
Did this PR add ANY work - DB query, HTTP round-trip, file I/O, lock
acquisition - to CreateSandbox or anything it calls?

If yes: state what was added, expected added latency, when it fires, and
whether it's bounded. "Only on the first call" is still impact and must be
called out.

If no: write "N/A - no work added to sandbox boot path."
-->

## Idempotency

<!--
For every API surface this PR touches, describe behavior under retry and
under concurrent calls with the same inputs. Sandbox APIs MUST be
idempotent (see pr-review.md §1).

If no API surface changed: write "N/A - no API surface changed."
-->

## Failure-path consistency

<!--
For any multi-step write that touches BOTH caddy and the store: what is the
rollback rule on partial failure? Who cleans up if step 2 of 3 fails?

If no multi-step write path was changed: write "N/A - no multi-step write
path changed."
-->

## L4 / host-port-pool changes

<!--
Did this PR touch TryReserveHostPort, the partial unique index on
host_port, allocateHostPort, EnsureLayer4, EnsureLayer4Ready, or the
l4Ready latch? If yes, link the regression test that covers the change.

If no: write "N/A - neither touched."
-->

## Test plan

<!-- Bulleted checklist of how this was verified. -->
