# E2B Compatibility Notes

This folder captures the implementation details behind the E2B compatibility work added in this session.

Files in this pack:

- `e2b-request-flow.md`: exact request flow from `Sandbox.create()` through `sandbox.commands.run()`.
- `e2b-idempotency-timeline.md`: why create idempotency was required and how the persisted retry window works.
- `e2b-sdk-method-map.md`: which E2B SDK methods map to which AerolVM handler or toolboxd runtime path.

These notes are focused on the current path-based compatibility shape:

- control plane under `/e2b`
- runtime gateway under `/e2b/runtime`
- toolboxd compatibility surface under `/envd`

They are intended as implementation notes, not end-user product docs.