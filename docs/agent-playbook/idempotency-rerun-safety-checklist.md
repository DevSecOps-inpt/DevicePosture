# Idempotency and Rerun Safety Checklist

1. Define deterministic keys for write operations.
2. Validate dedupe behavior for retries and replay windows.
3. Confirm sink semantics (append/upsert/merge/overwrite) are explicit.
4. Verify checkpoint/offset state transitions on partial failure.
5. Test same-window rerun and full-window replay scenarios.
6. Validate external side-effects are idempotent or compensatable.

