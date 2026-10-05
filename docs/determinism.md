# Determinism guarantee

Same explicit parameters → same key, across any release sharing the same
major version - only a major version bump may change key derivation. That
guarantee starts at 1.0; we're still on 0.x, so it doesn't apply yet (see
[`tests/golden/README.md`](../tests/golden/README.md)).
