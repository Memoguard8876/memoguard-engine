# Changelog

## v0.2.2 — 2026-10-09

- Accept a full Stellar RPC JSON-RPC reply for `soroban_simulation` by unwrapping its `result` object, as well as the bare result object.
- Fail closed on simulation input that is not recognizable (a JSON-RPC error, an unrelated JSON object, an empty result) instead of reporting a clean scan with nothing inspected.

## v0.2.1 — 2026-10-08

- Return an explicit error when supported input exceeds scan depth, field, or text limits instead of silently skipping it.
- Preserve numeric values in decoded JSON for configured ID rules.

## v0.2.0 — 2026-10-08

- Inspect numeric ID memos and printable hash/return memo bytes under configured rules.
- Add XDR memo and simulation tests plus a malformed-input fuzz target.

## v0.1.0 — 2026-10-07

- Added Stellar XDR, simulation, and decoded JSON scanning with redacted findings.
