<p align="center"><img src="assets/logo.svg" alt="MemoGuard logo" width="112"></p>

# memoguard-engine

Reusable Go engine for inspecting Stellar transaction data before submission.

## Owns

- Decoding Stellar transaction-envelope XDR with the official Go library.
- Extracting public memo, operation, contract-input, and supported simulation fields.
- Applying a policy from `memoguard-rules`.
- Returning safe findings with rule ID, severity, and field path.

## Does not own

CLI flags, GitHub Action annotations, rule authoring, transaction signing, or submission.

## Use

```go
scanner, err := engine.New(rules.Default())
if err != nil { return err }
report, err := scanner.Scan(ctx, engine.Input{Kind: engine.EnvelopeXDR, Payload: envelopeXDR})
if err != nil { return err }
if report.Blocked() { return errors.New("transaction blocked by privacy policy") }
```

Input kinds are `envelope_xdr`, `memo_text`, `soroban_simulation`, and `decoded_json`. The engine decodes Stellar XDR before inspecting text. It scans memo text, ManageData names and values, SetOptions home domains, supported Soroban contract arguments, and simulation event and return values. Findings include rule IDs and field paths but never the matched value. A clean report only covers supported decoded fields; it is not a guarantee that a transaction contains no sensitive data.

The scanner rejects malformed XDR, JSON, and inputs above 2 MiB. Use it before transaction submission to prevent a leak. Scanning after submission is an audit only and cannot remove data from the ledger.

Run `go test ./...` with access to the private, tagged `memoguard-rules` dependency. Go 1.26 is required.

Product PRD and architecture live in the parent `memguard/docs` folder in the local workspace.
