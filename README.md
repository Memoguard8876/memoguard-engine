<p align="center"><img src="assets/logo.svg" alt="MemoGuard logo" width="112"></p>

# memoguard-engine

[![Go CI](https://github.com/Memoguard8876/memoguard-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/Memoguard8876/memoguard-engine/actions/workflows/ci.yml)

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

Input kinds are `envelope_xdr`, `memo_text`, `soroban_simulation`, and `decoded_json`. The engine decodes Stellar XDR before inspecting text. It scans text and numeric ID memos, printable text in hash and return memos, ManageData names and values, SetOptions home domains, supported Soroban contract arguments, and simulation event and return values. Opaque binary memo content is not interpreted as personal information. Findings include rule IDs and field paths but never the matched value. A clean report only covers supported decoded fields; it is not a guarantee that a transaction contains no sensitive data.

The scanner rejects malformed XDR, JSON, inputs above 2 MiB, and supported content that exceeds depth, field, or text limits. These cases return an error rather than a clean report. Numeric values in decoded JSON can be checked by configured rules. Use the scanner before transaction submission to prevent a leak. Scanning after submission is an audit only and cannot remove data from the ledger.

Run `go test ./...` and `go vet ./...` with Go 1.26.3 or newer. The tagged `memoguard-rules` dependency is public; no module token is needed.

The public [product requirements](https://github.com/Memoguard8876/memoguard-cli/blob/main/product/docs/PRD.md), [architecture](https://github.com/Memoguard8876/memoguard-cli/blob/main/product/docs/ARCHITECTURE.md), and [Wave plan](https://github.com/Memoguard8876/memoguard-cli/blob/main/product/docs/WAVE.md) live in `memoguard-cli`.

See [CONTRIBUTING.md](CONTRIBUTING.md) for changes, [SECURITY.md](SECURITY.md) for private vulnerability reports, and [LICENSE](LICENSE) for MIT terms.

Maintainers: [Memoguard8876](https://github.com/Memoguard8876). Discuss public work in [issues](https://github.com/Memoguard8876/memoguard-engine/issues); report vulnerabilities privately through SECURITY.md.
