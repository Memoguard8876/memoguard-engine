<p align="center"><img src="assets/logo.svg" alt="MemoGuard logo" width="112"></p>

<h1 align="center">memoguard-engine</h1>

<p align="center"><b>Go engine that scans decoded Stellar XDR and Soroban data for accidental disclosure.</b></p>

<p align="center">
  <a href="https://github.com/Memoguard8876/memoguard-engine/actions/workflows/ci.yml"><img src="https://github.com/Memoguard8876/memoguard-engine/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/Memoguard8876/memoguard-engine?color=blue" alt="License: MIT"></a>
  <a href="https://github.com/Memoguard8876/memoguard-engine/tags"><img src="https://img.shields.io/github/v/tag/Memoguard8876/memoguard-engine?label=release&color=brightgreen" alt="Latest release"></a>
  <img src="https://img.shields.io/github/go-mod/go-version/Memoguard8876/memoguard-engine?color=00ADD8" alt="Go version">
  <a href="https://github.com/Memoguard8876/memoguard-engine/issues"><img src="https://img.shields.io/github/issues/Memoguard8876/memoguard-engine?color=orange" alt="Open issues"></a>
  <a href="https://github.com/Memoguard8876/memoguard-engine/issues?q=is%3Aopen+label%3A%22help+wanted%22"><img src="https://img.shields.io/badge/help%20wanted-welcome-8A2BE2" alt="Help wanted"></a>
  <img src="https://img.shields.io/badge/built%20for-Stellar-black" alt="Built for Stellar">
</p>

<p align="center">
  <a href="https://cjay-1.gitbook.io/memoguard-docs/">Documentation</a> ·
  <a href="https://github.com/Memoguard8876/memoguard-engine/releases">Releases</a> ·
  <a href="https://github.com/Memoguard8876/memoguard-engine/issues">Issues</a> ·
  <a href="CONTRIBUTING.md">Contributing</a> ·
  <a href="SECURITY.md">Security</a>
</p>

---

## What it is

`memoguard-engine` is the scanner. It decodes Stellar transaction data with the official Stellar Go SDK, lists the fields that become public, applies a policy from [memoguard-rules](https://github.com/Memoguard8876/memoguard-rules), and returns findings that **never contain the matched value**. Import it into a Go service to check a transaction before you sign it.

## Features

- Decodes v0, v1 and fee-bump transaction envelopes.
- Scans memos, ManageData names and values, SetOptions home domains, Soroban contract arguments and constructor arguments.
- Scans Soroban `simulateTransaction` events and return values.
- Scans decoded transaction JSON and plain memo text.
- Deterministic: same input and policy give the same findings.
- Fails closed: malformed or over-limit input is an error, never a clean report.
- Offline. No network call, no state.

## Install

```bash
go get github.com/memoguard8876/memoguard-engine@v0.2.1
```

Needs Go 1.26.3 or newer. The rules dependency is public, so no token is needed.

## Quick start

```go
scanner, err := engine.New(rules.Default())
if err != nil {
	return err
}
report, err := scanner.Scan(ctx, engine.Input{
	Kind:    engine.EnvelopeXDR,
	Payload: envelopeXDR, // base64 TransactionEnvelope
})
if err != nil {
	return err // could not finish: do NOT submit
}
if report.Blocked() {
	return errors.New("transaction blocked by privacy policy")
}
```

Treat a scan error as a failure, not a pass.

## Input kinds

| Kind | Payload |
| --- | --- |
| `envelope_xdr` | Base64 transaction envelope |
| `soroban_simulation` | The `result` object of a Stellar RPC `simulateTransaction` reply |
| `decoded_json` | Decoded transaction JSON (strings and numbers are scanned) |
| `memo_text` | Memo string, scanned as `transaction.memo.text` |

## Field paths

| Path | Source |
| --- | --- |
| `transaction.memo.text` | Text memo |
| `transaction.memo.id` | ID memo, as decimal text |
| `transaction.memo.hash`, `transaction.memo.return` | Hash and return memos, only if printable UTF-8 |
| `transaction.operations.N.manage_data.name` / `.value` | ManageData entry |
| `transaction.operations.N.set_options.home_domain` | SetOptions home domain |
| `transaction.operations.N.invoke_contract.args.J` | Contract call argument (follows `.vec.K` and `.map.K.key/.value`) |
| `transaction.operations.N.create_contract.constructor_args.J` | Contract creation argument |
| `simulation.events.I.topics.J`, `simulation.events.I.data` | Simulation events |
| `simulation.results.I.return_value` | Simulation return value |

Anything not in this table is **not scanned**: other operation types, asset codes, account IDs, signatures, footprints and authorization entries.

## Findings

```go
type Finding struct {
	RuleID      string           `json:"rule_id"`
	Severity    rules.Severity   `json:"severity"`
	Confidence  rules.Confidence `json:"confidence"`
	FieldPath   string           `json:"field_path"`
	Description string           `json:"description"`
	Remediation string           `json:"remediation"`
}
```

`Finding` has no field for the matched text, by design.

## Limits

| Limit | Value |
| --- | --- |
| Input size | 2 MiB |
| Fields per scan | 4096 |
| Nesting depth | 12 |
| One text value | 64 KiB |

Exceeding a limit returns an error.

## Prevention and audit

Scanning **before** submission can stop a leak. Scanning a transaction that is already on the ledger is an audit only. It tells you what was exposed and cannot remove it.

## Develop

```bash
go test ./...
go vet ./...
go test -run '^$' -fuzz FuzzMalformedInputDoesNotPanic -fuzztime 30s
```

Synthetic envelopes for tests live in [`testdata/`](testdata).

## Limits of this repository

A clean report covers only the supported fields above. It is not proof that a transaction holds no private data. There has been no formal audit or outside pilot.

> **Known gap:** `soroban_simulation` expects the `result` object. Passing the full JSON-RPC reply (with `jsonrpc`, `id` and `result`) is read as having no events and reports clean. Unwrap `result` first.

## The MemoGuard family

MemoGuard is four independent Go repositories. Each builds from tagged releases of the one before it.

```text
memoguard-rules ──► memoguard-engine ──► memoguard-cli ──► memoguard-action
```

| Repository | Role | Latest |
| --- | --- | --- |
| [memoguard-rules](https://github.com/Memoguard8876/memoguard-rules) | Policy schema, validation, built-in rules, expiring exceptions | v0.1.1 |
| [memoguard-engine](https://github.com/Memoguard8876/memoguard-engine) | Stellar XDR decoding, field extraction, scanning, redacted findings | v0.2.1 |
| [memoguard-cli](https://github.com/Memoguard8876/memoguard-cli) | `memoguard scan` command, output formats, exit codes, release binaries | v0.2.2 |
| [memoguard-action](https://github.com/Memoguard8876/memoguard-action) | GitHub Action: pinned CLI, annotations, failure threshold | v0.2.1 |

Full guides, the field-path reference and walkthroughs are in **[MemoGuard Docs](https://cjay-1.gitbook.io/memoguard-docs/)**. Product requirements and architecture are versioned in [memoguard-cli/product/docs](https://github.com/Memoguard8876/memoguard-cli/tree/main/product/docs).

## Contributing

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md).

- Browse [open issues](https://github.com/Memoguard8876/memoguard-engine/issues). Labels show the type (`enhancement`, `documentation`, `testing`), `help wanted`, and a `complexity` level.
- Comment on an issue and wait to be assigned before you start.
- Use **synthetic data only** in tests and fixtures. Never commit real customer data, keys, tokens or real transactions.
- Add tests for every behaviour change, including malformed input, and a line in [CHANGELOG.md](CHANGELOG.md).

## Security

A clean scan is not a guarantee, and there has been no formal security audit. Report vulnerabilities privately through GitHub's private vulnerability reporting for this repository. See [SECURITY.md](SECURITY.md). Do not post exploit details or real private data in a public issue.

## Maintainers

| Maintainer | Role | Contact |
| --- | --- | --- |
| [Memoguard8876](https://github.com/Memoguard8876) | Organization owner, releases | [GitHub issues](https://github.com/Memoguard8876/memoguard-engine/issues) |

## Community

Ask questions and propose changes in [GitHub issues](https://github.com/Memoguard8876/memoguard-engine/issues). Read the [documentation](https://cjay-1.gitbook.io/memoguard-docs/) first; the [FAQ](https://cjay-1.gitbook.io/memoguard-docs/faq) answers the common questions.

## Contributors

<a href="https://github.com/Memoguard8876/memoguard-engine/graphs/contributors"><img src="https://contrib.rocks/image?repo=Memoguard8876/memoguard-engine" alt="Contributors"></a>

## License

[MIT](LICENSE) © MemoGuard contributors.
