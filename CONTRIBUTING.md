# Contributing to memoguard-engine

Thanks for helping. MemoGuard checks Stellar transaction data for accidental private information before submission.

## Ground rules

- Go only for product logic and CLI code. Run `gofmt`, `go vet ./...` and `go test ./...` before opening a PR.
- Keep to this repository's responsibilities (see its README). Do not copy detection code into the CLI or Action.
- Use **synthetic data only** in tests and fixtures. Never commit real customer data, keys, tokens or real transaction payloads.
- Never log or print matched values or full transaction payloads. Reports identify the rule and field path only.
- Decode Stellar XDR with the Stellar Go SDK; do not scan opaque base64 as text.
- Add a test for every behavior change, including malformed-input cases.
- Add a line to `CHANGELOG.md`.

## Workflow

1. Comment on the issue you want to work on and wait for assignment.
2. Fork, branch, and keep the PR focused on one issue.
3. Describe what changed and how you tested it.

## Security issues

Do not open a public issue with exploit details or live sensitive data. Use GitHub's private vulnerability reporting for this repository.
