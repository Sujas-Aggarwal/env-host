# env-host implementation

Build and maintain the usable Go CLI. The current scope is project initialization,
encrypted project environment storage, dotenv editor management, import, snapshots, and direct
host execution with environment injection. The user's revised scope supersedes
the removed architecture/task gates. Do not restore deleted planning files.

- `envh --run` on macOS applies a Seatbelt file/network profile and a local
  domain-policy HTTP proxy. `envh --unsafe --run` bypasses them and executes
  directly. Normal mode on Linux/Windows must fail closed until implemented.
- Do not claim complete containment against IPC to unsandboxed host services.
  Unsupported secure mode must error rather than silently run.
- Preserve argv, cwd, terminal streams, signals, and application exit status.
  No run banners or log prefixes.
- Keep project identity separate from secret values. Never print values except
  an explicit get/reveal action. Never put values in markers or snapshots.
- Use Go and prefer the standard library. Keep dependencies justified and pinned.
- Test actual CLI workflows, data integrity, failure handling, and execution.
- Keep README/help synchronized with implemented behavior.
- macOS authentication currently uses LocalAuthentication before the CLI reads a
  login Keychain item. Do not describe the item itself as biometric protected.
- Do not restore or overwrite unrelated user changes. Do not publish or use real
  credentials in tests.

Checks: `go test ./...`, `go vet ./...`, and `go test -race ./...`.
Build: `go build -trimpath -o bin/envh ./cmd/envh`.
