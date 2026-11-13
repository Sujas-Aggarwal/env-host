# env-host implementation

Build and maintain the usable Go CLI. The current scope is project initialization,
encrypted project environment storage, import, management, snapshots, and direct
host execution with environment injection. The user's revised scope supersedes
the removed architecture/task gates. Do not restore deleted planning files.

- `envh --run` and `envh --unsafe --run` execute directly without isolation.
- Do not advertise filesystem/network isolation. Unsupported secure/standard
  modes must error rather than silently run.
- Preserve argv, cwd, terminal streams, signals, and application exit status.
  No run banners or log prefixes.
- Keep project identity separate from secret values. Never print values except
  an explicit get/reveal action. Never put values in markers or snapshots.
- Use Go and prefer the standard library. Keep dependencies justified and pinned.
- Test actual CLI workflows, data integrity, failure handling, and execution.
- Keep README/help synchronized with implemented behavior.
- Do not restore or overwrite unrelated user changes. Do not publish or use real
  credentials in tests.

Checks: `go test ./...`, `go vet ./...`, and `go test -race ./...`.
Build: `go build -trimpath -o bin/envh ./cmd/envh`.
