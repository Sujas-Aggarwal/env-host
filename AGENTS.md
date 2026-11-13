# Implementation instructions

This repository currently contains a design, not a working security runtime.

- Read `docs/plan/README.md`, `docs/plan/decisions.md`, and your assigned task in `docs/plan/tasks.json` before editing.
- Implement one task and its acceptance criteria at a time. Follow the dependency graph; do not silently absorb later tasks.
- All product logic and test helpers must be Go. CGO/native ABI glue is allowed only inside platform adapters, with no policy or cryptographic logic in that glue. JSON, Markdown, platform manifests, and build configuration are data, not alternate product languages.
- Standard and Secure must fail before application launch unless every required capability has accepted real-OS evidence for that backend/version. Test doubles must never be selectable in a production binary.
- Do not replace OS enforcement with path-prefix checks, DNS-only filters, proxy environment variables, process polling, or a watchdog. Those are not equivalent controls.
- Never log project IDs, secrets, complete environment maps, raw request bodies, tokens, or unfiltered command arguments. Do not use real secrets in tests.
- No persistent copy of a raw project ID outside the project marker. No project ID recovery by listing registrations. See the precise active-session and backup qualifications in `docs/plan/vault.md`.
- Sensitive management operations require a fresh, operation-bound authentication grant. Same-UID IPC access alone is not authorization.
- Keep terminal passthrough distinct from management output and approvals. Never insert runtime banners or prompts into the application's streams.
- Preserve versioned contracts. Contract/security changes require a written decision and senior review; ordinary implementation within an accepted task needs no repeated user confirmation.
- Run the checks relevant to the changed boundary. A skipped native test is unverified, never a pass. Record exact OS/build/architecture, toolchain, and test results.
- Stay in the assigned file scope. If a dependency or design contradiction blocks the task, report the smallest concrete issue; do not weaken an invariant to finish it.
- Do not create remote resources, publish, install system extensions, alter machine security settings, use real credentials, or contact external services as part of a documentation or pure-unit-test task.

Task completion output: files changed; acceptance criteria with evidence; commands/results; limitations; next dependency. Do not describe mocks or compilation as proof of isolation.
