# Handoff to implementation models

## How to use this package

Assign one task ID from [tasks.json](tasks.json), starting with **F01**. Give the worker only the task record, its `read_first` files, relevant schemas, `AGENTS.md`, and the code it touches. It should not need to reinterpret the entire product brief. Give it the requirements document only when resolving an actual requirement conflict.

Keep senior reasoning for F02–F05, V02, R01/R03/R04, P01, and release decisions. A cheaper worker can write scaffolding/fixtures for these, but must not decide the boundary is secure. Good inexpensive-model tasks include dotenv parsing, ID codecs, strict JSON, atomic storage, audit formatting, policy tables, snapshot writing, management UI, and a fixed declarative transform implementation. Crypto implementation from approved vectors can be delegated only with mandatory specialist review.

Task size target: a cohesive module with at most a handful of files and one externally observable behavior. Large native tasks are research work packets; split their implementation into one probe at a time, preserving the parent acceptance criteria. Avoid asking a worker to “finish the milestone” in one turn.

## Worker prompt

```text
Implement task <TASK_ID> from docs/plan/tasks.json in this repository.

Read AGENTS.md, the task record, its read_first files, and only relevant code.
Confirm dependencies have accepted implementation evidence; a design file is not evidence.
Stay within allowed_paths. Preserve all security and wire-format invariants.
Implement the smallest complete change satisfying the listed acceptance criteria.
Use Go for product logic/test helpers. Do not add a dependency without documenting why.
Do not enable unavailable enforcement, weaken a deny, retain a raw project ID,
print a secret, skip a failing security test, or invent an OS guarantee.
Do not make external calls or install native components unless this task and the
test environment explicitly authorize them.

Run the relevant verification checks. For native checks report exact OS/build,
architecture, signing/entitlement setup, and whether the check actually ran.
If a contract is insufficient, finish independent work and report the smallest
specific ambiguity with a proposed decision; do not silently change the contract.

Return: files changed, acceptance criteria with evidence, commands/results,
known limitations, and the next dependency. Do not mark the task accepted yourself.
```

## Reviewer prompt

```text
Review the diff for task <TASK_ID> against tasks.json, its contracts, and I01–I12.
Check the boundary and failure behavior, not just style and happy-path tests.
Inspect changed defaults, error paths, data retention, peer identity, and any
test skips. Look for path-prefix/DNS-only/process-polling substitutes for security.

Verify each acceptance criterion from implementation and independent tests.
Classify results as pure-unit, simulated, or real-OS evidence. Never merge these
categories into one “passed” claim. Reproduce the most consequential negative case.
Check that logs/errors/fixtures contain no secrets/raw IDs and new dependencies
are justified and pinned.

Return accept / request changes / blocked-by-external-evidence, with exact findings.
For requested contract changes, describe the security consequence and update the
decision record before a worker implements them. Ordinary contract-conforming
fixes do not require asking the user for permission again.
```

## First prompt, ready to use

```text
Implement F01 only. Build the Go feasibility probe harness and read-only capability
inventory described in docs/plan/tasks.json and docs/plan/macos-feasibility.md.
The planning machine was macOS 15.7.5/arm64; do not assume it has macOS 27 APIs.
Do not install system extensions, alter security settings, or claim isolation.
Use synthetic temp-directory and local-network canaries, with no external services.
Produce machine-readable pass/fail/unavailable/not-run results and sanitized
evidence. A deliberately permitted effect and a deliberately failing control must
demonstrate that the harness detects real effects independently of env-host logs.
Follow AGENTS.md and return the task completion evidence.
```

## Completion record

Store accepted task evidence separately from the manifest's original design:

```text
Task: I02
Base revision / implementation revision:
Worker / reviewer:
Files:
Acceptance criterion -> test/evidence:
Commands and exit status:
Native OS/build/signing (or not applicable):
Skipped/unavailable checks:
Security-relevant deviations:
Decision: accepted / changes requested / blocked
```

Update `status` only after review. Valid operational statuses: `not_started`, `in_progress`, `review`, `accepted`, `blocked`. Dependency readiness requires `accepted`, not merely finished model output. A blocked native gate does not prevent independent documentation or test-harness improvement, but blocks dependent security claims.

## Keeping cost under control

- Reuse source-linked decisions and fixtures; do not ask each model to research the whole architecture again.
- Give deterministic acceptance tests and bounded file ownership, not vague instructions to “make it production ready.”
- Land format/types before consumers. One reviewer owns cross-module changes and integration.
- Review small diffs when they arrive. Repeated cheap retries cannot resolve a missing OS primitive.
- After two failed attempts at the same boundary, summarize concrete failures and send that small issue to a senior model/engineer. Keep unrelated completed code.
- Use recorded local fixtures for provider tests. Real APIs and secrets are not default development dependencies.
- Measure accepted tasks and escaped defects, not token count or generated lines. Security work that produces a valid no-go result is useful completed work.

No sub-agents were used to produce this plan. The task graph is a future delegation guide, not a claim that implementation ran in parallel.
