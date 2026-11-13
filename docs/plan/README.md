# Implementation plan and model handoff

## Recommendation

Build a small, capability-gated runtime around a per-user coordinator, a protected vault service, a per-session launcher, and separately constrained enforcement/proxy processes. Establish the macOS enforcement boundary and the vault's loss semantics before building a complete management UI.

Use inexpensive models for bounded modules after their contracts are fixed. Reserve architecture changes, cryptography approval, native enforcement, launch ordering, and release decisions for senior review. A long prompt asking a cheap model to “build the whole runtime” would delegate the unresolved security design as well as the coding.

This package makes the shared decisions now. It supplies exact command semantics, state machines, key derivation, data formats, interface responsibilities, work dependencies, and adversarial acceptance tests. Native feasibility is a research result still to be measured, not a promise concealed inside an interface.

## The three decisive constraints

1. **macOS isolation is an evidence gate.** Current Apple documentation includes descendant-scoped Endpoint Security APIs available from macOS 27; this machine runs macOS 15.7.5 and cannot validate them. The older system-wide APIs have different privilege and deployment requirements. Neither the existence of AUTH callbacks nor a fail-closed deadline setting proves isolation when an enforcement process is killed. [Feasibility study](macos-feasibility.md).
2. **The project ID must be cryptographically required and not recoverable from local registration.** Generate 256 random bits, store the ID only in `.h.env`, and index local records by a one-way locator. Decryption needs both the ID and an authenticated root key. Deleting one file is not equivalent to erasing backups or already-loaded secrets. [Vault design](vault.md).
3. **A domain is not an IP address.** DNS history cannot distinguish malicious traffic to different tenants of one CDN. Strong hostname policies require an approved protocol mediator; opaque protocols require an explicit address grant or remain unsupported. Invisible execution does not imply every protocol can be transparently secured. [Network contract](policy-and-proxies.md).

## Deliverables

| Document | Purpose |
|---|---|
| [Decisions](decisions.md) | Chosen alternatives, scope, unresolved gates |
| [Feasibility](macos-feasibility.md) | Primary sources, local evidence, native experiments, go/no-go rule |
| [Threat model](threat-model.md) | Attacker capabilities, boundaries, security invariants |
| [Vault](vault.md) | Auth, exact key hierarchy, loss/backup lifecycle, crash safety |
| [Architecture](architecture.md) | Processes, packages, trust boundaries, launch and cleanup |
| [Behavior](behavior.md) | Commands, project discovery, import grammar, environment, terminal UX |
| [Contracts](contracts.md) | IPC, Go interfaces, state machines, errors, limits |
| [Policy and proxies](policy-and-proxies.md) | Policy semantics, egress, extension capabilities, initial integration scope |
| [Roadmap](roadmap.md) | Milestones, dependency graph, review gates, estimates |
| [Task manifest](tasks.json) | Machine-readable, scoped implementation assignments |
| [Worker handoff](worker-handoff.md) | Copy/paste worker/reviewer prompts and cost controls |
| [Validation](validation.md) | Adversarial checks, evidence format, requirements traceability |
| [Schemas](../../specs/README.md) | Parseable v1 policy/proxy/IPC envelopes and examples |
| [Package verification](verification.md) | Checks actually performed and evidence not yet available |

## Status and first assignment

- Requirements analysis and architecture handoff: **complete as a proposal**.
- Published documentation/SDK inspection: **performed**, with sources in the feasibility and vault documents.
- Real enforcement, entitlements, native authentication, cryptographic implementation, and adversarial runtime tests: **not performed**.
- Implementation tasks: **not started**. No task is marked done because it has a design document.

Start with **F01**, the Go feasibility harness and capability inventory, followed by **F02–F05**. Do not begin the complete CLI before the **G0** feasibility decision. Failed experiments are useful deliverables. They must not become simulated security controls.

The owner can subsequently choose a higher minimum macOS version, a clearly labeled experimental backend, or a revised isolation scope if G0 fails. None is silently substituted for the requested product.
