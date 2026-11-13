# env-host

An open-source, local-first application security runtime in Go. The executable is `envh`.

**Current state: architecture and implementation handoff; no runtime is implemented or certified.** Standard and Secure modes must remain unavailable until the platform evidence gates pass. This repository does not yet provide application isolation.

Start with [the implementation plan](docs/plan/README.md). It contains the architecture, security boundaries, detailed contracts, dependency-ordered work packets, and prompts for implementation models.

The [original product requirements](docs/reference/product-requirements.md) are preserved verbatim. The plan resolves ambiguities explicitly and identifies requirements that still depend on operating-system experiments.

## Reading order

1. [Decisions and scope](docs/plan/decisions.md)
2. [macOS feasibility and evidence gates](docs/plan/macos-feasibility.md)
3. [Threat model](docs/plan/threat-model.md) and [vault design](docs/plan/vault.md)
4. [Architecture](docs/plan/architecture.md)
5. [CLI behavior](docs/plan/behavior.md), [interfaces](docs/plan/contracts.md), and [policy/proxy formats](docs/plan/policy-and-proxies.md)
6. [Roadmap and task graph](docs/plan/roadmap.md)
7. [Worker handoff](docs/plan/worker-handoff.md) and [validation matrix](docs/plan/validation.md)

The plan was researched on **14 November 2026**. OS API availability must be rechecked against the SDK and release actually used for implementation.
