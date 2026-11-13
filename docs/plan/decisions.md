# Decisions and scope

Status: proposed implementation baseline, 2026-11-14. “Chosen” means a design decision; “gated” means it cannot be enabled until its stated evidence is accepted.

| ID | Decision | Rationale and rejected alternative |
|---|---|---|
| D01 | macOS first; minimum supported release set by G0 evidence | Do not claim all Macs support the same enforcement APIs. Linux/Windows get independent backends later. |
| D02 | Standard/Secure are capability-gated; no fallback | An unavailable mechanism must produce `ENFORCEMENT_UNAVAILABLE`, never execute unsandboxed. |
| D03 | Prefer supported descendant-scoped ES plus Network Extension if G0 passes | Reduces global inspection/privilege on applicable macOS versions. Older system-wide ES is a separate candidate. Deprecated Seatbelt profiles are research-only unless the owner explicitly changes the support contract. |
| D04 | Per-user coordinator; narrow privileged platform service only where needed | Keep secrets, request parsing, third-party code, and notifications out of root processes. |
| D05 | Per-session trusted launcher remains in the terminal's job | A global daemon cannot transparently own an application's controlling terminal. Native child containment is independently required. |
| D06 | 256-bit random project IDs; one-way registration locators | Short sample IDs are illustrative, not the entropy target. A plaintext ID registry defeats loss semantics. |
| D07 | Authenticated root key + project ID derive project KEK; random per-project data keys | ID is a required high-entropy input, but possession alone cannot decrypt. No global application-secret namespace. |
| D08 | No product backup/export/recovery in v0.1 | Minimize accidental recovery paths. Document OS backups and deliberate copies honestly. Future exports must retain the ID requirement. |
| D09 | Fresh operation-bound auth; session-limited runtime secret leases | Avoid indefinite unlock and repeated per-request prompts. Management grants cannot reuse runtime leases. |
| D10 | Encrypted per-project object plus atomic index metadata; no database dependency initially | One writer per user, small bounded records, atomic replacement and recovery journal suffice. SQLite adds a large dependency/CGO surface without a current query need. |
| D11 | JSON policy/proxy formats and strict schemas | Standard-library parsing; no YAML ambiguity, template evaluation, arbitrary expressions, or executable config. |
| D12 | Length-framed JSON IPC over private local channels | Language-neutral and inspectable; no `gob`, unauthenticated TCP, web admin server, or gRPC dependency. Native peer identity and FD passing remain platform-specific. |
| D13 | Domain rules mean broker-authenticated origins; IP grants are explicit | DNS-to-IP mapping, SNI peeking, and CONNECT host strings are insufficient against hostile clients. |
| D14 | Standard receives selected project secrets; Secure receives only declared nonsecret config and scoped proxy capabilities | Never infer that `DEBUG` is nonsecret by its name. Imported entries default to secret. |
| D15 | Unknown egress prompts have exactly three choices; timeout/dismissal denies | “This time” consumes one pending flow, never creates a short-lived destination allowlist. |
| D16 | Strict environment allowlist in restricted modes | Inheriting the shell environment may leak unrelated AWS/GitHub credentials before the vault matters. Compatibility additions are explicit policy changes. |
| D17 | Proxy plugins are separate OS-constrained Go executables | No in-process Go plugins, dynamic library loading, unrestricted vault API, or default outbound access. |
| D18 | v0.1 Secure includes declarative HTTP mediation, one live-provider adapter after contract verification | PostgreSQL/Redis protocols, a package registry, transformations beyond bounded built-ins, and arbitrary custom credential injection are later milestones. |
| D19 | Source distribution and signed macOS bundle are distinct outputs | A Go binary alone cannot assume it has Apple's entitlements or can install system extensions. |
| D20 | Open-source license selected by owner before public release | No legal rights/license are invented by a worker. Local implementation does not depend on this selection. |

## Product ambiguities resolved

- `.gitignore` missing: create it with `/.h.env`. Existing ignore rules: preserve content and verify effective ignore status; append a final root-specific rule only when needed. Initialization fails visibly if the marker cannot be made ignored.
- Root discovery: nearest ancestor marker from physical working directory, stop at filesystem root; a malformed nearest marker is an error, not permission to search further.
- Explicit ID: selects that identity, not a new working directory and not permission to bind arbitrary code to its secrets. The physical cwd must already be under an authenticated registered root for that identity. Otherwise require explicit `envh project bind`.
- Moved project: ID survives the move. If the old root has disappeared and the new root has the marker, authenticated rebinding updates metadata. A copy while the old root still exists requires explicit additional-root binding; sharing is never inferred.
- Missing marker at a registered root: return `PROJECT_ID_MISSING`; never recover an ID from registry. Creating a different identity requires `init --new-project` with authentication and explicit acknowledgement of the old vault consequence.
- Unsafe: retains project selection, session bookkeeping, and explicit project secret injection/auth, but applies no host isolation. It never follows automatically from another mode failing. No runtime banner; mode is visible in management/inspect output.
- Raw credential viewing: explicit authenticated action only, on the management terminal; never ordinary list output. Every committed mutation/reveal is a separate sensitive operation even within `manage`.
- Ordinary execution: signed policy and explicitly public configuration may be read without a fresh biometric if no protected credentials are needed. Classifying an entry as `config` explicitly authorizes a plaintext copy in the signed local runtime policy; imports never do this automatically. Releasing secrets authenticates once per session launch; Secure holds a narrow session lease. An unlock command never opens the whole vault indefinitely.
- Permission notifications: native trusted approval UI or `envh approvals` in another terminal. No prompts on the application terminal. A missing UI causes denial after the bounded timeout.
- Background descendants: parent exit ends the session and stops remaining descendants. Detached execution is a later explicit feature, not an accidental leak.
- `docker compose`, Docker/Podman sockets, SSH agents, IDE daemons, launch services, and host automation are escape capabilities. Restricted mode denies them unless an independently reviewed integration constrains downstream work. Merely sandboxing a Docker client does not sandbox containers created by an existing host daemon.
- Existing plaintext `.env` files stay untouched. Known import-source files are denied to restricted applications by default. Secure mode cannot protect a duplicate credential that the user deliberately makes readable elsewhere.

## Decisions deliberately dependent on experiments

G0 must establish the minimum macOS/SDK, concrete launch containment, complete filesystem authorization coverage, network crash behavior, independent approval UI, and native auth/key protection. It must also prove the native CGO bridge can meet Apple's bundle lifecycle. All business logic stays Go; minimal C/Objective-C ABI glue is permitted by the CGO allowance. If more native product logic is required, record the conflict instead of starting a Swift subsystem.

No estimate includes an assumed Apple entitlement approval date. No architecture label substitutes for an enforceable boundary.
