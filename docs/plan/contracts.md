# Shared contracts

These are normative semantic contracts. Types below are design sketches for the implementation tasks, not compiling source. Wire envelopes and policy/proxy data have schemas in [specs](../../specs/README.md).

## Value types and interfaces

```go
type ProjectLocator [32]byte // not the raw project ID
type SessionID [16]byte      // crypto/rand; public identifier, not auth
type PolicyHash [32]byte
type Generation uint64

type ProcessIdentity struct {
    PID int
    BootID string
    NativeInstance []byte // validated audit token / generation identity
}

type CapabilityReport struct {
    Backend string
    OSBuild string
    Architecture string
    EvidenceID string
    FilesystemDefaultDeny bool
    DescendantContainment bool
    NetworkDefaultDeny bool
    IPv4IPv6 bool
    ControlPlaneExclusion bool
    FailureContainment bool
    SingleFlowApproval bool
    TerminalPassthrough bool
}

type Backend interface {
    Probe(context.Context) (CapabilityReport, error)
    Prepare(context.Context, LaunchPlan) (PreparedSession, error)
    IdentifyPeer(context.Context, NativeConnection) (PeerIdentity, error)
}
type PreparedSession interface {
    Commit(context.Context, LaunchPermit) (RunningSession, error)
    Abort(context.Context) error // idempotent, including partial preparation
}
type RunningSession interface {
    Events() <-chan NativeEvent // bounded; overflow is a security event
    PermitFlow(context.Context, FlowGrant) error
    Revoke(context.Context) error
    Stop(context.Context, StopReason) error
    Wait(context.Context) (ExitStatus, error)
}

type PolicyEngine interface {
    Compile(ValidatedPolicy, BoundRoots, CapabilityReport) (PolicySnapshot, error)
    Evaluate(PolicySnapshot, Operation) Decision // pure, deterministic
}
type Authenticator interface {
    Authorize(context.Context, OperationBinding) (OneUseGrant, error)
}
type Vault interface {
    Names(context.Context, AuthenticatedProject) ([]EntryName, error)
    Mutate(context.Context, AuthenticatedProject, ExpectedRevision, MutationBatch) (Revision, error)
    Reveal(context.Context, AuthenticatedProject, EntryName) (SensitiveBuffer, error)
    Lease(context.Context, AuthenticatedProject, LeaseRequest) (LeaseHandle, error)
    Revoke(context.Context, LeaseHandle) error
}
```

`AuthenticatedProject`, `OneUseGrant`, and `LeaseHandle` must not be freely constructible evidence from request JSON. They are server-side opaque validated handles. Never expose `GetAllSecrets(projectID)` to plugins or to the coordinator. `SensitiveBuffer` is non-loggable by design; formatting produces only `[redacted]`, marshaling fails except in the dedicated secret handoff codec.

## Local transport and identity

- macOS/Linux: private Unix sockets or native XPC/Mach transports where peer audit identity is required; owner-only runtime directory, no symlink-following at creation, verified service ownership. Windows: named pipe with explicit ACL and authenticated caller identity.
- Wire serialization is a 4-byte unsigned big-endian payload length followed by UTF-8 JSON. Maximum control frame 1 MiB; management import uses a dedicated bounded stream with a 4 MiB cap. Zero-length/oversized frames terminate the connection.
- No network listener for management. Socket ownership and same UID are necessary but insufficient. Validate process instance/signing where available and reject managed-app/custom-plugin peers from management channels. Broker data channels have a separate authority surface.
- HELLO negotiates major=1 and minor/capabilities. Incompatible major fails closed. Unknown fields, duplicate JSON object keys, unsupported operations, malformed IDs, trailing bytes, and unbounded nesting are rejected. `encoding/json` alone does not reject duplicate keys; add a strict prevalidation/token pass.
- Request IDs are 128-bit random hex. Cancellation revokes only that request's pending authority. Deadlines use local monotonic time; wall-clock timestamps are for audit, never approval validity.
- Request input never declares its own UID/PID/trust level. Dispatcher injects peer identity from transport. Secret values cannot appear in generic error/detail fields.

General envelope: `version`, `request_id`, `kind` (`request|response|event`), `op`, `body`; a response has exactly one of `body` or `error`. Each operation has a closed typed payload checked by its handler. Envelope schema is intentionally not a claim that operation bodies are semantically validated.

## Operations

| Operation | Input (in addition to server peer context) | Result / side effect | Authority |
|---|---|---|---|
| `Capability.Get` | none | OS-specific report, no secrets | Trusted management peer |
| `Project.Register` | raw ID via protected channel, root handle, expected absent/revision | Atomic registration; ID discarded after derivation | Fresh auth |
| `Project.Bind` | ID, new root handle, expected revision | Signed root binding; copied/moved distinction explicit | Fresh auth |
| `Policy.Read` | locator or discovered selection | Effective public policy revision | Trusted peer; no vault unlock |
| `Policy.Commit` | selected identity, canonical proposal, expected revision | Signed policy for future launches | Fresh auth bound to full proposal |
| `Vault.Names` | selected identity | Names/classification only | Fresh auth |
| `Vault.Mutate` | selected identity, expected revision, bounded add/set/delete batch | New encrypted generation | Fresh auth; no partial commit |
| `Vault.Reveal` | selected identity, one name | Value to dedicated reveal channel | Fresh auth; no ordinary JSON logs |
| `Session.Prepare` | identity selection, root/cwd handles, argv/env-name plan, mode, policy revision | Prepared session + permit, never raw root keys | Trusted launcher; fresh auth if credentials needed |
| `Session.Commit` | permit, native launch handles | Running session identity | Bound launcher, one-use permit |
| `Session.List/Inspect` | session ID or safe project selector | Redacted process/session metadata | Trusted owning peer |
| `Session.Stop` | session ID/generation, reason | Revokes, closes, terminates tree | Trusted owning peer; no new vault access |
| `Approval.List` | optional session | Safe pending-flow descriptions | Trusted approval peer |
| `Approval.Decide` | request/session/generation, flow ID, policy hash, exact decision | Consume live request; apply flow/session grant or stop | Trusted approval peer, bound grant |
| `Vault.Lock` | user scope | Revoke leases/grants; stop credential-dependent sessions | Trusted owning peer |

Mutation idempotency: caller reuses `request_id` only for the identical canonical operation digest and expected revision. Store bounded nonsecret completion receipts; duplicate returns prior result, changed digest returns `CONFLICT`. A restarted service never replays a secret reveal or runtime lease automatically. Reauthentication is required if completion is ambiguous; do not guess based on a timeout.

`ProjectSelection` raw ID is ephemeral. It is not persisted in request receipts. Use locator plus digest of the action; secret-bearing request digests must be keyed inside the vault service to avoid dictionary attacks on low-entropy values.

## Session machine

```text
Created -> Preparing -> AwaitingAuth (if needed) -> Armed -> Running
 any pre-running state -> Aborting -> Failed
 Running -> Revoking -> Stopping -> Exited
 Running -> Revoking -> Stopping -> Failed  (security/health failure)
```

Only `Armed -> Running` consumes a launch permit. No “running but still installing rules” state. Pending permissions do not suspend the whole session state machine; they are per-flow records. Any transition away from Running invalidates them. Terminal states are immutable. Repeated revoke/stop/cleanup is safe. Storage keeps enough nonsecret generation/tombstone data to reject stale callbacks after restart.

Capability fields must all be true for baseline Standard/Secure, plus required mediation features from the selected policy. Evidence ID must map to accepted signed-build/OS test results. `Probe` combines installation health with accepted evidence; it must not manufacture a passing report from the OS version alone. Unsupported platforms return stable unavailable errors, not permissive stub implementations.

## Approval machine

```text
Pending -> AllowedOnce | AllowedSession | Stopped | Expired | Canceled
```

Pending record fields: random request ID, locator, session/generation, native flow ID + process instance, normalized destination (`origin` or explicit `IP:port`), protocol, policy hash, creation time, deadline, bounded UI label. TTL is 30 seconds or the smaller backend safe hold deadline. Max 16 pending per session and 128 per user. Excess attempts fail immediately; aggregate notification counts. UI displays no unescaped application strings.

Exactly three selectable actions: **Allow this time**, **Allow for this session**, **Stop application**. Closing, timing out, losing UI, or failing verification denies the flow; it does not add a fourth action. User-presence approval itself authorizes the transient grant; persistent policy edits separately require vault/native authentication. Never offer a permission broader than the prompt states.

Allow-once atomically consumes a live `(session,generation,flow)` and releases that same connection. It does not authorize a retry. TCP retransmits are part of that flow; a new connect is another flow. UDP approvals need a backend-defined flow identity and bounded datagram/lifetime semantics; v1 general UDP stays denied until that contract is proven. A backend that can only deny-now/retry-later does not implement allow-once and fails the baseline gate.

Allow-session adds a rule keyed by exact destination type, normalized host/address, transport, port, and session generation. It expires on session end, not on a timer reused by another session. A prompt for an IP cannot silently become a domain grant. Stop invalidates permits first, then executes tree termination.

An allowed TCP connection may carry many requests. Allow-once is one connection, not one HTTP operation. Secure proxy operation permissions are checked on every request, even over reused connections.

## Errors, limits, and exit behavior

Stable codes: `INVALID_ARGUMENT`, `PROJECT_NOT_FOUND`, `PROJECT_ID_MISSING`, `PROJECT_BINDING_REQUIRED`, `AUTH_FAILED`, `AUTH_UNAVAILABLE`, `PERMISSION_DENIED`, `ENFORCEMENT_UNAVAILABLE`, `UNSUPPORTED_PROTOCOL`, `CONFLICT`, `EXPIRED`, `RESOURCE_LIMIT`, `AUDIT_UNAVAILABLE`, `INTEGRITY_FAILED`, `INTERNAL`.

Errors contain code, safe message, retryable boolean, and optional fixed next-action enum. No opaque upstream string propagation. Map details separately for authenticated users. Retryable means an identical request may be retried under the documented idempotency contract, not that a denied connection receives approval automatically.

Before launch: 2 syntax, 3 identity/binding, 4 auth, 5 enforcement/policy, 6 internal/IPC/audit, 126 not executable, 127 executable not found. After launch: return the application's normal exit code unchanged; POSIX signal termination maps conventionally to `128+signal`, Windows preserves native exit status as supported by the parent shell. Security termination is distinguished in audit/inspect, not by rewriting the app's terminal output.

Default deadlines: control call 5 seconds; prepared launch permit 30 seconds; auth interaction 120 seconds with explicit cancellation; grant use 60 seconds; network prompt 30 seconds bounded by backend; graceful stop 2 seconds. All time comparisons use monotonic clocks and injectable clocks in tests. Security callback deadlines are OS-provided, not these UI defaults.
