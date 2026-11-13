# Validation, release evidence, and traceability

## Evidence levels

1. **Design/source review:** an API is documented, an algorithm is specified, a schema parses. This package reaches this level only.
2. **Pure unit/property/fuzz:** parsing, key derivation vectors, state transitions, decisions, data bounds. Proves those functions, not isolation.
3. **Controlled integration:** actual Go processes and controlled local servers with fault injection. Proves component interaction under the fixture's assumptions.
4. **Native adversarial:** real supported OS/kernel, signed components, normal security settings, malicious child processes, independently observed effects.
5. **Release qualification:** clean installation of the actual signed artifact, supported OS/hardware matrix, upgrades/uninstall, and independent review.

Standard/Secure require levels 4–5 for their boundaries. A mock backend, successful compile, or skipped CI job cannot satisfy them. Capture stdout/stderr bytes separately from security events and receivers.

## Adversarial acceptance matrix

| Test ID | Attack/condition | Required observation | Tasks |
|---|---|---|---|
| ID01 | Nearest malformed marker with valid parent marker | Error; parent identity never used | I01 |
| ID02 | Explicit foreign project ID under unbound cwd | Binding required; no keys released | I01, I03 |
| ID03 | Moved/copied/deleted marker | Authenticated move/add-root; no recovered or silently replaced ID | I01, I03 |
| ID04 | Full persistent-store/log/journal inspection | No raw ID outside marker; no secret plaintext | I01, V01, A01 |
| IN01 | Repeated init, missing ignore file, negated ignore, tracked marker | Deterministic idempotency; marker really ignored or explicit error | I03 |
| IN02 | Source contains empty, quotes, duplicates, shell expansion, malformed line | Exact grammar; no evaluation; atomic import; original untouched | I02, I03 |
| IN03 | Crash between ignore/marker/vault/registration writes | Explicit resumable old/new state; no replacement identity | I03 |
| VA01 | ID without root / root without ID | Cannot open encrypted project | F04, V01 |
| VA02 | Swap project/section/revision ciphertext; truncate/flip bits | Integrity failure; no partial plaintext returned | V01 |
| VA03 | Wrong/canceled/reused native auth; direct file read | No key release; no silent fallback | F04, V02 |
| VA04 | Auth grant replay/different action/digest/revision/session/peer | Rejected and not consumed for another operation | V02 |
| VA05 | Two projects share variable name | Completely independent values/leases | V01, V02 |
| VA06 | Root/keychain/ID/passphrase loss and surviving backup | Outcomes match loss table, including explicit limitations | F04, V02 |
| VA07 | Snap instrumentation + sentinel secrets | No value decrypt/read/output; names sorted empty assignments | V03 |
| VA08 | Snapshot symlink/hardlink/concurrent target replacement | Refuse unsafe or changed target; prior file intact | V03 |
| VA09 | Rotation/lock with running Standard and Secure sessions | No new stale leases; documented exported-value limits | V02, V03 |
| FS01 | Read/write/exec outside grants via child/native syscalls | Forbidden effect never occurs | F02, R03 |
| FS02 | Symlink swap, `..`, rename parent, hardlink, mounted volume | No path escape; object-level result checked | F02, R03 |
| FS03 | mmap/truncate/delete/create/directory FD and `/dev/fd` | Denied rights cannot be recovered through alternate operation | F02, R03 |
| FS04 | Extra inherited FD or `SCM_RIGHTS` from host helper | No unauthorized descriptor/capability access | F02, R03, R04 |
| FS05 | Access own marker/import source/vault/other project | Hard denies hold despite project-tree allow | R03 |
| PR01 | Fork storm, exec, setsid, double fork, reparent | Every child contained before first protected operation | F02, R03 |
| PR02 | PID exit/reuse and stale callbacks | New process never inherits old authority or receives stale kill | R02, R03 |
| PR03 | `sudo`, setuid, launchctl, XPC, Docker socket, SSH agent | Unsupported escalation/delegation denied | F02, R03 |
| PR04 | Parent exit while child stays alive | Session closes, all remaining descendants stopped | R04, R06 |
| IP01 | Same UID sandboxed process connects to management | Rejected by peer/session boundary | R01 |
| IP02 | Malformed/duplicate/oversized/replayed IPC | Bounded rejection; no mutation/secret leak | B02, R01 |
| IP03 | Two control clients mutate same revision | One commit; other conflict; no lost update | B03, V02 |
| NE01 | Direct IPv4/IPv6 TCP/UDP/QUIC/DNS/DoH/DoT/raw traffic | No receiver bytes absent explicit supported grant | F03, R03 |
| NE02 | Shared CDN IP, SNI vs HTTP authority, CONNECT tunneling | Domain grant cannot access another origin | F03, P01 |
| NE03 | DNS/CNAME rebinding to local/private/IPv4-mapped target | Broker refuses prohibited address at dial/reuse boundary | P01 |
| NE04 | Localhost/named socket/host proxy forwarding | No broad local bypass | F03, R03 |
| NE05 | Two projects same destination/executable; approval replay | Grant remains exact session/generation | R05 |
| NE06 | Allow-once and simultaneous/retried connects | One pending flow succeeds; others remain denied | F03, R05 |
| NE07 | Timeout/UI absent/close/dialog flood | Deny; exactly three choices; bounded resources | R05 |
| NE08 | Session end with pooled existing connections | Channel closed, no new authorized request/bytes | R03, P01 |
| NE09 | Loopback development listener and browser input | Only selected bind accepted; inbound does not grant outbound | R03, R06 |
| CR01 | Kill/suspend/crash coordinator, enforcer, supervisor, broker independently | No unprotected interval; sessions terminate or remain denied | F02, F03, R03, P01 |
| CR02 | Queue overflow/event sequence gaps and CPU pressure | Denial/teardown; never default allow | F02, F03, R03 |
| CR03 | Sleep/wake, logout, fast user switch, VPN/network change | No stale permit/identity or policy leakage | R03, Q01 |
| PX01 | Plugin/broker request picks another project/secret/upstream | Denied; caller cannot select vault authority | P01, P04 |
| PX02 | Header smuggling, encoded path separators, redirect, mutation retry | Invalid/blocklisted route denied; no credential sent elsewhere | P01, P02 |
| PX03 | Huge/slow/infinite stream, cancellation, 429/5xx | Backpressure/limits; no secret exposure or duplicate unsafe request | P01, P03 |
| PX04 | Malicious plugin network/file/vault access and stream replay | Capability and OS restrictions hold; no fall-through | P04 |
| UX01 | Silent app with success and nonzero exit; stderr/stdout pipes | Exact bytes/exit behavior; no env-host banner | R04, R06 |
| UX02 | TTY colour/progress/stdin/resize/Ctrl+C/Ctrl+Z/fg/SIGHUP | Native interaction and restored terminal state | R04 |
| UX03 | Shell env contains unrelated credentials and loader hooks | Restricted child cannot see them; approved config still works | R04 |
| UX04 | Config-only launch; secret reclassified or shadowed as config | Public snapshot needs explicit classification; no launch auth for public-only config; secret shadow rejected | B04, V03, R04 |
| AU01 | Secret/ID canaries in every error/log/failure path | No canary in persistent logs or ordinary management output | A01, Q01 |
| AU02 | Disk full, permission failure, audit queue saturation | No new unaudited authority; bounded teardown | A01, R02 |
| DI01 | Clean install/update/uninstall, missing entitlement | Clear capability state; no unsandboxed fallback/orphans | Q02 |

State the expected forbidden effect before running a test. A test that only asserts an internal “deny” return value does not demonstrate that the OS prevented the effect. Race tests need repeated runs and a stated sampling limit; no finite test count proves the absence of every race.

## Functional/compatibility matrix

Run synthetic Go commands as the deterministic baseline. Then validate installed Python, Node/npm, and Go dev commands with explicit narrow toolchain templates; record missing tools as unavailable. Test read-only project, spaces/Unicode in paths, nested projects, no Git repo, noninteractive input, multiple project roots, large env preflight, and two sessions of the same project. Docker and delegated host agents are expected denied cases until their own integration exists.

For Secure, record exact provider operation, client/SDK version, endpoint override settings, streaming behavior, and whether any code change is required. “Works with existing apps” is a tested compatibility table, not a universal assertion.

## Performance/reliability targets

Initial engineering targets, to measure after correctness: warm credential-free launch overhead p95 ≤100 ms; no output buffering; permission-decision application p95 ≤100 ms after user response; no unbounded queue/memory growth under 100 synthetic sessions; less than 5% steady CPU overhead for representative permitted development I/O. Authentication, user response, initial installation, and external service latency are excluded and reported separately. These are provisional targets, not measured claims or reasons to relax denial.

Go checks: `go test ./...`, `go vet ./...`, relevant `go test -race`, bounded fuzzing for parser/IPC/policy/proxy inputs, and a pinned Go vulnerability check in CI. Native suites run on dedicated test machines with normal protections. Never deploy privileged unreviewed PR artifacts to a developer's main workstation automatically.

## Evidence record

```json
{
  "test_id": "CR01",
  "status": "not_run",
  "implementation_revision": null,
  "artifact_sha256": null,
  "os_version": null,
  "os_build": null,
  "architecture": null,
  "sdk_version": null,
  "go_version": null,
  "signing_profile_class": null,
  "capability_evidence_id": null,
  "scenario": "Kill filesystem enforcement component during forbidden reads",
  "expected_effect": "No canary read succeeds",
  "observed_effect": null,
  "iterations": 0,
  "artifacts": [],
  "reviewer": null
}
```

Use `passed`, `failed`, `unavailable`, or `not_run`. No default “passed” when a process cannot start. Preserve sanitized logs/canary receiver counts/timing and native process identities without raw project IDs. Evidence is tied to artifact + OS build + configuration; changing the native mechanism invalidates prior qualification as appropriate.

## Original requirements traceability

| Original section | Design owner | Implementation tasks | Acceptance evidence |
|---|---|---|---|
| 1 Core product | architecture, decisions | M1–M4 tasks | I01–I12 invariants, Q01 |
| 2 Init/identity/import | behavior, vault | I01–I03 | ID01–04, IN01–03 |
| 3 Project-aware execution | behavior, architecture | R02, R04, R06 | ID02, PR01–04, UX01–03 |
| 4 Project vault/loss | vault | F04, V01–V02 | VA01–06, VA09 |
| 5 Authentication | vault, contracts | F04, V02 | VA03–04, IP01 |
| 6 Snapshots | behavior | V03 | VA07–08 |
| 7 Three modes | decisions, behavior | R06, P01–P03 | NE01–09, PX01–03, UX03 |
| 8 CLI | behavior | I03, V03, R04–R06 | Command grammar and workflow fixtures |
| 9 Transparent execution | architecture, behavior | R04 | UX01–02 |
| 10 Permissions/session UX | contracts | R02, R05 | NE05–08, CR01 |
| 11 Filesystem | feasibility, policy | F02, R03 | FS01–05 |
| 12 Network | feasibility, policy | F03, R03, P01 | NE01–09 |
| 13 Proxy ecosystem | policy-and-proxies | P01–P04, X03 | PX01–04 |
| 14 Go/modules/concurrency | architecture, contracts | B01, R01–R03 | Dependency checks, IP01–03, PR02 |
| 15 Platforms | feasibility, roadmap | F01–F05, X01–X02 | Independent native evidence per OS |
| 16 Security/reliability | threat-model, validation | Q01 plus boundary owners | Full adversarial matrix |
| 17 Developer workflow | behavior | I03, V03, R06, P03 | End-to-end and SDK compatibility matrix |
| 18 Long-term direction | roadmap | M5–M6 | Separate platform/ecosystem gates |
| 19 Delivery priorities | roadmap/tasks | F01 first, G0 before full CLI | Gate acceptance/dependency records |
| 20 Implementation guidance | AGENTS, worker-handoff | All tasks | Diff review, source/evidence separation |

Every deferred feature is labeled in the roadmap. Every unresolved platform guarantee is a gate, not a claimed completed requirement.
