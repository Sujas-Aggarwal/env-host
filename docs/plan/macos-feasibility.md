# macOS feasibility study and G0 gate

Research date: 2026-11-14. This is a sourced assessment and experiment specification, **not a completed proof of isolation**.

## Findings

Apple documents `es_new_descendants_client` from macOS 27. It scopes events to the caller's process subtree, requires the Endpoint Security entitlement, and does not require root or TCC approval. This is the preferred candidate for per-session process/file mediation on compatible systems. Verify availability against the final SDK/runtime: some indexed Apple pages still label this family beta. [Apple function documentation](https://developer.apple.com/documentation/endpointsecurity/es_new_descendants_client(_:_:).md).

Apple also documents `es_set_deadline_miss_mode` from macOS 27. Its fail-closed setting covers authorization deadlines and authorization messages dropped on a full queue. **Inference:** this improves two failure cases, but does not establish what happens after the ES client is killed, unsubscribes, or disappears. Those are distinct mandatory tests. [Apple deadline-mode documentation](https://developer.apple.com/documentation/endpointsecurity/es_set_deadline_miss_mode(_:_:).md).

The older system-wide ES route requires a different deployment model. Apple's sample requires signing, the ES entitlement, extension activation, and Full Disk Access; the client API includes a not-root error. It is a candidate for comparison, not a portability layer assumed equivalent to descendant-scoped ES. [Apple sample](https://developer.apple.com/documentation/endpointsecurity/monitoring-system-events-with-endpoint-security), [client result codes](https://developer.apple.com/documentation/endpointsecurity/es_new_client_result_t).

For network enforcement, macOS content filters deploy as system extensions; transparent proxies have their own packaging options. Developer ID distribution is supported for the relevant system-extension rows in Apple's deployment matrix. The plan requires an installer/containing app and approved configuration, not just `go install`. [Apple TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment.md).

Socket filtering must be explicitly enabled. Network Extension's filter data/control providers also have distinct sandbox and information-flow constraints. The design must test a supported control channel rather than assuming the filter can freely call the coordinator or vault. [Socket filtering](https://developer.apple.com/documentation/networkextension/nefilterproviderconfiguration/filtersockets), [content filter architecture](https://developer.apple.com/documentation/networkextension/content-filter-providers).

Apple's supported sandbox-helper instructions describe embedded helper tools with inherited app-sandbox entitlements. **Inference:** that documentation alone does not prove that arbitrary unsigned developer executables, dynamic per-project path grants, and arbitrary descendants satisfy this product. [Apple helper documentation](https://developer.apple.com/documentation/xcode/embedding-a-helper-tool-in-a-sandboxed-app).

## Local evidence collected

Read-only commands on the current machine returned:

```text
sw_vers: macOS 15.7.5, build 24G624
go version: go1.27.1 darwin/arm64
SDK: /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk
```

The installed SDK's `usr/include/sandbox.h` marks the header deprecated and warns of possible removal. Its `usr/include/EndpointSecurity/ESClient.h` does not contain the descendant-client or new deadline-mode symbols. The first attempted framework-header path did not exist; inspection used the actual SDK include directory. No entitled binary was built, no extension installed, no system settings changed, and no sandbox trial run.

Consequence: this machine can host Go core work and older-backend experiments, but cannot prove the macOS 27 candidate. Obtain a supported physical test machine/SDK before claiming that path works. A VM can help test development tooling but does not replace physical-device biometric and shipping-environment evidence.

## Candidate comparison

| Candidate | Potential value | Missing proof / limitation | Decision |
|---|---|---|---|
| Descendant ES + NE filter/broker | Narrow process scope; OS authorization; network attribution | macOS 27 baseline, entitlement, file event completeness, client death, IPC escapes, Go lifecycle bridge | Preferred experiment |
| System-wide ES + NE | Older macOS candidate; process/file events | Root/FDA/global scope, event deadlines, death gap, inherited FDs and delegation | Compare explicitly |
| App Sandbox launcher | Persistent kernel restrictions | Arbitrary executables, dynamic grants, child inheritance, supported deployment | Investigate as independent persistent boundary |
| `sandbox-exec` / Seatbelt profiles | Fast exploration of inherited restrictions | Deprecated API/profile support and distribution durability | Research only; cannot silently become production |
| `pf`, DNS filtering, environment proxy settings | Supplemental controls or routing | Per-session attribution, IPv6/UDP, local sockets, bypass, domains | Insufficient alone |
| Poll process tree + kill on daemon failure | Cleanup | Race permits protected operations before termination | Insufficient security boundary |
| VM/mandatory container | Stronger available isolation direction | Contradicts requested initial product shape | Only a separately approved scope change |

## Experiment protocol

Each probe is a Go executable with synthetic canaries, temporary directories, and a controlled local network receiver. Tests must observe the forbidden effect at the filesystem/server, not merely an env-host “deny” log. Store sanitized artifacts under `docs/evidence/<gate>/<os-build>/`; do not commit machine identifiers, secret markers, or credentials.

| Probe | Experiment | Pass condition |
|---|---|---|
| F-P01 | Entitled signed minimal Go client and provider bundle installed with normal protections enabled | Repeatable install/start/uninstall on clean machine without disabling SIP or requiring development exemptions |
| F-P02 | Fork/exec/spawn, double fork, setsid, reparent, fast grandchildren, PID reuse | Every descendant attributed before its first protected action; identity uses kernel lifetime information |
| F-P03 | Read/write/execute, rename, unlink, create, truncate, mmap, hardlinks, symlink races, directory descriptors, external volumes | Denied effects never occur; exact supported filesystem semantics documented |
| F-P04 | Inherited and passed FDs; `SCM_RIGHTS`; `/dev/fd`; helper execution; Mach/XPC/Unix sockets | Restricted app cannot gain a denied object/capability through an intermediary |
| F-P05 | Kill/panic/suspend ES client, coordinator, supervisor, network provider independently; overflow queues | No new denied reads/writes/execs or outbound bytes while components are unavailable; existing grants behave as specified |
| F-P06 | Raw IPv4/IPv6 TCP/UDP, QUIC, DoH, DoT, DNS, loopback, multicast, raw sockets and packet tunnels | Only expressly supported policy paths work; every bypass fixture fails |
| F-P07 | Two projects + two sessions each, same executable/port/CDN IP, rapid churn | No cross-session grant; cannot consume another session's pending approval |
| F-P08 | Pause and resume one specific socket flow during approval | “Allow this time” releases exactly that flow; retries and sibling flows remain blocked |
| F-P09 | DNS rebinding, CNAMEs, IPv4-mapped IPv6, shared IPs, SNI/HTTP authority mismatch | Domain policy only permits origins the broker itself authenticates; no inferred IP grant |
| F-P10 | Native Keychain user presence through CGO, repeated operations, canceled auth, enrollment change, nonbiometric device | Key release is gated; UI success alone cannot authorize raw-file decryption; fallback behavior measured on macOS |
| F-P11 | Native approval UI with exactly three actions; offline UI; sleep/wake; login/logout; VPN coexistence | Correct session visible, bounded requests, no app-output pollution, no accidental allow |
| F-P12 | TTY, pipes, job control, 100 concurrent synthetic sessions, CPU/event pressure | Correct output/exit/signals plus retained enforcement under load |

Do not assume every ES notify event has an AUTH equivalent. Build an event-to-operation table from the target SDK. Cached authorization must not leak across policy versions or sessions. If a necessary operation cannot be mediated, identify the independent persistent boundary that blocks it or fail that capability.

## Hard go/no-go rule

G0 accepts a backend only when all required filesystem, child containment, egress, control-plane exclusion, crash, and Go/native integration probes pass on an explicitly listed release. A watchdog's reaction time is not an allowed unprotected interval. Any forbidden effect is a failed gate.

If persistent crash containment cannot be achieved under the stated constraints, the conclusion is **“production macOS isolation not established under these constraints.”** Continue vault/core design only as clearly scoped work; Standard/Secure remain unavailable. The owner then chooses whether to change the minimum OS, accept an explicitly experimental product, permit a stronger isolation substrate, or stop. Do not mislabel an endpoint monitor as a sandbox.

G0 also requires an independent cryptography review of [the vault design](vault.md). “Go uses AES” is insufficient evidence for the key hierarchy, ID loss semantics, and authorization lifecycle.

## Later platforms

Linux candidate: namespaces where available, a dedicated network namespace with broker-only egress, cgroup v2 membership/lifecycle, Landlock filesystem restrictions, `no_new_privs`, and seccomp. Probe supported Landlock ABI and operations; its capabilities vary by ABI, including IPC scoping. A distribution disabling unprivileged namespaces is a support constraint. [Linux Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html).

Windows candidate: AppContainer/restricted identity plus explicit resource ACLs, Job Objects for lifecycle, and an independently validated WFP/network boundary. AppContainer's documented isolation is useful, but arbitrary developer-tool compatibility and fine-grained destination mediation still need tests. [Microsoft AppContainer documentation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation).

Neither backend is enabled by a successful cross-compile.
