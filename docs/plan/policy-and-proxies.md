# Policy, networking, and proxy design

## Effective policy

Use schema-versioned JSON; [schemas/examples](../../specs/README.md) define syntax. The authoritative policy is the authenticated signed copy in the local store. A repository policy file may be imported as a proposal only; running an untrusted checkout must not auto-grant its requests.

Compile validated syntax against actual bound roots and backend capabilities. Unknown keys, ambiguous paths, unsupported rights, malformed destinations, and unsupported protocols are hard errors. Every compiled snapshot has a deterministic hash and revision. Session policy is immutable; only transient flow/session grants augment it.

`environment.public_config` contains only explicitly declassified configuration values. Authenticated vault/policy mutations keep classification and this public snapshot in one journaled transaction. A policy proposal cannot publish an existing secret entry or shadow it as config without the explicit classification operation. This snapshot is what makes credential-free configuration launches possible; it must never be populated by default import behavior.

Filesystem rules identify absolute paths or the fixed `$PROJECT`, `$SESSION_HOME`, `$SESSION_TMP` anchors, with read/write/execute rights and recursive scope. No general environment expansion, shell syntax, globs, or string-prefix authorization. Resolve bindings through native object handles, reject escape paths and untrusted symlink ancestors, and let the OS enforce access at use time. A canonical-path check before launch does not solve later races.

Default template: project tree read/write, execution only from explicitly approved project/toolchain locations, session-private temp/home read/write, minimum OS/runtime read/execute. No entire-home grants. Always deny vault/control-plane/keychain access, raw devices/debug capabilities, other projects, `.h.env`, and known imported credential source files. Default `.git` access is read-only; approved workflows may add writes deliberately. Explicit deny overrides allow; reserved hard denies cannot be overridden by a normal project policy. Verify the backend can express this precedence; otherwise reject the policy.

Separate read/write/execute reflects native semantics. An interpreter may read a script and execute its contents even when the script itself lacks native execute permission. Document this limit; do not market execute bits as code-provenance enforcement. Mount changes, hardlinks, mapped files, path renames, and inherited descriptors require native tests.

## Outbound network semantics

Four destination classes:

| Class | Meaning | v1 behavior |
|---|---|---|
| `origin` | Exact HTTPS scheme, ASCII/punycode host, port authenticated by trusted broker | Supported only through declared HTTP mediation |
| `address` | Exact normalized IP, transport, port | Explicit exceptional grant; no inference from a domain |
| `local-service` | Specific session-visible local endpoint | Needs protocol/capability restriction; broad loopback access is never default |
| `integration` | Approved proxy binding and operation set | Secure credentials accessible only through its broker |

ASCII DNS names are lowercase with one trailing dot removed; reject malformed names, empty labels, embedded credentials, wildcards in v1, and ambiguous URL forms. International names must be provided as validated ASCII A-labels until an audited IDNA implementation is approved. Normalize addresses using `net/netip`, including IPv4-mapped IPv6. Ports are explicit; transport is explicit. DNS caching is broker-local, bounded by TTL, and does not create application permissions.

**Do not translate a hostname allowlist into a set of generally allowed IPs.** A shared CDN or DNS rebinding can turn that into access to another destination. A hostname supplied by a malicious app, DNS observation, TLS SNI, or CONNECT authority is not authentication of encrypted HTTP authority. Trusted broker outbound TLS validates the configured hostname and pins each request to the selected validated address. Reject loopback, link-local, multicast, private/internal targets by default for public origins, including all answers after CNAME resolution; explicitly bound local services are separate. Re-resolve/recheck on new connections, never follow rebinding into a prohibited class.

For v1, existing apps that support endpoint/proxy configuration can use broker-mediated HTTP without source changes. HTTPS CONNECT passthrough does not satisfy the strong origin contract and is denied for origin rules. No automatic installation of a local CA or universal TLS interception. Opaque/custom/pinned protocols remain unsupported unless a reviewed integration exists or the user grants an explicit address exception. This is a real compatibility limit, not a weakened definition of domain security.

The OS layer denies app direct egress except approved broker channels or explicit address grants. Proxy environment variables only route cooperative apps; they are not enforcement. The broker has only configured outbound origins; platform boundary plus internal request validation constrain it. Deny direct DNS/DoH/DoT, UDP/QUIC, raw sockets, ICMP, multicast, alternate interfaces, localhost relays, and host Unix/Mach/named-pipe delegation unless explicitly supported. IPv4 and IPv6 are equally tested. An allowed origin that itself offers a general tunnel remains an exfiltration risk; do not grant it as an unrestricted service.

Unknown direct socket flows may have only a trustworthy IP/port. Display that numeric destination; a reported hostname may be informational but cannot change the scope granted. Allow-once/session then refers to that exact address. Mediated requests can request an origin grant. Enforcement holds the live flow under the contract in [contracts](contracts.md); it does not briefly open a shared firewall rule.

## Local development listeners

Outbound and listening permissions are separate. Default deny bind/listen except an authenticated development template such as loopback TCP port 3000. Do not open wildcard interfaces or random ports automatically. Browser connections into a dev server do not grant that server outbound network access. Reverse connections, WebSockets, hot reload, callbacks, and localhost databases each need explicit directional policy. Secure service bindings prefer per-session Unix sockets when the client supports them; loopback compatibility requires kernel-attributed peer/session validation plus an unguessable scoped capability. A bearer token alone cannot prevent another session using a stolen token.

## Declarative engine

Bindings name one exact upstream HTTPS origin, named secret references in the same project, allowed methods/path patterns, operation limits, header removal/injection, and bounded transformations. The broker obtains only the binding's selected credential lease. A project ID or secret name in an application request never selects credentials.

Request pipeline:

1. Verify channel/session/generation and live lease; bound frame/body/header/time limits.
2. Parse HTTP once using Go's `net/http`; reject conflicting framing, malformed headers, CONNECT, upgrade/WebSocket, absolute-form targets not expressly supported, and path ambiguities.
3. Normalize route under an exact documented grammar. Match method and path. V1 patterns are exact path or segment-bounded prefix, not regex. Reject encoded separators, dot segments, NUL, and inconsistent double decoding.
4. Apply bounded built-in transformations/removals. Strip hop-by-hop, inbound authorization, proxy authorization, cookies unless explicitly allowed, and caller attempts to set trusted injection fields.
5. Revalidate transformed method/path/body constraints. Trusted engine injects the selected secret into an approved header only after custom/untrusted processing. Set authority/SNI from immutable binding; no caller URL override.
6. Resolve and dial validated upstream through the controlled egress path; validate public TLS normally. Redirects are disabled in v1. Retries are disabled for mutations unless provider-specific idempotency is proven.
7. Stream bounded response with cancellation/backpressure. Remove credential-bearing headers. Enforce response byte/time limits and close on session revoke. Do not log request/response bodies.

No general scripting, arbitrary URL templates, secret substitution into logs/errors, exec hooks, or custom CA trust by default. Request bodies can contain sensitive data, and streaming redaction is not universally safe: v1 supports named header removal and a small bounded JSON field-removal operation for explicitly buffered JSON content. Other transformations are unsupported. Credentials must never be injected into response bodies. A hostile upstream might echo credentials; exact known-value leak checks are defense-in-depth, not a universal guarantee against encoded echoes.

## Custom proxy protocol v1

Use the same bounded framing transport with a separate operation namespace, `proxy.*`. No Go `plugin` package. HELLO advertises major/minor, integration ID, package hash, supported operations, and declared capabilities. Host assigns an opaque instance ID; plugin cannot choose project/session authority.

Messages: `proxy.begin` (request ID, operation, sanitized metadata, capability IDs), `proxy.body` (bounded sequenced chunk), `proxy.end`, `proxy.cancel`, and response equivalents. Max control frame 1 MiB, chunk 64 KiB, 16 in-flight chunks, 16 concurrent requests per instance by default. Explicit credit/ack windows provide backpressure. Every stream is bound to a live instance/session; out-of-order, excess, stale, or duplicate terminal frames terminate it. Timeouts revoke the request; plugin crash closes pending work and never falls through to direct network.

Capabilities can authorize a bounded transformation, a broker request to a fixed named origin/operation, or a particular preopened resource handle. Default plugin filesystem is empty except executable/runtime and private scratch; default network is none; default secrets are none. Credential injection occurs after plugin output has been validated. Protocols that require the plugin itself to see a credential are a different, explicitly trusted integration class outside v0.1. PostgreSQL/Redis authentication cannot be declared solved by an HTTP header template.

Pin local package content hashes and review manifests before installation. Registry discovery, signature trust policies, auto-update, community publication, and arbitrary downloadable executables are later work. Installing a proxy never automatically grants the capabilities it requests.

## First integrations and contract verification

Build the engine against a synthetic local HTTPS fixture with a synthetic bearer header, exact POST path, streaming success, cancellation, redirect, 401/403, 429, delayed headers, malformed body, and disconnect cases. This proves mechanics without real keys or billable requests.

Then add one readably scoped external HTTPS integration (OpenAI is the initial candidate from the requirements). Before choosing operations or SDK environment bindings, retrieve the provider's current official contract, record its date/source, and confirm which unchanged clients accept endpoint override and placeholder authentication. No provider-specific endpoint or SDK compatibility is asserted by this planning package. Freeze the selected operation contract in task P03, then test with a faithful local fixture before an explicitly configured live smoke test.

Standard with raw secrets can exfiltrate to an already approved destination. Secure prevents ordinary app access to the protected provider credential, but permitted API operations may still be abused. Both limits must appear in release documentation.
