# Proposed v1 schemas

These JSON Schema 2020-12 artifacts specify syntax for the handoff. They are not implemented validators or proof of policy enforcement.

| Schema | Valid example |
|---|---|
| [Policy](policy-v1.schema.json) | [Local development proposal](examples/policy-v1.json) |
| [Declarative proxy](proxy-v1.schema.json) | [Synthetic HTTPS fixture](examples/proxy-v1.json) |
| [Control envelope](ipc-envelope-v1.schema.json) | [Unavailable-backend response](examples/ipc-error-v1.json) |

The policy example deliberately lacks a toolchain profile and secret exports. It is a parseable proposal, not a ready-to-run permission set. Reserved deny rules, authenticated root bindings, signed storage wrapper, and platform compilation are mandatory additions by trusted code. Empty `export_entries` exports no entries; initialization chooses explicit entry names for its effective default policy. `public_config` contains only explicitly declassified nonsecret values; a semantic validator also enforces its 256 KiB aggregate byte cap and prevents secret-name shadowing.

The proxy example uses `.invalid` and synthetic names. It is not a live provider configuration. Fixture tests supply a controlled resolver/certificate in test-only builds. Production must not disable certificate verification to make it work.

Schemas reject unknown envelope/format fields; handlers must additionally reject duplicate JSON keys, normalize paths/hosts/IPs, enforce reserved keys, validate operation-specific IPC bodies, reject unsafe header names/injection fields, and check platform capabilities and authorization. JSON Schema does not establish any of those security properties by itself.

All persisted policy and vault revisions are constrained to the safe interoperable integer range `1..2^53-1`, even when Go storage uses uint64. Plugin messages use a separate `proxy.*` protocol with its own task to add closed message schemas; the control envelope's operation-name grammar is intentionally not reused for it.

Do not maintain a second hand-written collection/spec for local native IPC. Future external HTTP integration contracts should be saved locally in P03 and used to derive tests/mocks, following the contract-first workflow.
