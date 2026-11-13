# CLI and project behavior

## Parsing

Recognize env-host flags only before `--run`. Everything after it is the exact child argv, including flags named `--secure`, `--project-id`, or `--run`. Do not invoke a shell implicitly. `envh --run sh -c '...'` explicitly asks for a shell and remains subject to child containment. Empty command and conflicting `--secure --unsafe` are syntax errors. Management subcommands reject `--run` combinations.

```text
envh init [--env PATH] [--replace-existing] [--new-project]
envh [--project-id ID] [--unsafe | --secure] --run EXEC [ARG...]
envh manage [--project-id ID]
envh snap [--project-id ID] [--force]
envh policy show|edit [--project-id ID]
envh project bind --project-id ID --root PATH
envh ps [--json]
envh inspect SESSION_OR_PROJECT [--json]
envh stop SESSION_OR_PROJECT [--all]
envh approvals
envh lock
envh doctor [--json]
```

`manage` is a Go terminal management UI with list/add/edit/delete/reveal/import/classify/rotate actions. “Rotate” sets a replacement local value; it does not imply remote provider key issuance or revocation. Noninteractive automation may later get dedicated commands; do not accept secret values on command lines in v1. Inputs use masked terminal input or an explicit protected import stream.

## Root and identity resolution

1. Obtain physical cwd through an OS handle; preserve application cwd rather than `chdir` to the discovered root.
2. Without explicit ID, walk physical ancestors to the nearest `.h.env`, stopping at filesystem root. Do not search unrelated roots. Refuse symlink markers, malformed files, or ownership/permission violations; do not skip them and find a parent marker.
3. Parse ID, derive locator, verify registered signed binding for the root. A descendant cwd must remain inside that bound root under actual OS object/path semantics.
4. With explicit ID, it selects the namespace even if another marker is nearer, but cwd must belong to an approved root for that ID. It is not a grant to run arbitrary foreign code with selected secrets. Never search by secret name or silently use another project's policy.
5. Root changes require authenticated binding. Nearest nested project boundaries are respected. Registering an extra root for the same ID is explicit; creating a distinct project uses a new ID and empty vault.

`inspect <project-id>` resolves in memory and shows safe label/session metadata, not the supplied ID. `ps` lists session IDs, labels, mode, state, safe executable basename, and start time. Do not show full argv or environment. If `stop <project-id>` selects multiple live sessions, require `--all` or a session ID; one session is unambiguous.

## Initialization and import transaction

`init` is local to the current directory. It does not initialize an ancestor automatically. Authenticate before creating/changing registration or importing secrets. Repeated initialization with a valid registered marker is a no-op unless an import was requested. A complete marker plus an incomplete matching journal can resume after auth. A missing marker at a known root errors; `--new-project` is an explicit acknowledged different identity, not recovery.

Create `.gitignore` if absent. If Git is available, `git check-ignore --no-index` can inform effective ignore evaluation through a shell-free subprocess; it is only a convenience, never a trust boundary. Preserve all bytes of existing `.gitignore` except adding a necessary newline and final `/.h.env` rule. Check tracked state: an already tracked marker is a visible error requiring explicit untracking by the user; adding an ignore rule alone does not remove tracked content. Do not edit Git's index automatically. Handle symlinked/read-only ignore files as errors, not overwrite targets.

Import is parse → validate → preview names/count/conflicts → authenticate → commit. Names/errors can be shown; values never printed. The caller provides the ID, not the import file. No shell execution, interpolation, `source`, or variable expansion.

Dotenv v1 grammar:

| Input | Result |
|---|---|
| blank lines; leading whitespace; `# comment` | Ignored |
| optional `export ` then `NAME = value` | Name matches `[A-Za-z_][A-Za-z0-9_]*`, at most 128 characters |
| `EMPTY=` | Stored empty value |
| unquoted value | Trim edge spaces; ` #` starts a comment; interior `#` stays literal |
| single-quoted value | Literal contents; no escapes or interpolation |
| double-quoted value | `\\n`, `\\r`, `\\t`, `\\"`, `\\\\` decoded; unsupported escapes rejected |
| quoted value followed by whitespace/comment | Accepted; other trailing text is error |
| `$X`, `${X}`, `$(cmd)`, backticks inside value | Literal bytes, never evaluated |
| CRLF; UTF-8 BOM at start | Normalize line endings; strip one leading BOM |
| multiline quote or line continuation | Unsupported in v1; report line number with no value excerpt |
| missing `=`, invalid UTF-8/NUL/name, oversized entry/file | Reject entire import; no partial writes |

Duplicate names in one file: last declaration wins, deterministic, warn with name and line numbers only. Existing vault names: reject the entire conflicting import unless `--replace-existing` was explicitly chosen; preview the affected names. Empty does not mean absent/deleted. Known import source paths are recorded as default-denied credential-file paths in signed policy. Leave the source bytes and permissions unchanged.

An import to a new project is committed with initialization using the journal described in [vault](vault.md). Source read errors, canceled authentication, ignore-file failure, and storage failure return safe actionable errors. Never output a parsed offending line containing a value.

## Snapshot

After fresh auth, read manifest names only; sort bytewise ascending; output `NAME=\n` with no comments/values. Fixed target is `.env.example` at the bound project root, not an arbitrary `--output` path. Explain the root when invoked from a subdirectory in management output.

Refuse symlinks, nonregular targets, and unsafe ownership. A target that aliases `.env` or an import source via hardlink is rejected. If target exists, show a confirmation prompt in this management command; `--force` is explicit noninteractive overwrite authorization. No terminal available and no `--force`: return error. No change to `.gitignore`. Use mode 0644 subject to umask for this public template.

Write a sibling temp file, fsync, revalidate the exact target observed at confirmation, and atomically publish. Changed target identity/content revision causes `CONFLICT`, not overwriting a replacement the user never confirmed. Concurrent snap runs use project-level serialization. Test failure leaves either the previous complete file or the new complete file.

## Mode and environment rules

| Behavior | Unsafe | Standard | Secure |
|---|---|---|---|
| OS isolation | None | Required | Required |
| Project selection/session records | Yes | Yes | Yes |
| Project secrets | Selected values, authenticated release | Selected values, authenticated release | Never raw protected values |
| Shell environment | Preserved, with explicit project overlay | Strict allowlist | Strict allowlist |
| Nonsecret config entries | Inject | Inject | Inject |
| Proxy integration | Optional | Optional for compatibility/egress | Required for protected credential usage |

Restricted inheritance starts with locale (`LANG`, selected `LC_*`), terminal (`TERM`, `COLORTERM`), and safe user-display variables. Rebuild `PATH` from approved executable directories, `HOME`/`TMPDIR`/XDG caches from per-session locations, and `PWD` from the actual cwd. Do not automatically inherit `SSH_AUTH_SOCK`, `AWS_*`, `GITHUB_TOKEN`, `DYLD_*`, `LD_*`, `NODE_OPTIONS`, `PYTHONPATH`, proxy variables, browser/debug sockets, or toolchain init hooks. Additional environment names/values require an authenticated policy or project config entry.

Merge order: safe inherited base → declared config → selected Standard/Unsafe secrets → reserved runtime values. Reserved names (`ENVH_*`, `HOME`, `TMPDIR`, `PATH`, `PWD`, platform loader variables) cannot be assigned as imported secret exports; storing them can be supported for metadata, but launch must reject a selected conflicting entry rather than silently ignore it. Explicit integration bindings replace only their declared SDK endpoint/auth settings. No env dump in an error.

Select all project entries by default in Standard/Unsafe to meet expected `.env` behavior; policy may narrow exports. Secure exports only explicitly classified config plus nonsecret broker endpoint/capability material. A loopback proxy bearer/capability is session-scoped authority, not a provider key, and still must not be logged. Inherited/project plaintext copies can defeat Secure's protection; do not claim the broker erases them.

Explicit `config` classification publishes a copy into signed local `environment.public_config`; the management confirmation explains this exposure. Configuration-only runs use that snapshot without unlocking keys. Imports classify every entry as secret until the user chooses otherwise. Reclassifying public data as secret cannot retract copies already read or backed up.

## Transparent execution and approvals

Success produces no env-host startup output. Pre-exec errors can use stderr because the application has not started. Once started, runtime diagnostics go to audit/native UI/separate `envh approvals`; application stdout/stderr remain untouched. Management commands may print ordinary status and errors.

No prompt on application stdin. Notifications name safe project label, session, executable basename, normalized destination/protocol/port, and scope; then exactly the three prescribed choices. Missing UI/expiry denies. Tests must compare bytes and terminal state with an unwrapped fixture, including Ctrl+C, job control, signals, pipes, colour, progress bars, and exit status.

`doctor` explains unavailable capabilities and exact setup actions without launching the application. It cannot turn unsupported enforcement on by ignoring a warning. Headless/CI vault access uses explicitly configured passphrase/OS auth with protected input; native biometric cancellation never downgrades to an anonymous run.
