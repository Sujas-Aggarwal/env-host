# env-host

A Go CLI for project-specific environment variables. Initialize a project, import or manage its values, then run your application with those values injected.

On macOS, `--run` applies a per-project Seatbelt file and network policy. HTTP and HTTPS traffic goes through a local proxy that checks the project's domain rules. `--unsafe --run` bypasses the policy and executes directly. Normal mode on Linux and Windows fails closed for now; use `--unsafe` there. Secure credential-proxy mode is not implemented.

## Build and install

Requires Go 1.27 or newer.

```sh
make build                  # creates bin/envh
./bin/envh --help
make install                # installs envh into ~/.local/bin
```

Choose another location with `make install INSTALL_DIR=/absolute/path/to/bin`.
The installer prints a PATH instruction if the chosen directory is not on your PATH.

Without make: `go build -trimpath -o bin/envh ./cmd/envh` and
`GOBIN="$HOME/.local/bin" go install ./cmd/envh`.

If your shell cannot find `envh`, add this line to `~/.zshrc` (or your shell's
startup file), then open a new terminal:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

A plain `go install ./cmd/envh` uses Go's configured `GOBIN` or `GOPATH/bin`, which
may be a different directory and may not be on your shell's PATH.

## Quick start

```sh
cd my-project
envh init --env .env
envh manage                 # opens vim, or $VISUAL / $EDITOR
envh policy manage          # edit default, allow, block, read, and write rules
envh snap
envh --run npm run dev
envh --unsafe --run npm run dev  # direct execution without policy
```

Initialization creates a random project ID in `.h.env` and ensures Git ignores it. Imported values go into an encrypted local vault, not the marker. The original `.env` stays untouched.

On macOS, envh uses LocalAuthentication to ask for Touch ID or the Mac's login password before it reads a project's random key from the user's login Keychain. This uses the same LocalAuthentication prompt flow as your `myohmy` CLI and works with an ordinary `go install` build. Run `envh auth status` to check availability or `envh auth probe` to try an actual prompt with a temporary key. A new passphrase must contain at least 12 characters.

Existing passphrase projects remain usable. `envh migrate` converts one to Keychain authentication after verifying the old passphrase and then asking macOS to authenticate the user. Migration leaves the vault unchanged if setup or authentication fails. Passphrases and interactive values are entered without echo. Repeating `init` on an unchanged project is harmless. The LocalAuthentication prompt gates envh's own key reads; the login Keychain item does not itself enforce biometric access against other programs running as the same macOS user.

Project values **override matching shell variables**. Other shell variables, including PATH, remain available. Empty values stay empty. Unsafe execution replaces envh with the application on macOS/Linux. Normal macOS execution keeps envh running to enforce the proxy, preserving the application's cwd, terminal streams, and exit status. There is no startup banner or implicit shell.

## Commands

| Command | Behavior |
|---|---|
| `envh init` | Create a project and empty encrypted environment; tries macOS Keychain authentication |
| `envh init --passphrase` | Create a project using an env-host passphrase |
| `envh init --env FILE` | Initialize and import a dotenv file |
| `envh import FILE` | Add dotenv entries; conflicts abort the whole import |
| `envh import --replace FILE` | Explicitly overwrite conflicting entries |
| `envh set NAME` | Set a value through a hidden prompt; also rotates a local value |
| `printf %s 'value' \| envh set NAME --stdin` | Read an exact value from stdin, including any supplied newlines |
| `envh get NAME` | Explicitly reveal one value on stdout, with no added newline |
| `envh list` | List names in sorted order, never values |
| `envh unset NAME [NAME...]` | Delete entries; all requested names must exist |
| `envh passwd` | Change a passphrase project's encryption passphrase |
| `envh manage` | Open a dotenv-style text buffer in `$VISUAL`, `$EDITOR`, or `vi` |
| `envh policy manage` | Edit this project's network and file access rules |
| `envh policy show` | Show the current project policy |
| `envh migrate` | Move a passphrase project to macOS Keychain authentication |
| `envh auth status` | Check whether macOS user authentication is available |
| `envh auth probe` | Try Touch ID/login-password authentication and Keychain access |
| `envh snap` | Generate `.env.example` with names and empty assignments |
| `envh snap --force` | Explicitly overwrite an existing snapshot |
| `envh --run COMMAND [ARGS...]` | macOS: execute with injected values and project policy |
| `envh --unsafe --run COMMAND [ARGS...]` | Direct execution with injected values, bypassing policy |
| `envh --project-id ID --run COMMAND` | Explicitly select another registered project |
| `envh version` | Print the version |

Global `--project-id ID` can also be supplied on management commands. All arguments after `--run` belong to the application, including flags that resemble envh flags. For shell syntax, explicitly use `envh --run sh -c '...'`.

`envh manage` shows active variables as `NAME="value"`. Add lines, edit values, delete lines, or prefix a line with `#` to disable it. Comments and blank lines are kept in the encrypted vault for later edits. Saving the editor updates all active variables at once. If the edited file is malformed, nothing is saved. Env-host temporarily writes the editable values to an owner-only file and deletes that file when the editor exits; your editor may also create swap or backup files, so configure it accordingly for sensitive values.

## macOS project policy

`envh policy manage` opens a text editor. The policy lives in an owner-only project file under env-host's local storage. Lines beginning with `#` are comments. For example:

```text
default block
allow api.example.com:443
allow *.example.org
block telemetry.example.org
read ./data
write ./build
```

`default` can be `allow` or `block`; a missing rule defaults to `block`. Matching `block` rules take precedence over `allow` rules, followed by the default. Host rules can name a domain, wildcard subdomains, or a literal IP, with an optional port. Literal IPs require an explicit `allow` even when the default is `allow`. `read` and `write` add existing directories, resolved relative to the project root or given as absolute paths. The project root is readable and writable by default. System program locations are readable; other file reads and writes are denied by Seatbelt. `write` also grants read access to that directory.

Normal mode starts a short-lived HTTP proxy on localhost. It sets common proxy environment variables for the child and permits the sandboxed process to connect only to that proxy port. Proxy-aware HTTP and HTTPS clients can reach destinations permitted by the policy. Clients that ignore proxy settings, use unsupported protocols, or try direct sockets will fail to connect. The proxy resolves each permitted hostname once and dials that numeric address. Private and loopback destinations require an explicit literal-IP allow rule; named hosts that resolve there are denied. Normal mode also permits local inbound listening so a development server can bind localhost.

This controls direct file operations and network connections by the launched process and descendants. It does not isolate every macOS IPC route to unsandboxed system services, and domain rules cannot identify a different HTTPS hostname tunneled over an already permitted IP. `sandbox-exec` is deprecated by macOS; a future macOS release may require another enforcement backend. If the sandbox cannot launch, envh fails rather than running the app without the policy.

The nearest ancestor `.h.env` selects the project when running from a subdirectory. Snapshots go to the project root. An explicit ID uses the vault's registered root for snapshots; it does not change the application's cwd.

## Import behavior

Supported: blank lines, comments, `export NAME=value`, empty values, single/double quotes, CRLF, UTF-8 BOM, and common double-quoted escapes (`\n`, `\r`, `\t`, `\\`, `\"`). No variable expansion or command execution. Quotes must close on the same physical line; use escaped newlines in double quotes for multiline values.

Duplicate declarations within one file use the last value and warn by name only. Invalid input rejects the entire import. Names must match `[A-Za-z_][A-Za-z0-9_]*` and be at most 128 characters; the `ENVH_` prefix is reserved. Limits: 1 MiB input/combined environment, 1,024 variables, 64 KiB per value. The OS can impose a smaller launch-environment limit.

A snapshot contains names only. Existing files require confirmation or `--force`. Symlink targets and hardlinks to the project's `.env` are refused. `.env.example` is not added to Git ignore rules.

## Storage and automation

Default storage: the OS user configuration directory plus `env-host/projects` (on macOS, `~/Library/Application Support/env-host/projects`). Use `ENVH_HOME` to choose a different directory.

Each project is independently encrypted using AES-256-GCM with a fresh random salt and nonce. PBKDF2-HMAC-SHA256 (600,000 iterations) derives the encryption key from either the project passphrase or a random project key held in macOS Keychain, together with the high-entropy project ID. File names use a hash of that ID. The recorded project root is authenticated but not encrypted. Writes use atomic replacement and a cross-process writer lock. Unix vault directories/files use 0700/0600 permissions.

For CI, supply `ENVH_PASSPHRASE` through your CI's secret environment. `ENVH_NEW_PASSPHRASE` supplies a replacement for `passwd`. Env-host removes `ENVH_*` control variables from the launched application's environment. Other inherited shell credentials are retained: this is explicitly unsafe execution. Avoid putting real values in shell history; interactive `set` is preferable.

Moving a directory with `.h.env` preserves its identity. Run `envh init` in the new location to update its registered root (authentication required). Deleting the marker does not automatically recover or replace it. Restore the marker, or deliberately choose `init --new-project` for a new, empty identity. For an existing marker with no local vault, `init --register` creates a new local vault; it cannot recover old data. It also resumes initialization interrupted after marker creation.

Back up the marker and encrypted vault deliberately. Losing either the project ID or passphrase can make stored values unrecoverable. There is no reset/recovery key. Old backups may still be decryptable with old credentials.

## Current limits

No daemon, cloud sync, automatic provider-side key rotation, or credential-proxy integration. Applications receive raw environment values and can read, log, or transmit them wherever the selected run mode permits. At-rest encryption does not protect against a compromised running application or developer account. This implementation has not had an independent cryptographic audit.

macOS is the development/test platform. Linux and Windows builds are checked separately; Windows uses a child process instead of POSIX exec and still needs native workflow validation. On Windows, filesystem access also depends on the directory's existing ACLs.

## Development

```sh
make test
make vet
make race
```

Tests use temporary projects, synthetic values, and actual subprocess execution. They cover encrypted storage, wrong-password/tamper rejection, imports, identity loss, snapshots, concurrent updates, application arguments/streams/exit codes, and POSIX interrupts.

Dependencies are Go's official `golang.org/x/term` for hidden input and `golang.org/x/sys` for platform support/Windows locks. Versions and checksums are pinned in `go.mod` and `go.sum`.

The original long-term requirements remain in [docs/reference/product-requirements.md](docs/reference/product-requirements.md). This README describes the implemented release.
