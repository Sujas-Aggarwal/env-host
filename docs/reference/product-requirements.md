# **env-host: Complete Product and Technical Requirements**

Build **env-host**, an open-source, local-first application security runtime written entirely in Go.

Its CLI executable is `envh`.

env-host allows developers to run applications on their machines without giving those applications unrestricted access to the host filesystem, network, and credentials.

The goal is to make local development safer, particularly against malicious or compromised dependencies, without requiring developers to containerize every project or modify their application code.

The product should feel like a natural part of a developer's workflow. Initialize a project, manage its credentials, grant it permissions, and run it through env-host.

**Core product principle: env-host should be almost invisible during normal application execution. The developer should feel like they are running their application directly.**

## **1. Core product requirements**

env-host must provide:

- A central encrypted secrets vault, isolated by project identity.
- Unique project IDs.
- Project-specific secrets and permission policies.
- Importing existing `.env` files.
- Generating `.env.example` files without exposing secret values.
- Filesystem access restrictions.
- Outbound network access restrictions.
- Process and child-process tracking.
- Session management and permission approvals.
- Authentication before sensitive management operations.
- Audit logs for security-relevant activity.
- A proxy framework for applications that need secure access to external services without receiving raw credentials.

Multiple projects must be able to run simultaneously, with independent permissions, process trees, sessions, credentials, and audit records.

The system should work with existing applications wherever possible, without requiring application code changes.

**Important scope decision:** There is no global secrets store in the initial version. Every secret belongs to exactly one project. Secrets must never be shared automatically between projects.

## **2. Project initialization and identity**

env-host must provide:

```
envh init
```

When executed inside a project directory, it should:

1. Generate a unique project ID.
2. Create a `.h.env` file in that directory.
3. Store the project ID in that file.
4. Add `.h.env` to the project's `.gitignore` if one exists.
5. Avoid duplicating entries if `.h.env` is already ignored.
6. Preserve existing `.gitignore` contents.
7. Register the project in env-host's local metadata store.
8. Handle repeated initialization safely.

Example `.h.env`:

```
PROJECT_ID=2kvcndsvldn
```

Requirements:

- `.h.env` contains only basic project metadata.
- Never store actual secrets in `.h.env`.
- Never store passwords, authentication tokens, or vault keys in this file.
- The file must be ignored by Git.
- Project IDs must be generated securely and be sufficiently unique.
- A project ID is the primary identifier for retrieving that project's secrets, policies, and configuration.

If the project directory is moved, its identity should remain intact as long as `.h.env` moves with it.

If `.h.env` is deleted, env-host must not silently generate a replacement identity and treat it as the same project. It should clearly explain the consequences.

### **Importing existing environment files**

`envh init` must support an optional `--env` flag.

Example:

```
envh init --env .env.example
```

It should also accept an actual environment file:

```
envh init --env .env
envh init --env config/development.env
```

The purpose is to initialize a project and import its predefined environment variables directly into that project's encrypted vault.

Requirements:

- Parse standard environment variable declarations.
- Import variable names and values into the project's vault.
- Support empty values.
- Preserve valid variable names and values.
- Handle quoted values and common `.env` formatting correctly.
- Reject or clearly report malformed entries.
- Never copy imported secret values into `.h.env`.
- Never print imported secret values to the terminal.
- Do not modify or delete the original source file.
- Authenticate the user before importing secrets.
- Handle duplicate variable names deterministically and explain the outcome.
- Allow initialization without an environment file.

For example, given:

```
OPENAI_API_KEY=sk-example
DATABASE_URL=postgres://localhost/mydb
DEBUG=true
EMPTY_SECRET=
```

All four entries should be imported into the project's vault, including the empty value.

The original `.env` file remains untouched. Developers can remove it themselves after verifying the import.

## **3. Project-aware application execution**

The primary application execution command is:

```
envh --run npm run dev
```

When `--project-id` is not explicitly provided, env-host should discover the project ID from `.h.env` in the current project directory.

An explicit project ID overrides automatic discovery.

Example:

```
envh --project-id 2kvcndsvldn --run npm run dev
```

Execution modes:

```
# Unsafe mode
envh --unsafe --run npm run dev

# Standard mode (default)
envh --run npm run dev

# Secure mode
envh --secure --run npm run dev
```

The project ID determines which project's secrets, policies, and configuration should be applied.

Requirements:

- Do not require users to specify a project ID every time.
- Automatically resolve it from `.h.env`.
- Support explicit project ID overrides.
- Validate that the project exists and is registered.
- Do not silently fall back to another project's configuration.
- Prevent one project from accessing another project's secrets or permissions.
- Make project identity resolution deterministic.
- Clearly define how project roots are discovered.

The runtime should support arbitrary executable commands rather than being designed specifically around Node.js.

Examples:

```
envh --run python manage.py runserver
envh --run go run .
envh --run npm run dev
envh --run docker compose up
```

## **4. Project-specific secrets vault**

Every project must have its own isolated secrets namespace.

There must be no global secrets store in the initial version.

For example:

```
Project A
  OPENAI_API_KEY
  DATABASE_URL
  GITHUB_TOKEN

Project B
  STRIPE_SECRET_KEY
  DATABASE_URL

Project C
  REDIS_URL
  DEBUG
```

Even if two projects use the same secret name, their values must remain completely independent.

Requirements:

- Secrets are associated with exactly one project ID.
- A project can only retrieve its own secrets.
- No automatic sharing between projects.
- No global secret inheritance.
- No cross-project access.
- Support adding, viewing, editing, deleting, and rotating project secrets.
- Support empty secret values.
- Support secret names independently of their values.
- Never expose secret values in logs or ordinary management output.
- Never store plaintext secrets in project configuration files.

The project ID is central to the vault's identity and retrieval model.

### **Project ID loss and recovery policy**

Losing a project's ID should have serious consequences.

The intended security property is:

**If the project ID is permanently lost, the associated secrets should be permanently unrecoverable.**

Secrets must be retrievable only through the combination of:

1. The correct project ID.
2. Successful user authentication through the vault's configured authentication mechanism.

There should be no global recovery key, automatic fallback identity, or cross-project lookup mechanism that bypasses this requirement.

The implementation must carefully design this cryptographic relationship. A project ID should not be treated as a substitute for a cryptographically secure encryption key. Use appropriate key derivation, authenticated encryption, and OS-backed key protection.

Biometric authentication should authorize access to protected key material rather than being treated as a reusable encryption secret.

The design must explicitly consider:

- Project ID entropy.
- Key derivation.
- Vault encryption.
- Authentication.
- Local metadata protection.
- Backup and recovery implications.
- What happens if `.h.env` is deleted.
- What happens if the machine is reinstalled.
- What happens if the user loses their authentication credentials.

Do not introduce a recovery mechanism that contradicts the stated unrecoverability requirement.

## **5. Vault authentication**

Access to the vault must be protected by user authentication.

The developer should authenticate before performing sensitive management operations.

Examples include:

- Adding, viewing, editing, or deleting secrets.
- Importing environment files.
- Changing project security policies.
- Changing sensitive project configuration.
- Modifying project metadata.
- Performing sensitive vault operations.

The preferred experience is native biometric authentication, such as Touch ID on supported macOS devices.

Where biometric authentication is unavailable, support a secure fallback such as a master passphrase or another appropriate OS-backed authentication mechanism.

Requirements:

- Never store authentication secrets in plaintext.
- Use OS-backed key protection wherever possible.
- Require authentication for each sensitive management operation.
- Do not rely on an indefinitely unlocked vault.
- Do not repeatedly prompt for authentication during ordinary application execution unless protected credentials are required.
- Define an explicit vault lock/unlock lifecycle.
- Ensure authentication cannot be bypassed by directly accessing local vault files.
- Possession of a project ID alone must not authorize access to its secrets.
- Authentication failures must not reveal whether a particular secret exists.

The authentication design must be evaluated against the actual capabilities of each supported operating system. Do not assume biometric authentication is universally available.

## **6. Secret snapshots**

env-host must provide:

```
envh snap
```

This command creates a `.env.example` file in the current project directory.

Its purpose is to provide a useful environment-variable template for developers and collaborators without exposing secret values.

Example: if the project's vault contains:

```
OPENAI_API_KEY = [secret value]
DATABASE_URL = [secret value]
DEBUG = true
EMPTY_SECRET = 
```

Running:

```
envh snap
```

Should generate:

```
OPENAI_API_KEY=
DATABASE_URL=
DEBUG=
EMPTY_SECRET=
```

Requirements:

- Include secret names, never secret values.
- Include all environment variable names configured for the project.
- Write empty assignments.
- Never reveal actual values in the generated file.
- Preserve valid environment variable names.
- Handle an existing `.env.example` safely.
- Ask for confirmation before overwriting an existing file.
- Do not accidentally overwrite an actual `.env` file.
- Make the generated file suitable for Git commits.
- Do not add `.env.example` to `.gitignore`.

The snapshot should be generated from the project's vault metadata, not from an existing `.env` file.

This command should work without exposing the actual secret values to the terminal.

## **7. Execution modes**

env-host must support three execution modes.

| Mode     | Behaviour                                                                                                                                    |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Unsafe   | Runs directly on the host without additional isolation.                                                                                      |
| Standard | Restricts filesystem and network access. Secrets are injected through environment variables.                                                 |
| Secure   | Applies the same restrictions as Standard, but credentials remain inside env-host and are accessed through approved proxies or integrations. |

### **Unsafe mode**

Explicitly disables env-host's security enforcement. It exists for compatibility and convenience, not security.

### **Standard mode**

- Filesystem access is denied by default, except for explicitly permitted paths.
- Network access is denied by default, except for explicitly permitted destinations.
- Direct IP connections are denied by default unless explicitly allowed.
- The project's authorized secrets are injected as environment variables.
- Child processes must inherit the application's restrictions.
- Each application has its own identity, policy, and session.

### **Secure mode**

- Retains all Standard mode restrictions.
- Does not expose raw credentials to the application environment.
- Routes supported external service requests through env-host-managed proxies.
- Allows credentials to be injected into requests by trusted env-host components.
- Supports fine-grained permissions for individual service operations where possible.

Secure mode should not pretend to support every protocol or service transparently. Unsupported integrations must be clearly identified.

## **8. CLI experience**

The primary application execution syntax is:

```
envh --run npm run dev
```

Other modes:

```
envh --unsafe --run npm run dev
envh --secure --run npm run dev
```

Explicit project selection:

```
envh --project-id 2kvcndsvldn --run npm run dev
```

Project initialization:

```
envh init
envh init --env .env.example
```

Secret management:

```
envh manage
```

Snapshot generation:

```
envh snap
```

Other illustrative management commands:

```
envh ps
envh inspect 2kvcndsvldn
envh stop 2kvcndsvldn
```

The exact management command structure can be designed independently.

### **CLI rules**

- `--run` explicitly indicates application execution.
- `--unsafe`, `--secure`, and the default Standard mode determine the execution mode.
- `--project-id` explicitly selects a project.
- If no project ID is supplied, resolve it from `.h.env`.
- `init`, `manage`, and `snap` are independent commands.
- Configuration, initialization, secrets management, inspection, and other management operations must not require `--run`.
- The current working directory should be preserved as the application's working directory.

## **9. Transparent execution: critical UX requirement**

env-host must not feel like a wrapper around the developer's application.

When someone executes:

```
envh --run npm run dev
```

The terminal should show the application's output as if the developer had executed:

```
npm run dev
```

Requirements:

- No env-host startup banners.
- No unnecessary status messages.
- No decorative output.
- No repeated security notifications in application output.
- No log prefixes added to application stdout or stderr.
- Preserve the application's exit code.
- Preserve normal terminal interaction, including stdin, stdout, and stderr.
- Support interactive applications and terminal-based tools.
- Preserve sensible environment and working-directory behaviour.
- Handle Ctrl+C and process termination naturally.
- Avoid buffering that changes the application's normal output behaviour.
- Do not interfere with terminal colours, progress bars, or interactive prompts.

Security notifications and permission prompts must be handled separately from application stdout and stderr, using native notifications or an appropriate independent interface.

**The application owns the terminal output. env-host should not.**

## **10. Permissions and user interaction**

When an application attempts an operation that its policy does not permit, env-host should block it and request user approval where applicable.

For an unknown outbound network destination, provide exactly three choices:

1. **Allow this time:** Permit only the pending connection attempt.
2. **Allow for this session:** Permit the destination for the current application session.
3. **Stop application:** Terminate the application's tracked process tree and revoke its session.

Session permissions must expire when the application exits.

Approvals must be associated with the correct project identity and application session. One project's permissions must never affect another project's permissions.

env-host must fail closed if its enforcement mechanism or trusted daemon becomes unavailable. It must not silently allow restricted operations because a component has crashed.

## **11. Filesystem security**

Standard and Secure modes must provide OS-enforced filesystem restrictions.

Requirements:

- Explicitly allowlisted directories.
- Default-deny behaviour.
- Separate read, write, and execute permissions.
- Protection against path traversal and symlink escapes.
- Protection against access through child processes.
- Isolation of application-specific temporary directories.
- Sensible defaults for sensitive operating system locations.
- No reliance on simple string-prefix path checks as a security boundary.

The objective is to restrict what an application and its descendants can actually access, not merely what env-host's configuration says they can access.

## **12. Network security**

Network restrictions must be enforced at the operating-system level wherever supported, not just through DNS filtering or an application-level proxy.

Requirements:

- Default-deny outbound networking.
- Domain and port allowlists.
- Direct IP connections blocked by default.
- IPv4 and IPv6 support.
- Per-application connection attribution.
- Detection of unknown connection attempts.
- Temporary and session-level permission grants.
- Protection against common bypass techniques, including DNS-over-HTTPS, QUIC, proxy bypasses, and localhost forwarding.
- Session-specific network permissions.

The system must account for DNS resolution, shared CDN addresses, and DNS rebinding when enforcing domain-based policies.

A critical limitation must be documented: Standard mode exposes secrets as environment variables. A compromised dependency may read those secrets and send them to an already-authorized destination. Secure mode exists to reduce this risk by keeping raw credentials outside the application process.

## **13. Proxy ecosystem**

The proxy system is a core part of env-host, not an optional afterthought.

Developers should eventually be able to contribute integrations for services such as OpenAI, PostgreSQL, Redis, Stripe, and other external APIs.

There should be two types of proxies.

### **Declarative proxies**

A configuration-driven format for defining:

- Supported hosts and protocols.
- Credential injection.
- Allowed HTTP methods and paths.
- Request and response transformations.
- Header removal.
- Data redaction.
- Request blocking rules.

These should run inside a trusted built-in proxy engine without requiring arbitrary custom code.

### **Custom proxies**

Developers should be able to write custom integrations using Go.

Custom proxy code must run outside the privileged env-host daemon. It must communicate through a versioned, language-neutral interface and receive only explicitly granted capabilities.

A proxy must not automatically receive unrestricted access to the secrets vault or host network. Trusted env-host components should handle credential injection wherever possible.

The architecture should allow a future community ecosystem, package registry, and proxy installation workflow.

## **14. Architecture and implementation requirements**

**Go is the only accepted implementation language for the project.**

Use Go for:

- CLI and command handling.
- Background daemon.
- Policy engine.
- Application identity and session management.
- Process tracking.
- Filesystem and network orchestration.
- Secrets management.
- Proxy engine and orchestration.
- IPC.
- Audit logging.
- Notifications.

CGO is acceptable when required for operating-system integration or native functionality that cannot reasonably be accessed through pure Go.

Prefer Go's standard library. Any external Go package should have a clear technical justification, established maintenance history, and reviewed security implications.

Avoid unnecessary third-party dependencies, especially in privileged components.

The architecture should separate:

- CLI and developer-facing interfaces.
- Trusted background daemon.
- Application identity and session management.
- Policy evaluation.
- Filesystem enforcement.
- Network enforcement.
- Process tracking.
- Secrets management.
- Proxy execution and orchestration.
- Audit and notification systems.
- Platform-specific enforcement backends.

The daemon must manage multiple independent application sessions concurrently.

Keep the core modular, with clear interfaces between platform-specific implementations and shared Go logic.

## **15. Platform support**

macOS is the primary development and initial release target.

Linux and Windows should be supported through separate platform-specific enforcement implementations.

Do not assume that an enforcement mechanism available on one operating system is available on another.

A major early technical requirement is to establish whether macOS can reliably enforce filesystem and network restrictions for arbitrary application processes and their descendants without requiring VMs or mandatory containers.

Investigate the practical constraints of Apple's security frameworks, entitlements, signing, and distribution requirements before committing to the final enforcement architecture.

Cross-platform support must be validated through real operating-system tests, not just successful compilation.

## **16. Security and reliability expectations**

env-host is a security product. Security must be treated as a product requirement rather than a later enhancement.

The implementation must account for:

- Malicious dependencies.
- Application process spawning.
- Process identity inheritance.
- Symlink and filesystem traversal.
- File descriptor abuse.
- Direct network connections.
- DNS and proxy bypasses.
- Localhost forwarding.
- Daemon crashes.
- Permission escalation.
- Cross-project access.
- Session expiration.
- Proxy compromise.
- Vault authentication bypasses.
- Unauthorized secret access.
- Project ID loss.
- Sensitive data leakage through logs.

Create adversarial tests for these cases. Do not consider a feature complete simply because its normal use case works.

Document the threat model and clearly state what env-host can and cannot protect against. Avoid claiming complete protection against arbitrary malicious code running under the developer's user account.

## **17. Expected developer experience**

The intended workflow should be straightforward.

### **Initial setup**

```
cd my-project
envh init
```

This creates a project ID and `.h.env`.

### **Import existing environment variables**

```
envh init --env .env.example
```

This imports the predefined environment variables into the project's encrypted vault.

### **Secret management**

```
envh manage
```

The developer authenticates and can add, view, edit, delete, and manage project secrets.

### **Generate an environment template**

```
envh snap
```

This creates a `.env.example` containing secret names but no values.

### **Application execution**

```
envh --run npm run dev
```

env-host automatically identifies the project using `.h.env`, retrieves its configuration, applies the appropriate security policies, and starts the application.

### **Explicit project selection**

```
envh --project-id 2kvcndsvldn --run npm run dev
```

The security layer should operate in the background. Developers should interact with env-host primarily when initializing projects, managing secrets, configuring policies, inspecting sessions, or approving access.

The application should not need to know that env-host exists.

## **18. Long-term product direction**

env-host should evolve into a developer security platform with:

- A reliable local application isolation runtime.
- A central encrypted vault with project-specific namespaces.
- Unique project identities.
- Environment file importing.
- Environment template generation.
- Secure credential mediation.
- A community-driven proxy ecosystem.
- Cross-platform enforcement.
- Auditing and security visibility.
- A straightforward developer experience.

The architecture should leave room for these capabilities without implementing every feature in the first release.

## **19. Initial delivery priorities**

Prioritize the work in this order:

1. **Security feasibility:** Prove that the required macOS filesystem, network, and process restrictions are achievable.
2. **Threat model:** Define the attack surface, security boundaries, assumptions, and limitations.
3. **Vault design:** Define project ID handling, encryption, authentication, key derivation, and unrecoverability guarantees.
4. **Architecture:** Establish the daemon, CLI, session, identity, vault, and platform abstraction boundaries.
5. **Project identity:** Implement `envh init`, project ID generation, `.h.env` handling, and project registration.
6. **Environment import:** Implement `envh init --env` and safely import environment variables into the vault.
7. **Core runtime:** Build application registration, process tracking, IPC, and session management.
8. **Enforcement:** Implement and validate filesystem and network restrictions.
9. **Secrets management:** Implement `envh manage`, encrypted storage, authentication, project-specific secrets, and Standard mode injection.
10. **Snapshots:** Implement `envh snap` to generate `.env.example` files without secret values.
11. **Proxy framework:** Establish the extension contract and implement initial Secure mode integrations.
12. **Cross-platform support:** Develop and validate Linux and Windows backends.
13. **Ecosystem:** Add documentation, package distribution, verification, and community contribution workflows.

## **20. Implementation guidance for Codex**

This document defines the product requirements and desired technical outcomes. It does not prescribe every implementation detail.

Make architectural decisions independently, compare alternatives, and document trade-offs.

Follow these principles:

- Prioritize security correctness over implementation speed.
- Validate operating-system enforcement before building higher-level features around it.
- Keep the codebase modular and maintainable.
- Prefer standard Go functionality over unnecessary dependencies.
- Do not simulate security controls that the operating system cannot enforce.
- Do not claim a feature is secure without meaningful tests.
- Keep application execution transparent and native-feeling.
- Keep project metadata separate from secrets.
- Treat project IDs as critical project identifiers, not as standalone authentication credentials.
- Do not introduce global secrets or cross-project sharing.
- Require authentication for sensitive vault operations.
- Ensure losing a project ID has the explicitly documented unrecoverable consequences.
- Never expose secret values through `.h.env`, `.env.example`, logs, or ordinary CLI output.
- Maintain documentation alongside implementation.
- Build incrementally, with testable milestones.

**The first milestone should be a feasibility study covering macOS enforcement and the vault's cryptographic design.** Establish that the security boundaries and project-specific secret model are achievable before building the complete CLI.

A smaller runtime with verified isolation is more valuable than a feature-rich application that only simulates security.