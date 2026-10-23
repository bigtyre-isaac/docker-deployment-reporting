# Working on this repository

## Scope and architecture

- Keep this a small, stateless .NET 10 ASP.NET Core Minimal API using Docker.DotNet and built-in configuration, DI, HTTP clients, logging, and JWT authentication.
- Keep Docker collection separate from federation and keep business logic out of endpoint handlers. Public DTOs must not expose Docker.DotNet models.
- Avoid speculative abstractions, unnecessary interfaces, background jobs, persistence, or Harbor/report-generation placeholders. Implement only the requested functionality.
- Preserve original image references and explicit tags/digests. Swarm service specifications remain authoritative for deployments.

## Readability preferences

- Prioritize readable code over compact code, especially in `Program.cs`. Use `var services = builder.Services` instead of repeating `builder.Services`.
- Separate logical sections with blank lines. Add short comments where they explain purpose, constraints, or non-obvious behavior; avoid narrating obvious statements.
- Keep fluent calls compact when they fit comfortably. Break long arguments and conditions across lines when that makes them easier to follow.
- Use descriptive names and local variables to simplify dense expressions. Avoid nested object creation and long chains when a named intermediate value reads better.
- Prefer `var` where appropriate, early returns, braces for every control-flow block, file-scoped namespaces, and async APIs with cancellation propagated.
- Give all classes, records, interfaces, and methods meaningful XML documentation. Use multiline summary blocks:

  ```csharp
  /// <summary>
  /// Explains responsibility or behavior.
  /// </summary>
  ```

- Document public properties when their meaning is not obvious. Preserve user edits and established formatting instead of reformatting unrelated code.

## Configuration and security

- Keep committed examples generic, using reserved example domains such as `example.com`. Do not add company-specific infrastructure details, credentials, real tokens, or key files. Keep local deployment secrets out of Git and the Docker build context; only commit sanitized environment templates.
- Use standard ASP.NET Core configuration. Key-per-file settings are loaded from `Secrets:Directory` (default `/run/secrets`) before JWT validation and override matching existing configuration keys. Filenames use `__` for nesting.
- Validate JWTs with the issuer's RSA public key; never require a private key or implement token issuance. Missing/invalid authentication configuration must fail closed.
- Retain the `ImageReport.Read` role policy and existing role-claim compatibility. Audience validation is intentionally disabled for existing tokens; keep that limitation documented.
- Forward bearer tokens only to configured trusted peers. Keep redirects disabled, require HTTPS unless explicitly allowed for development, prevent recursive federation, and never log JWT values.
- Retain manager-only Swarm placement, no published host ports, and the Docker socket privilege warning. Use a Swarm secret for the JWT public key in deployment examples.

## Documentation and verification

- Keep the README brief and practical: overview, configuration first, succinct API details with one subheading per endpoint/action, then minimum build/deployment instructions.
- Include a concrete Compose example with application settings in `environment` and the JWT public key mounted as a Swarm secret. Keep it synchronized with `docker-compose.yml` and implemented defaults.
- Use a small number of useful MSTest tests without live Docker or federation dependencies. Do not add elaborate mocking infrastructure or tests that merely mirror formatting changes.
- Run `dotnet test --solution ImageReport.sln` for behavior changes and validate Compose when deployment configuration changes.
- In this Windows sandbox, MSBuild worker processes and the test host can fail to connect. A working fallback is `dotnet build ImageReport.sln --no-restore -m:1 -nr:false -p:UseSharedCompilation=false`, followed by `dotnet ImageReport.Tests/bin/Debug/net10.0/ImageReport.Tests.dll --progress off --timeout 45s`. Set `DOTNET_CLI_HOME` to a writable directory when needed. Do not claim live Swarm or container verification unless performed.
