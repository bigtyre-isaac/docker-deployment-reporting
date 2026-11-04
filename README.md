# Swarm Image Report

A stateless .NET 10 API that reads Docker Swarm service specifications, federates inventories from other Swarms, and enriches Harbor-hosted images with existing Trivy vulnerability counts.

The sign-in page is served from `wwwroot`. It sends credentials to the report backend, which exchanges them with the configured authentication service and keeps the returned JWT in an HttpOnly cookie.

The app serves its routes from `/`. When publishing it under a URL prefix, configure the reverse proxy to strip that prefix before forwarding requests to the container; the browser UI uses relative URLs so login, API calls, and redirects stay within the published prefix.

## Configuration

The [docker-compose.yml](docker-compose.yml) example below includes all application settings. Edit the image, Swarm name, issuer, and trusted peers; remove the peer entries for local-only reporting. It requires a Swarm manager, the listed external Swarm secrets, and an existing internal overlay network shared with your API gateway.

```yaml
version: "3.8"
services:
  image-report:
    image: ${IMAGE_REPORT_IMAGE:-registry.example.com/example/image-report:1.0.0}
    environment:
      ASPNETCORE_ENVIRONMENT: ${ASPNETCORE_ENVIRONMENT:-Production}
      ASPNETCORE_HTTP_PORTS: "8080"
      Swarm__Name: ${SWARM_NAME:-production}
      Docker__Endpoint: unix:///var/run/docker.sock
      Docker__TimeoutSeconds: "30"
      Authentication__Issuer: ${JWT_ISSUER:-Example Authentication API}
      Authentication__ApiBaseUrl: ${AUTH_API:-}
      Authentication__ApiTimeoutSeconds: "15"
      Secrets__Directory: /run/secrets
      Federation__TimeoutSeconds: "15"
      Federation__AllowHttp: "false"
      Harbor__BaseUrl: ${HARBOR_BASE_URL:-}
      Harbor__Username: ${HARBOR_USERNAME:-}
      Harbor__Password: ${HARBOR_PASSWORD:-}
      Harbor__TimeoutSeconds: "15"
      Harbor__AllowHttp: "false"
      # Edit these trusted peers, or remove all peer entries for local-only reporting.
      Federation__Peers__0__Name: factory
      Federation__Peers__0__BaseUrl: https://factory-reports.example.com
      Federation__Peers__1__Name: secondary
      Federation__Peers__1__BaseUrl: https://secondary-reports.example.com
      Logging__LogLevel__Default: Information
      Logging__LogLevel__Microsoft.AspNetCore: Warning
      AllowedHosts: "*"
    secrets:
      - source: jwt-public-key
        target: Authentication__PublicKey
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      - gateway
    deploy:
      replicas: 1
      placement:
        constraints:
          - node.role == manager
networks:
  gateway:
    external: true
    name: ${GATEWAY_NETWORK:-api-gateway}
secrets:
  jwt-public-key:
    external: true
    name: image-report-jwt-public-key
```

Settings use `__` for nesting. Defaults are in [appsettings.json](ImageReport/appsettings.json): Swarm name `local`, Docker timeout 30 seconds, peer timeout 15 seconds, and no peers. Timeouts must be positive. Peer URLs must be HTTPS origins without credentials, paths, queries, or fragments; permit HTTP only for trusted internal development with `Federation__AllowHttp=true`.

**Secrets:** create the external Swarm secret `image-report-jwt-public-key` before deploying (for example, in Portainer's Swarm secrets UI). Compose mounts it as `Authentication__PublicKey`. The standard key-per-file provider reads `Secrets__Directory` (default `/run/secrets`); each filename is a configuration key, and its contents are the value. Secret files override matching appsettings and environment configuration. Harbor's base URL and credentials are configured through the `HARBOR_BASE_URL`, `HARBOR_USERNAME`, and `HARBOR_PASSWORD` stack environment variables shown in Compose; provide credentials through your deployment platform's protected environment settings and never commit them. Restart/update the service after changing configuration.

**JWTs:** supply an RSA public PEM of at least 2048 bits (`BEGIN PUBLIC KEY` or `BEGIN RSA PUBLIC KEY`), with real newlines. The API validates signature, issuer, and lifetime, and requires the `ImageReport.Read` role via `role`, `roles`, or the standard .NET role claim. Invalid/missing authentication configuration prevents startup. Audience validation is currently disabled because existing tokens have no `aud` claim.

Peers receive the caller's bearer token and independently validate it against the same issuer/key and role. Requests run concurrently, disable redirects, and use `includeFederated=false` to prevent recursion.

**Authentication service:** configure `Authentication:ApiBaseUrl` in `appsettings.json` or through the `Authentication__ApiBaseUrl` container environment variable. The Compose example maps the `AUTH_API` stack variable to this setting; set `AUTH_API` in Portainer's stack environment or in the shell before `docker stack deploy`. No `.env` file is required. The value is the authentication service base URL, including any API path prefix and ending with `/` (for example, `http://host.docker.internal:44122/api/`). The service environment defaults to `Production`, where HTTPS is required. For local Docker Desktop development, set `ASPNETCORE_ENVIRONMENT=Development` in the environment used to deploy the stack; `http://host.docker.internal:<port>` is allowed only in Development. HTTP sends credentials without transport encryption and must not be used in deployment. The backend appends `auth/login` to the configured base URL and posts JSON containing `CredentialType: "BasicAuth"`, `Username`, and `Password`. The request timeout is configured by `Authentication:ApiTimeoutSeconds` (default 15). It reads the `__Host-BigTyreAuth` cookie from the response, validates the JWT signature, issuer, lifetime, and `ImageReport.Read` role, then sets its own Secure, HttpOnly, SameSite session cookie. The browser never receives the upstream token in JavaScript. The same JWT is accepted from a bearer header for existing API clients.

## API

### POST /auth/login

The browser sign-in form posts `{"username":"...","password":"..."}` to this same-origin endpoint. The backend forwards the credentials to the configured auth service. Successful login sets an HttpOnly cookie and returns `204`; rejected credentials return `401`, missing report role returns `403`, and upstream failures return `502`.

### POST /auth/logout

Deletes the browser session cookie and returns `204`. This endpoint is safe to call without an active session.

### GET /api/images

Returns service images sorted by Swarm and service. The browser report calls this endpoint with its same-origin HttpOnly session cookie; the JWT is not exposed to JavaScript. `includeFederated`, `includeVulnerabilities`, and `includeImageUpdates` default to `true`; set them to `false` to omit peer inventories, Harbor vulnerability lookups, or same-tag update checks, respectively. For Harbor project `dockerhub`, scan and tag lookups retry with `library/` prepended to the repository path only when the original lookup returns 404. The report shows specific reasons when vulnerability counts are unavailable, including Harbor authentication or access errors, HTTP errors, timeouts, connection failures, invalid reports, Harbor 404 responses, and unavailable digests.

The report table shows the image reference, update status, scan status, and (for scanned images) a severity distribution. It is client-side paginated with page sizes of 10, 20, 50 (default), and 100. Use the `Sort by` control to order services by vulnerability severity, highest count first; the severity badges are display-only. Refresh duration appears beside the last-updated time; hover it for total, server-wait, and browser-render timings. Server logs include separate Docker collection, federation, and Harbor enrichment durations. Update status compares the deployed digest with the current digest for the same explicit tag in Harbor: a changed digest shows `Update available`, while a matching digest shows `Up to date`. It does not search for newer version tags. Unknown means the tag, digest, or Harbor lookup was unavailable. A crossed-out lighthouse marks a local image whose registry does not match the configured Harbor registry; it does not change the separate update-status icon. Harbor 404 responses are reported as 404s; they do not prove an artifact or scan is absent because Harbor may also use 404 for inaccessible resources. The update icon's details popover distinguishes the deployed image-reference digest, local repository digest, and Harbor tag digest. The Harbor digest shows `Unavailable` when its tag lookup did not return a digest. Matching image-reference and local digests are identified beside the local digest. A source-error details icon next to the collection status shows which Swarm sources failed and why.

```sh
curl -H "Authorization: Bearer $TOKEN" \
  'https://reports.example.com/api/images?includeFederated=true'
```

```json
{
  "images": [
    {
      "swarm": "production",
      "service": "auth_api",
      "image": "registry.example.com/example/auth:1.2.3@sha256:abc123",
      "repository": "registry.example.com/example/auth",
      "tag": "1.2.3",
      "digest": "sha256:abc123",
      "localImageId": "sha256:def456",
      "localRepoDigest": "sha256:abc123",
      "harborRegistryMatched": true,
      "imageUpdate": {
        "status": "upToDate",
        "reason": null,
        "currentDigest": "sha256:abc123"
      },
      "vulnerabilities": {
        "status": "complete",
        "reason": null,
        "count": {
          "critical": 0,
          "high": 3,
          "medium": 12,
          "low": 8,
          "none": 1
        }
      }
    }
  ],
  "errors": []
}
```

Original references are preserved; absent tags/digests are `null`, and no implicit `latest` is added. Services sharing an image remain separate entries. `localImageId` and `localRepoDigest` are populated only when the image reference matches an image available on the local Docker daemon; they are `null` otherwise. The image ID identifies the local image configuration, while the repository digest identifies a registry manifest. Harbor lookups use the digest from the configured service image reference; a local image ID is not used as a Harbor digest. Update status and the current same-tag Harbor digest are grouped under `imageUpdate`; vulnerability status, reason, and severity counts are grouped under `vulnerabilities`. Vulnerability counts remain `null` when the scan is unavailable, rather than implying zero findings.

HTTP 200 includes partial peer results with errors shaped as `{ "swarm": "factory", "message": "..." }`. Errors identify the configured peer; returned images retain the remote Swarm name. Local Docker unavailability returns 503, other Docker API failures 502, invalid query values 400, missing/invalid tokens 401, insufficient roles 403, and unexpected errors 500. Local collection failure stops federation.

## Build and deploy

Build and push the image to a registry accessible to the Swarm:

```sh
docker build -t registry.example.com/example/image-report:1.0.0 .
docker push registry.example.com/example/image-report:1.0.0
```

Create the `image-report-jwt-public-key` Swarm secret, create the external overlay network configured by `GATEWAY_NETWORK`, set the stack environment variables described above, then deploy:

```sh
docker stack deploy -c docker-compose.yml image-report
```

The service is constrained to a Swarm manager and exposes container port 8080 on published port 8081. The mounted Docker socket grants the service control-plane access to the Docker daemon; restrict access to the report and its host.

Application request, login, Docker collection, federation, and Harbor progress logs are written to the container console (Docker stdout/stderr). For a stack named `image-report`, follow them with `docker service logs --follow image-report_image-report`. Logs include request paths and result counts, but not request bodies, passwords, cookies, or tokens.