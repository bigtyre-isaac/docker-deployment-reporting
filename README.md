# Swarm Image Report

A stateless .NET 10 API that reads Docker Swarm service specifications and reports deployed image references, tags, and digests. It can aggregate other instances. Harbor vulnerability reporting is planned, but not implemented.

## Configuration

The [docker-compose.yml](docker-compose.yml) example below includes all application settings. Edit the image, Swarm name, issuer, and trusted peers; remove the peer entries for local-only reporting. It requires a Swarm manager and an existing internal overlay network shared with your API gateway.

```yaml
version: "3.8"
services:
  image-report:
    image: ${IMAGE_REPORT_IMAGE:-registry.example.com/example/image-report:1.0.0}
    environment:
      ASPNETCORE_HTTP_PORTS: "8080"
      Swarm__Name: ${SWARM_NAME:-production}
      Docker__Endpoint: unix:///var/run/docker.sock
      Docker__TimeoutSeconds: "30"
      Authentication__Issuer: ${JWT_ISSUER:-Example Authentication API}
      Secrets__Directory: /run/secrets
      Federation__TimeoutSeconds: "15"
      Federation__AllowHttp: "false"
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

**Secrets:** the standard key-per-file provider reads `Secrets__Directory` (default `/run/secrets`). Each filename is a configuration key, and its contents are the value. The mounted `Authentication__PublicKey` file overrides the matching JSON/environment/command-line setting. The directory is optional for local development; the JWT key remains required. Alternatively, supply the PEM through `Authentication__PublicKey` in the environment. Restart the service after changing secrets.

**JWTs:** supply an RSA public PEM of at least 2048 bits (`BEGIN PUBLIC KEY` or `BEGIN RSA PUBLIC KEY`), with real newlines. The API validates signature, issuer, and lifetime, and requires the `ImageReport.Read` role via `role`, `roles`, or the standard .NET role claim. Invalid/missing authentication configuration prevents startup. Audience validation is currently disabled because existing tokens have no `aud` claim.

Peers receive the caller's bearer token and independently validate it against the same issuer/key and role. Requests run concurrently, disable redirects, and use `includeFederated=false` to prevent recursion.

## API

### GET /api/images

Returns service images sorted by Swarm and service. `includeFederated` defaults to `true`; set it to `false` to report only the local Swarm.

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
      "digest": "sha256:abc123"
    }
  ],
  "errors": []
}
```

Original references are preserved; absent tags/digests are `null`, and no implicit `latest` is added. Services sharing an image remain separate entries.

HTTP 200 includes partial peer results with errors shaped as `{ "swarm": "factory", "message": "..." }`. Errors identify the configured peer; returned images retain the remote Swarm name. Local Docker unavailability returns 503, other Docker API failures 502, invalid query values 400, missing/invalid tokens 401, insufficient roles 403, and unexpected errors 500. Local collection failure stops federation.