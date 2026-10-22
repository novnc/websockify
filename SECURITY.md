# Security Policy

## Supported versions

Security fixes are applied to the latest release of websockify.

## Reporting a vulnerability

Please report vulnerabilities via GitHub Security Advisories on this repository.
Do not open a public issue for unfixed security problems.

## Deployment notes

websockify is a TCP proxy. Treat it as an application-level bridge, not as an
internet-facing edge:

- Terminate TLS on a reverse proxy when possible, or use `--ssl-only` with
  `--ssl-version tlsv1_2` or `tlsv1_3`.
- Require `--auth-plugin` (and `--web-auth` if `--web` is enabled).
- Prefer signed JWS tokens (`JWTTokenApi`); encrypted JWE tokens are rejected.
- Use `--allowed-targets` to restrict token-resolved backends.
- Use `--max-connections` to cap concurrent handler processes.
- Store Basic-auth and Redis secrets in files (`@/path/to/secret`) rather than
  on the command line.
