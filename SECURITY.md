# Security Policy

## Reporting

Please report security vulnerabilities privately: use GitHub's private
vulnerability reporting on this repository. Do **not** open a public issue
for a security problem.

We aim to acknowledge reports within 3 business days and publish a fix
release promptly after a confirmed report.

## Scope

den executes coding-agent CLIs as child processes. The security boundary is:

- **In scope**: the HTTP API (`den serve`), bearer auth and key handling,
  process-group isolation and kill semantics, file access via the API,
  anything that lets one session or one key reach another's data.
- **Hardened, opt-in backend (not part of this distribution)**: the FUSE +
  namespace sandbox. If you need strong isolation between untrusted agents,
  run `den serve` with that backend — see docs/oss-launch.md.
- **Out of scope by design**: `den serve` executes the agent CLIs configured
  in profiles *as the user running it*. It is not a defense against a
  malicious agent that shares your user account; grant API tokens only to
  principals you trust.

## Key handling

- `DEN_API_TOKEN` is the deployment root token; `den serve` refuses to
  listen without it.
- Minted `dk_...` keys are stored only as SHA-256 hashes; raw keys are shown
  once at creation.
- All routes require bearer auth; foreign-owned sessions return 404.

## Supported versions

The latest tagged release and `develop` HEAD receive security fixes.
