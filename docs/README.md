# LLM Notary documentation

LLM Notary has three documentation surfaces:

- This directory contains the source and operator reference.
- The public site contains the shorter user journey and trust explanation.
- Running services expose generated OpenAPI contracts for exact HTTP schemas.

Use the generated contract when prose and an installed service disagree.

## Start here

| Goal | Guide |
| --- | --- |
| Build and run the local service | [Getting started](getting-started.md) |
| Understand the proof and trust assumptions | [Architecture and trust model](architecture.md) |
| Connect an SDK or agent | [Provider and agent setup](provider-setup.md) |
| Understand `.llmbundle`, `.llmtrace`, and public traces | [Artifact formats and verification](artifact-formats.md) |
| Operate the daemon, CLI, or local REST API | [Local service and REST API](local-service.md) |
| Use the visual local workflow | [Local dashboard](local-dashboard.md) |
| Run CI, cron, or unattended hosts | [API keys for automation](api-key-automation.md) |
| Give a coding agent safe API instructions | [Coding-agent playbook](agent-playbook.md) |

## Operators

| Goal | Guide |
| --- | --- |
| Run a local notary or full hosted stack | [Self-hosting](self-hosting.md) |
| Rotate or revoke notary keys | [Notary key lifecycle](notary-key-lifecycle.md) |
| Operate PostgreSQL or Neon | [Database operations](database-operations.md) |
| Deploy the production Fly.io stack | [Fly.io deployment](../deploy/fly/README.md) |
| Understand upload staging | [Publication intake API v1](publish-intake-v1.md) |
| Understand admission and public storage | [Publication admission v1](publication-admission-v1.md) |

## Contributors

- [Development and validation](development.md)
- [Design language](../DESIGN.md)
- [Repository agent instructions](../AGENTS.md)
- [Contributing](../CONTRIBUTING.md)

## Generated API references

The local daemon serves OpenAPI 3.1 at
`http://127.0.0.1:8788/openapi.json`. Its committed copy is
`js/app/src/local-dashboard/generated/openapi.json`.

The hosted API contract is committed at
`js/app/src/platform-api/generated/openapi.json`. Regenerate both through the
npm scripts described in [Development and validation](development.md).
