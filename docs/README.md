# LLM Notary documentation

LLM Notary has separate private product and public runtime documentation:

- This directory contains hosted-product and contributor references.
- [`runtime/docs`](../runtime/docs/README.md) contains public runtime guidance.
- The public site contains the shorter user journey and trust explanation.
- Running services expose generated OpenAPI contracts for exact HTTP schemas.

Use the generated contract when prose and an installed service disagree.

## Start here

| Goal | Guide |
| --- | --- |
| Install the guided macOS app | [Desktop app](desktop-app.md) |
| Install the CLI and local service | [Runtime getting started](../runtime/docs/getting-started.md) |
| Understand the runtime trust boundary | [Runtime architecture](../runtime/docs/architecture.md) |
| Connect an SDK or agent | [Runtime provider setup](../runtime/docs/provider-setup.md) |
| Understand `.llmcapture` and `.llmtrace` | [Runtime artifact formats](../runtime/docs/artifact-formats.md) |
| Operate the daemon or local REST API | [Runtime local service](../runtime/docs/local-service.md) |
| Run CI, cron, or unattended hosts | [API keys for automation](api-key-automation.md) |
| Install or brief a coding agent for safe local trace operations | [Runtime coding-agent playbook](../runtime/docs/agent-playbook.md) |

## Operators

| Goal | Guide |
| --- | --- |
| Run a local notary | [Runtime self-hosting](../runtime/docs/self-hosting.md) |
| Rotate or revoke notary keys | [Runtime notary key lifecycle](../runtime/docs/notary-key-lifecycle.md) |
| Operate PostgreSQL or Neon | [Database operations](database-operations.md) |
| Run clustered daemon replicas | [Runtime cluster operations](../runtime/docs/cluster-operations.md) |
| Deploy the production Fly.io stack | [Fly.io deployment](../deploy/fly/README.md) |
| Understand upload staging | [Share intake API v1](share-intake-v1.md) |
| Understand plans and usage | [Plans and usage](hosted-credits.md) |
| Understand admission and public storage | [Share admission v1](share-admission-v1.md) |

## Contributors

- [Development and validation](development.md)
- [Cursor-pagination contract and array inventory](adr/0001-cursor-pagination.md)
- [Provider-neutral account identities](adr/0002-provider-neutral-identities.md)
- [Design language](../DESIGN.md)
- [Provider icon assets and usage terms](provider-icons.md)
- [OpenCode production canary](../runtime/benchmarks/opencode-e2e/README.md)
- [Repository agent instructions](../AGENTS.md)
- [Contributing](../CONTRIBUTING.md)

## Generated API references

The local daemon serves OpenAPI 3.1 at
`http://127.0.0.1:8788/openapi.json`. Its committed copy is
`runtime/apps/local-dashboard/src/generated/openapi.json`.

The hosted API contract is committed at
`js/app/src/platform-api/generated/openapi.json`. Regenerate both through the
npm scripts described in [Development and validation](development.md).
