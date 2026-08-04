# LLM Notary agent guide

## Project map

- `crates/llm-notary-core/` contains the Proxy-TLS protocol, bundle/package and public-trace contracts, normalization, trust-directory logic, and verification.
- `crates/llm-notary-client/` implements the `llm-notaryd` local proxy/API daemon and the REST-backed `llm-notary` client. `crates/llm-notary-server/` and `crates/llm-notary-platform/` own the remote notary and hosted API binaries.
- `vendor/tlsn/` is a pinned, locally patched TLSNotary dependency. Treat it as third-party code; change it only when the protocol requires it and explain the patch.
- `js/app/` is the Vite/React SPA. Follow [`DESIGN.md`](DESIGN.md) for any UI work.
- `docs/README.md` indexes user, operator, and contributor documentation. `compose.yml`, `deploy/`, and `.github/workflows/` define the container configuration and Fly.io deployment.

## Non-negotiable trust boundaries

- The local proxy handles plaintext and credentials; the remote notary must not receive either. Never log or publish API-key values. A deferred `.llmcapture` necessarily retains an encrypted client checkpoint that can reconstruct the original request, including credentials, so treat it as the most sensitive local artifact and never write it without vault encryption.
- Keep the provider hostname allowlist explicit. The notary, not the local machine, resolves and opens the upstream provider connection.
- A capture is private evidence. Its artifacts, hashes, selective-disclosure behavior, save/load logic, and verifier must evolve together.
- Public artifacts must remain independently verifiable and must not silently claim cryptographic guarantees the implementation does not provide.

## Validate changes

Run the checks relevant to edited code before handing work off:

```bash
cargo fmt --check
cargo test -p llm-notary-core -p llm-notary-client -p llm-notary-server -p llm-notary-platform --all-targets --all-features
npm --prefix js/app run build
npm --prefix js/app run check:local-docs
```

For Compose or deployment changes, also validate `docker compose config --quiet` with placeholder required variables. Do not put real keys, tunnel tokens, signing keys, captures, or `.env` files in Git.

## Stacked pull requests

Use `gh stack` for two or more dependent PRs; use a normal PR for an independent change. Keep stacks linear, ordered from foundational changes at the bottom to dependent changes at the top. Use separate stacks for parallel work.

Before the first stack, install the extension with `gh extension install github/gh-stack` if `gh stack` is unavailable, then configure non-interactive operation:

```bash
git config rerere.enabled true
git config remote.pushDefault origin
```

Use `codex/` branch names and standard `git add`/`git commit` so every layer is deliberate:

```bash
gh stack init codex/<bottom-branch>
gh stack add codex/<next-branch>
gh stack submit --auto          # creates draft PRs
gh stack submit --auto --open   # marks the stack ready for review
gh stack view --json
```

- All agent commands must be non-interactive: give `init`, `add`, and `checkout` a branch or PR argument; use `submit --auto`, `view --json`, and `merge --yes`.
- Put fixes on the layer where they belong. After changing a lower layer, run `gh stack rebase --upstack`, then `gh stack push`; use `gh stack sync` after trunk or remote stack changes.
- After approval and green checks, merge with `gh stack merge --yes --squash`, not `gh pr merge`. Then run `gh stack sync --prune`.
- On a rebase conflict, resolve and stage the files, then run `gh stack rebase --continue`; use `gh stack rebase --abort` if the stack cannot be resolved safely.

## Working conventions

- Keep ordinary tests deterministic and offline. Real-provider and large proof profiles are explicit opt-in checks.
- Preserve HTTP/1.1 and streaming behavior unless intentionally expanding the documented prototype scope.
- The Cloudflare tunnel targets the stable `web` gateway. Do not rename or routinely recreate that service; replaceable SPA/API containers belong behind it.
- Treat generated OpenAPI as the exact HTTP contract. Regenerate clients and update every affected guide when a route, status, field, or authentication rule changes.
- Keep `README.md` short; put task and reference depth under `docs/`, and keep public-site copy and `js/app/public/llms.txt` aligned with the same trust boundaries.
- Prefer small, task-focused diffs. Update README or docs when CLI behavior, capture artifacts, trust assumptions, or deployment steps change.
