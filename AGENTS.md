# LLM Notary agent guide

## Project map

- `src/lib.rs` contains the Proxy-TLS protocol, private capture format, and local verification.
- `src/cli/` implements the `llm-notary` local proxy and verifier; `src/bin/` contains the notary and website API binaries.
- `vendor/tlsn/` is a pinned, locally patched TLSNotary dependency. Treat it as third-party code; change it only when the protocol requires it and explain the patch.
- `js/app/` is the Vite/React SPA. Follow [`DESIGN.md`](DESIGN.md) for any UI work.
- `compose.yml`, `deploy/`, and `.github/workflows/` define the DigitalOcean/Cloudflare deployment.

## Non-negotiable trust boundaries

- The local proxy handles plaintext and credentials; the remote notary must not receive either. Never log or publish API-key values. A deferred `.llmbundle` necessarily retains an encrypted client checkpoint that can reconstruct the original request, including credentials, so treat it as the most sensitive local artifact and never write it without vault encryption.
- Keep the provider hostname allowlist explicit. The notary, not the local machine, resolves and opens the upstream provider connection.
- A capture is private evidence. Its artifacts, hashes, selective-disclosure behavior, save/load logic, and verifier must evolve together.
- Public artifacts must remain independently verifiable and must not silently claim cryptographic guarantees the implementation does not provide.

## Validate changes

Run the checks relevant to edited code before handing work off:

```bash
cargo fmt --check
cargo test --all-targets
npm --prefix js/app run build
```

For Compose or deployment changes, also validate `docker compose config --quiet` with placeholder required variables. Do not put real keys, tunnel tokens, signing keys, captures, or `.env` files in Git.

## Working conventions

- Keep ordinary tests deterministic and offline. Real-provider and large proof profiles are explicit opt-in checks.
- Preserve HTTP/1.1 and streaming behavior unless intentionally expanding the documented prototype scope.
- The Cloudflare tunnel targets the stable `web` gateway. Do not rename or routinely recreate that service; replaceable SPA/API containers belong behind it.
- Prefer small, task-focused diffs. Update README or docs when CLI behavior, capture artifacts, trust assumptions, or deployment steps change.
