# Production examples execution report

Status: **production run complete with a local release-mode CLI**.

CLI version: `llm-notary 0.1.0`, built with `cargo build --release` from the
deployed source commit. GitHub release packaging and clean installation remain
separate distribution checks.

Source commit: `dbc6d26dde184280c15b6b917db96b6ef863316a`

Production deploy: GitHub Actions run `30463481771`

Platform key ID:
`sha256:125a8fe1427269ffc44e1ba8f02dadadd54c29011263cb7995e338605765fdf6`

Notary key ID:
`sha256:c832d665e9dbd9e17c7669ec4a8c9db401e35ec930df15f076cef9b2b6e57eff`

Publishing account: `exalto-ai`

## Per-task results

| Task | Model | Selected captures | Finalize | Admitted publications |
| --- | --- | --- | --- | --- |
| `openai-api-structured-extraction` | `gpt-4.1-mini` / `gpt-4.1-mini-2025-04-14` | `cap-1785346917580-0001` | 4s | `4a20ff1e-13fa-47a1-a820-7258fe73cc68` |
| `openai-api-tool-roundtrip` | `gpt-4.1-mini` / `gpt-4.1-mini-2025-04-14` | `cap-1785347012848-0002`, `cap-1785347057458-0003` | 3s, 3s | `b3d3987b-5b5a-43cf-9a0f-41f190ab6a37`, `eb34018a-df0d-47a9-88ae-7aa380963d60` |
| `anthropic-api-safety-summary` | `claude-haiku-4-5-20251001` | `cap-1785346917593-0001` | 2s | `da0e09c1-7fb8-4009-85f1-6af789b2eaca` |
| `anthropic-api-tool-roundtrip` | `claude-haiku-4-5-20251001` | `cap-1785347029411-0003`, `cap-1785347072785-0004` | 2s, 2s | `bbd25886-c967-4f23-bea3-9a98faf81da9`, `31b59b77-35de-4738-80e9-e0fdedab07a2` |
| `deepseek-api-classification` | `deepseek-chat` / `deepseek-v4-flash` | `cap-1785346990847-0003` | 4s | `657b3834-59ac-48f0-bd1e-31f31c57ac26` |
| `deepseek-api-tool-roundtrip` | `deepseek-chat` / `deepseek-v4-flash` | `cap-1785347012862-0004`, `cap-1785347085011-0005` | 3s, 3s | `795b6090-6722-40b5-b855-4eee0c38c0c4`, `52c538f5-2d75-4f7c-821c-e9b3cc3a23e5` |
| `codex-cli-calculator` | `gpt-5.4-mini` / `gpt-5.4-mini-2026-03-17` | `cap-1785348040625-0001`, `cap-1785348068509-0010` | 25s, 31s | `1256bea5-8b49-4e9c-8569-00e453a299ac`, `3b53e254-ea10-4693-bb13-3cb2097d524a` |
| `codex-cli-classifier` | `gpt-5.4-mini` / `gpt-5.4-mini-2026-03-17` | `cap-1785348149261-0001`, `cap-1785348165804-0005` | 23s, 24s | `3d3d727f-e0b1-432e-be3c-0b2e3ead35d1`, `9baf1a88-c3fe-45fa-ac6b-a0f1c3a8404e` |
| `claude-code-parser` | `claude-haiku-4-5-20251001` | `cap-1785347504638-0002`, `cap-1785347529078-0010` | 4s, 7s | `e492ddf8-23ee-47cb-a140-1ba2800eddfb`, `007c038e-ef73-46fa-b5f3-ccd1e893372d` |
| `claude-code-evaluation` | `claude-haiku-4-5-20251001` | `cap-1785347574089-0002`, `cap-1785347587728-0005` | 5s, 5s | `641c3bf9-fbf0-461d-8ccd-1b5a0d0ca826`, `30ddb59a-f334-4e12-8cd9-d7b01316e5dd` |

All requests streamed. The three direct tool scenarios contain a
provider-authenticated tool request followed by a later request carrying the
matching synthetic result ID. The Codex and Claude Code examples publish the
initial tool-oriented call and the final call containing accumulated tool
results and final model output; they do not claim that local tool execution is
provider-authenticated.

Every selected finalized package passed `llm-notary verify-trace`, the
automated disclosure scanner, and manual task-content review. Every admitted
trace/stamp pair was downloaded through its public API URL, passed
`llm-notary verify-public` against the production platform key, matched the
local `trace.otlp.json` byte-for-byte, and passed the disclosure scanner again.

## Run notes

- The original fixtures used pytest-style functions without declaring pytest.
  They were converted to standard-library `unittest` before the clean runs.
- A first Codex attempt used `gpt-4.1-mini`, which repeatedly attempted an
  unavailable patch tool and was discarded.
- Host-run Codex traces correctly captured the complete system context, which
  included local `/Users/...` skill paths. They were rejected by the disclosure
  scan and never published.
- Codex was rerun in an ephemeral Linux container rooted at synthetic
  `/workspace`; those packages passed the same scanner and manual review.
- One concurrent Anthropic request received a transient 502 during capture and
  was retried. One duplicate DeepSeek classification capture was excluded.
- The scanner originally matched uppercase `sK-` inside encrypted reasoning as
  though it were a lowercase OpenAI API key prefix. Header scans remain
  case-insensitive, while the actual `sk-` prefix is now checked
  case-sensitively.
- Release-mode finalization was 2–7 seconds for the selected direct and Claude
  Code calls and 23–31 seconds for the selected 237–302 KB Codex calls.

## Final checklist

- [x] Seventeen admitted publications cover all five requested surfaces.
- [x] All artifacts passed independent local release-mode CLI verification.
- [x] No credential, cookie, token, personal path, email address, or unrelated
      session identifier was disclosed.
- [x] Provider/model/tool ordering/system context/usage fields were reviewed.
- [x] `publications.json` contains only admitted production IDs.
- [ ] The production collection contains these IDs after this manifest deploy.
- [x] Every current public trace and stamp download link was checked.
- [ ] A packaged GitHub release and clean installer verification are complete.
