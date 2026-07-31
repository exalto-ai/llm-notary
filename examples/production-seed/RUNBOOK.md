# Production examples runbook

This directory records the inaugural production run for issue #43.
Each production job must reach `admitted` and its downloaded trace/stamp pair
must pass independent verification. The Library generates its non-evidentiary
title and tags from the admitted public trace; do not maintain an editorial
allowlist in source control.

## Preconditions

- Use an optimized `llm-notary` binary built from the deployed commit. Before
  a public CLI launch, repeat the workflow with the packaged release and clean
  installer.
- Sign in through the production site as the project-controlled `exalto-ai`
  account with `llm-notary login`.
- Supply provider credentials only through their documented environment
  variables. Never place values in commands, fixtures, logs, or this tree.
- Copy each fixture into a new temporary directory outside any personal or
  proprietary repository. Initialize synthetic Git metadata if an agent
  requires a repository.
- Record the CLI commit, model identifier, provider, invocation, bundle ID,
  finalization duration, publication job ID, and public URLs in `RUN_REPORT.md`.

## Execution order

1. Run one proxy per provider and point only the intended tool or direct SDK at
   it. Use a new empty bundle directory for this controlled run.
2. Execute the ten definitions in `tasks.json`. Agent tasks must operate only
   on copied fixture directories.
3. List bundles and select the provider calls that make each task
   understandable. Do not publish incidental setup or retry calls.
4. Finalize each selected bundle into a new package directory:

   ```text
   llm-notary finalize BUNDLE.llmbundle --output FINALIZED_DIRECTORY
   ```

5. Inspect the request, response, manifest, and normalized trace manually.
   Then run:

   ```text
   ./scan-publication.sh FINALIZED_DIRECTORY
   ```

6. Publish only after both reviews pass:

   ```text
   llm-notary publish FINALIZED_DIRECTORY --json
   ```

7. Poll the returned authenticated job URL until it is `admitted`. Download
   its `trace_url` and `stamp_url`; do not copy artifacts directly from the
   server database or Space.
8. Fetch `/api/platform`, then independently verify the downloaded pair:

   ```text
   llm-notary verify-public trace.otlp.json stamp.json \
     --trusted-platform-key PLATFORM_PUBLIC_KEY
   ```

9. Confirm the public Library has generated a title and controlled tags for the
   admitted trace. These are discoverability metadata, not evidence claims.
10. Repeat the disclosure scan on every downloaded pair and complete the
    manual checklist in `RUN_REPORT.md`.

## Direct API tool round trips

A tool example is two provider calls: the first model response requests a
named synthetic tool; the second request returns a synthetic result with the
same provider call ID and asks for final text. Capture and publish both calls
when both are required to make the workflow intelligible. Do not claim that
the trace proves a local tool executed—the authenticated facts are the
model-issued call and the later client-supplied result.

## Library metadata

Provider, model, author, date, span count, tool use, stamp, and download links
are derived from admitted artifacts. The server uses the configured metadata
model to create a short factual title and up to four controlled tags. Metadata
generation never changes admission and falls back to a deterministic title if
the model is unavailable.
