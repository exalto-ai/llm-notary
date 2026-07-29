# Direct API invocation templates

Run each provider proxy with a separate bundle directory:

```sh
llm-notary proxy start --provider openai --listen 127.0.0.1:8787 --bundle-dir bundles/openai
llm-notary proxy start --provider anthropic --listen 127.0.0.1:8788 --bundle-dir bundles/anthropic
llm-notary proxy start --provider deepseek --listen 127.0.0.1:8789 --bundle-dir bundles/deepseek
```

Use model names through `OPENAI_EXAMPLE_MODEL`, `ANTHROPIC_EXAMPLE_MODEL`, and
`DEEPSEEK_EXAMPLE_MODEL` so the report records the exact production choice.
Credentials appear only in provider-standard environment variables.

## OpenAI Responses

```sh
curl --no-buffer http://127.0.0.1:8787/v1/responses \
  -H "authorization: Bearer $OPENAI_API_KEY" \
  -H "content-type: application/json" \
  -d '{"model":"'"$OPENAI_EXAMPLE_MODEL"'","stream":true,"input":"Extract the synthetic incident service, severity, start time, and region as JSON: Checkout latency rose in us-west at 14:05 UTC. Customer impact was moderate."}'
```

For the tool task, add a `lookup_weather` function with one required string
argument. Save the returned call ID outside the repository, then make a second
streamed Responses request whose input contains the matching
`function_call_output` with the synthetic value
`{"temperature_c":18,"condition":"clear"}`.

## Anthropic Messages

```sh
curl --no-buffer http://127.0.0.1:8788/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"'"$ANTHROPIC_EXAMPLE_MODEL"'","max_tokens":256,"stream":true,"messages":[{"role":"user","content":"Summarize this benign synthetic policy test in two bullets: the assistant refused a request for credentials and suggested account recovery documentation."}]}'
```

For tool use, declare `catalog_search` with a required `item_id`. Return the
model's exact tool-use ID in a later user `tool_result` block containing the
synthetic result `{"item_id":"NB-42","available":true}`.

## DeepSeek Chat Completions

```sh
curl --no-buffer http://127.0.0.1:8789/chat/completions \
  -H "authorization: Bearer $DEEPSEEK_API_KEY" \
  -H "content-type: application/json" \
  -d '{"model":"'"$DEEPSEEK_EXAMPLE_MODEL"'","stream":true,"messages":[{"role":"user","content":"Classify as bug, question, or feature request and return JSON: A) Export fails on empty input. B) Does export support CSV? C) Please add Parquet."}]}'
```

For tool use, declare `synthetic_inventory` with a required `item_id`. Return
the model's exact tool-call ID in a later `tool` message containing
`{"item_id":"DS-7","stock":12}`.

Tool schemas and follow-up requests must be saved in the execution report with
credential values omitted. Model-generated IDs belong in the authenticated
trace; local shell history and temporary response files do not belong in the
repository.
