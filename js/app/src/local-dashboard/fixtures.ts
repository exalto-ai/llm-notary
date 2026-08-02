import type {
  Capture, CaptureDetail, Event, LocalApi, Operation, PublicationAuth, Status, Trace, Verification
} from './api';

const hour = 60 * 60 * 1000;
const fixtureNow = Date.UTC(2026, 6, 28, 16, 42, 0);

export const fixtureCaptures: Capture[] = [
  {
    capture_id: 'cap-20260728-knowledge-eval', created_at_unix_ms: fixtureNow - hour * 2,
    completed_at_unix_ms: fixtureNow - hour * 2 + 1842, provider: 'openai', operation: '/v1/responses',
    requested_model: 'gpt-5.2', response_model: 'gpt-5.2', http_status: 200, streaming: true,
    request_bytes: 1842, response_bytes: 9421, duration_ms: 1842, capture_state: 'pending',
    finalization_state: 'not_requested', prompt_preview: 'Compare two sanitized evaluation strategies and identify the stronger evidence trail.',
    prompt_preview_truncated: false, output_preview: 'The second strategy preserves a clearer chain of independently checkable claims…',
    output_preview_truncated: true
  },
  {
    capture_id: 'cap-20260728-safety-review', created_at_unix_ms: fixtureNow - hour * 4,
    completed_at_unix_ms: fixtureNow - hour * 4 + 967, provider: 'anthropic', operation: '/v1/messages',
    requested_model: 'claude-sonnet-4-6', response_model: 'claude-sonnet-4-6', http_status: 200,
    streaming: false, request_bytes: 1210, response_bytes: 5110, duration_ms: 967,
    capture_state: 'pending', finalization_state: 'running', prompt_preview: 'Review a synthetic policy response for unsupported claims.',
    prompt_preview_truncated: false, output_preview: 'Three claims require either a citation or more qualified language.',
    output_preview_truncated: false
  },
  {
    capture_id: 'cap-20260727-research-brief', created_at_unix_ms: fixtureNow - hour * 18,
    completed_at_unix_ms: fixtureNow - hour * 18 + 2312, provider: 'openrouter', operation: '/api/v1/chat/completions',
    requested_model: 'openai/gpt-5-mini', response_model: 'openai/gpt-5-mini', http_status: 200,
    streaming: true, request_bytes: 2208, response_bytes: 14392, duration_ms: 2312,
    capture_state: 'pending', finalization_state: 'finalized', prompt_preview: 'Summarize the supplied public research notes into a concise brief.',
    prompt_preview_truncated: false, output_preview: 'The evidence supports three conclusions, each tied to a source in the supplied notes.',
    output_preview_truncated: false
  },
  {
    capture_id: 'cap-20260727-benchmark', created_at_unix_ms: fixtureNow - hour * 25,
    completed_at_unix_ms: fixtureNow - hour * 25 + 1400, provider: 'deepseek', operation: '/chat/completions',
    requested_model: 'deepseek-v4-flash', response_model: 'deepseek-v4-flash', http_status: 200,
    streaming: false, request_bytes: 3101, response_bytes: 8802, duration_ms: 1400,
    capture_state: 'pending', finalization_state: 'failed', prompt_preview: 'Run the deterministic benchmark fixture.',
    prompt_preview_truncated: false, output_preview: 'Benchmark fixture complete.', output_preview_truncated: false,
    failure_code: 'notary_capacity'
  },
  {
    capture_id: 'cap-20260728-active', created_at_unix_ms: fixtureNow - 42_000,
    provider: 'openai', operation: '/v1/responses', requested_model: 'gpt-5.2-mini', streaming: true,
    request_bytes: 720, capture_state: 'capturing', finalization_state: 'not_requested',
    prompt_preview: 'Create a sanitized fixture summary.', prompt_preview_truncated: false,
    output_preview: '', output_preview_truncated: false
  }
];

export const fixtureOperations: Operation[] = [
  {
    operation_id: 'op-finalize-safety-review', kind: 'finalization',
    capture_id: 'cap-20260728-safety-review', state: 'running', attempt: 1,
    created_at_unix_ms: fixtureNow - 112_000, started_at_unix_ms: fixtureNow - 108_000
  },
  {
    operation_id: 'op-finalize-benchmark', kind: 'finalization',
    capture_id: 'cap-20260727-benchmark', state: 'failed', attempt: 2,
    created_at_unix_ms: fixtureNow - hour, started_at_unix_ms: fixtureNow - hour + 2_000,
    completed_at_unix_ms: fixtureNow - hour + 18_000, failure_code: 'notary_capacity'
  },
  {
    operation_id: 'op-finalize-research-brief', kind: 'finalization',
    capture_id: 'cap-20260727-research-brief', state: 'finalized', attempt: 1,
    created_at_unix_ms: fixtureNow - hour * 17, started_at_unix_ms: fixtureNow - hour * 17 + 1_000,
    completed_at_unix_ms: fixtureNow - hour * 17 + 184_000
  }
];

export const fixtureEvents: Event[] = [
  { event_id: 14, created_at_unix_ms: fixtureNow - 28_000, event_type: 'finalization_started',
    capture_id: 'cap-20260728-safety-review', operation_id: 'op-finalize-safety-review',
    severity: 'info', message: 'Finalization started' },
  { event_id: 13, created_at_unix_ms: fixtureNow - hour, event_type: 'finalization_failed',
    capture_id: 'cap-20260727-benchmark', operation_id: 'op-finalize-benchmark',
    severity: 'error', message: 'Finalization failed' },
  { event_id: 12, created_at_unix_ms: fixtureNow - hour * 17, event_type: 'finalization_completed',
    capture_id: 'cap-20260727-research-brief', operation_id: 'op-finalize-research-brief',
    severity: 'success', message: 'Finalization completed' }
];

export const fixtureStatus: Status = {
  version: '0.1.0', proxy_listener: '127.0.0.1:8787', admin_listener: '127.0.0.1:8788',
  vault: 'OS vault', notary: 'directory', preview_chars: 1000,
  counts: { total_captures: 5, capturing: 1, pending: 4, finalized: 1, failed: 1, active_operations: 1 }
};

const fixtureTrace: Trace = {
  capture_id: 'cap-20260727-research-brief',
  manifest: {
    format: 'llm-notary/verified-trace-package/v1', normalizer_version: 'llm-notary/normalizer/v1',
    trace_sha256: '9a32d7c66a7e4fdd525ea6c803355273ade0f46e7c8dc4973343399731585b26',
    source: { provider: { name: 'openrouter', host: 'openrouter.ai' }, created_at_unix_ms: fixtureNow - hour * 18 }
  },
  trace: {
    resourceSpans: [{ scopeSpans: [{ spans: [{ name: 'gen_ai.inference', traceId: '31f90c419f264b70b09fb1baf4f567d0',
      attributes: [{ key: 'gen_ai.system', value: { stringValue: 'openrouter' } },
        { key: 'gen_ai.request.model', value: { stringValue: 'openai/gpt-5-mini' } }] }] }] }]
  }
};

const fixtureVerification: Verification = {
  capture_id: fixtureTrace.capture_id, verified: true, verified_at_unix_ms: fixtureNow,
  notary_key_id: 'sha256:3828b21f26c49a0ff546f6f4bcee6a64bdc685faf4a961b3c00d05814cda9801',
  trust_source: 'directory'
};

let captures = structuredClone(fixtureCaptures);
let operations = structuredClone(fixtureOperations);
let publicationAuth: PublicationAuth = { signed_in: false };

function detail(captureId: string): CaptureDetail {
  const capture = captures.find((item) => item.capture_id === captureId) ?? captures[0];
  return {
    capture,
    artifacts: [
      { kind: 'deferred_bundle', size_bytes: 189_442, sha256: '20e24d8f7e9c375e9bea72bb15b02e0d6a2e2a18023a5606799f001a84cff7b1' },
      ...(capture.finalization_state === 'finalized'
        ? [{ kind: 'finalized_package', size_bytes: 482_013, sha256: '9a32d7c66a7e4fdd525ea6c803355273ade0f46e7c8dc4973343399731585b26' }]
        : [])
    ]
  };
}

export function createFixtureApi(): LocalApi {
  captures = structuredClone(fixtureCaptures);
  operations = structuredClone(fixtureOperations);
  publicationAuth = { signed_in: false };
  return {
    session: async () => undefined,
    endSession: async () => undefined,
    status: async () => fixtureStatus,
    captures: async (filters = {}) => {
      const query = String(filters.query ?? '').toLowerCase();
      const state = String(filters.finalization_state ?? '');
      const provider = String(filters.provider ?? '');
      const items = captures.filter((capture) =>
        (!query || `${capture.prompt_preview} ${capture.output_preview} ${capture.requested_model}`.toLowerCase().includes(query))
        && (!state || capture.finalization_state === state)
        && (!provider || capture.provider === provider));
      return { items, limit: 50, offset: 0 };
    },
    capture: async (captureId) => detail(captureId),
    startFinalization: async (captureId) => {
      const existing = operations.find((operation) => operation.capture_id === captureId
        && ['queued', 'running', 'finalized'].includes(operation.state));
      if (existing) return { operation: existing, deduplicated: true };
      const operation: Operation = { operation_id: 'op-finalize-queued-fixture', kind: 'finalization',
        capture_id: captureId, state: 'queued', attempt: 0, created_at_unix_ms: fixtureNow };
      operations = [operation, ...operations];
      captures = captures.map((capture) => capture.capture_id === captureId
        ? { ...capture, finalization_state: 'queued' } : capture);
      return { operation, deduplicated: false };
    },
    operations: async () => ({ items: operations }),
    operation: async (operationId) => operations.find((item) => item.operation_id === operationId) ?? operations[0],
    retry: async (operationId) => {
      operations = operations.map((operation) => operation.operation_id === operationId
        ? { ...operation, state: 'queued', failure_code: null } : operation);
      return operations.find((operation) => operation.operation_id === operationId)!;
    },
    events: async () => ({ items: fixtureEvents, next_cursor: 14 }),
    trace: async () => fixtureTrace,
    verify: async () => fixtureVerification,
    publicationAuth: async () => publicationAuth,
    startPublicationAuth: async () => ({ request_id: 'auth-docs-fixture', user_code: 'NOTARY-7K3',
      verification_uri_complete: 'https://llm-notary.example/activate?code=NOTARY-7K3', expires_in_seconds: 600,
      poll_interval_seconds: 3, state: 'pending' }),
    pollPublicationAuth: async () => {
      publicationAuth = { signed_in: true, github_login: 'fixture-user', device_name: 'Local dashboard' };
      return publicationAuth;
    },
    publish: async (captureId) => ({ capture_id: captureId, job_id: 'pub-job-fixture', state: 'queued', status_url: '/library/jobs/pub-job-fixture' })
  };
}
