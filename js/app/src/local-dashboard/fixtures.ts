import { LocalApiError } from './api';
import type {
  AccountConnection, Capture, CaptureDetail, Event, LocalApi, Notaries, Operation,
  ShareVisibility, Status, Trace, Verification
} from './api';

const hour = 60 * 60 * 1000;
const fixtureNow = Date.UTC(2026, 6, 28, 16, 42, 0);

const proofProgress = (
  bytesCompleted: number,
  bytesTotal: number,
  commitmentsCompleted: number,
  commitmentsTotal: number,
  updatedAt: number
) => ({
  phase: 'proving', updated_at_unix_ms: updatedAt,
  proof: {
    bytes_completed: bytesCompleted, bytes_total: bytesTotal,
    commitments_completed: commitmentsCompleted, commitments_total: commitmentsTotal
  }
});

export const fixtureCaptures: Capture[] = [
  {
    capture_id: 'cap-20260728-knowledge-eval', created_at_unix_ms: fixtureNow - hour * 2,
    completed_at_unix_ms: fixtureNow - hour * 2 + 1842, provider: 'openai', operation: '/v1/responses',
    requested_model: 'gpt-5.2', response_model: 'gpt-5.2', http_status: 200, streaming: true,
    request_bytes: 1842, response_bytes: 9421, duration_ms: 1842, capture_state: 'captured',
    finalization_state: 'not_requested', finalization_eligible: true,
    prompt_preview: 'Compare two sanitized evaluation strategies and identify the stronger evidence trail.',
    prompt_preview_truncated: false, output_preview: 'The second strategy preserves a clearer chain of independently checkable claims…',
    output_preview_truncated: true
  },
  {
    capture_id: 'cap-20260728-safety-review', created_at_unix_ms: fixtureNow - hour * 4,
    completed_at_unix_ms: fixtureNow - hour * 4 + 967, provider: 'anthropic', operation: '/v1/messages',
    requested_model: 'claude-sonnet-4-6', response_model: 'claude-sonnet-4-6', http_status: 200,
    streaming: false, request_bytes: 1210, response_bytes: 5110, duration_ms: 967,
    capture_state: 'captured', finalization_state: 'running', finalization_eligible: true,
    prompt_preview: 'Review a synthetic policy response for unsupported claims.',
    prompt_preview_truncated: false, output_preview: 'Three claims require either a citation or more qualified language.',
    output_preview_truncated: false
  },
  {
    capture_id: 'cap-20260727-research-brief', created_at_unix_ms: fixtureNow - hour * 18,
    completed_at_unix_ms: fixtureNow - hour * 18 + 2312, provider: 'openrouter', operation: '/api/v1/chat/completions',
    requested_model: 'openai/gpt-5-mini', response_model: 'openai/gpt-5-mini', http_status: 200,
    streaming: true, request_bytes: 2208, response_bytes: 14392, duration_ms: 2312,
    capture_state: 'captured', finalization_state: 'finalized', finalization_eligible: true,
    prompt_preview: 'Choose a reproducibility baseline from two sanitized evaluation runs and explain the limits of the evidence.',
    prompt_preview_truncated: false, output_preview: 'Use Run 15 as the baseline; its settings were recorded and all 20 reruns matched.',
    output_preview_truncated: false
  },
  {
    capture_id: 'cap-20260726-direct-link', created_at_unix_ms: fixtureNow - hour * 31,
    completed_at_unix_ms: fixtureNow - hour * 31 + 1288, provider: 'anthropic', operation: '/v1/messages',
    requested_model: 'claude-sonnet-4-6', response_model: 'claude-sonnet-4-6', http_status: 200,
    streaming: false, request_bytes: 1540, response_bytes: 7290, duration_ms: 1288,
    capture_state: 'captured', finalization_state: 'finalized', finalization_eligible: true,
    prompt_preview: 'Check whether the direct-link fixture keeps its provider and model identity.',
    prompt_preview_truncated: false,
    output_preview: 'The fixture identity remains Anthropic / claude-sonnet-4-6 in every view.',
    output_preview_truncated: false
  },
  {
    capture_id: 'cap-20260727-benchmark', created_at_unix_ms: fixtureNow - hour * 25,
    completed_at_unix_ms: fixtureNow - hour * 25 + 1400, provider: 'deepseek', operation: '/chat/completions',
    requested_model: 'deepseek-v4-flash', response_model: 'deepseek-v4-flash', http_status: 200,
    streaming: false, request_bytes: 3101, response_bytes: 8802, duration_ms: 1400,
    capture_state: 'captured', finalization_state: 'failed', finalization_eligible: true,
    prompt_preview: 'Run the deterministic benchmark fixture.',
    prompt_preview_truncated: false, output_preview: 'Benchmark fixture complete.', output_preview_truncated: false,
    failure_code: 'notary_capacity'
  },
  {
    capture_id: 'cap-20260728-auth-error', created_at_unix_ms: fixtureNow - hour * 6,
    completed_at_unix_ms: fixtureNow - hour * 6 + 412, provider: 'openai', operation: '/v1/responses',
    requested_model: 'gpt-5.2', response_model: null, http_status: 401, streaming: true,
    request_bytes: 988, response_bytes: 214, duration_ms: 412, capture_state: 'captured',
    finalization_state: 'not_requested', finalization_eligible: false,
    finalization_ineligibility_code: 'unsupported_provider_http_status',
    prompt_preview: 'Summarize the sanitized authentication-error fixture.', prompt_preview_truncated: false,
    output_preview: '', output_preview_truncated: false
  },
  {
    capture_id: 'cap-20260728-active', created_at_unix_ms: fixtureNow - 42_000,
    provider: 'openai', operation: '/v1/responses', requested_model: 'gpt-5.2-mini', streaming: true,
    request_bytes: 720, capture_state: 'capturing', finalization_state: 'not_requested', finalization_eligible: false,
    prompt_preview: 'Create a sanitized fixture summary.', prompt_preview_truncated: false,
    output_preview: '', output_preview_truncated: false
  }
];

export const fixtureOperations: Operation[] = [
  {
    operation_id: 'op-finalize-safety-review', kind: 'finalization',
    capture_id: 'cap-20260728-safety-review', state: 'running', attempt: 1,
    created_at_unix_ms: fixtureNow - 112_000, started_at_unix_ms: fixtureNow - 108_000,
    progress: proofProgress(612_352, 1_284_096, 4, 10, fixtureNow - 28_000),
    retryable: false,
    attempt_history: [{ attempt: 1, state: 'running', started_at_unix_ms: fixtureNow - 108_000 }]
  },
  {
    operation_id: 'op-finalize-benchmark', kind: 'finalization',
    capture_id: 'cap-20260727-benchmark', state: 'failed', attempt: 2,
    created_at_unix_ms: fixtureNow - hour, started_at_unix_ms: fixtureNow - hour + 2_000,
    completed_at_unix_ms: fixtureNow - hour + 18_000, failure_code: 'notary_capacity',
    progress: proofProgress(262_144, 731_480, 2, 6, fixtureNow - hour + 17_000),
    retryable: true,
    attempt_history: [
      { attempt: 2, state: 'failed', started_at_unix_ms: fixtureNow - hour + 2_000,
        completed_at_unix_ms: fixtureNow - hour + 18_000, failure_code: 'notary_capacity' },
      { attempt: 1, state: 'interrupted', started_at_unix_ms: fixtureNow - hour * 2,
        completed_at_unix_ms: fixtureNow - hour * 2 + 9_000, failure_code: 'service_restarted' }
    ]
  },
  {
    operation_id: 'op-finalize-research-brief', kind: 'finalization',
    capture_id: 'cap-20260727-research-brief', state: 'finalized', attempt: 1,
    created_at_unix_ms: fixtureNow - hour * 17, started_at_unix_ms: fixtureNow - hour * 17 + 1_000,
    completed_at_unix_ms: fixtureNow - hour * 17 + 184_000,
    progress: { phase: 'complete', updated_at_unix_ms: fixtureNow - hour * 17 + 184_000,
      proof: { bytes_completed: 1_934_120, bytes_total: 1_934_120, commitments_completed: 16, commitments_total: 16 } },
    retryable: false,
    attempt_history: [{ attempt: 1, state: 'finalized', started_at_unix_ms: fixtureNow - hour * 17 + 1_000,
      completed_at_unix_ms: fixtureNow - hour * 17 + 184_000 }]
  },
  {
    operation_id: 'op-finalize-direct-link', kind: 'finalization',
    capture_id: 'cap-20260726-direct-link', state: 'finalized', attempt: 1,
    created_at_unix_ms: fixtureNow - hour * 30, started_at_unix_ms: fixtureNow - hour * 30 + 1_000,
    completed_at_unix_ms: fixtureNow - hour * 30 + 161_000, retryable: false,
    progress: { phase: 'complete', updated_at_unix_ms: fixtureNow - hour * 30 + 161_000,
      proof: { bytes_completed: 1_224_930, bytes_total: 1_224_930, commitments_completed: 10, commitments_total: 10 } },
    attempt_history: [{ attempt: 1, state: 'finalized', started_at_unix_ms: fixtureNow - hour * 30 + 1_000,
      completed_at_unix_ms: fixtureNow - hour * 30 + 161_000 }]
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
    severity: 'success', message: 'Finalization completed' },
  { event_id: 11, created_at_unix_ms: fixtureNow - hour * 30, event_type: 'finalization_completed',
    capture_id: 'cap-20260726-direct-link', operation_id: 'op-finalize-direct-link',
    severity: 'success', message: 'Finalization completed' }
];

export const fixtureStatus: Status = {
  version: '0.1.0', build_id: 'dev', runtime_profile: 'local', lifecycle: 'ready',
  proxy_listener: '127.0.0.1:8787', admin_listener: '127.0.0.1:8788',
  proxy_origin: 'http://127.0.0.1:8787', admin_origin: 'http://127.0.0.1:8788',
  metadata_backend: 'sqlite', metadata_status: 'ready', artifact_backend: 'filesystem', artifact_status: 'ready', vault: 'OS vault', notary: 'directory', preview_chars: 1000,
  counts: { total_captures: 7, capturing: 1, ready_to_finalize: 1, finalized: 2, failed: 1, active_operations: 1 },
  updates: { enabled: false, current_build_id: 'dev', latest_build_id: null, update_available: false, last_checked_unix_ms: null, error_code: null }
};

export const fixtureNotaries: Notaries = {
  source: 'directory',
  directory_source: 'https://notary.exalto.ai/api/notary',
  generation: 12,
  active_key_id: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  notaries: [
    {
      endpoint: 'tls://llm-notary-prod-notary.fly.dev:443', transport: 'tls',
      key_id: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', status: 'active',
      valid_from_unix_ms: fixtureNow - hour * 24 * 30, valid_until_unix_ms: null, finalize_until_unix_ms: null
    },
    {
      endpoint: 'tls://notary-old.exalto.ai:7047', transport: 'tls',
      key_id: 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', status: 'retiring',
      valid_from_unix_ms: fixtureNow - hour * 24 * 120, valid_until_unix_ms: fixtureNow - hour * 24 * 7,
      finalize_until_unix_ms: fixtureNow + hour * 24 * 14
    },
    {
      endpoint: 'tls://notary-history.exalto.ai:7047', transport: 'tls',
      key_id: 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', status: 'retired',
      valid_from_unix_ms: fixtureNow - hour * 24 * 240, valid_until_unix_ms: fixtureNow - hour * 24 * 121,
      finalize_until_unix_ms: fixtureNow - hour * 24 * 90
    },
    {
      endpoint: 'tls://notary-revoked.exalto.ai:7047', transport: 'tls',
      key_id: 'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', status: 'revoked',
      valid_from_unix_ms: fixtureNow - hour * 24 * 360, valid_until_unix_ms: fixtureNow - hour * 24 * 241,
      finalize_until_unix_ms: fixtureNow - hour * 24 * 220
    }
  ]
};

const fixtureTrace: Trace = {
  capture_id: 'cap-20260727-research-brief',
  manifest: {
    format: 'llm-notary/verified-trace-package/v2', normalizer_version: 'llm-notary/normalizer/v1',
    trace_sha256: '9a32d7c66a7e4fdd525ea6c803355273ade0f46e7c8dc4973343399731585b26',
    source: { provider: { name: 'openrouter', host: 'openrouter.ai' }, created_at_unix_ms: fixtureNow - hour * 18 }
  },
  trace: {
    resourceSpans: [{ scopeSpans: [{ spans: [{ name: 'gen_ai.inference', traceId: '31f90c419f264b70b09fb1baf4f567d0',
      attributes: [
        { key: 'gen_ai.provider.name', value: { stringValue: 'openrouter' } },
        { key: 'gen_ai.operation.name', value: { stringValue: 'chat' } },
        { key: 'gen_ai.request.model', value: { stringValue: 'openai/gpt-5-mini' } },
        { key: 'gen_ai.response.model', value: { stringValue: 'openai/gpt-5-mini' } },
        { key: 'server.address', value: { stringValue: 'openrouter.ai' } },
        { key: 'gen_ai.usage.input_tokens', value: { intValue: '184' } },
        { key: 'gen_ai.usage.output_tokens', value: { intValue: '126' } },
        { key: 'gen_ai.input.messages', value: { stringValue: JSON.stringify([
          { role: 'system', parts: [{ type: 'text', content: 'Write a short research note. Preserve source labels and flag conclusions that go beyond the notes.' }] },
          { role: 'user', parts: [{ type: 'text', content: 'Choose a reproducibility baseline from these sanitized evaluation notes.\n\nRun 14 (Source A): The model version was pinned, but temperature was omitted. A 20-case rerun produced three different answers.\nRun 15 (Source B): The model version and temperature=0 were pinned. A 20-case rerun matched every answer.\nArchive check (Source C): The stored response SHA-256 matched the bytes downloaded from the provider.' }] }
        ]) } },
        { key: 'gen_ai.output.messages', value: { stringValue: JSON.stringify([
          { role: 'assistant', finish_reason: 'stop', parts: [{ type: 'text', content: 'Use Run 15 as the reproducibility baseline. It records both the model version and temperature, and its 20-case rerun matched exactly (Source B).\n\nRun 14 is weaker because the missing temperature leaves a plausible explanation for its three mismatches (Source A). The notes do not prove that temperature caused them.\n\nThe archive check confirms that the retained response matches the downloaded provider bytes (Source C). It does not establish that the response is factually correct.' }] }
        ]) } }
      ] }] }] }]
  }
};

const fixtureVerification: Verification = {
  capture_id: fixtureTrace.capture_id, verified: true, verified_at_unix_ms: fixtureNow,
  notary_key_id: 'sha256:3828b21f26c49a0ff546f6f4bcee6a64bdc685faf4a961b3c00d05814cda9801',
  trust_source: 'directory'
};

function detail(captureId: string, captures: Capture[], operations: Operation[]): CaptureDetail {
  const capture = captures.find((item) => item.capture_id === captureId);
  if (!capture) throw new LocalApiError(404, 'capture_not_found', 'Capture not found');
  return {
    capture,
    artifacts: [
      { kind: 'deferred_bundle', size_bytes: 189_442, sha256: deterministicHex(`${capture.capture_id}:bundle`, 64) },
      ...(capture.finalization_state === 'finalized'
        ? [{ kind: 'finalized_package', size_bytes: 482_013, sha256: deterministicHex(`${capture.capture_id}:package`, 64) }]
        : [])
    ],
    finalizations: operations.filter((operation) => operation.capture_id === capture.capture_id)
  };
}

function shiftCapture(capture: Capture, offset: number): Capture {
  return {
    ...capture,
    created_at_unix_ms: capture.created_at_unix_ms + offset,
    completed_at_unix_ms: capture.completed_at_unix_ms == null ? capture.completed_at_unix_ms : capture.completed_at_unix_ms + offset
  };
}

function shiftOperation(operation: Operation, offset: number): Operation {
  return {
    ...operation,
    created_at_unix_ms: operation.created_at_unix_ms + offset,
    started_at_unix_ms: operation.started_at_unix_ms == null ? operation.started_at_unix_ms : operation.started_at_unix_ms + offset,
    completed_at_unix_ms: operation.completed_at_unix_ms == null ? operation.completed_at_unix_ms : operation.completed_at_unix_ms + offset,
    attempt_history: operation.attempt_history.map((attempt) => ({
      ...attempt,
      started_at_unix_ms: attempt.started_at_unix_ms == null ? attempt.started_at_unix_ms : attempt.started_at_unix_ms + offset,
      completed_at_unix_ms: attempt.completed_at_unix_ms == null ? attempt.completed_at_unix_ms : attempt.completed_at_unix_ms + offset
    }))
  };
}

const providerHosts: Record<string, string> = {
  anthropic: 'api.anthropic.com', deepseek: 'api.deepseek.com', openai: 'api.openai.com', openrouter: 'openrouter.ai'
};

function deterministicHex(value: string, length: number) {
  let state = 2_166_136_261;
  let output = '';
  while (output.length < length) {
    for (const character of value) {
      state ^= character.charCodeAt(0);
      state = Math.imul(state, 16_777_619);
    }
    output += (state >>> 0).toString(16).padStart(8, '0');
    state ^= output.length;
  }
  return output.slice(0, length);
}

function traceForCapture(capture: Capture): Trace {
  const trace = structuredClone(fixtureTrace);
  const manifest = trace.manifest as {
    trace_sha256?: string; source?: { provider?: { name?: string; host?: string }; created_at_unix_ms?: number }
  };
  manifest.trace_sha256 = deterministicHex(`${capture.capture_id}:trace-bytes`, 64);
  if (manifest.source) {
    manifest.source.provider = { name: capture.provider, host: providerHosts[capture.provider] ?? `${capture.provider}.example` };
    manifest.source.created_at_unix_ms = capture.created_at_unix_ms;
  }
  const span = (trace.trace as { resourceSpans?: Array<{ scopeSpans?: Array<{ spans?: Array<{
    traceId?: string; spanId?: string; attributes?: Array<{ key: string; value: { stringValue?: string } }>
  }> }> }> }).resourceSpans?.[0]?.scopeSpans?.[0]?.spans?.[0];
  if (span) {
    span.traceId = deterministicHex(`${capture.capture_id}:trace`, 32);
    span.spanId = deterministicHex(`${capture.capture_id}:span`, 16);
    const values: Record<string, string> = {
      'gen_ai.provider.name': capture.provider,
      'gen_ai.operation.name': capture.operation,
      'gen_ai.request.model': capture.requested_model ?? 'Model not reported',
      'gen_ai.response.model': capture.response_model ?? capture.requested_model ?? 'Model not reported',
      'server.address': providerHosts[capture.provider] ?? `${capture.provider}.example`,
      'gen_ai.input.messages': JSON.stringify([{ role: 'user', parts: [{ type: 'text', content: capture.prompt_preview || 'Fixture prompt preview is disabled.' }] }]),
      'gen_ai.output.messages': JSON.stringify([{ role: 'assistant', finish_reason: 'stop', parts: [{ type: 'text', content: capture.output_preview || 'Fixture response preview is disabled.' }] }])
    };
    const preserveDetailedTranscript = capture.capture_id === fixtureTrace.capture_id;
    for (const attribute of span.attributes ?? []) {
      if (attribute.key in values
        && (!preserveDetailedTranscript || !['gen_ai.input.messages', 'gen_ai.output.messages'].includes(attribute.key))) {
        attribute.value.stringValue = values[attribute.key];
      }
    }
  }
  return { ...trace, capture_id: capture.capture_id };
}

export function createFixtureApi({ nowUnixMs = Date.now() }: { nowUnixMs?: number } = {}): LocalApi {
  const clock = Number.isFinite(nowUnixMs) && nowUnixMs > 0 ? nowUnixMs : Date.now();
  const offset = clock - fixtureNow;
  let captures = fixtureCaptures.map((capture) => shiftCapture(structuredClone(capture), offset));
  let operations = fixtureOperations.map((operation) => shiftOperation(structuredClone(operation), offset));
  let events = fixtureEvents.map((event) => ({ ...structuredClone(event), created_at_unix_ms: event.created_at_unix_ms + offset }));
  const traces = new Map(captures.filter((capture) => capture.finalization_state === 'finalized')
    .map((capture) => [capture.capture_id, traceForCapture(capture)]));
  let account: AccountConnection = {
    signed_in: true, connection_state: 'connected', github_login: 'sample-user', display_name: 'Sample User', auth_provider: 'github',
    device_name: 'Local dashboard', credential_kind: 'cli_session', credential_name: 'Local dashboard',
    billing: { service_plan: 'one_gb', billing_status: 'active', purchase_mode: 'test' },
    credits: {
      reset_at: Math.floor((fixtureNow + hour * 24 * 10) / 1000),
      capture: { total_granted_bytes: 10_000_000, total_used_bytes: 1_000_000, total_remaining_bytes: 9_000_000, included_monthly_remaining_bytes: 9_000_000, supplemental_remaining_bytes: 0, next_grant_expiration: null },
      notarization: { total_granted_bytes: 10_000_000, total_used_bytes: 2_000_000, total_remaining_bytes: 8_000_000, included_monthly_remaining_bytes: 8_000_000, supplemental_remaining_bytes: 0, next_grant_expiration: null }
    },
    links: { account: 'https://notary.exalto.ai/#/dashboard', usage: 'https://notary.exalto.ai/#/dashboard/credits', plans: 'https://notary.exalto.ai/#/pricing', settings: 'https://notary.exalto.ai/#/dashboard/settings' }
  };
  let nextEventId = Math.max(...events.map((event) => event.event_id)) + 1;
  let nextActionTime = clock;
  const progressingOperations = new Set<string>();
  const operationPolls = new Map<string, number>();
  const shares = new Map<string, { captureId: string; state: string; visibility: ShareVisibility }>();
  const actionTimestamp = () => {
    nextActionTime += 1000;
    return nextActionTime;
  };
  const recordEvent = (eventType: string, message: string, severity: string, captureId?: string, operationId?: string) => {
    events = [{ event_id: nextEventId, created_at_unix_ms: actionTimestamp(),
      event_type: eventType, capture_id: captureId, operation_id: operationId, severity, message }, ...events];
    nextEventId += 1;
  };
  const setCaptureFinalization = (captureId: string, finalizationState: string) => {
    captures = captures.map((capture) => capture.capture_id === captureId
      ? { ...capture, finalization_state: finalizationState } : capture);
  };
  const advanceFixtureOperation = (operationId: string) => {
    if (!progressingOperations.has(operationId)) return;
    const polls = operationPolls.get(operationId) ?? 0;
    operationPolls.set(operationId, polls + 1);
    if (polls === 0) return;
    const operation = operations.find((item) => item.operation_id === operationId);
    if (!operation?.capture_id) {
      progressingOperations.delete(operationId);
      return;
    }
    if (operation.state === 'queued') {
      const attempt = operation.attempt + 1;
      const startedAt = actionTimestamp();
      operations = operations.map((item) => item.operation_id === operationId ? {
        ...item, state: 'running', attempt, started_at_unix_ms: startedAt, completed_at_unix_ms: null,
        progress: proofProgress(384_000, 1_120_000, 3, 9, startedAt),
        retryable: false,
        attempt_history: [{ attempt, state: 'running', started_at_unix_ms: startedAt }, ...item.attempt_history]
      } : item);
      setCaptureFinalization(operation.capture_id, 'running');
      recordEvent('finalization_started', 'Finalization started', 'info', operation.capture_id, operationId);
    } else if (operation.state === 'running') {
      const completedAt = actionTimestamp();
      operations = operations.map((item) => item.operation_id === operationId ? {
        ...item, state: 'finalized', completed_at_unix_ms: completedAt,
        progress: { ...item.progress, phase: 'complete', updated_at_unix_ms: completedAt,
          proof: item.progress.proof ? {
            ...item.progress.proof,
            bytes_completed: item.progress.proof.bytes_total,
            commitments_completed: item.progress.proof.commitments_total
          } : null },
        retryable: false,
        attempt_history: item.attempt_history.map((attempt, index) => index === 0
          ? { ...attempt, state: 'finalized', completed_at_unix_ms: completedAt } : attempt)
      } : item);
      setCaptureFinalization(operation.capture_id, 'finalized');
      const capture = captures.find((item) => item.capture_id === operation.capture_id);
      if (capture) traces.set(capture.capture_id, traceForCapture(capture));
      recordEvent('finalization_completed', 'Finalization completed', 'success', operation.capture_id, operationId);
      progressingOperations.delete(operationId);
      operationPolls.delete(operationId);
    }
  };
  const status = (): Status => ({
    ...fixtureStatus,
    counts: {
      total_captures: captures.length,
      capturing: captures.filter((capture) => capture.capture_state === 'capturing').length,
      ready_to_finalize: captures.filter((capture) => capture.capture_state === 'captured' && capture.finalization_state === 'not_requested' && capture.finalization_eligible).length,
      finalized: captures.filter((capture) => capture.finalization_state === 'finalized').length,
      failed: captures.filter((capture) => ['failed', 'interrupted'].includes(capture.finalization_state)).length,
      active_operations: operations.filter((operation) => ['queued', 'running'].includes(operation.state)).length
    }
  });
  const filteredCaptures = (filters: Record<string, string | number | boolean | undefined> = {}) => {
    const queryTerms = String(filters.query ?? '').toLowerCase().split(/[^\p{L}\p{N}_]+/u).filter(Boolean);
    const state = String(filters.finalization_state ?? '');
    const captureState = String(filters.capture_state ?? '');
    const provider = String(filters.provider ?? '');
    const model = String(filters.model ?? '');
    const streaming = filters.streaming === undefined ? null : filters.streaming === true || filters.streaming === 'true';
    const createdAfter = Number(filters.created_after_unix_ms ?? 0);
    return captures.filter((capture) =>
      (queryTerms.length === 0 || queryTerms.every((term) =>
        `${capture.prompt_preview} ${capture.output_preview} ${capture.requested_model}`.toLowerCase().includes(term)))
      && (!state || capture.finalization_state === state)
      && (!captureState || capture.capture_state === captureState)
      && (!provider || capture.provider === provider)
      && (!model || capture.requested_model === model)
      && (streaming == null || capture.streaming === streaming)
      && (!createdAfter || capture.created_at_unix_ms >= createdAfter));
  };
  const cursorPosition = (value: unknown) => {
    if (typeof value !== 'string') return undefined;
    const position = Number(value.split(':').at(-1));
    return Number.isFinite(position) ? position : undefined;
  };
  const cursor = (kind: string, position: number) => `fixture:${kind}:${position}`;
  return {
    session: async () => undefined,
    endSession: async () => undefined,
    status: async () => status(),
    notaries: async () => structuredClone(fixtureNotaries),
    captures: async (filters = {}) => {
      const limit = Number(filters.limit ?? 50);
      const all = filteredCaptures(filters);
      const start = cursorPosition(filters.cursor) ?? 0;
      const items = all.slice(start, start + limit);
      const next = start + items.length;
      return { items, next_cursor: next < all.length ? cursor('captures', next) : null };
    },
    capture: async (captureId) => detail(captureId, captures, operations),
    startFinalization: async (captureId) => {
      const capture = captures.find((item) => item.capture_id === captureId);
      if (!capture) throw new LocalApiError(404, 'pending_capture_not_found', 'Capture not found');
      if (!capture.finalization_eligible) {
        throw new LocalApiError(409, capture.finalization_ineligibility_code ?? 'capture_not_eligible', 'Capture is not eligible for finalization');
      }
      const existing = operations.find((operation) => operation.capture_id === captureId);
      if (existing) return { operation: existing, deduplicated: true };
      const operation: Operation = { operation_id: 'op-finalize-queued-fixture', kind: 'finalization',
        capture_id: captureId, state: 'queued', attempt: 0, created_at_unix_ms: actionTimestamp(),
        progress: { phase: 'queued', updated_at_unix_ms: nextActionTime, proof: null },
        retryable: false, attempt_history: [] };
      operations = [operation, ...operations];
      setCaptureFinalization(captureId, 'queued');
      progressingOperations.add(operation.operation_id);
      recordEvent('finalization_queued', 'Finalization queued', 'info', captureId, operation.operation_id);
      return { operation, deduplicated: false };
    },
    operations: async (filters = {}) => {
      const limit = Number(filters.limit ?? 50);
      const all = operations.filter((operation) =>
        (!filters.state || operation.state === filters.state)
        && (!filters.kind || operation.kind === filters.kind)
        && (!filters.capture_id || operation.capture_id === filters.capture_id));
      const start = cursorPosition(filters.cursor) ?? 0;
      const items = structuredClone(all.slice(start, start + limit));
      const next = start + items.length;
      return { items, next_cursor: next < all.length ? cursor('operations', next) : null };
    },
    operation: async (operationId) => {
      const operation = operations.find((item) => item.operation_id === operationId);
      if (!operation) throw new LocalApiError(404, 'operation_not_found', 'Operation not found');
      advanceFixtureOperation(operationId);
      return structuredClone(operations.find((item) => item.operation_id === operationId)!);
    },
    retry: async (operationId) => {
      const existing = operations.find((operation) => operation.operation_id === operationId);
      if (!existing?.retryable) throw new LocalApiError(409, 'operation_not_retryable', 'Operation is not retryable');
      operations = operations.map((operation) => operation.operation_id === operationId
        ? { ...operation, state: 'queued', failure_code: null, completed_at_unix_ms: null,
          progress: { phase: 'queued', updated_at_unix_ms: actionTimestamp(), proof: null }, retryable: false } : operation);
      const operation = operations.find((item) => item.operation_id === operationId)!;
      if (operation.capture_id) {
        setCaptureFinalization(operation.capture_id, 'queued');
        operationPolls.delete(operationId);
        progressingOperations.add(operationId);
        recordEvent('finalization_queued', 'Finalization retry queued', 'info', operation.capture_id, operationId);
      }
      return operation;
    },
    events: async (filters = {}) => {
      const pagePosition = cursorPosition(filters.cursor);
      const after = cursorPosition(filters.after);
      const createdAfter = Number(filters.created_after_unix_ms ?? 0);
      const limit = Number(filters.limit ?? 100);
      const matching = events.filter((event) =>
        (after === undefined
          ? pagePosition === undefined || event.event_id < pagePosition
          : event.event_id > (pagePosition ?? after))
        && (!filters.severity || event.severity === filters.severity)
        && (!filters.event_type || event.event_type === filters.event_type)
        && (!filters.capture_id || event.capture_id === filters.capture_id)
        && (!filters.operation_id || event.operation_id === filters.operation_id)
        && (!createdAfter || event.created_at_unix_ms >= createdAfter));
      if (after !== undefined) matching.sort((left, right) => left.event_id - right.event_id);
      const items = matching.slice(0, limit);
      return {
        items,
        next_cursor: matching.length > limit && items.length
          ? cursor('events', items.at(-1)!.event_id) : null,
        high_water_cursor: events.length ? cursor('events', events[0].event_id) : null
      };
    },
    trace: async (captureId) => {
      const trace = traces.get(captureId);
      if (!trace) throw new LocalApiError(404, 'finalized_trace_not_found', 'Finalized trace not found');
      return structuredClone(trace);
    },
    downloadPackage: async (captureId) => new Blob(
      [`fixture .llmtrace for ${captureId}`],
      { type: 'application/vnd.llmnotary.trace-package+zip' }
    ),
    verify: async (captureId) => {
      if (!traces.has(captureId)) throw new LocalApiError(422, 'trace_verification_failed', 'Trace verification failed');
      return { ...fixtureVerification, capture_id: captureId, verified_at_unix_ms: fixtureVerification.verified_at_unix_ms + offset };
    },
    account: async () => account,
    startAccountConnection: async () => ({ request_id: 'auth-docs-fixture', user_code: 'NOTARY-7K3',
      verification_uri_complete: '#/sharing', expires_in_seconds: 600,
      poll_interval_seconds: 0, state: 'pending' }),
    pollAccountConnection: async () => {
      account = {
        ...account, signed_in: true, connection_state: 'connected', github_login: 'sample-user', display_name: 'Sample User',
        device_name: 'Local dashboard', credential_kind: 'cli_session', credential_name: 'Local dashboard'
      };
      return account;
    },
    disconnectAccount: async () => {
      account = { signed_in: false, connection_state: 'disconnected', links: account.links };
    },
    share: async (captureId, visibility) => {
      if (!traces.has(captureId)) throw new LocalApiError(404, 'finalized_trace_not_found', 'Finalized trace not found');
      const shareId = 'share-fixture';
      shares.set(shareId, { captureId, state: 'queued', visibility });
      return { capture_id: captureId, share_id: shareId, state: 'queued', visibility, status_url: `/v1/shares/${shareId}`, share_url: null, package_url: null };
    },
    shareStatus: async (shareId) => {
      const share = shares.get(shareId);
      if (!share) throw new LocalApiError(404, 'share_not_found', 'Share not found');
      const state = share.state;
      if (state === 'queued') share.state = 'verifying';
      else if (state === 'verifying') share.state = 'admitted';
      return {
        share_id: shareId,
        state,
        visibility: share.visibility,
        failure_code: null,
        share_url: state === 'admitted' ? `https://llm-notary.example/s/${shareId}` : null,
        package_url: state === 'admitted' ? `https://llm-notary.example/api/public/shares/${shareId}/package.llmtrace` : null,
      };
    }
  };
}
