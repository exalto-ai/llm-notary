import type { components } from './generated/api.generated';

export type Status = components['schemas']['StatusResponse'];
export type Capture = components['schemas']['CaptureResponse'];
export type CaptureDetail = components['schemas']['CaptureDetailResponse'];
export type Operation = components['schemas']['OperationResponse'];
export type Event = components['schemas']['EventResponse'];
export type Trace = components['schemas']['TraceResponse'];
export type Verification = components['schemas']['VerificationResponse'];
export type PublicationAuth = components['schemas']['PublicationAuthResponse'];
export type PublicationAuthStarted = components['schemas']['PublicationAuthStartedResponse'];
export type Publication = components['schemas']['PublicationResponse'];

export class LocalApiError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

type RequestOptions = {
  method?: 'GET' | 'POST' | 'DELETE';
  body?: unknown;
};

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const response = await fetch(path, {
    method: options.method ?? 'GET',
    credentials: 'same-origin',
    headers: {
      'x-llm-notary-request': 'dashboard',
      ...(options.body === undefined ? {} : { 'content-type': 'application/json' })
    },
    body: options.body === undefined ? undefined : JSON.stringify(options.body)
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null) as {
      error?: { code?: string; message?: string };
    } | null;
    throw new LocalApiError(
      response.status,
      payload?.error?.code ?? 'request_failed',
      payload?.error?.message ?? 'The local service could not complete the request.'
    );
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

function queryString(values: Record<string, string | number | undefined>) {
  const query = new URLSearchParams();
  Object.entries(values).forEach(([key, value]) => {
    if (value !== undefined && value !== '') query.set(key, String(value));
  });
  const encoded = query.toString();
  return encoded ? `?${encoded}` : '';
}

export const localApi = {
  session: (token: string) => request<void>('/v1/session', { method: 'POST', body: { token } }),
  endSession: () => request<void>('/v1/session', { method: 'DELETE' }),
  status: () => request<Status>('/v1/status'),
  captures: (filters: Record<string, string | number | undefined> = {}) =>
    request<{ items: Capture[]; limit: number; offset: number }>(`/v1/captures${queryString(filters)}`),
  capture: (captureId: string) => request<CaptureDetail>(`/v1/captures/${encodeURIComponent(captureId)}`),
  startFinalization: (captureId: string) =>
    request<{ operation: Operation; deduplicated: boolean }>(
      `/v1/captures/${encodeURIComponent(captureId)}/finalizations`,
      { method: 'POST' }
    ),
  operations: () => request<{ items: Operation[] }>('/v1/operations'),
  operation: (operationId: string) => request<Operation>(`/v1/operations/${encodeURIComponent(operationId)}`),
  retry: (operationId: string) => request<Operation>(
    `/v1/operations/${encodeURIComponent(operationId)}/retry`,
    { method: 'POST' }
  ),
  events: () => request<{ items: Event[]; next_cursor?: number }>('/v1/events'),
  trace: (captureId: string) => request<Trace>(`/v1/captures/${encodeURIComponent(captureId)}/trace`),
  verify: (captureId: string) => request<Verification>(
    `/v1/captures/${encodeURIComponent(captureId)}/trace:verify`,
    { method: 'POST' }
  ),
  publicationAuth: () => request<PublicationAuth>('/v1/publication/auth'),
  startPublicationAuth: () => request<PublicationAuthStarted>('/v1/publication/auth', {
    method: 'POST', body: {}
  }),
  pollPublicationAuth: (requestId: string) =>
    request<PublicationAuth>(`/v1/publication/auth/${encodeURIComponent(requestId)}`),
  publish: (captureId: string) => request<Publication>(
    `/v1/captures/${encodeURIComponent(captureId)}/publications`,
    { method: 'POST' }
  )
};

export type LocalApi = typeof localApi;
