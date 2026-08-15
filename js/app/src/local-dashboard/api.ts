import type { components, paths } from './generated/api.generated';

export type Status = components['schemas']['StatusResponse'];
export type CaptureSetting = components['schemas']['CaptureSettingResponse'];
export type Notaries = components['schemas']['NotariesResponse'];
export type Notary = components['schemas']['NotaryResponse'];
export type Capture = components['schemas']['CaptureResponse'];
export type CaptureDetail = components['schemas']['CaptureDetailResponse'];
export type Operation = components['schemas']['OperationResponse'];
export type OperationSummary = components['schemas']['OperationSummaryResponse'];
export type Event = components['schemas']['EventResponse'];
export type Trace = components['schemas']['TraceResponse'];
export type Verification = components['schemas']['VerificationResponse'];
export type AccountConnection = components['schemas']['AccountConnectionResponse'];
export type AccountConnectionStarted = components['schemas']['AccountConnectionStartedResponse'];
export type Share = components['schemas']['ShareResponse'];
export type ShareStatus = components['schemas']['ShareStatusResponse'];
export type ShareVisibility = components['schemas']['ShareVisibility'];
type CaptureList = paths['/v1/captures']['get']['responses'][200]['content']['application/json'];
type FinalizationResult = paths['/v1/captures/{capture_id}/finalizations']['post']['responses'][202]['content']['application/json'];
type OperationList = paths['/v1/operations']['get']['responses'][200]['content']['application/json'];
type EventList = paths['/v1/events']['get']['responses'][200]['content']['application/json'];

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
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  body?: unknown;
  basicAuth?: { username: string; password: string };
};

function basicAuthorization(username: string, password: string) {
  const bytes = new TextEncoder().encode(`${username}:${password}`);
  let binary = '';
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return `Basic ${btoa(binary)}`;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const response = await fetch(path, {
    method: options.method ?? 'GET',
    credentials: 'same-origin',
    headers: {
      'x-llm-notary-request': 'dashboard',
      ...(options.basicAuth ? { authorization: basicAuthorization(options.basicAuth.username, options.basicAuth.password) } : {}),
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

async function requestBlob(path: string): Promise<Blob> {
  const response = await fetch(path, {
    credentials: 'same-origin',
    headers: { 'x-llm-notary-request': 'dashboard' }
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
  return response.blob();
}

function queryString(values: Record<string, string | number | boolean | undefined>) {
  const query = new URLSearchParams();
  Object.entries(values).forEach(([key, value]) => {
    if (value !== undefined && value !== '') query.set(key, String(value));
  });
  const encoded = query.toString();
  return encoded ? `?${encoded}` : '';
}

export const localApi = {
  session: (username: string, password: string) => request<void>('/v1/session', {
    method: 'POST', basicAuth: { username, password }
  }),
  endSession: () => request<void>('/v1/session', { method: 'DELETE' }),
  status: () => request<Status>('/v1/status'),
  captureSetting: () => request<CaptureSetting>('/v1/settings/capture'),
  updateCaptureSetting: (enabled: boolean) => request<CaptureSetting>('/v1/settings/capture', {
    method: 'PUT', body: { enabled }
  }),
  notaries: () => request<Notaries>('/v1/notaries'),
  captures: (filters: Record<string, string | number | boolean | undefined> = {}) =>
    request<CaptureList>(`/v1/captures${queryString(filters)}`),
  capture: (captureId: string) => request<CaptureDetail>(`/v1/captures/${encodeURIComponent(captureId)}`),
  startFinalization: (captureId: string) =>
    request<FinalizationResult>(
      `/v1/captures/${encodeURIComponent(captureId)}/finalizations`,
      { method: 'POST' }
    ),
  operations: (filters: Record<string, string | number | boolean | undefined> = {}) =>
    request<OperationList>(`/v1/operations${queryString(filters)}`),
  operation: (operationId: string) => request<Operation>(`/v1/operations/${encodeURIComponent(operationId)}`),
  retry: (operationId: string) => request<Operation>(
    `/v1/operations/${encodeURIComponent(operationId)}/retry`,
    { method: 'POST' }
  ),
  events: (filters: Record<string, string | number | boolean | undefined> = {}) =>
    request<EventList>(`/v1/events${queryString(filters)}`),
  trace: (captureId: string) => request<Trace>(`/v1/captures/${encodeURIComponent(captureId)}/trace`),
  downloadPackage: (captureId: string) => requestBlob(
    `/v1/captures/${encodeURIComponent(captureId)}/package`
  ),
  verify: (captureId: string) => request<Verification>(
    `/v1/captures/${encodeURIComponent(captureId)}/trace:verify`,
    { method: 'POST' }
  ),
  account: () => request<AccountConnection>('/v1/account'),
  startAccountConnection: () => request<AccountConnectionStarted>('/v1/account', {
    method: 'POST', body: {}
  }),
  pollAccountConnection: (requestId: string) =>
    request<AccountConnection>(`/v1/account/${encodeURIComponent(requestId)}`),
  disconnectAccount: () => request<void>('/v1/account', { method: 'DELETE' }),
  share: (captureId: string, visibility: ShareVisibility) => request<Share>(
    `/v1/captures/${encodeURIComponent(captureId)}/shares`,
    { method: 'POST', body: { visibility } }
  ),
  shareStatus: (shareId: string) => request<ShareStatus>(
    `/v1/shares/${encodeURIComponent(shareId)}`
  )
};

export type LocalApi = typeof localApi;
