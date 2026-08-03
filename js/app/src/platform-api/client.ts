import createClient from 'openapi-fetch';
import type { components, paths } from './generated/api.generated';

const client = createClient<paths>({ credentials: 'same-origin' });

export class PlatformApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
    this.name = 'PlatformApiError';
  }
}

function errorMessage(error: unknown, fallback: string): string {
  if (error && typeof error === 'object' && 'error' in error && typeof error.error === 'string') {
    return error.error;
  }
  return fallback;
}

export async function getListedShares() {
  const { data, error, response } = await client.GET('/api/public/shares');
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not load the Library.'), response.status);
  }
  return data.shares;
}

export async function getNotaryDirectory() {
  const { data, error, response } = await client.GET('/api/notary');
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not load the notary directory.'), response.status);
  }
  return data;
}

export async function getPublicShare(shareId: string) {
  const { data, error, response } = await client.GET('/api/public/shares/{share_id}', {
    params: { path: { share_id: shareId } },
  });
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not load this shared session.'), response.status);
  }
  return data;
}

export async function getSharedTrace(shareId: string) {
  const { data, error, response } = await client.GET('/api/public/shares/{share_id}/trace.otlp.json', {
    params: { path: { share_id: shareId } },
  });
  if (!response.ok || data === undefined) {
    throw new PlatformApiError(errorMessage(error, 'Could not load this shared transcript.'), response.status);
  }
  return data;
}

export async function getCliSessions() {
  const { data, error, response } = await client.GET('/api/cli/sessions');
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not load connected local services.'), response.status);
  }
  return data.sessions;
}

export type AccountApiKey = components['schemas']['ApiKeyResponse'];
export type ApiKeyScope = components['schemas']['ApiScope'];

export async function getApiKeys() {
  const { data, error, response } = await client.GET('/api/me/api-keys');
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not load API keys.'), response.status);
  }
  return data.api_keys;
}

export async function createApiKey(body: {
  name: string;
  scopes: string[];
  expires_at: number | null;
}) {
  const { data, error, response } = await client.POST('/api/me/api-keys', { body });
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not create the API key.'), response.status);
  }
  return data;
}

export async function revokeApiKey(apiKeyId: string) {
  const { error, response } = await client.DELETE('/api/me/api-keys/{api_key_id}', {
    params: { path: { api_key_id: apiKeyId } },
  });
  if (!response.ok) {
    throw new PlatformApiError(errorMessage(error, 'Could not revoke the API key.'), response.status);
  }
}

export async function getMyShares() {
  const { data, error, response } = await client.GET('/api/me/shares');
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not load your shares.'), response.status);
  }
  return data.shares;
}

export async function revokeCliSession(sessionId: string) {
  const { error, response } = await client.DELETE('/api/cli/sessions/{session_id}', {
    params: { path: { session_id: sessionId } },
  });
  if (!response.ok) {
    throw new PlatformApiError(errorMessage(error, 'Could not revoke this local service session.'), response.status);
  }
}

export async function getCliApproval(requestId: string, approvalSecret: string) {
  const { data, error, response } = await client.GET('/api/cli/authorizations/{request_id}/approval', {
    params: { path: { request_id: requestId }, query: { approval_secret: approvalSecret } },
  });
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'This authorization request is unavailable.'), response.status);
  }
  return data;
}

export async function approveCli(requestId: string, approvalSecret: string) {
  const { error, response } = await client.POST('/api/cli/authorizations/{request_id}/approval', {
    params: { path: { request_id: requestId }, query: { approval_secret: approvalSecret } },
  });
  if (!response.ok) {
    throw new PlatformApiError(errorMessage(error, 'Could not approve this local service request.'), response.status);
  }
}

export async function getCurrentUser() {
  const { data, error, response } = await client.GET('/api/me');
  if (response.status === 401) return null;
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not load the current account.'), response.status);
  }
  return { ...data.user, plan: data.plan, entitlements: data.entitlements };
}

export async function changeServicePlan(plan: 'free' | 'paid_preview') {
  const { data, error, response } = await client.PUT('/api/me/plan', {
    body: { plan },
  });
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not change the service plan.'), response.status);
  }
  return data;
}

export async function logoutBrowser() {
  const { error, response } = await client.POST('/api/auth/logout');
  if (!response.ok) {
    throw new PlatformApiError(errorMessage(error, 'Could not end the browser session.'), response.status);
  }
}

export type HostedVerificationResult = components['schemas']['VerificationResponse'];

export async function verifyTracePackage(file: File): Promise<HostedVerificationResult> {
  const response = await fetch('/api/verify', {
    method: 'POST',
    credentials: 'omit',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/vnd.llmnotary.trace-package+zip' },
    body: file,
  });
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new PlatformApiError('verification_unavailable', response.status);
  }
  if (!response.ok) {
    throw new PlatformApiError(errorMessage(payload, 'verification_unavailable'), response.status);
  }
  if (!payload || typeof payload !== 'object' || !('verified' in payload) || payload.verified !== true) {
    throw new PlatformApiError('verification_unavailable', response.status);
  }
  return payload as HostedVerificationResult;
}
