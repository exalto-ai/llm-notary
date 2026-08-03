import createClient from 'openapi-fetch';
import type { paths } from './generated/api.generated';

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

export async function getTraceCollection() {
  const { data, error, response } = await client.GET('/api/public/collections/traces');
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not load the collection.'), response.status);
  }
  return data;
}

export async function getPublishedTrace(traceId: string) {
  const { data, error, response } = await client.GET('/api/public/traces/{trace_id}/trace.otlp.json', {
    params: { path: { trace_id: traceId } },
  });
  if (!response.ok || data === undefined) {
    throw new PlatformApiError(errorMessage(error, 'Could not load this trace preview.'), response.status);
  }
  return data;
}

export async function getCliSessions() {
  const { data, error, response } = await client.GET('/api/cli/sessions');
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not load publishing sessions.'), response.status);
  }
  return data.sessions;
}

export async function getPublishJobs() {
  const { data, error, response } = await client.GET('/api/me/publish-jobs');
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not load your traces.'), response.status);
  }
  return data.jobs;
}

export async function revokeCliSession(sessionId: string) {
  const { error, response } = await client.DELETE('/api/cli/sessions/{session_id}', {
    params: { path: { session_id: sessionId } },
  });
  if (!response.ok) {
    throw new PlatformApiError(errorMessage(error, 'Could not revoke this publishing session.'), response.status);
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
  return data.user;
}

export async function logoutBrowser() {
  const { error, response } = await client.POST('/api/auth/logout');
  if (!response.ok) {
    throw new PlatformApiError(errorMessage(error, 'Could not end the browser session.'), response.status);
  }
}
