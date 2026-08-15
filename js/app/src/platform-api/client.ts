import createClient from 'openapi-fetch';
import type { components, paths } from './generated/api.generated';

const client = createClient<paths>({ credentials: 'same-origin' });

export class PlatformApiError extends Error {
  constructor(message: string, readonly status: number, readonly code?: string) {
    super(message);
    this.name = 'PlatformApiError';
  }
}

function errorCode(error: unknown): string | undefined {
  if (error && typeof error === 'object' && 'error' in error && typeof error.error === 'string') {
    return error.error;
  }
  return undefined;
}

function errorMessage(error: unknown, fallback: string): string {
  if (error && typeof error === 'object' && 'message' in error && typeof error.message === 'string') {
    return error.message;
  }
  if (error && typeof error === 'object' && 'error' in error && typeof error.error === 'string') {
    return error.error;
  }
  return fallback;
}

type PageOptions = { limit?: number; cursor?: string };

export async function getListedShares(options: PageOptions & { search?: string; provider?: string } = {}) {
  const { data, error, response } = await client.GET('/api/public/shares', {
    params: { query: options },
  });
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not load the Library.'), response.status);
  }
  return data;
}

export async function getNotaryDirectory() {
  const { data, error, response } = await client.GET('/api/notary');
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not load the notary directory.'), response.status);
  }
  return data;
}

export function encodeSharePassword(password: string) {
  const bytes = new TextEncoder().encode(password);
  const binary = String.fromCharCode(...bytes);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function sharePasswordHeaders(password?: string) {
  return password ? { 'X-Share-Password': encodeSharePassword(password) } : undefined;
}

export async function getPublicShare(shareId: string, password?: string) {
  const { data, error, response } = await client.GET('/api/public/shares/{share_id}', {
    params: { path: { share_id: shareId } },
    headers: sharePasswordHeaders(password),
  });
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not load this shared session.'), response.status, errorCode(error));
  }
  return data;
}

export async function getSharedTrace(shareId: string, password?: string) {
  const { data, error, response } = await client.GET('/api/public/shares/{share_id}/trace.otlp.json', {
    params: { path: { share_id: shareId } },
    headers: sharePasswordHeaders(password),
  });
  if (!response.ok || data === undefined) {
    throw new PlatformApiError(errorMessage(error, 'Could not load this shared transcript.'), response.status, errorCode(error));
  }
  return data;
}

export async function downloadSharedPackage(shareId: string, password?: string) {
  const response = await fetch(`/api/public/shares/${encodeURIComponent(shareId)}/package.llmtrace`, {
    credentials: 'same-origin',
    headers: sharePasswordHeaders(password),
  });
  if (!response.ok) {
    const error = await response.json().catch(() => null);
    throw new PlatformApiError(errorMessage(error, 'Could not download this trace package.'), response.status, errorCode(error));
  }
  return response.blob();
}

export async function reportPublicShare(shareId: string, body: {
  reason: 'sensitive_information' | 'harassment' | 'illegal_content' | 'spam' | 'other';
  message?: string;
}, password?: string) {
  const { data, error, response } = await client.POST('/api/public/shares/{share_id}/reports', {
    params: { path: { share_id: shareId } },
    headers: sharePasswordHeaders(password),
    body,
  });
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not send this report.'), response.status, errorCode(error));
  }
  return data;
}

export async function getCliSessions(options: PageOptions = {}) {
  const { data, error, response } = await client.GET('/api/cli/sessions', {
    params: { query: options },
  });
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not load connected local services.'), response.status);
  }
  return data;
}

export type AccountApiKey = components['schemas']['ApiKeyResponse'];
export type ApiKeyScope = components['schemas']['ApiScope'];

export async function getApiKeys(options: PageOptions = {}) {
  const { data, error, response } = await client.GET('/api/me/api-keys', {
    params: { query: options },
  });
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not load API keys.'), response.status);
  }
  return data;
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

export async function getMyShares(options: PageOptions = {}) {
  const { data, error, response } = await client.GET('/api/me/shares', {
    params: { query: options },
  });
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not load your shares.'), response.status);
  }
  return data;
}

export async function updateMyShare(shareId: string, body: {
  visibility?: 'unlisted' | 'listed';
  published?: boolean;
  password?: string;
  expires_in_days?: number;
}) {
  const { data, error, response } = await client.PATCH('/api/shares/{share_id}', {
    params: { path: { share_id: shareId } },
    body,
  });
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not update this trace.'), response.status, errorCode(error));
  }
  return data;
}

export async function getCreditHistory(options: PageOptions = {}) {
  const { data, error, response } = await client.GET('/api/me/credits/history', {
    params: { query: options },
  });
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not load credit activity.'), response.status);
  }
  return data;
}

export async function getBillingPurchases() {
  const { data, error, response } = await client.GET('/api/me/billing/purchases');
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not load credit purchases.'), response.status);
  }
  return data.purchases;
}

export async function getBillingPurchase(purchaseId: string) {
  const { data, error, response } = await client.GET('/api/me/billing/purchases/{purchase_id}', {
    params: { path: { purchase_id: purchaseId } },
  });
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not load this credit purchase.'), response.status);
  }
  return data;
}

export async function createCheckoutSession(quantityGb: number, idempotencyKey: string) {
  const { data, error, response } = await client.POST('/api/me/billing/checkout-sessions', {
    body: { quantity_gb: quantityGb, idempotency_key: idempotencyKey },
  });
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not start Stripe Checkout.'), response.status);
  }
  return data;
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
  return {
    ...data.user,
    billing: data.billing,
    credits: data.credits,
    notary_stats: data.notary_stats,
    share_stats: data.share_stats,
  };
}

export async function getAuthProviders() {
  const { data, error, response } = await client.GET('/api/auth/providers');
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not load sign-in options.'), response.status);
  }
  return data;
}

export async function getCreditOffers() {
  const { data, error, response } = await client.GET('/api/me/credit-offers');
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not load available credit offers.'), response.status);
  }
  return data.offers;
}

export async function claimCreditOffer(offerId: string) {
  const { data, error, response } = await client.POST('/api/me/credit-offers/{offer_id}/claim', {
    params: { path: { offer_id: offerId } },
  });
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not claim this credit offer.'), response.status);
  }
  return data;
}

export async function logoutBrowser() {
  const { error, response } = await client.POST('/api/auth/logout');
  if (!response.ok) {
    throw new PlatformApiError(errorMessage(error, 'Could not end the browser session.'), response.status);
  }
}

export async function deleteCurrentAccount() {
  const { error, response } = await client.DELETE('/api/me');
  if (!response.ok) {
    throw new PlatformApiError(errorMessage(error, 'Could not delete the account.'), response.status);
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
