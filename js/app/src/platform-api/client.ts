import createClient from 'openapi-fetch';
import type { components, paths } from './generated/api.generated';

const client = createClient<paths>({ credentials: 'same-origin' });

export class PlatformApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code?: string,
  ) {
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
  if (
    error &&
    typeof error === 'object' &&
    'message' in error &&
    typeof error.message === 'string'
  ) {
    return error.message;
  }
  if (error && typeof error === 'object' && 'error' in error && typeof error.error === 'string') {
    return error.error;
  }
  return fallback;
}

type PageOptions = { limit?: number; cursor?: string };

export async function getListedTraces(
  options: PageOptions & { search?: string; provider?: string } = {},
) {
  const { data, error, response } = await client.GET('/api/public/traces', {
    params: { query: options },
  });
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not load the Library.'), response.status);
  }
  return data;
}

export async function getRegistry() {
  const { data, error, response } = await client.GET('/api/registry');
  if (!response.ok || !data) {
    throw new PlatformApiError(
      errorMessage(error, 'Could not load the notary Registry.'),
      response.status,
    );
  }
  return data;
}

export async function accessPublicTrace(traceId: string, password: string) {
  const { error, response } = await client.POST('/api/public/traces/{trace_id}/access', {
    params: { path: { trace_id: traceId } },
    body: { password },
  });
  if (!response.ok) {
    throw new PlatformApiError(
      errorMessage(error, 'Could not open this public Trace.'),
      response.status,
      errorCode(error),
    );
  }
}

export async function getPublicTrace(traceId: string) {
  const { data, error, response } = await client.GET('/api/public/traces/{trace_id}', {
    params: { path: { trace_id: traceId } },
  });
  if (!response.ok || !data) {
    throw new PlatformApiError(
      errorMessage(error, 'Could not load this shared session.'),
      response.status,
      errorCode(error),
    );
  }
  return data;
}

export async function getPublicTraceOtlp(traceId: string) {
  const { data, error, response } = await client.GET(
    '/api/public/traces/{trace_id}/trace.otlp.json',
    {
      params: { path: { trace_id: traceId } },
    },
  );
  if (!response.ok || data === undefined) {
    throw new PlatformApiError(
      errorMessage(error, 'Could not load this shared transcript.'),
      response.status,
      errorCode(error),
    );
  }
  return data;
}

export async function downloadPublicTracePackage(traceId: string) {
  const response = await fetch(
    `/api/public/traces/${encodeURIComponent(traceId)}/package.llmtrace`,
    { credentials: 'same-origin' },
  );
  if (!response.ok) {
    const error = await response.json().catch(() => null);
    throw new PlatformApiError(
      errorMessage(error, 'Could not download this trace package.'),
      response.status,
      errorCode(error),
    );
  }
  return response.blob();
}

export async function reportPublicTrace(
  traceId: string,
  body: {
    reason: 'sensitive_information' | 'harassment' | 'illegal_content' | 'spam' | 'other';
    message?: string;
  },
) {
  const { data, error, response } = await client.POST('/api/public/traces/{trace_id}/reports', {
    params: { path: { trace_id: traceId } },
    body,
  });
  if (!response.ok || !data) {
    throw new PlatformApiError(
      errorMessage(error, 'Could not send this report.'),
      response.status,
      errorCode(error),
    );
  }
  return data;
}

export async function getDevices(options: PageOptions = {}) {
  const { data, error, response } = await client.GET('/api/devices', {
    params: { query: options },
  });
  if (!response.ok || !data) {
    throw new PlatformApiError(
      errorMessage(error, 'Could not load connected local services.'),
      response.status,
    );
  }
  return data;
}

export type AccountApiKey = components['schemas']['ApiKeyResponse'];
export type ApiKeyScope = components['schemas']['ApiScope'];

export async function getApiKeys(options: PageOptions = {}) {
  const { data, error, response } = await client.GET('/api/api-keys', {
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
  const { data, error, response } = await client.POST('/api/api-keys', { body });
  if (!response.ok || !data) {
    throw new PlatformApiError(
      errorMessage(error, 'Could not create the API key.'),
      response.status,
    );
  }
  return data;
}

export async function revokeApiKey(apiKeyId: string) {
  const { error, response } = await client.DELETE('/api/api-keys/{api_key_id}', {
    params: { path: { api_key_id: apiKeyId } },
  });
  if (!response.ok) {
    throw new PlatformApiError(
      errorMessage(error, 'Could not revoke the API key.'),
      response.status,
    );
  }
}

export async function getHostedTraces(options: PageOptions = {}) {
  const { data, error, response } = await client.GET('/api/traces', {
    params: { query: options },
  });
  if (!response.ok || !data) {
    throw new PlatformApiError(errorMessage(error, 'Could not load your shares.'), response.status);
  }
  return data;
}

export async function updateHostedTrace(
  traceId: string,
  body: {
    visibility?: 'unlisted' | 'listed';
    password?: string;
    expires_in_days?: number;
  },
) {
  const { data, error, response } = await client.PATCH('/api/traces/{trace_id}', {
    params: { path: { trace_id: traceId } },
    body,
  });
  if (!response.ok || !data) {
    throw new PlatformApiError(
      errorMessage(error, 'Could not update this trace.'),
      response.status,
      errorCode(error),
    );
  }
  return data;
}

export async function stopHostedTraceSharing(traceId: string) {
  const { error, response } = await client.DELETE('/api/traces/{trace_id}/share', {
    params: { path: { trace_id: traceId } },
  });
  if (!response.ok) {
    throw new PlatformApiError(
      errorMessage(error, 'Could not stop sharing this Trace.'),
      response.status,
      errorCode(error),
    );
  }
}

export async function getCreditHistory(options: PageOptions = {}) {
  const { data, error, response } = await client.GET('/api/me/credits/history', {
    params: { query: options },
  });
  if (!response.ok || !data) {
    throw new PlatformApiError(
      errorMessage(error, 'Could not load credit activity.'),
      response.status,
    );
  }
  return data;
}

export async function getBillingPurchases() {
  const { data, error, response } = await client.GET('/api/billing/purchases');
  if (!response.ok || !data) {
    throw new PlatformApiError(
      errorMessage(error, 'Could not load credit purchases.'),
      response.status,
    );
  }
  return data.purchases;
}

export async function getBillingPurchase(purchaseId: string) {
  const { data, error, response } = await client.GET('/api/billing/purchases/{purchase_id}', {
    params: { path: { purchase_id: purchaseId } },
  });
  if (!response.ok || !data) {
    throw new PlatformApiError(
      errorMessage(error, 'Could not load this credit purchase.'),
      response.status,
    );
  }
  return data;
}

export async function createCheckoutSession(quantityGb: number, idempotencyKey: string) {
  const { data, error, response } = await client.POST('/api/billing/checkout-sessions', {
    body: { quantity_gb: quantityGb, idempotency_key: idempotencyKey },
  });
  if (!response.ok || !data) {
    throw new PlatformApiError(
      errorMessage(error, 'Could not start Stripe Checkout.'),
      response.status,
    );
  }
  return data;
}

export async function createSubscriptionCheckoutSession(
  plan: 'one_gb' | 'ten_gb',
  idempotencyKey: string,
) {
  const { data, error, response } = await client.POST(
    '/api/billing/subscription-checkout-sessions',
    {
      body: { plan, idempotency_key: idempotencyKey },
    },
  );
  if (!response.ok || !data) {
    throw new PlatformApiError(
      errorMessage(error, 'Could not start subscription Checkout.'),
      response.status,
    );
  }
  return data;
}

export async function createBillingPortalSession() {
  const { data, error, response } = await client.POST('/api/billing/portal-sessions');
  if (!response.ok || !data) {
    throw new PlatformApiError(
      errorMessage(error, 'Could not open subscription management.'),
      response.status,
    );
  }
  return data;
}

export async function revokeDevice(sessionId: string) {
  const { error, response } = await client.DELETE('/api/devices/{device_id}', {
    params: { path: { device_id: sessionId } },
  });
  if (!response.ok) {
    throw new PlatformApiError(
      errorMessage(error, 'Could not revoke this local service session.'),
      response.status,
    );
  }
}

export async function getDeviceAuthorizationApproval(requestId: string, approvalSecret: string) {
  const { data, error, response } = await client.GET(
    '/api/device-authorizations/{request_id}/approval',
    {
      params: {
        path: { request_id: requestId },
        header: { 'X-Notary-Approval-Secret': approvalSecret },
      },
    },
  );
  if (!response.ok || !data) {
    throw new PlatformApiError(
      errorMessage(error, 'This authorization request is unavailable.'),
      response.status,
    );
  }
  return data;
}

export async function approveDeviceAuthorization(requestId: string, approvalSecret: string) {
  const { error, response } = await client.POST(
    '/api/device-authorizations/{request_id}/approval',
    {
      params: {
        path: { request_id: requestId },
        header: { 'X-Notary-Approval-Secret': approvalSecret },
      },
    },
  );
  if (!response.ok) {
    throw new PlatformApiError(
      errorMessage(error, 'Could not approve this local service request.'),
      response.status,
    );
  }
}

export async function getCurrentUser() {
  const { data, error, response } = await client.GET('/api/account');
  if (response.status === 401) return null;
  if (!response.ok || !data) {
    throw new PlatformApiError(
      errorMessage(error, 'Could not load the current account.'),
      response.status,
    );
  }
  const usage = await client.GET('/api/usage');
  if (!usage.response.ok || !usage.data) {
    throw new PlatformApiError(
      errorMessage(usage.error, 'Could not load account usage.'),
      usage.response.status,
    );
  }
  return {
    ...data.account,
    billing: data.billing,
    usage: usage.data,
  };
}

export async function getAuthProviders() {
  const { data, error, response } = await client.GET('/api/auth/providers');
  if (!response.ok || !data) {
    throw new PlatformApiError(
      errorMessage(error, 'Could not load sign-in options.'),
      response.status,
    );
  }
  return data;
}

export async function getCreditOffers() {
  const { data, error, response } = await client.GET('/api/me/credit-offers');
  if (!response.ok || !data) {
    throw new PlatformApiError(
      errorMessage(error, 'Could not load available credit offers.'),
      response.status,
    );
  }
  return data.offers;
}

export async function claimCreditOffer(offerId: string) {
  const { data, error, response } = await client.POST('/api/me/credit-offers/{offer_id}/claim', {
    params: { path: { offer_id: offerId } },
  });
  if (!response.ok || !data) {
    throw new PlatformApiError(
      errorMessage(error, 'Could not claim this credit offer.'),
      response.status,
    );
  }
  return data;
}

export async function logoutBrowser() {
  const { error, response } = await client.POST('/api/auth/logout');
  if (!response.ok) {
    throw new PlatformApiError(
      errorMessage(error, 'Could not end the browser session.'),
      response.status,
    );
  }
}

export async function deleteCurrentAccount() {
  const { error, response } = await client.DELETE('/api/account', {
    body: { confirmation: 'DELETE' },
  });
  if (!response.ok) {
    throw new PlatformApiError(
      errorMessage(error, 'Could not delete the account.'),
      response.status,
    );
  }
}

export type HostedVerificationResult = components['schemas']['VerificationResponse'];

export async function verifyTracePackage(file: File): Promise<HostedVerificationResult> {
  const response = await fetch('/api/verify', {
    method: 'POST',
    credentials: 'omit',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/vnd.exalto.notary.trace-package+zip' },
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
  if (
    !payload ||
    typeof payload !== 'object' ||
    !('verified' in payload) ||
    payload.verified !== true
  ) {
    throw new PlatformApiError('verification_unavailable', response.status);
  }
  return payload as HostedVerificationResult;
}
