import createClient from 'openapi-fetch';
import type { paths } from './generated/api.generated';

const typedClient = createClient<paths>();

async function contractAssertions() {
  // @ts-expect-error Unknown hosted paths must not compile.
  await typedClient.GET('/api/unknown');

  // @ts-expect-error POST is not registered for the current-user endpoint.
  await typedClient.POST('/api/account');

  // @ts-expect-error Removed CLI paths must not compile.
  await typedClient.POST('/api/cli/token');

  // @ts-expect-error Token refresh requires its generated request body.
  await typedClient.POST('/api/device-session/token');

  await typedClient.GET('/api/api-keys', { params: { query: { limit: 20 } } });
  await typedClient.GET('/api/credits/history', { params: { query: { cursor: 'opaque' } } });
  await typedClient.GET('/api/billing/purchases');
  await typedClient.GET('/api/billing/purchases/{purchase_id}', {
    params: { path: { purchase_id: 'purchase-id' } },
  });
  await typedClient.POST('/api/billing/checkout-sessions', {
    body: { quantity_gb: 5, idempotency_key: 'checkout-attempt' },
  });
  await typedClient.POST('/api/api-keys', {
    body: { name: 'CI', scopes: ['notarization:request'], expires_at: null },
  });
  await typedClient.DELETE('/api/api-keys/{api_key_id}', {
    params: { path: { api_key_id: 'key-id' } },
  });

  const { data } = await typedClient.GET('/api/account');
  if (data) {
    data.account.provider_display_name;
    data.account.display_name;
    data.account.auth_provider;
    data.billing.plan;
    data.billing.billing_status;
    // @ts-expect-error Verified Google email addresses are not retained.
    data.account.email;
    // @ts-expect-error Provider access tokens are never part of the account response.
    data.account.access_token;
  }
}

void contractAssertions;
