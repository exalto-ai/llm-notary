import createClient from 'openapi-fetch';
import type { paths } from './generated/api.generated';

const typedClient = createClient<paths>();

async function contractAssertions() {
  // @ts-expect-error Unknown hosted paths must not compile.
  await typedClient.GET('/api/unknown');

  // @ts-expect-error POST is not registered for the current-user endpoint.
  await typedClient.POST('/api/me');

  // @ts-expect-error Token refresh requires its generated request body.
  await typedClient.POST('/api/cli/token');

  await typedClient.GET('/api/me/api-keys', { params: { query: { limit: 20 } } });
  await typedClient.GET('/api/me/credits/history', { params: { query: { cursor: 'opaque' } } });
  await typedClient.POST('/api/me/api-keys', {
    body: { name: 'CI', scopes: ['notary:admit'], expires_at: null },
  });
  await typedClient.DELETE('/api/me/api-keys/{api_key_id}', {
    params: { path: { api_key_id: 'key-id' } },
  });

  const { data } = await typedClient.GET('/api/me');
  if (data) {
    data.user.github_login;
    // @ts-expect-error The generated response has no display_name property.
    data.user.display_name;
  }
}

void contractAssertions;
