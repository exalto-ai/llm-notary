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

  const { data } = await typedClient.GET('/api/me');
  if (data) {
    data.user.github_login;
    // @ts-expect-error The generated response has no display_name property.
    data.user.display_name;
  }
}

void contractAssertions;
