import { createTheme, MantineProvider } from '@mantine/core';
import { Notifications } from '@mantine/notifications';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { page, userEvent } from 'vitest/browser';
import { type LocalApi, LocalApiError, localApi, type Notaries } from './api';
import { Dashboard } from './Dashboard';
import { createFixtureApi, fixtureNotaries } from './fixtures';
import '@mantine/core/styles.css';
import '@mantine/notifications/styles.css';

const theme = createTheme({ defaultRadius: 0, primaryColor: 'dark' });

function renderDashboard(hash = '/overview', api: LocalApi = createFixtureApi()) {
  window.location.hash = hash;
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MantineProvider theme={theme} defaultColorScheme="auto">
      <Notifications />
      <QueryClientProvider client={queryClient}>
        <Dashboard api={api} fixture />
      </QueryClientProvider>
    </MantineProvider>,
  );
}

beforeEach(() => localStorage.clear());
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('local evidence dashboard', () => {
  test('navigates, filters captures, and selects a capture', async () => {
    renderDashboard();
    await expect.element(page.getByRole('heading', { name: 'Online' })).toBeVisible();
    await page.getByRole('button', { name: /Captures/ }).click();
    await expect.element(page.getByLabelText('Search captures')).toBeVisible();
    await page.getByLabelText('Search captures').fill('**benchmark**');
    await expect.element(page.getByText('deepseek-v4-flash')).toBeVisible();
    await expect.element(page.getByText('gpt-5.2', { exact: true })).not.toBeInTheDocument();
    await page.getByRole('list', { name: 'Captures' }).getByRole('button').click();
    await expect.element(page.getByText('trc-20260727-benchmark').first()).toBeVisible();
  });

  test('loads another cursor page without downloading the full capture catalog', async () => {
    const fixture = createFixtureApi();
    const samples = (await fixture.traces({ limit: 200 })).items;
    const cursors: Array<string | undefined> = [];
    const api: LocalApi = {
      ...fixture,
      traces: async (filters = {}) => {
        const cursor = typeof filters.cursor === 'string' ? filters.cursor : undefined;
        cursors.push(cursor);
        return cursor === 'fixture:next'
          ? { items: [samples[1]], next_cursor: null }
          : { items: [samples[0]], next_cursor: 'fixture:next' };
      },
    };
    renderDashboard('/captures', api);
    await expect.element(page.getByRole('button', { name: 'Load more captures' })).toBeVisible();
    await page.getByRole('button', { name: 'Load more captures' }).click();
    await expect.poll(() => cursors).toContain('fixture:next');
    const requestedModel = samples[1].requested_model;
    if (!requestedModel) throw new Error('Expected the second fixture capture to name a model');
    await expect.element(page.getByText(requestedModel, { exact: true })).toBeVisible();
  });

  test('retains the live Trace cursor when a projected notarization page is empty', async () => {
    const fixture = createFixtureApi();
    const trace = (await fixture.traces({ limit: 1 })).items[0];
    const traceDetail = { ...(await fixture.trace(trace.trace_id)), notarization: null };
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input);
      if (path === '/v1/traces?limit=1') {
        return Response.json({ items: [trace], next_cursor: 'trace:next' });
      }
      if (path === `/v1/traces/${trace.trace_id}`) return Response.json(traceDetail);
      throw new Error(`Unexpected dashboard request: ${path}`);
    });

    await expect(localApi.operations({ limit: 1 })).resolves.toEqual({
      items: [],
      next_cursor: 'trace:next',
    });
  });

  test('can load older notarizations after an empty projected Trace page', async () => {
    const fixture = createFixtureApi();
    const operation = (await fixture.operations()).items[0];
    const cursors: Array<string | undefined> = [];
    const api: LocalApi = {
      ...fixture,
      operations: async (filters = {}) => {
        const cursor = typeof filters.cursor === 'string' ? filters.cursor : undefined;
        cursors.push(cursor);
        return cursor === 'trace:next'
          ? { items: [operation], next_cursor: null }
          : { items: [], next_cursor: 'trace:next' };
      },
    };

    renderDashboard('/notarizations', api);
    await expect
      .element(page.getByRole('button', { name: 'Load more notarizations' }))
      .toBeVisible();
    await page.getByRole('button', { name: 'Load more notarizations' }).click();
    await expect.poll(() => cursors).toContain('trace:next');
    await expect
      .element(page.getByRole('button', { name: `Inspect ${operation.operation_id}` }))
      .toBeVisible();
  });

  test('uses the authenticated provider for icons instead of a namespaced model slug', async () => {
    renderDashboard('/captures/trc-20260727-research-brief');
    await expect
      .element(page.getByText('openai/gpt-5-mini', { exact: true }).first())
      .toBeVisible();
    const inspector = document.querySelector('.capture-inspector');
    expect(inspector?.querySelector('[data-provider-icon="openrouter"]')).not.toBeNull();
    expect(inspector?.querySelector('[data-provider-icon="openai"]')).toBeNull();
  });

  test('persists an explicit theme and can return to system mode', async () => {
    renderDashboard('/settings');
    await page.getByRole('button', { name: 'Dark color scheme' }).click();
    await expect.poll(() => document.documentElement.dataset.mantineColorScheme).toBe('dark');
    expect(localStorage.getItem('mantine-color-scheme-value')).toBe('dark');
    await page.getByRole('button', { name: 'System color scheme' }).click();
    expect(localStorage.getItem('mantine-color-scheme-value')).toBe('auto');
  });

  test('changes the authoritative capture mode and explains direct passthrough', async () => {
    const api = createFixtureApi();
    renderDashboard('/settings', api);
    const toggle = page.getByRole('switch', { name: 'Capture requests' });
    await expect.element(toggle).toBeChecked();
    await toggle.click();
    await expect.element(toggle).not.toBeChecked();
    await expect
      .element(
        page.getByText(
          'Off — requests still pass through the local daemon, go directly to the provider, and create no evidence.',
        ),
      )
      .toBeVisible();
    await expect.poll(async () => (await api.captureSetting()).enabled).toBe(false);
  });

  test('distinguishes capture-off service readiness on the overview', async () => {
    const fixture = createFixtureApi();
    await fixture.updateCaptureSetting(false);
    renderDashboard('/overview', fixture);
    await expect.element(page.getByRole('heading', { name: 'Online · Capture off' })).toBeVisible();
    await expect.element(page.getByRole('heading', { name: 'Direct passthrough' })).toBeVisible();
    await expect.element(page.getByText('No notary or evidence artifact')).toBeVisible();
  });

  test('shows public endpoints and deployment-managed updates in cluster mode', async () => {
    const fixture = createFixtureApi();
    const clusterStatus = {
      ...(await fixture.status()),
      runtime_profile: 'cluster',
      instance_id: 'notary-2',
      incarnation_id: '8a8a8a8a-1111-4222-8333-123456789abc',
      proxy_origin: 'https://proxy.notary.example',
      admin_origin: 'https://admin.notary.example',
      metadata_backend: 'postgres',
      artifact_backend: 's3',
      vault: 'shared cluster key',
    };
    renderDashboard('/settings', { ...fixture, status: async () => clusterStatus });
    await expect.element(page.getByRole('heading', { name: 'Cluster endpoints' })).toBeVisible();
    await expect
      .element(page.getByText('https://proxy.notary.example', { exact: true }))
      .toBeVisible();
    await expect.element(page.getByText('notary-2', { exact: true })).toBeVisible();
    await expect.element(page.getByText('Managed by deployment', { exact: true })).toBeVisible();
    await expect
      .element(page.getByText('https://proxy.notary.example/openai/v1', { exact: true }))
      .toBeVisible();
    await expect
      .element(page.getByText('Both listeners are restricted to loopback.', { exact: true }))
      .not.toBeInTheDocument();
  });

  test('renders pinned notary lifecycle records in trust order without health claims', async () => {
    const api: LocalApi = {
      ...createFixtureApi(),
      notaries: async () => ({
        ...structuredClone(fixtureNotaries),
        notaries: [...structuredClone(fixtureNotaries.notaries)].reverse(),
      }),
    };
    renderDashboard('/settings', api);
    await expect.element(page.getByRole('heading', { name: 'Configured trust' })).toBeVisible();
    await expect
      .element(page.getByRole('heading', { name: 'Accepts new captures and notarizations' }))
      .toBeVisible();
    await expect.element(page.getByRole('heading', { name: 'Notarization-only' })).toBeVisible();
    await expect
      .element(page.getByRole('heading', { name: 'Historical verification only' }))
      .toBeVisible();
    await expect.element(page.getByRole('heading', { name: 'Untrusted' })).toBeVisible();
    await expect
      .element(page.getByText('It does not accept new captures.', { exact: false }))
      .toBeVisible();
    await expect
      .element(
        page.getByText(
          'Revoked and not trusted for capture, notarization, or historical verification.',
        ),
      )
      .toBeVisible();
    await expect
      .poll(() =>
        Array.from(document.querySelectorAll('.local-notary-record h3')).map(
          (node) => node.textContent,
        ),
      )
      .toEqual([
        'Accepts new captures and notarizations',
        'Notarization-only',
        'Historical verification only',
        'Untrusted',
      ]);
    await expect.element(page.getByText('Online', { exact: true })).not.toBeInTheDocument();
  });

  test('distinguishes explicit self-hosted configuration from the Registry', async () => {
    const explicit: Notaries = {
      source: 'explicit_configuration',
      registry_source: null,
      generation: null,
      active_key_id: null,
      notaries: [
        {
          name: 'Configured Notary',
          operator: 'Local configuration',
          endpoint: 'tcp://127.0.0.1:7047',
          transport: 'tcp',
          key_id: 'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
          verification_key: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
          lifecycle: 'configured',
          valid_from_unix_ms: null,
          valid_until_unix_ms: null,
          notarize_until_unix_ms: null,
        },
      ],
    };
    renderDashboard('/settings', { ...createFixtureApi(), notaries: async () => explicit });
    await expect
      .element(page.getByRole('heading', { name: 'Explicit self-hosted configuration' }))
      .toBeVisible();
    await expect
      .element(page.getByText('are not members of the hosted Registry', { exact: false }))
      .toBeVisible();
    await expect
      .element(page.getByText('Registry generation', { exact: false }))
      .not.toBeInTheDocument();
  });

  test('renders a zero notary lower bound as an unbounded interval in settings', async () => {
    const notaries = structuredClone(fixtureNotaries);
    notaries.notaries[0].valid_from_unix_ms = 0;
    renderDashboard('/settings', { ...createFixtureApi(), notaries: async () => notaries });
    await expect.element(page.getByText('No lower bound configured')).toBeVisible();
    await expect.element(page.getByText(/1969|1970/)).not.toBeInTheDocument();
  });

  test('handles empty, malformed, and unavailable local notary trust without a false status', async () => {
    const empty: Notaries = {
      source: 'registry',
      registry_source: null,
      generation: null,
      active_key_id: null,
      notaries: [],
    };
    const view = renderDashboard('/settings', {
      ...createFixtureApi(),
      notaries: async () => empty,
    });
    await expect.element(page.getByText('No pinned notary records')).toBeVisible();
    view.unmount();

    renderDashboard('/settings', {
      ...createFixtureApi(),
      notaries: async () => {
        throw new LocalApiError(500, 'notary_trust_state_invalid', 'Invalid');
      },
    });
    await expect.element(page.getByText('Pinned trust state is malformed')).toBeVisible();
    cleanup();

    renderDashboard('/settings', {
      ...createFixtureApi(),
      notaries: async () => {
        throw new LocalApiError(503, 'request_failed', 'Unavailable');
      },
    });
    await expect.element(page.getByText('Local notary trust is unavailable')).toBeVisible();
    await expect.element(page.getByText('Online', { exact: true })).not.toBeInTheDocument();
  });

  test('queues a notarization and makes the durable operation visible', async () => {
    renderDashboard('/captures/trc-20260728-knowledge-eval');
    await page.getByRole('button', { name: 'Notarize', exact: true }).click();
    await expect
      .element(page.getByText('op-notarize-queued-fixture', { exact: true }))
      .toBeVisible();
    await expect.element(page.getByText('queued', { exact: true }).first()).toBeVisible();
  });

  test('shows concrete proof work instead of equal-sized stage progress', async () => {
    renderDashboard('/notarizations/op-notarize-safety-review');
    await expect
      .element(page.getByRole('progressbar', { name: 'Private transcript bytes authenticated' }))
      .toHaveAttribute('aria-valuenow', '612352');
    await expect.element(page.getByText('598.0 KB / 1.2 MB', { exact: true })).toBeVisible();
    await expect
      .element(page.getByText('4 / 10 commitments sealed', { exact: true }))
      .toBeVisible();
    await expect.element(page.getByText('47%', { exact: true })).toBeVisible();
  });

  test('explains why a provider authentication error cannot be notarized', async () => {
    renderDashboard('/captures/trc-20260728-auth-error');
    await expect.element(page.getByText('Provider response cannot be notarized')).toBeVisible();
    await expect
      .element(page.getByText('The provider returned HTTP 401.', { exact: false }))
      .toBeVisible();
    await expect.element(page.getByText('unsupported_provider_http_status')).toBeVisible();
    await expect
      .element(page.getByRole('button', { name: 'Notarize', exact: true }))
      .not.toBeInTheDocument();
    await expect
      .element(page.getByRole('button', { name: 'Retry notarization' }))
      .not.toBeInTheDocument();
  });

  test('shows independent trace verification feedback', async () => {
    renderDashboard('/traces/trc-20260727-research-brief');
    await expect
      .element(page.getByRole('button', { name: 'Download verified package' }))
      .toBeVisible();
    await page.getByRole('button', { name: 'Verify locally' }).click();
    await page.getByRole('tab', { name: 'Verification' }).click();
    await expect.element(page.getByText('Verification passed')).toBeVisible();
    await expect.element(page.getByText(/sha256:3828b21f/)).toBeVisible();
  });

  test('renders the disclosed prompt and response as a readable transcript', async () => {
    renderDashboard('/traces/trc-20260727-research-brief');
    await expect.element(page.getByRole('heading', { name: 'Prompt and response' })).toBeVisible();
    await expect.element(page.getByText(/Run 14 \(Source A\):/)).toBeVisible();
    await expect
      .element(page.getByText(/Use Run 15 as the reproducibility baseline/))
      .toBeVisible();
    await expect.element(page.getByText('assistant', { exact: true })).toBeVisible();
  });

  test('clears verification when a different trace is selected', async () => {
    renderDashboard('/traces/trc-20260727-research-brief');
    await page.getByRole('button', { name: 'Verify locally' }).click();
    await expect.element(page.getByText('Verification passed')).toBeVisible();
    window.location.hash = '/traces/trc-20260726-direct-link';
    await expect
      .element(page.getByRole('heading', { name: 'trc-20260726-direct-link' }))
      .toBeVisible();
    expect(
      document.querySelector('.document-panel [data-provider-icon="anthropic"]'),
    ).not.toBeNull();
    await expect.element(page.getByText('api.anthropic.com', { exact: true })).toBeVisible();
    await page.getByRole('tab', { name: 'Verification' }).click();
    await expect
      .element(page.getByRole('heading', { name: 'Run an independent check' }))
      .toBeVisible();
  });

  test('retries a failed capture through its durable operation', async () => {
    renderDashboard('/captures/trc-20260727-benchmark');
    await page.getByRole('button', { name: 'Retry notarization' }).click();
    await expect.element(page.getByText('op-notarize-benchmark', { exact: true })).toBeVisible();
    await expect.element(page.getByText('queued', { exact: true }).first()).toBeVisible();
  });

  test('shows capture notarization and durable attempt histories', async () => {
    renderDashboard('/captures/trc-20260727-benchmark');
    await expect.element(page.getByRole('heading', { name: 'Notarization history' })).toBeVisible();
    await expect.element(page.getByText('Attempt 2', { exact: true })).toBeVisible();
    await expect.element(page.getByText('Attempt 1', { exact: true })).toBeVisible();
    await expect.element(page.getByText('service_restarted')).toBeVisible();
  });

  test('labels operation fixtures and anchors their timestamps to the supplied clock', async () => {
    const now = Date.UTC(2030, 0, 2, 12, 0, 0);
    const api = createFixtureApi({ nowUnixMs: now });
    expect((await api.operation('op-notarize-safety-review')).started_at_unix_ms).toBe(
      now - 108_000,
    );
    renderDashboard('/notarizations/op-notarize-safety-review', api);
    await expect.element(page.getByText('Simulation only.', { exact: false })).toBeVisible();
    await expect
      .element(page.getByText('No proof worker is running.', { exact: false }))
      .toBeVisible();
  });

  test('advances a fixture notarization and keeps related state consistent', async () => {
    const api = createFixtureApi();
    const captureId = 'trc-20260728-knowledge-eval';
    const queued = await api.startNotarization('trc-20260728-knowledge-eval');
    expect(queued.operation.state).toBe('queued');
    expect(
      (await api.operations()).items.find(
        (item) => item.operation_id === queued.operation.operation_id,
      )?.state,
    ).toBe('queued');
    expect(
      (await api.traces({ state: 'notarized', limit: 200 })).items.some(
        (item) => item.trace_id === captureId,
      ),
    ).toBe(false);
    await expect(api.traceContent(captureId)).rejects.toMatchObject({
      code: 'notarized_trace_not_found',
    });
    expect((await api.operation(queued.operation.operation_id)).state).toBe('queued');
    expect(
      (await api.operations()).items.find(
        (item) => item.operation_id === queued.operation.operation_id,
      )?.state,
    ).toBe('queued');
    expect((await api.operation(queued.operation.operation_id)).state).toBe('running');
    expect(
      (await api.operations()).items.find(
        (item) => item.operation_id === queued.operation.operation_id,
      )?.state,
    ).toBe('running');
    expect((await api.trace(captureId)).status).toBe('notarizing');
    expect(
      (await api.traces({ state: 'notarized', limit: 200 })).items.some(
        (item) => item.trace_id === captureId,
      ),
    ).toBe(false);
    expect((await api.operation(queued.operation.operation_id)).state).toBe('succeeded');
    expect(
      (await api.operations()).items.find(
        (item) => item.operation_id === queued.operation.operation_id,
      )?.state,
    ).toBe('succeeded');
    const capture = await api.trace(captureId);
    expect(capture.state).toBe('notarized');
    expect(
      (await api.traces({ state: 'notarized', limit: 200 })).items.some(
        (item) => item.trace_id === captureId,
      ),
    ).toBe(true);
    expect(
      (await api.events()).items.some(
        (event) =>
          event.event_type === 'notarization_completed' &&
          event.trace_id === captureId &&
          event.operation_id === queued.operation.operation_id,
      ),
    ).toBe(true);

    const trace = await api.traceContent(captureId);
    const traceJson = JSON.stringify(trace.trace);
    expect(trace.trace_id).toBe(captureId);
    expect(trace.manifest).toMatchObject({
      source: { provider: { name: capture.provider, host: 'api.openai.com' } },
    });
    expect(traceJson).toContain(capture.requested_model);
    expect(traceJson).toContain(capture.prompt_preview);
    expect(traceJson).toContain(capture.output_preview);
    expect((await api.verify(captureId)).trace_id).toBe(captureId);
    expect((await api.share(captureId, 'unlisted')).trace_id).toBe(captureId);
    const initialShare = await api.shareStatus(captureId);
    expect(initialShare.progress).toBe('preparing');
    expect((await api.shareStatus(captureId)).progress).toBe('verifying');
    const admitted = await api.shareStatus(captureId);
    expect(admitted.progress).toBe('shared');
    expect(admitted.share_url).toContain('/traces/share-fixture');

    renderDashboard(`/traces/${captureId}`, api);
    await expect.element(page.getByRole('heading', { name: captureId })).toBeVisible();
    expect(document.querySelector('.document-panel [data-provider-icon="openai"]')).not.toBeNull();
    await expect.element(page.getByText('api.openai.com', { exact: true })).toBeVisible();
    await expect.element(page.getByText(capture.prompt_preview)).toBeVisible();
    await expect.element(page.getByText(capture.output_preview)).toBeVisible();
  });

  test('keeps a pending account authorization visible until approval and defaults to Unlisted', async () => {
    const api = createFixtureApi();
    let polls = 0;
    let sharedCapture: string | null = null;
    let chosenVisibility: string | null = null;
    const sharingApi: LocalApi = {
      ...api,
      account: async () => ({ signed_in: false }),
      startAccountConnection: async () => ({
        request_id: 'auth-test',
        user_code: 'TEST-123',
        verification_uri_complete: '#/sharing',
        expires_in_seconds: 600,
        poll_interval_seconds: 0,
        state: 'pending',
      }),
      pollAccountConnection: async () =>
        ++polls === 1
          ? { signed_in: false }
          : {
              signed_in: true,
              provider_display_name: 'approved-user',
              device_name: 'Local dashboard',
              credential_kind: 'cli_session',
              credential_name: 'Local dashboard',
            },
      share: async (captureId, visibility) => {
        sharedCapture = captureId;
        chosenVisibility = visibility;
        return {
          trace_id: captureId,
          share_id: 'share-fixture',
          progress: 'preparing',
          visibility,
          access_enabled: true,
          password_protected: false,
          updated_at_unix_ms: Date.now(),
          share_url: null,
          package_url: null,
        };
      },
    };
    renderDashboard('/sharing', sharingApi);
    await page.getByRole('button', { name: 'Connect account' }).click();
    await expect.element(page.getByText('TEST-123')).toBeVisible();
    await expect
      .element(page.getByRole('link', { name: 'Open approval page' }))
      .not.toBeInTheDocument();
    await expect.element(page.getByRole('button', { name: 'Check approval' })).toBeEnabled();
    await page.getByRole('button', { name: 'Check approval' }).click();
    await expect.element(page.getByText('TEST-123')).toBeVisible();
    await page.getByRole('button', { name: 'Check approval' }).click();
    await expect.element(page.getByText('approved-user')).toBeVisible();
    await page.getByRole('button', { name: 'Share trace' }).click();
    await page.getByRole('button', { name: 'Create share' }).click();
    await expect.element(page.getByText('share-fixture')).toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Refresh status' })).toBeVisible();
    expect(sharedCapture).toBe('trc-20260727-research-brief');
    expect(chosenVisibility).toBe('unlisted');
  });

  test('identifies API-key mode without offering browser authorization', async () => {
    const api: LocalApi = {
      ...createFixtureApi(),
      account: async () => ({
        signed_in: true,
        provider_display_name: 'automation-user',
        credential_kind: 'api_key',
        credential_name: 'Nightly CI',
      }),
    };

    renderDashboard('/sharing', api);
    await expect.element(page.getByText('automation-user')).toBeVisible();
    await expect.element(page.getByText('Nightly CI')).toBeVisible();
    await expect.element(page.getByText('API key', { exact: true })).toBeVisible();
    await expect
      .element(page.getByRole('button', { name: 'Connect account' }))
      .not.toBeInTheDocument();
  });

  test('completes the documentation sharing flow without external services', async () => {
    renderDashboard('/sharing');
    await expect.element(page.getByText('Sample data')).toBeVisible();
    await expect.element(page.getByText('sample-user')).toBeVisible();
    await expect.element(page.getByText(/demo account/i)).not.toBeInTheDocument();
    await expect.element(page.getByRole('heading', { name: 'Prompt and response' })).toBeVisible();
    await page.getByRole('button', { name: 'Share trace' }).click();
    await expect
      .element(page.getByText('Anyone with the URL can read', { exact: false }))
      .toBeVisible();
    await page.getByRole('button', { name: 'Create share' }).click();
    await expect.element(page.getByText('preparing', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Refresh status' }).click();
    await expect.element(page.getByText('verifying', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Refresh status' }).click();
    await expect.element(page.getByText('shared', { exact: true })).toBeVisible();
    await expect.element(page.getByRole('heading', { name: 'Share ready' })).toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Copy URL' })).toBeVisible();
    await page.getByRole('button', { name: 'Open local trace' }).click();
    await expect.element(page.getByRole('heading', { name: 'Prompt and response' })).toBeVisible();
  });

  test('shows the authentication gate after a 401 status response', async () => {
    const api: LocalApi = {
      ...createFixtureApi(),
      status: async () => {
        throw new LocalApiError(401, 'unauthorized', 'Unauthorized');
      },
    };
    renderDashboard('/overview', api);
    await expect.element(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  });

  test('exchanges configured credentials for a dashboard session', async () => {
    let credentials: [string, string] | undefined;
    const api: LocalApi = {
      ...createFixtureApi(),
      status: async () => {
        throw new LocalApiError(401, 'unauthorized', 'Unauthorized');
      },
      session: async (username, password) => {
        credentials = [username, password];
      },
    };
    renderDashboard('/overview', api);
    await page.getByLabelText('Username').fill('local-admin');
    await page.getByRole('textbox', { name: 'Password' }).fill('correct horse battery staple');
    await page.getByRole('button', { name: 'Open dashboard' }).click();
    await expect.poll(() => credentials).toEqual(['local-admin', 'correct horse battery staple']);
  });

  test('does not show stale online state after a status failure', async () => {
    const api: LocalApi = {
      ...createFixtureApi(),
      status: async () => {
        throw new LocalApiError(503, 'service_unavailable', 'Unavailable');
      },
    };
    renderDashboard('/overview', api);
    await expect
      .element(page.getByRole('heading', { name: 'The local service is unavailable' }))
      .toBeVisible();
    await expect.element(page.getByText('Online', { exact: true })).not.toBeInTheDocument();
  });

  test('uses an accessible drawer at the mobile breakpoint', async () => {
    await page.viewport(800, 760);
    renderDashboard();
    await page.getByRole('button', { name: 'Open navigation' }).click();
    await expect.element(page.getByRole('dialog')).toBeVisible();
    await expect.element(page.getByText('Sample data')).toBeVisible();
    await page
      .getByRole('dialog')
      .getByRole('button', { name: /Activity/ })
      .click();
    await expect.element(page.getByRole('combobox', { name: 'Activity severity' })).toBeVisible();
  });

  test('does not repeat service status in the dashboard shell', async () => {
    renderDashboard();
    await expect.element(page.getByText('Admin 127.0.0.1:8788')).not.toBeInTheDocument();
    await expect.element(page.getByText('Online', { exact: true })).not.toBeInTheDocument();
  });

  test('sends activity filters to the service', async () => {
    const api: LocalApi = createFixtureApi();
    let receivedFilters: Record<string, string | number | boolean | undefined> = {};
    const filteredApi: LocalApi = {
      ...api,
      events: async (filters = {}) => {
        receivedFilters = filters;
        return api.events(filters);
      },
    };
    renderDashboard('/activity', filteredApi);
    await page.getByLabelText('Activity event type').fill('notarization_completed');
    await expect.poll(() => receivedFilters.event_type).toBe('notarization_completed');
    await expect.element(page.getByText('Notarization completed').first()).toBeVisible();
    await expect.element(page.getByText('Notarization failed')).not.toBeInTheDocument();
  });

  test('uses separate trace list and detail views on mobile', async () => {
    await page.viewport(390, 760);
    renderDashboard('/traces');
    await expect.element(page.getByRole('listitem').first()).toBeVisible();
    await expect
      .element(page.getByRole('button', { name: 'Verify locally' }))
      .not.toBeInTheDocument();
    await page.getByRole('list', { name: 'Notarized traces' }).getByRole('button').first().click();
    await expect.element(page.getByRole('button', { name: 'All notarized traces' })).toBeVisible();
    await expect.element(page.getByRole('listitem')).not.toBeInTheDocument();
  });

  test('shares an adjustable list width across split views', async () => {
    await page.viewport(1280, 800);
    renderDashboard('/captures');
    const divider = page.getByRole('separator', { name: 'Resize list and detail panels' });
    await expect.element(divider).toHaveAttribute('aria-valuenow', '320');
    document.querySelector<HTMLElement>('[role="separator"]')?.focus();
    await userEvent.keyboard('{ArrowRight}');
    await expect.element(divider).toHaveAttribute('aria-valuenow', '336');
    expect(localStorage.getItem('llm-notary-dashboard-split-width')).toBe('336');

    window.location.hash = '/notarizations';
    await expect.element(page.getByRole('list', { name: 'Notarizations' })).toBeVisible();
    await expect
      .element(page.getByRole('separator', { name: 'Resize list and detail panels' }))
      .toHaveAttribute('aria-valuenow', '336');
  });
});
