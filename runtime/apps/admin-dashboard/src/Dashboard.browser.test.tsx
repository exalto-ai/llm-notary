import { createTheme, MantineProvider } from '@mantine/core';
import { Notifications, notifications } from '@mantine/notifications';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { page, userEvent } from 'vitest/browser';
import { type LocalApi, LocalApiError, type TraceSummary } from './api';
import { Dashboard } from './Dashboard';
import { createFixtureApi, fixtureCaptures, fixtureNotaries } from './fixtures';
import '@mantine/core/styles.css';
import '@mantine/notifications/styles.css';

const theme = createTheme({ defaultRadius: 0, primaryColor: 'dark' });

function renderDashboard(hash = '/overview', api: LocalApi = createFixtureApi(), embedded = false) {
  window.location.hash = hash;
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MantineProvider theme={theme} defaultColorScheme="auto">
      <Notifications />
      <QueryClientProvider client={queryClient}>
        <Dashboard api={api} fixture embedded={embedded} />
      </QueryClientProvider>
    </MantineProvider>,
  );
}

beforeEach(() => localStorage.clear());
afterEach(() => {
  notifications.clean();
  notifications.cleanQueue();
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('Notary admin dashboard', () => {
  test('exposes exactly the five Milestone 2 destinations', async () => {
    renderDashboard();
    await expect
      .poll(() =>
        Array.from(document.querySelectorAll('.local-topbar nav button')).map((node) =>
          node.textContent?.replace(/\s+/g, '').trim(),
        ),
      )
      .toEqual(['Overview', 'Traces4', 'Activity', 'Providers', 'Settings']);
    await expect.element(page.getByText('Captures', { exact: true })).not.toBeInTheDocument();
    await expect.element(page.getByText('Notarizations', { exact: true })).not.toBeInTheDocument();
    await expect.element(page.getByText('Share', { exact: true })).not.toBeInTheDocument();
  });

  test('does not preserve aliases for removed routes', async () => {
    renderDashboard('/captures/trc-20260727-benchmark');
    await expect.element(page.getByRole('heading', { name: 'Online' })).toBeVisible();
    await expect.element(page.getByLabelText('Search traces')).not.toBeInTheDocument();
  });

  test('shows the four canonical trace counts and routes all of them to Traces', async () => {
    renderDashboard();
    await expect
      .poll(() =>
        Array.from(document.querySelectorAll('.count-strip button')).map((node) =>
          node.textContent?.replace(/\s+/g, ' ').trim(),
        ),
      )
      .toEqual(['4Captured', '1Notarizing', '2Notarized', '1Needs attention']);
    await page.getByRole('button', { name: /Notarizing/ }).click();
    await expect.element(page.getByLabelText('Search traces')).toBeVisible();
  });

  test('filters the unified trace collection and opens a trace', async () => {
    renderDashboard('/traces');
    await page.getByLabelText('Search traces').fill('**benchmark**');
    await expect.element(page.getByText('deepseek-v4-flash')).toBeVisible();
    await expect.element(page.getByText('gpt-5.2', { exact: true })).not.toBeInTheDocument();
    await page.getByRole('list', { name: 'Traces' }).getByRole('button').click();
    await expect.element(page.getByText('trc-20260727-benchmark').first()).toBeVisible();
  });

  test('keeps lifecycle primary while placing operational filters under More filters', async () => {
    renderDashboard('/traces?status=notarizing');
    await expect.element(page.getByRole('button', { name: 'All', exact: true })).toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Captured', exact: true })).toBeVisible();
    await expect
      .element(page.getByRole('button', { name: 'Notarized', exact: true }))
      .toBeVisible();
    await expect.element(page.getByRole('combobox', { name: 'Provider filter' })).toBeVisible();
    await expect.element(page.getByRole('combobox', { name: 'Trace time filter' })).toBeVisible();
    await expect
      .element(page.getByRole('combobox', { name: 'Operational status filter' }))
      .toBeVisible();
    await expect.element(page.getByText('notarizing', { exact: true }).first()).toBeVisible();

    cleanup();
    renderDashboard('/traces');
    await expect
      .element(page.getByRole('combobox', { name: 'Operational status filter' }))
      .not.toBeInTheDocument();
    await page.getByRole('button', { name: 'More filters' }).click();
    await expect.element(page.getByLabelText('Model filter')).toBeVisible();
    await expect.element(page.getByRole('combobox', { name: 'Streaming filter' })).toBeVisible();
  });

  test('uses the provider identity when no private prompt preview is retained', async () => {
    const fixture = createFixtureApi();
    const fallback: TraceSummary = {
      ...structuredClone(fixtureCaptures[0]),
      prompt_preview: '',
      provider: 'openai',
      state: 'captured',
      status: 'notarizing',
    };
    const api: LocalApi = {
      ...fixture,
      traces: async () => ({ items: [fallback], next_cursor: null }),
      trace: async () => ({ ...(await fixture.trace(fallback.trace_id)), ...fallback }),
    };
    renderDashboard('/traces', api);
    await expect.element(page.getByText('OpenAI request', { exact: true }).first()).toBeVisible();
    await expect
      .element(page.getByText('Captured · Notarizing', { exact: true }).first())
      .toBeVisible();
  });

  test('loads another trace cursor without downloading the catalog', async () => {
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
    renderDashboard('/traces', api);
    await page.getByRole('button', { name: 'Load more traces' }).click();
    await expect.poll(() => cursors).toContain('fixture:next');
    await expect.element(page.getByText(samples[1].requested_model ?? '')).toBeVisible();
  });

  test('opens notarized evidence from the same trace route', async () => {
    renderDashboard('/traces/trc-20260727-research-brief');
    await expect
      .element(page.getByRole('heading', { name: 'Prompt and response preview' }))
      .toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Verify locally' })).toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Export .llmtrace' })).toBeVisible();
    await expect.element(page.getByRole('tab', { name: 'Summary' })).toBeVisible();
    await expect.element(page.getByRole('tab', { name: 'Notarization' })).toBeVisible();
    await expect.element(page.getByRole('tab', { name: 'Evidence' })).toBeVisible();
    await expect.element(page.getByRole('tab', { name: 'Technical' })).toBeVisible();
    await expect.element(page.getByText('Private on this device', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Share' }).click();
    await expect.element(page.getByText('Anyone with the URL can read')).toBeVisible();
    await page.getByRole('button', { name: 'Create unlisted share' }).click();
    await expect.element(page.getByText('Unlisted share', { exact: true })).toBeVisible();
  });

  test('shows private Captured detail, progress, retry, and ineligibility in one inspector', async () => {
    renderDashboard('/traces/trc-20260728-safety-review');
    await expect.element(page.getByText('Private on this device', { exact: true })).toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Copy Trace ID' })).toBeVisible();
    await page.getByRole('tab', { name: 'Notarization' }).click();
    await expect
      .element(page.getByRole('progressbar', { name: 'Private transcript bytes authenticated' }))
      .toHaveAttribute('aria-valuenow', '612352');
    await expect.element(page.getByText('Attempt 1', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'View Trace activity' }).click();
    await expect
      .element(page.getByLabelText('Activity trace ID'))
      .toHaveValue('trc-20260728-safety-review');

    cleanup();
    renderDashboard('/traces/trc-20260727-benchmark');
    await expect.element(page.getByRole('button', { name: 'Retry notarization' })).toBeVisible();
    await page.getByRole('tab', { name: 'Notarization' }).click();
    await expect.element(page.getByText('Attempt 2', { exact: true })).toBeVisible();
    await expect.element(page.getByText('notary_capacity', { exact: true }).first()).toBeVisible();

    cleanup();
    renderDashboard('/traces/trc-20260728-auth-error');
    await expect
      .element(page.getByText('Provider response cannot be notarized', { exact: true }))
      .toBeVisible();
    await expect
      .element(page.getByRole('button', { name: 'Notarize', exact: true }))
      .not.toBeInTheDocument();
  });

  test('moves a Trace atomically from Captured to Notarized on the same route', async () => {
    const fixture = createFixtureApi();
    const captured = structuredClone(fixtureCaptures[0]);
    const packageTemplate = await fixture.traceContent('trc-20260727-research-brief');
    let current: TraceSummary = captured;
    let packageReads = 0;
    const api: LocalApi = {
      ...fixture,
      traces: async () => ({ items: [current], next_cursor: null }),
      trace: async () => ({ ...(await fixture.trace(captured.trace_id)), ...current }),
      startNotarization: async (traceId) => {
        const result = await fixture.startNotarization(traceId);
        current = { ...current, state: 'notarized', status: null };
        return result;
      },
      traceContent: async (traceId) => {
        packageReads += 1;
        return { ...packageTemplate, trace_id: traceId };
      },
    };
    renderDashboard(`/traces/${captured.trace_id}`, api);
    await expect.element(page.getByRole('button', { name: 'Notarize', exact: true })).toBeVisible();
    expect(packageReads).toBe(0);
    await page.getByRole('button', { name: 'Notarize', exact: true }).click();
    await expect.element(page.getByRole('button', { name: 'Export .llmtrace' })).toBeVisible();
    expect(window.location.hash).toBe(`#/traces/${captured.trace_id}`);
    expect(packageReads).toBeGreaterThan(0);
  });

  test('exports the exact package bytes with the canonical Trace identity', async () => {
    const fixture = createFixtureApi();
    const traceId = 'trc-20260727-research-brief';
    const packageBytes = new Blob(['exact package bytes'], { type: 'application/zip' });
    const downloadPackage = vi.fn(async () => packageBytes);
    const createObjectURL = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:exact-package');
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
    let downloadedAs = '';
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      downloadedAs = this.download;
    });
    renderDashboard(`/traces/${traceId}`, { ...fixture, downloadPackage });
    await page.getByRole('button', { name: 'Export .llmtrace' }).click();
    await expect.poll(() => downloadPackage).toHaveBeenCalledWith(traceId);
    expect(createObjectURL).toHaveBeenCalledWith(packageBytes);
    expect(downloadedAs).toBe(`${traceId}.llmtrace`);
  });

  test('uses explicit empty, loading, and error states for the trace collection', async () => {
    const fixture = createFixtureApi();
    const emptyApi: LocalApi = {
      ...fixture,
      traces: async () => ({ items: [], next_cursor: null }),
    };
    renderDashboard('/traces', emptyApi);
    await expect
      .element(page.getByRole('heading', { name: 'No traces have been captured yet.' }))
      .toBeVisible();
    await page.getByRole('button', { name: 'Captured', exact: true }).click();
    await expect
      .element(
        page.getByRole('heading', { name: 'No traces are currently in the Captured state.' }),
      )
      .toBeVisible();
    await page.getByRole('button', { name: 'Notarized', exact: true }).click();
    await expect
      .element(page.getByRole('heading', { name: 'No traces have been notarized yet.' }))
      .toBeVisible();
    await page.getByLabelText('Search traces').fill('missing');
    await expect
      .element(page.getByRole('heading', { name: 'No traces match these filters.' }))
      .toBeVisible();

    cleanup();
    renderDashboard('/traces', {
      ...fixture,
      traces: async () => {
        throw new LocalApiError(503, 'service_unavailable', 'Unavailable');
      },
    });
    await expect
      .element(page.getByRole('heading', { name: 'Traces are unavailable' }))
      .toBeVisible();

    cleanup();
    renderDashboard('/traces', {
      ...fixture,
      traces: () => new Promise(() => undefined),
    });
    await expect.element(page.getByText('Loading local evidence', { exact: true })).toBeVisible();
  });

  test('uses the generated Trace date-filter contract', async () => {
    const fixture = createFixtureApi();
    const filters: Array<Parameters<LocalApi['traces']>[0]> = [];
    const api: LocalApi = {
      ...fixture,
      traces: async (next = {}) => {
        filters.push(next);
        return fixture.traces(next);
      },
    };
    renderDashboard('/traces', api);
    await page.getByLabelText('Trace time filter').click();
    await page.getByRole('option', { name: 'Last 24 hours' }).click();
    await expect.poll(() => filters.at(-1)?.created_from_unix_ms).toBeTypeOf('number');
  });

  test('lists provider allowlist entries, readiness, and SDK base URLs', async () => {
    renderDashboard('/providers');
    await expect.element(page.getByRole('heading', { name: 'Providers' })).toBeVisible();
    await expect.element(page.getByText('Local admin').first()).toBeVisible();
    await expect.element(page.getByRole('heading', { name: 'OpenAI' })).toBeVisible();
    await expect.element(page.getByText('api.openai.com', { exact: true }).first()).toBeVisible();
    await expect.element(page.getByText('http://127.0.0.1:8787/openai/v1')).toBeVisible();
    await expect.element(page.getByText('Ready', { exact: true }).first()).toBeVisible();
  });

  test('keeps provider routes out of Settings and preserves the required group order', async () => {
    renderDashboard('/settings');
    await expect
      .poll(() =>
        Array.from(document.querySelectorAll('.settings-group-title')).map(
          (heading) => heading.textContent,
        ),
      )
      .toEqual([
        'General',
        'Account',
        'Notarization',
        'Security & storage',
        'Service',
        'Developer',
      ]);
    await expect.element(page.getByText('Proxy base URLs')).not.toBeInTheDocument();
  });

  test('changes capture behavior and persists an explicit theme', async () => {
    const api = createFixtureApi();
    renderDashboard('/settings', api);
    const toggle = page.getByRole('switch', { name: 'Capture requests' });
    await toggle.click();
    await expect.element(toggle).not.toBeChecked();
    await expect
      .element(page.getByText('Off — requests still pass through', { exact: false }))
      .toBeVisible();
    await expect.poll(async () => (await api.captureSetting()).enabled).toBe(false);
    await page.getByRole('button', { name: 'Dark color scheme' }).click();
    expect(localStorage.getItem('mantine-color-scheme-value')).toBe('dark');
  });

  test('turns capture on directly from Overview', async () => {
    const fixture = createFixtureApi();
    let captureEnabled = false;
    const api: LocalApi = {
      ...fixture,
      status: async () => ({
        ...(await fixture.status()),
        capture_enabled: captureEnabled,
        counts: {
          captured: 0,
          notarizing: 0,
          notarized: 0,
          needs_attention: 0,
          capturing: 0,
          capture_failed: 0,
        },
      }),
      updateCaptureSetting: async (enabled) => {
        captureEnabled = enabled;
        return { enabled };
      },
    };
    renderDashboard('/overview', api);
    await page.getByRole('button', { name: 'Turn capture on' }).click();
    await expect.poll(() => captureEnabled).toBe(true);
    await expect.element(page.getByRole('button', { name: 'View providers' })).toBeVisible();
  });

  test('shows pinned notary lifecycle records in trust order without health claims', async () => {
    const api: LocalApi = {
      ...createFixtureApi(),
      notaries: async () => ({
        ...structuredClone(fixtureNotaries),
        notaries: [...structuredClone(fixtureNotaries.notaries)].reverse(),
      }),
    };
    renderDashboard('/settings', api);
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

  test('renders cluster administration context without making local-only claims', async () => {
    const fixture = createFixtureApi();
    const clusterStatus = {
      ...(await fixture.status()),
      runtime_profile: 'cluster',
      instance_id: 'notary-2',
      proxy_origin: 'https://proxy.notary.example',
      admin_origin: 'https://admin.notary.example',
      metadata_backend: 'postgres',
      artifact_backend: 's3',
      vault: 'shared cluster key',
    };
    const api: LocalApi = {
      ...fixture,
      status: async () => clusterStatus,
      providers: async () => ({
        providers: [
          {
            id: 'openai',
            name: 'OpenAI',
            host: 'api.openai.com',
            client_api: 'responses',
            route_prefix: '/openai/v1',
            proxy_base_url: 'https://proxy.notary.example/openai/v1',
            ready: true,
          },
        ],
      }),
    };
    renderDashboard('/providers', api);
    await expect.element(page.getByText('Cluster admin').first()).toBeVisible();
    await expect.element(page.getByText('https://proxy.notary.example/openai/v1')).toBeVisible();
    cleanup();
    renderDashboard('/settings', api);
    await expect.element(page.getByRole('heading', { name: 'Cluster endpoints' })).toBeVisible();
    await expect.element(page.getByText('notary-2', { exact: true })).toBeVisible();
    await expect
      .element(page.getByText('Both listeners are restricted to loopback.', { exact: true }))
      .not.toBeInTheDocument();
    await expect.element(page.getByText('Cluster admin')).toBeVisible();
  });

  test('keeps admin authentication distinct from the hosted Account setting', async () => {
    const api: LocalApi = {
      ...createFixtureApi(),
      status: async () => {
        throw new LocalApiError(401, 'unauthorized', 'Unauthorized');
      },
    };
    renderDashboard('/overview', api);
    await expect.element(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
    await expect
      .element(page.getByText('credentials configured under admin.auth', { exact: false }))
      .toBeVisible();
    await expect.element(page.getByText('Hosted account connection')).not.toBeInTheDocument();
    await expect.element(page.getByText('Loopback only')).not.toBeInTheDocument();
  });

  test('does not show stale readiness after a status failure', async () => {
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

  test('uses the same route content in embedded mode without standalone navigation', async () => {
    renderDashboard('/providers', createFixtureApi(), true);
    await expect.element(page.getByRole('heading', { name: 'Providers' })).toBeVisible();
    await expect
      .element(page.getByRole('navigation', { name: 'Admin dashboard' }))
      .not.toBeInTheDocument();
  });

  test('uses an accessible navigation drawer on narrow screens', async () => {
    await page.viewport(800, 760);
    renderDashboard();
    await page.getByRole('button', { name: 'Open navigation' }).click();
    const drawer = page.getByRole('dialog');
    await expect.element(drawer).toBeVisible();
    await drawer.getByRole('button', { name: /Activity/ }).click();
    await expect.element(page.getByRole('combobox', { name: 'Activity severity' })).toBeVisible();
  });

  test('sends activity filters to the service', async () => {
    const fixture = createFixtureApi();
    let receivedFilters: Record<string, string | number | boolean | undefined> = {};
    const api: LocalApi = {
      ...fixture,
      events: async (filters = {}) => {
        receivedFilters = filters;
        return fixture.events(filters);
      },
    };
    renderDashboard('/activity', api);
    await page.getByLabelText('Activity event type').fill('notarization_completed');
    await expect.poll(() => receivedFilters.event_type).toBe('notarization_completed');
    await expect.element(page.getByText('Notarization completed').first()).toBeVisible();
    await expect.element(page.getByText('Notarization failed')).not.toBeInTheDocument();
  });

  test('uses a separate trace list and detail view on mobile', async () => {
    await page.viewport(390, 760);
    renderDashboard('/traces');
    await expect.element(page.getByRole('list', { name: 'Traces' })).toBeVisible();
    await page.getByRole('list', { name: 'Traces' }).getByRole('button').first().click();
    await expect.element(page.getByRole('button', { name: 'All traces' })).toBeVisible();
    await expect.element(page.getByRole('list', { name: 'Traces' })).not.toBeInTheDocument();
  });

  test('persists the adjustable trace list width', async () => {
    await page.viewport(1280, 800);
    renderDashboard('/traces');
    const divider = page.getByRole('separator', { name: 'Resize list and detail panels' });
    await expect.element(divider).toHaveAttribute('aria-valuenow', '320');
    document.querySelector<HTMLElement>('[role="separator"]')?.focus();
    await userEvent.keyboard('{ArrowRight}');
    await expect.element(divider).toHaveAttribute('aria-valuenow', '336');
    expect(localStorage.getItem('notary-admin-dashboard-split-width')).toBe('336');
  });

  test('preserves a persisted Listed share without changing its visibility', async () => {
    const traceId = 'trc-20260727-research-brief';
    const api = createFixtureApi({
      initialShare: { traceId, visibility: 'listed', accessEnabled: true },
    });
    renderDashboard(`/traces/${traceId}`, api);

    await expect.element(page.getByText('Listed share', { exact: true })).toBeVisible();
    await expect
      .element(page.getByText('This disclosed Trace is publicly listed and readable.'))
      .toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Copy URL' })).toBeVisible();
    await expect
      .element(page.getByRole('button', { name: 'Share', exact: true }))
      .not.toBeInTheDocument();
  });

  test('does not present an access-disabled share as publicly readable', async () => {
    const traceId = 'trc-20260727-research-brief';
    const api = createFixtureApi({
      initialShare: { traceId, visibility: 'unlisted', accessEnabled: false },
    });
    renderDashboard(`/traces/${traceId}`, api);

    await expect.element(page.getByText('Public access is disabled for this share.')).toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Stop sharing' })).toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Copy URL' })).not.toBeInTheDocument();
    await expect
      .element(page.getByRole('button', { name: 'Share', exact: true }))
      .not.toBeInTheDocument();
  });

  test('keeps the last persisted share visible when status refresh fails', async () => {
    const traceId = 'trc-20260727-research-brief';
    const fixture = createFixtureApi({
      initialShare: { traceId, visibility: 'unlisted', accessEnabled: true },
    });
    const api: LocalApi = {
      ...fixture,
      shareStatus: async () => {
        throw new LocalApiError(503, 'share_status_unavailable', 'Unavailable');
      },
    };
    renderDashboard(`/traces/${traceId}`, api);

    await expect.element(page.getByText('Unlisted share', { exact: true })).toBeVisible();
    await expect
      .element(page.getByText('Could not refresh share status. Showing the last known state.'))
      .toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Stop sharing' })).toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Retry status' })).toBeVisible();
    await expect
      .element(page.getByRole('button', { name: 'Share', exact: true }))
      .not.toBeInTheDocument();
  });

  test('restores a persisted share when the Trace inspector reloads', async () => {
    const traceId = 'trc-20260727-research-brief';
    const api = createFixtureApi();
    await api.share(traceId, 'unlisted');
    await api.shareStatus(traceId);
    await api.shareStatus(traceId);
    await api.shareStatus(traceId);

    renderDashboard(`/traces/${traceId}`, api);
    await expect.element(page.getByRole('button', { name: 'Copy URL' })).toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Stop sharing' })).toBeVisible();

    cleanup();
    renderDashboard(`/traces/${traceId}`, api);
    await expect.element(page.getByRole('button', { name: 'Copy URL' })).toBeVisible();
    await page.getByRole('button', { name: 'Stop sharing' }).click();
    await expect
      .element(page.getByRole('button', { name: 'Stop sharing' }))
      .not.toBeInTheDocument();
  });
});
