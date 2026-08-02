import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { page, userEvent } from 'vitest/browser';
import { cleanup, render } from '@testing-library/react';
import { MantineProvider, createTheme } from '@mantine/core';
import { Notifications } from '@mantine/notifications';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Dashboard } from './Dashboard';
import { createFixtureApi } from './fixtures';
import { LocalApiError, type LocalApi } from './api';
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
    </MantineProvider>
  );
}

beforeEach(() => localStorage.clear());
afterEach(() => cleanup());

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
    await expect.element(page.getByText('cap-20260727-benchmark')).toBeVisible();
  });

  test('persists an explicit theme and can return to system mode', async () => {
    renderDashboard('/settings');
    await page.getByRole('button', { name: 'Dark color scheme' }).click();
    await expect.poll(() => document.documentElement.dataset.mantineColorScheme).toBe('dark');
    expect(localStorage.getItem('mantine-color-scheme-value')).toBe('dark');
    await page.getByRole('button', { name: 'System color scheme' }).click();
    expect(localStorage.getItem('mantine-color-scheme-value')).toBe('auto');
  });

  test('queues a finalization and makes the durable operation visible', async () => {
    renderDashboard('/captures/cap-20260728-knowledge-eval');
    await page.getByRole('button', { name: 'Finalize', exact: true }).click();
    await expect.element(page.getByText('op-finalize-queued-fixture', { exact: true })).toBeVisible();
    await expect.element(page.getByText('queued', { exact: true }).first()).toBeVisible();
  });

  test('shows independent trace verification feedback', async () => {
    renderDashboard('/traces/cap-20260727-research-brief');
    await page.getByRole('button', { name: 'Verify now' }).click();
    await page.getByRole('tab', { name: 'Verification' }).click();
    await expect.element(page.getByText('Verification passed')).toBeVisible();
    await expect.element(page.getByText(/sha256:3828b21f/)).toBeVisible();
  });

  test('renders the disclosed prompt and response as a readable transcript', async () => {
    renderDashboard('/traces/cap-20260727-research-brief');
    await expect.element(page.getByRole('heading', { name: 'Prompt and response' })).toBeVisible();
    await expect.element(page.getByText(/Run 14 \(Source A\):/)).toBeVisible();
    await expect.element(page.getByText(/Use Run 15 as the reproducibility baseline/)).toBeVisible();
    await expect.element(page.getByText('assistant', { exact: true })).toBeVisible();
  });

  test('clears verification when a different trace is selected', async () => {
    renderDashboard('/traces/cap-20260727-research-brief');
    await page.getByRole('button', { name: 'Verify now' }).click();
    await expect.element(page.getByText('Verification passed')).toBeVisible();
    window.location.hash = '/traces/cap-direct-link';
    await expect.element(page.getByRole('heading', { name: 'cap-direct-link' })).toBeVisible();
    await page.getByRole('tab', { name: 'Verification' }).click();
    await expect.element(page.getByRole('heading', { name: 'Run an independent check' })).toBeVisible();
  });

  test('retries a failed capture through its durable operation', async () => {
    renderDashboard('/captures/cap-20260727-benchmark');
    await page.getByRole('button', { name: 'Retry finalization' }).click();
    await expect.element(page.getByText('op-finalize-benchmark', { exact: true })).toBeVisible();
    await expect.element(page.getByText('queued', { exact: true }).first()).toBeVisible();
  });

  test('shows capture finalization and durable attempt histories', async () => {
    renderDashboard('/captures/cap-20260727-benchmark');
    await expect.element(page.getByRole('heading', { name: 'Finalization history' })).toBeVisible();
    await page.getByRole('button', { name: 'Inspect' }).click();
    await expect.element(page.getByText('Attempt 2', { exact: true })).toBeVisible();
    await expect.element(page.getByText('Attempt 1', { exact: true })).toBeVisible();
    await expect.element(page.getByText('service_restarted')).toBeVisible();
  });

  test('labels operation fixtures and anchors their timestamps to the supplied clock', async () => {
    const now = Date.UTC(2030, 0, 2, 12, 0, 0);
    const api = createFixtureApi({ nowUnixMs: now });
    expect((await api.operation('op-finalize-safety-review')).started_at_unix_ms).toBe(now - 108_000);
    renderDashboard('/finalizations/op-finalize-safety-review', api);
    await expect.element(page.getByText('Simulation only.', { exact: false })).toBeVisible();
    await expect.element(page.getByText('No proof worker is running.', { exact: false })).toBeVisible();
  });

  test('advances a fixture finalization and keeps related state consistent', async () => {
    const api = createFixtureApi();
    const queued = await api.startFinalization('cap-20260728-knowledge-eval');
    expect(queued.operation.state).toBe('queued');
    expect((await api.operations()).items.find((item) => item.operation_id === queued.operation.operation_id)?.state).toBe('queued');
    expect((await api.operations()).items.find((item) => item.operation_id === queued.operation.operation_id)?.state).toBe('running');
    expect((await api.operations()).items.find((item) => item.operation_id === queued.operation.operation_id)?.state).toBe('finalized');
    expect((await api.capture('cap-20260728-knowledge-eval')).capture.finalization_state).toBe('finalized');
    expect((await api.events()).items.some((event) => event.event_type === 'finalization_completed'
      && event.capture_id === 'cap-20260728-knowledge-eval')).toBe(true);
  });

  test('keeps a pending publication authorization visible until approval', async () => {
    const api = createFixtureApi();
    let polls = 0;
    let publishedCapture: string | null = null;
    const publicationApi: LocalApi = {
      ...api,
      startPublicationAuth: async () => ({
        request_id: 'auth-test', user_code: 'TEST-123', verification_uri_complete: '#/publishing',
        expires_in_seconds: 600, poll_interval_seconds: 0, state: 'pending'
      }),
      pollPublicationAuth: async () => ++polls === 1
        ? { signed_in: false }
        : { signed_in: true, github_login: 'approved-user', device_name: 'Local dashboard' },
      publish: async (captureId) => {
        publishedCapture = captureId;
        return { capture_id: captureId, job_id: 'pub-job-fixture', state: 'queued', status_url: '/v1/publications/pub-job-fixture' };
      }
    };
    renderDashboard('/publishing', publicationApi);
    await page.getByRole('button', { name: 'Begin authorization' }).click();
    await expect.element(page.getByText('TEST-123')).toBeVisible();
    await expect.element(page.getByRole('link', { name: 'Open approval page' })).not.toBeInTheDocument();
    await expect.element(page.getByRole('button', { name: 'Approve demo session' })).toBeEnabled();
    await page.getByRole('button', { name: 'Approve demo session' }).click();
    await expect.element(page.getByText('TEST-123')).toBeVisible();
    await page.getByRole('button', { name: 'Approve demo session' }).click();
    await expect.element(page.getByRole('heading', { name: 'approved-user' })).toBeVisible();
    await page.getByRole('button', { name: 'Review publication' }).click();
    await page.getByRole('button', { name: 'Publish trace' }).click();
    await expect.element(page.getByText('pub-job-fixture')).toBeVisible();
    await expect.element(page.getByText('cap-20260727-research-brief')).toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Refresh status' })).toBeVisible();
    expect(publishedCapture).toBe('cap-20260727-research-brief');
  });

  test('completes the documentation publication flow without external services', async () => {
    renderDashboard('/publishing');
    await page.getByRole('button', { name: 'Begin authorization' }).click();
    await expect.element(page.getByText('This fixture stays in the browser and does not contact GitHub.')).toBeVisible();
    await page.getByRole('button', { name: 'Approve demo session' }).click();
    await expect.element(page.getByRole('heading', { name: 'fixture-user' })).toBeVisible();
    await page.getByRole('button', { name: 'Review publication' }).click();
    await page.getByRole('button', { name: 'Publish trace' }).click();
    await expect.element(page.getByText('queued', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Refresh status' }).click();
    await expect.element(page.getByText('verifying', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Refresh status' }).click();
    await expect.element(page.getByText('admitted', { exact: true })).toBeVisible();
    await expect.element(page.getByText('It did not upload data.', { exact: false })).toBeVisible();
    await page.getByRole('button', { name: 'Inspect admitted fixture' }).click();
    await expect.element(page.getByRole('heading', { name: 'Prompt and response' })).toBeVisible();
  });

  test('shows the authentication gate after a 401 status response', async () => {
    const api: LocalApi = { ...createFixtureApi(), status: async () => { throw new LocalApiError(401, 'unauthorized', 'Unauthorized'); } };
    renderDashboard('/overview', api);
    await expect.element(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  });

  test('exchanges configured credentials for a dashboard session', async () => {
    let credentials: [string, string] | undefined;
    const api: LocalApi = {
      ...createFixtureApi(),
      status: async () => { throw new LocalApiError(401, 'unauthorized', 'Unauthorized'); },
      session: async (username, password) => { credentials = [username, password]; }
    };
    renderDashboard('/overview', api);
    await page.getByLabelText('Username').fill('local-admin');
    await page.getByRole('textbox', { name: 'Password' }).fill('correct horse battery staple');
    await page.getByRole('button', { name: 'Open dashboard' }).click();
    await expect.poll(() => credentials).toEqual(['local-admin', 'correct horse battery staple']);
  });

  test('does not show stale online state after a status failure', async () => {
    const api: LocalApi = { ...createFixtureApi(), status: async () => { throw new LocalApiError(503, 'service_unavailable', 'Unavailable'); } };
    renderDashboard('/overview', api);
    await expect.element(page.getByRole('heading', { name: 'The local service is unavailable' })).toBeVisible();
    await expect.element(page.getByText('Online', { exact: true })).not.toBeInTheDocument();
  });

  test('uses an accessible drawer at the mobile breakpoint', async () => {
    await page.viewport(800, 760);
    renderDashboard();
    await page.getByRole('button', { name: 'Open navigation' }).click();
    await expect.element(page.getByRole('dialog')).toBeVisible();
    await expect.element(page.getByText('Documentation fixture')).not.toBeInTheDocument();
    await page.getByRole('dialog').getByRole('button', { name: /Activity/ }).click();
    await expect.element(page.getByRole('combobox', { name: 'Activity severity' })).toBeVisible();
  });

  test('does not repeat service status in the dashboard shell', async () => {
    renderDashboard();
    await expect.element(page.getByText('Admin 127.0.0.1:8788')).not.toBeInTheDocument();
    await expect.element(page.getByText('Online', { exact: true })).not.toBeInTheDocument();
  });

  test('sends activity filters to the service', async () => {
    const api: LocalApi = createFixtureApi();
    let receivedFilters: Record<string, string | number | undefined> = {};
    const filteredApi: LocalApi = {
      ...api,
      events: async (filters = {}) => {
        receivedFilters = filters;
        return api.events(filters);
      }
    };
    renderDashboard('/activity', filteredApi);
    await page.getByLabelText('Activity event type').fill('finalization_completed');
    await expect.poll(() => receivedFilters.event_type).toBe('finalization_completed');
    await expect.element(page.getByText('Finalization completed')).toBeVisible();
    await expect.element(page.getByText('Finalization failed')).not.toBeInTheDocument();
  });

  test('uses separate trace list and detail views on mobile', async () => {
    await page.viewport(390, 760);
    renderDashboard('/traces');
    await expect.element(page.getByRole('listitem')).toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Verify now' })).not.toBeInTheDocument();
    await page.getByRole('list', { name: 'Finalized traces' }).getByRole('button').click();
    await expect.element(page.getByRole('button', { name: 'All finalized traces' })).toBeVisible();
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

    window.location.hash = '/finalizations';
    await expect.element(page.getByRole('list', { name: 'Finalizations' })).toBeVisible();
    await expect.element(page.getByRole('separator', { name: 'Resize list and detail panels' })).toHaveAttribute('aria-valuenow', '336');
  });
});
