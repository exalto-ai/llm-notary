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
    await expect.element(page.getByRole('heading', { name: 'Service overview' })).toBeVisible();
    await page.getByRole('button', { name: /Captures/ }).click();
    await expect.element(page.getByRole('heading', { name: 'Captures' })).toBeVisible();
    await page.getByLabelText('Search captures').fill('benchmark');
    await expect.element(page.getByText('deepseek-v4-flash')).toBeVisible();
    await expect.element(page.getByText('gpt-5.2', { exact: true })).not.toBeInTheDocument();
    await page.getByRole('list', { name: 'Captures' }).getByRole('button').click();
    await expect.element(page.getByText('cap-20260727-benchmark')).toBeVisible();
  });

  test('persists an explicit theme and can return to system mode', async () => {
    renderDashboard();
    await page.getByRole('button', { name: 'Dark color scheme' }).click();
    await expect.poll(() => document.documentElement.dataset.mantineColorScheme).toBe('dark');
    expect(localStorage.getItem('mantine-color-scheme-value')).toBe('dark');
    await page.getByRole('button', { name: 'System color scheme' }).click();
    expect(localStorage.getItem('mantine-color-scheme-value')).toBe('auto');
  });

  test('queues a finalization and makes the durable operation visible', async () => {
    renderDashboard('/captures/cap-20260728-knowledge-eval');
    await page.getByRole('button', { name: 'Finalize', exact: true }).click();
    await expect.element(page.getByRole('heading', { name: 'Finalizations' })).toBeVisible();
    await expect.element(page.getByText('op-finalize-queued-fixture')).toBeVisible();
    await expect.element(page.getByText('queued', { exact: true }).first()).toBeVisible();
  });

  test('shows independent trace verification feedback', async () => {
    renderDashboard('/traces/cap-20260727-research-brief');
    await page.getByRole('button', { name: 'Verify now' }).click();
    await page.getByRole('tab', { name: 'Verification' }).click();
    await expect.element(page.getByText('Verification passed')).toBeVisible();
    await expect.element(page.getByText(/sha256:3828b21f/)).toBeVisible();
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
    await expect.element(page.getByRole('heading', { name: 'Finalizations' })).toBeVisible();
    await expect.element(page.getByText('op-finalize-benchmark')).toBeVisible();
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

  test('keeps a pending publication authorization visible until approval', async () => {
    const api = createFixtureApi();
    let polls = 0;
    let publishedCapture: string | null = null;
    const publicationApi: LocalApi = {
      ...api,
      startPublicationAuth: async () => ({
        request_id: 'auth-test', user_code: 'TEST-123', verification_uri_complete: 'https://example.test/activate',
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
    await expect.element(page.getByRole('button', { name: 'Check approval' })).toBeEnabled();
    await page.getByRole('button', { name: 'Check approval' }).click();
    await expect.element(page.getByText('TEST-123')).toBeVisible();
    await page.getByRole('button', { name: 'Check approval' }).click();
    await expect.element(page.getByRole('heading', { name: 'approved-user' })).toBeVisible();
    await page.getByRole('button', { name: 'Review publication' }).click();
    await page.getByRole('button', { name: 'Publish trace' }).click();
    await expect.element(page.getByText('pub-job-fixture')).toBeVisible();
    await expect.element(page.getByText('cap-20260727-research-brief')).toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Refresh status' })).toBeVisible();
    expect(publishedCapture).toBe('cap-20260727-research-brief');
  });

  test('shows the authentication gate after a 401 status response', async () => {
    const api: LocalApi = { ...createFixtureApi(), status: async () => { throw new LocalApiError(401, 'unauthorized', 'Unauthorized'); } };
    renderDashboard('/overview', api);
    await expect.element(page.getByRole('heading', { name: 'Sign in to the local dashboard' })).toBeVisible();
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
    await page.getByRole('dialog').getByRole('button', { name: /Activity/ }).click();
    await expect.element(page.getByRole('heading', { name: 'Activity' })).toBeVisible();
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
});
