import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { page, userEvent } from 'vitest/browser';
import { cleanup, render } from '@testing-library/react';
import { MantineProvider, createTheme } from '@mantine/core';
import { Notifications } from '@mantine/notifications';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Dashboard } from './Dashboard';
import { createFixtureApi } from './fixtures';
import '@mantine/core/styles.css';
import '@mantine/notifications/styles.css';

const theme = createTheme({ defaultRadius: 0, primaryColor: 'dark' });

function renderDashboard(hash = '/overview') {
  window.location.hash = hash;
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MantineProvider theme={theme} defaultColorScheme="auto">
      <Notifications />
      <QueryClientProvider client={queryClient}>
        <Dashboard api={createFixtureApi()} fixture />
      </QueryClientProvider>
    </MantineProvider>
  );
}

beforeEach(() => localStorage.clear());
afterEach(() => cleanup());

describe('local evidence dashboard', () => {
  test('navigates, filters captures, and selects a capture', async () => {
    renderDashboard();
    await expect.element(page.getByRole('heading', { name: 'Evidence at a glance.' })).toBeVisible();
    await page.getByRole('button', { name: /Captures/ }).click();
    await expect.element(page.getByRole('heading', { name: 'Captures' })).toBeVisible();
    await page.getByLabelText('Search captures').fill('benchmark');
    await expect.element(page.getByText('deepseek-v4-flash')).toBeVisible();
    await expect.element(page.getByText('gpt-5.2', { exact: true })).not.toBeInTheDocument();
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

  test('uses an accessible drawer at the mobile breakpoint', async () => {
    await page.viewport(390, 760);
    renderDashboard();
    await page.getByRole('button', { name: 'Open navigation' }).click();
    await expect.element(page.getByRole('dialog')).toBeVisible();
    await page.getByRole('dialog').getByRole('button', { name: /Activity/ }).click();
    await expect.element(page.getByRole('heading', { name: 'Activity' })).toBeVisible();
  });
});
