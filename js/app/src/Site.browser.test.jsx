import { useEffect, useState } from 'react';
import { afterEach, describe, expect, test } from 'vitest';
import { page } from 'vitest/browser';
import { cleanup, render } from '@testing-library/react';
import { Collections, HostedNotaryRecord } from './main';

afterEach(async () => {
  cleanup();
  window.location.hash = '';
  await page.viewport(1280, 900);
});

const libraryPublications = Array.from({ length: 20 }, (_, index) => ({
  id: `pub-${index + 1}`,
  title: `Trace ${String(index + 1).padStart(2, '0')}`,
  provider: index === 11 ? 'anthropic' : 'openai',
  host: index === 11 ? 'api.anthropic.com' : 'api.openai.com',
  model: index === 11 ? 'claude-sonnet-4-6' : 'gpt-5.2',
  tags: ['evaluation'], author: 'fixture-user', tool_use: false,
  span_count: 1, admitted_at: 1_786_000_000 - index, recent_downloads: 20 - index
}));

const loadLibrary = async () => ({ publications: structuredClone(libraryPublications) });
const loadLibraryTrace = async (id) => ({
  resourceSpans: [{ scopeSpans: [{ spans: [{
    name: 'gen_ai.inference', spanId: `${id}-span`, attributes: [
      { key: 'gen_ai.input.messages', value: { stringValue: JSON.stringify([{ role: 'user', parts: [{ type: 'text', content: `Prompt for ${id}` }] }]) } },
      { key: 'gen_ai.output.messages', value: { stringValue: JSON.stringify([{ role: 'assistant', parts: [{ type: 'text', content: `Response for ${id}` }] }]) } }
    ]
  }] }] }]
});

function RoutedLibrary() {
  const selectedFromHash = () => window.location.hash.replace(/^#\/?library\/?/, '') || undefined;
  const [selectedId, setSelectedId] = useState(selectedFromHash);
  useEffect(() => {
    const update = () => setSelectedId(selectedFromHash());
    window.addEventListener('hashchange', update);
    return () => window.removeEventListener('hashchange', update);
  }, []);
  return <Collections selectedId={selectedId} loadCollection={loadLibrary} loadTrace={loadLibraryTrace} />;
}

describe('hosted site', () => {
  test('renders a zero notary lower bound as an unbounded interval', async () => {
    render(<HostedNotaryRecord
      record={{
        host: 'notary.example', port: 7047, transport: 'tls', status: 'active',
        key_id: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        valid_from_unix_ms: 0, valid_until_unix_ms: null, finalize_until_unix_ms: null
      }}
      activeKeyId="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      copiedKeyId={null}
      onCopy={() => {}}
    />);

    await expect.element(page.getByText('No lower bound configured')).toBeVisible();
    await expect.element(page.getByText(/1969|1970/)).not.toBeInTheDocument();
  });

  test('uses a focused list-to-detail flow for the Library on a phone', async () => {
    await page.viewport(390, 760);
    window.location.hash = '/library';
    render(<RoutedLibrary />);

    const list = page.getByRole('button', { name: /Trace 12/ });
    await expect.element(list).toBeVisible();
    window.scrollTo({ top: 500, behavior: 'instant' });
    await list.click();

    const heading = page.getByRole('heading', { name: 'Trace 12' });
    await expect.element(heading).toBeVisible();
    await expect.element(page.getByLabelText('Browse traces')).not.toBeInTheDocument();
    await expect.element(page.getByRole('button', { name: /Trace 01/ })).not.toBeInTheDocument();
    await expect.poll(() => document.activeElement?.textContent).toBe('Trace 12');
    await expect.poll(() => {
      const bounds = document.querySelector('.library-back')?.getBoundingClientRect();
      return Boolean(bounds && bounds.top >= 0 && bounds.bottom <= window.innerHeight);
    }).toBe(true);
    expect(getComputedStyle(document.activeElement).outlineStyle).not.toBe('none');

    await page.getByRole('button', { name: '← Back to all traces' }).click();
    await expect.element(page.getByLabelText('Browse traces')).toBeVisible();
    await expect.element(list).toHaveFocus();
    expect(window.scrollY).toBeGreaterThan(0);
  });

  test('keeps the Library list and inspector together on desktop', async () => {
    window.location.hash = '/library';
    render(<RoutedLibrary />);
    await expect.element(page.getByLabelText('Browse traces')).toBeVisible();
    await expect.element(page.getByRole('button', { name: /Trace 02/ })).toBeVisible();
    await expect.element(page.getByRole('heading', { name: 'Trace 01' })).toBeVisible();
  });
});
