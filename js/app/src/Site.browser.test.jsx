import { afterEach, describe, expect, test } from 'vitest';
import { page } from 'vitest/browser';
import { cleanup, render } from '@testing-library/react';
import { HostedNotaryRecord } from './main';

afterEach(() => cleanup());

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
});
