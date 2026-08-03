import { afterEach, describe, expect, test } from 'vitest';
import { page } from 'vitest/browser';
import { cleanup, fireEvent, render } from '@testing-library/react';
import { ApiKeysPanel, CliApproval, Header, HostedNotaryRecord, Library, SharePage, VerificationPage } from './main';

afterEach(async () => {
  cleanup();
  window.location.hash = '';
  await page.viewport(1280, 900);
});

const libraryShares = Array.from({ length: 20 }, (_, index) => ({
  id: `share-${index + 1}`,
  provider: index === 11 ? 'anthropic' : 'openai',
  model: index === 11 ? 'claude-sonnet-4-6' : 'gpt-5.2',
  publisher: 'fixture-user',
  authenticated_at_unix_ms: 1_786_000_000_000 - index,
  share_url: `https://example.test/s/share-${index + 1}`,
}));

const loadLibrary = async () => structuredClone(libraryShares);
const loadLibraryTrace = async (id) => ({
  resourceSpans: [{ scopeSpans: [{ spans: [{
    name: 'gen_ai.inference', spanId: `${id}-span`, attributes: [
      { key: 'gen_ai.input.messages', value: { stringValue: JSON.stringify([{ role: 'user', parts: [{ type: 'text', content: `Prompt for ${id}` }] }]) } },
      { key: 'gen_ai.output.messages', value: { stringValue: JSON.stringify([{ role: 'assistant', parts: [{ type: 'text', content: `Response for ${id}` }] }]) } }
    ]
  }] }] }]
});

describe('hosted site', () => {
  test('makes local service authorization a clear two-step decision', async () => {
    window.location.hash = '#/authorize?request_id=request-123&approval_secret=secret-456';
    render(<>
      <Header user={null} hideSignIn theme="light" onThemeChange={() => {}} />
      <CliApproval route="authorize?request_id=request-123&approval_secret=secret-456" user={null} />
    </>);

    await expect.element(page.getByRole('heading', { name: 'Sign in to continue' })).toBeVisible();
    await expect.element(page.getByRole('link', { name: 'Continue with GitHub' })).toBeVisible();
    await expect.element(page.getByText('Repository access')).toBeVisible();
    await expect.element(page.getByText('Not requested')).toBeVisible();
    await expect.element(page.getByRole('link', { name: 'Sign in' })).not.toBeInTheDocument();
  });

  test('shows the device, account, and code before approval', async () => {
    const loadApproval = async () => ({
      device_name: 'Research MacBook',
      user_code: 'NOTARY-7K3',
      expires_at: 1_786_000_000,
    });
    let approved;
    render(<CliApproval
      route="authorize?request_id=request-123&approval_secret=secret-456"
      user={{ github_login: 'fixture-user' }}
      loadApproval={loadApproval}
      approveRequest={async (...args) => { approved = args; }}
    />);

    await expect.element(page.getByRole('heading', { name: 'Approve this local service?' })).toBeVisible();
    await expect.element(page.getByText('Research MacBook')).toBeVisible();
    await expect.element(page.getByText('fixture-user')).toBeVisible();
    await expect.element(page.getByText('NOTARY-7K3')).toBeVisible();
    await page.getByRole('button', { name: 'Approve service' }).click();

    expect(approved).toEqual(['request-123', 'secret-456']);
    await expect.element(page.getByRole('heading', { name: 'Local service approved' })).toBeVisible();
  });

  test('shows a new API key once and revokes it from the account list', async () => {
    const secret = `llmn_v1_${'a'.repeat(32)}_${'b'.repeat(64)}`;
    let createRequest;
    let revokedId;
    render(<ApiKeysPanel
      loadKeys={async () => []}
      createKey={async (request) => {
        createRequest = request;
        return {
          secret,
          api_key: {
            id: 'a'.repeat(32), prefix: `llmn_v1_${'a'.repeat(12)}`, name: request.name,
            scopes: request.scopes, created_at: 1_786_000_000, last_used_at: null,
            expires_at: request.expires_at, revoked_at: null
          }
        };
      }}
      revokeKey={async (id) => { revokedId = id; }}
    />);

    await expect.element(page.getByText('No API keys')).toBeVisible();
    await page.getByRole('button', { name: 'Create API key' }).click();
    await page.getByLabelText('Name').fill('Nightly CI');
    await page.getByRole('dialog').getByRole('button', { name: 'Create API key' }).click();

    await expect.element(page.getByText(secret)).toBeVisible();
    expect(createRequest.name).toBe('Nightly CI');
    expect(createRequest.scopes).toEqual(['account:read', 'notary:admit', 'publish:read', 'publish:write']);
    await page.getByRole('button', { name: 'I stored the key' }).click();
    await expect.element(page.getByText(secret)).not.toBeInTheDocument();
    await expect.element(page.getByText('Nightly CI')).toBeVisible();

    await page.getByRole('button', { name: 'Revoke' }).click();
    await page.getByRole('button', { name: 'Revoke API key' }).click();
    expect(revokedId).toBe('a'.repeat(32));
    await expect.element(page.getByText('Revoked')).toBeVisible();
  });

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

  test('keeps the Listed Library as a compact index on a phone', async () => {
    await page.viewport(390, 760);
    render(<Library loadShares={loadLibrary} />);
    await expect.element(page.getByRole('heading', { name: 'Library' })).toBeVisible();
    await expect.element(page.getByRole('link', { name: /claude-sonnet-4-6/ })).toBeVisible();
    await expect.element(page.getByText('Unlisted shares never appear in this index.')).not.toBeInTheDocument();
  });

  test('filters the Listed Library without loading share contents', async () => {
    render(<Library loadShares={loadLibrary} />);
    await expect.element(page.getByLabelText('Browse Listed shares')).toBeVisible();
    const search = page.getByPlaceholder('Model, provider, or publisher');
    await search.fill('claude');
    await expect.element(page.getByRole('link', { name: /claude-sonnet-4-6/ })).toBeVisible();
    await expect.element(page.getByRole('link', { name: /gpt-5.2/ })).not.toBeInTheDocument();
  });

  test('puts the disclosed conversation before collapsible evidence and tools', async () => {
    const loadShare = async () => ({
      id: 'share-12', visibility: 'unlisted', publisher: 'fixture-user', admitted_at: 1_786_000_000,
      authenticated_at_unix_ms: 1_786_000_000_000, verified_at: 1_786_000_001,
      provider: 'anthropic', host: 'api.anthropic.com', model: 'claude-sonnet-4-6',
      verification_state: 'verified', notary_key_id: 'sha256:abc', directory_generation: 42,
      trust_source: 'hosted_notary_directory', trace_sha256: 'b'.repeat(64), package_available: true,
      package_size_bytes: 4096, package_sha256: 'c'.repeat(64),
      public_package_safety_version: 'llm-notary/public-package-safety/v1',
      trace_url: '/api/public/shares/share-12/trace.otlp.json',
      package_url: '/api/public/shares/share-12/package.llmtrace', share_url: 'https://example.test/s/share-12',
    });
    const loadTrace = async () => ({ resourceSpans: [{ scopeSpans: [{ spans: [{
      name: 'gen_ai.inference', spanId: 'span-12', attributes: [
        { key: 'gen_ai.input.messages', value: { stringValue: JSON.stringify([{ role: 'user', parts: [{ type: 'text', content: 'Compare these two evidence trails.' }] }]) } },
        { key: 'gen_ai.output.messages', value: { stringValue: JSON.stringify([{ role: 'assistant', parts: [{ type: 'text', content: 'The second trail is stronger.' }, { type: 'tool_call', id: 'call-1', name: 'lookup_record', arguments: { id: 42 } }, { type: 'tool_call_response', id: 'call-1', result: { source: 'fixture record 42' } }] }]) } },
      ],
    }] }] }] });
    render(<SharePage shareId="share-12" loadShare={loadShare} loadTrace={loadTrace} />);
    await expect.element(page.getByRole('heading', { name: 'Conversation' })).toBeVisible();
    await expect.element(page.getByText('Compare these two evidence trails.')).toBeVisible();
    await expect.element(page.getByText('The second trail is stronger.')).toBeVisible();
    const tool = page.getByText('lookup_record');
    await expect.element(tool).toBeVisible();
    expect(tool.element().closest('details')?.open).toBe(false);
    await tool.click();
    await expect.element(page.getByText('arguments')).toBeVisible();
    const toolResult = page.getByText('Tool result');
    await expect.element(toolResult).toBeVisible();
    await toolResult.click();
    await expect.element(page.getByText('fixture record 42')).toBeVisible();
    await expect.element(page.getByRole('link', { name: /Download .llmtrace/ })).toBeVisible();
    expect(document.querySelector('meta[name="robots"]')?.getAttribute('content')).toContain('noindex');
  });

  test('requires disclosure consent before hosted package verification', async () => {
    const verified = {
      verified: true,
      capture_id: 'sanitized-capture',
      provider: 'openai',
      host: 'api.openai.com',
      authenticated_at_unix_ms: 1_786_000_000_000,
      notary_key_id: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      trust_source: 'production_directory',
      directory_generation: 42,
      trace_sha256: 'b'.repeat(64),
      package_sha256: 'c'.repeat(64),
      trace: await loadLibraryTrace('verified')
    };
    let calls = 0;
    render(<VerificationPage verifyFile={async () => { calls += 1; return verified; }} />);
    const input = document.querySelector('input[type="file"]');
    const file = new File(['sanitized fixture'], 'sanitized.llmtrace', { type: 'application/vnd.llmnotary.trace-package+zip' });
    fireEvent.change(input, { target: { files: [file] } });

    await expect.element(page.getByText('Your package may contain sensitive content.')).toBeVisible();
    await expect.element(page.getByText('Header values are hidden by default, but prompts, responses, tool definitions, and tool results can be present. The service processes the package without durable retention. This live result is not a signed receipt.')).toBeVisible();
    await expect.element(page.getByText('I understand that this package may contain sensitive content.')).toBeVisible();
    expect(calls).toBe(0);
    const submit = page.getByRole('button', { name: 'Verify package' });
    await expect.element(submit).toBeDisabled();
    await page.getByRole('checkbox').click();
    await expect.element(submit).toBeEnabled();
    await submit.click();

    await expect.element(page.getByRole('heading', { name: 'Verification passed.' })).toBeVisible();
    await expect.element(page.getByText('api.openai.com')).toBeVisible();
    await expect.element(page.getByText('Prompt for verified')).toBeVisible();
    expect(calls).toBe(1);
  });

  test('rejects an oversized or mislabeled upload before sending it', async () => {
    let calls = 0;
    render(<VerificationPage verifyFile={async () => { calls += 1; }} />);
    const input = document.querySelector('input[type="file"]');
    fireEvent.change(input, { target: { files: [new File(['not a package'], 'notes.zip')] } });

    await expect.element(page.getByRole('heading', { name: 'File type is unsupported' })).toBeVisible();
    expect(calls).toBe(0);
  });

  test('ignores an in-flight verification result after the selected file changes', async () => {
    let resolveVerification;
    const pendingVerification = new Promise((resolve) => { resolveVerification = resolve; });
    render(<VerificationPage verifyFile={() => pendingVerification} />);
    const input = document.querySelector('input[type="file"]');
    fireEvent.change(input, { target: { files: [new File(['first'], 'first.llmtrace')] } });
    await page.getByRole('checkbox').click();
    await page.getByRole('button', { name: 'Verify package' }).click();

    fireEvent.change(input, { target: { files: [new File(['second'], 'second.llmtrace')] } });
    await expect.element(page.getByText('second.llmtrace')).toBeVisible();
    resolveVerification({
      verified: true,
      trace: { resourceSpans: [] }
    });
    await new Promise((resolve) => window.requestAnimationFrame(() => window.requestAnimationFrame(resolve)));

    expect(document.body.textContent).not.toContain('Verification passed.');
    await expect.element(page.getByText('second.llmtrace')).toBeVisible();
  });
});
