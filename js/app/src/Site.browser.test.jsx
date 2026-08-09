import { afterEach, describe, expect, test } from 'vitest';
import { page } from 'vitest/browser';
import { cleanup, fireEvent, render } from '@testing-library/react';
import { AccountSettings, ApiKeysPanel, CliApproval, Dashboard, DeleteAccountPanel, Header, HostedNotaryRecord, Landing, Library, ListedSharesPreview, SharePage, SignInPage, VerificationPage } from './main';
import { ProviderIdentity } from './ProviderIdentity';
import { latestMacosDownloadHref } from './releaseDownloads';
import { initialThemePreference } from './theme';

afterEach(async () => {
  cleanup();
  window.location.hash = '';
  window.localStorage.removeItem('llm-notary-theme');
  await page.viewport(1280, 900);
});

const libraryShares = Array.from({ length: 20 }, (_, index) => ({
  id: `share-${index + 1}`,
  provider: index === 11 ? 'anthropic' : 'openai',
  model: index === 11 ? 'claude-sonnet-4-6' : 'gpt-5.2',
  publisher: 'fixture-user',
  authenticated_at_unix_ms: 1_786_000_000_000 - index,
  input_preview: `Prompt for share-${index + 1}`,
  output_preview: `Response for share-${index + 1}`,
  share_url: `https://example.test/s/share-${index + 1}`,
}));

const loadLibrary = async ({ limit = 20, cursor, search, provider } = {}) => {
  const query = search?.toLowerCase() || '';
  const matches = libraryShares.filter((share) => {
    const text = `${share.provider} ${share.model} ${share.publisher} ${share.input_preview} ${share.output_preview}`.toLowerCase();
    return (!query || text.includes(query)) && (!provider || share.provider === provider);
  });
  const offset = cursor ? Number(cursor) : 0;
  const items = matches.slice(offset, offset + limit);
  return { items: structuredClone(items), next_cursor: offset + limit < matches.length ? String(offset + limit) : null };
};
const loadLibraryTrace = async (id) => ({
  resourceSpans: [{ scopeSpans: [{ spans: [{
    name: 'gen_ai.inference', spanId: `${id}-span`, attributes: [
      { key: 'gen_ai.input.messages', value: { stringValue: JSON.stringify([{ role: 'user', parts: [{ type: 'text', content: `Prompt for ${id}` }] }]) } },
      { key: 'gen_ai.output.messages', value: { stringValue: JSON.stringify([{ role: 'assistant', parts: [{ type: 'text', content: `Response for ${id}` }] }]) } }
    ]
  }] }] }]
});

describe('hosted site', () => {
  test('makes the current macOS app the primary landing action', async () => {
    expect(latestMacosDownloadHref('build-123 0.1.0')).toBe('/downloads/cli/builds/build-123/LLM-Notary-macos-arm64.dmg');
    expect(() => latestMacosDownloadHref('../build 0.1.0')).toThrow('latest download pointer is invalid');
    render(<Landing loadLatestPointer={async () => 'build-123 0.1.0'} />);

    const download = page.getByRole('link', { name: /Download for macOS/ });
    await expect.element(download).toHaveAttribute('href', '/downloads/cli/builds/build-123/LLM-Notary-macos-arm64.dmg');
    await expect.element(download).toHaveAttribute('download', 'LLM-Notary-macos-arm64.dmg');
    await expect.element(page.getByText('Apple silicon · macOS 12+')).not.toBeInTheDocument();
    await expect.element(page.getByRole('link', { name: 'build on the LLM Notary stack' })).toHaveAttribute('href', '#/docs/getting-started');
    expect(document.querySelector('.hero-developer-path')?.textContent).toBe('or, build on the LLM Notary stack');
    await expect.element(page.getByRole('link', { name: 'Get started' })).not.toBeInTheDocument();
    await expect.element(page.getByRole('link', { name: 'Browse Library' })).not.toBeInTheDocument();
    expect(document.querySelector('.receipt [data-provider-icon="openai"]')).not.toBeNull();
  });

  test('sends the macOS action to install options when the latest pointer is unavailable', async () => {
    render(<Landing loadLatestPointer={async () => { throw new Error('offline'); }} />);

    const download = page.getByRole('link', { name: /Download for macOS/ });
    await expect.element(download).toHaveAttribute('href', '#/docs/getting-started');
    await expect.element(page.getByText('View install options')).toBeVisible();
  });

  test('defaults to light and keeps appearance choices out of the signed-in account menu', async () => {
    expect(initialThemePreference()).toBe('light');
    render(<Header user={{ github_login: 'fixture-user' }} onLogout={() => {}} />);

    await page.getByRole('button', { name: 'Account menu for fixture-user' }).click();
    await expect.element(page.getByRole('menuitem', { name: 'Dashboard' })).toBeVisible();
    await expect.element(page.getByRole('group', { name: 'Appearance' })).not.toBeInTheDocument();
  });

  test('reserves the account slot while browser authentication is loading', async () => {
    render(<Header user={null} authPending onLogout={() => {}} />);

    await expect.element(page.getByRole('status', { name: 'Checking sign-in status' })).toBeVisible();
    await expect.element(page.getByRole('link', { name: 'Sign in' })).not.toBeInTheDocument();
  });

  test('offers Google first and preserves a local-service return route', async () => {
    render(<SignInPage
      route="signin?return_to=%23%2Fauthorize%3Frequest_id%3Drequest-123"
      loadProviders={async () => ({ google: true, github: true })}
    />);

    const google = page.getByRole('link', { name: 'Continue with Google' });
    await expect.element(google).toBeVisible();
    await expect.element(google).toHaveAttribute('href', '/api/auth/google?return_to=%23%2Fauthorize%3Frequest_id%3Drequest-123');
    await expect.element(page.getByRole('link', { name: 'Continue with GitHub' })).toBeVisible();
    expect(document.querySelectorAll('[data-auth-provider-icon]')).toHaveLength(2);
    expect(document.querySelector('[data-auth-provider-icon="google"]')).not.toBeNull();
    expect(document.querySelector('[data-auth-provider-icon="github"]')).not.toBeNull();
    expect(document.querySelector('.auth-provider')?.textContent).toContain('Google');
    await expect.element(page.getByText('Google access')).not.toBeInTheDocument();
    await expect.element(page.getByText('Provider tokens')).not.toBeInTheDocument();
  });

  test('shows only the configured sign-in provider', async () => {
    render(<SignInPage loadProviders={async () => ({ google: false, github: true })} />);

    await expect.element(page.getByRole('link', { name: 'Continue with GitHub' })).toBeVisible();
    await expect.element(page.getByRole('link', { name: 'Continue with Google' })).not.toBeInTheDocument();
    expect(document.querySelectorAll('[data-auth-provider-icon="github"]')).toHaveLength(1);
  });

  test('shows progress while handing off to an auth provider', async () => {
    render(<SignInPage loadProviders={async () => ({ google: true, github: true })} />);

    const google = page.getByRole('link', { name: 'Continue with Google' });
    await expect.element(google).toBeVisible();
    google.element().addEventListener('click', (event) => event.preventDefault());
    await google.click();

    await expect.element(page.getByRole('link', { name: 'Connecting to Google…' })).toHaveAttribute('aria-busy', 'true');
    await expect.element(page.getByRole('link', { name: 'Continue with GitHub' })).toHaveAttribute('aria-disabled', 'true');
    expect(document.querySelectorAll('.auth-provider-progress i')).toHaveLength(3);
  });

  test('offers Auto, Light, and Dark in Dashboard account settings', async () => {
    let selectedTheme;
    render(<AccountSettings theme="light" onThemeChange={(theme) => { selectedTheme = theme; }} />);

    await expect.element(page.getByRole('heading', { name: 'Account settings' })).toBeVisible();
    const appearance = page.getByRole('radiogroup', { name: 'Appearance' });
    await expect.element(appearance.getByRole('radio', { name: 'light' })).toHaveAttribute('aria-checked', 'true');
    await appearance.getByRole('radio', { name: 'auto' }).click();
    expect(selectedTheme).toBe('auto');
    await expect.element(appearance.getByRole('radio', { name: 'dark' })).toBeVisible();
  });

  test('collapses Dashboard navigation into a mobile dropdown', async () => {
    await page.viewport(390, 844);
    render(<Dashboard
      user={{ github_login: 'fixture-user', credits: null, share_stats: { total: 3, admitted: 2, in_progress: 1 } }}
      view="credits"
      theme="light"
      onThemeChange={() => {}}
      onAccountDeleted={() => {}}
      loadCliSessions={async () => ({ items: [], next_cursor: null })}
      loadMyShares={async () => ({ items: [], next_cursor: null })}
      loadCreditOffers={async () => []}
      loadCreditHistory={async () => ({ items: [], next_cursor: null })}
      loadBillingPurchases={async () => []}
    />);

    const navigation = page.getByRole('navigation', { name: 'Dashboard navigation' });
    const trigger = navigation.getByRole('button', { name: 'Dashboard menu: Credits' });
    await expect.element(trigger).toHaveAttribute('aria-expanded', 'false');
    await trigger.click();
    await expect.element(trigger).toHaveAttribute('aria-expanded', 'true');
    await expect.element(navigation.getByRole('link', { name: /^Traces\s*3$/ })).toBeVisible();
    await expect.element(navigation.getByRole('link', { name: 'Credits' })).toHaveAttribute('aria-current', 'page');
    fireEvent.keyDown(window, { key: 'Escape' });
    await expect.element(trigger).toHaveAttribute('aria-expanded', 'false');
  });

  test('discards an old credit-history page after claiming an offer', async () => {
    let rootRequests = 0;
    let resolveOldPage;
    let markOldPageStarted;
    const oldPageStarted = new Promise((resolve) => { markOldPageStarted = resolve; });
    const entry = (id, label, createdAt) => ({
      id,
      kind: 'grant',
      amount_bytes: 1_024,
      display_label: label,
      created_at: createdAt,
    });
    const loadCreditHistory = async (options) => {
      if (options.cursor) {
        markOldPageStarted();
        return new Promise((resolve) => { resolveOldPage = resolve; });
      }
      rootRequests += 1;
      return rootRequests === 1
        ? { items: [entry('initial', 'Initial credit', 100)], next_cursor: 'old-cursor' }
        : { items: [entry('claimed', 'Claimed credit', 200), entry('initial', 'Initial credit', 100)], next_cursor: 'fresh-cursor' };
    };
    render(<Dashboard
      user={{ github_login: 'fixture-user', credits: { included_monthly_remaining_bytes: 1_024, supplemental_remaining_bytes: 0, total_granted_bytes: 1_024, total_remaining_bytes: 1_024, total_used_bytes: 0, reset_at: 4_102_444_800, next_grant_expiration: null }, share_stats: { total: 0, admitted: 0, in_progress: 0 } }}
      view="credits"
      theme="light"
      onThemeChange={() => {}}
      onAccountDeleted={() => {}}
      loadCliSessions={async () => ({ items: [], next_cursor: null })}
      loadMyShares={async () => ({ items: [], next_cursor: null })}
      loadCreditOffers={async () => [{ id: 'offer-1', title: 'Test credit', description: 'One-time test credit.', amount_bytes: 1_024, claim_expires_at: 4_102_444_800, credit_expires_at: 4_102_444_800 }]}
      loadCreditHistory={loadCreditHistory}
      loadBillingPurchases={async () => []}
      claimOfferRequest={async () => ({ credits: { included_monthly_remaining_bytes: 2_048, supplemental_remaining_bytes: 0, total_granted_bytes: 2_048, total_remaining_bytes: 2_048, total_used_bytes: 0, reset_at: 4_102_444_800, next_grant_expiration: null } })}
    />);

    await expect.element(page.getByText('Initial credit')).toBeVisible();
    await page.getByRole('button', { name: 'Load older activity' }).click();
    await oldPageStarted;
    await page.getByRole('button', { name: /^Claim / }).click();
    await expect.element(page.getByText('Claimed credit')).toBeVisible();

    resolveOldPage({ items: [entry('stale', 'Stale older credit', 50)], next_cursor: 'stale-cursor' });
    await new Promise((resolve) => window.setTimeout(resolve, 0));
    await expect.element(page.getByText('Stale older credit')).not.toBeInTheDocument();
    await expect.element(page.getByText('Claimed credit')).toBeVisible();
  });

  test('starts a fixed-price Stripe Checkout from the credit quantity rail', async () => {
    let checkoutRequest;
    let checkoutUrl;
    render(<Dashboard
      user={{ github_login: 'fixture-user', billing: { service_plan: 'free', billing_status: 'active', purchase_mode: 'live' }, credits: { included_monthly_remaining_bytes: 1_024, supplemental_remaining_bytes: 0, total_granted_bytes: 1_024, total_remaining_bytes: 1_024, total_used_bytes: 0, reset_at: 4_102_444_800, next_grant_expiration: null }, share_stats: { total: 0, admitted: 0, in_progress: 0 } }}
      view="credits"
      theme="light"
      onThemeChange={() => {}}
      onAccountDeleted={() => {}}
      loadCliSessions={async () => ({ items: [], next_cursor: null })}
      loadMyShares={async () => ({ items: [], next_cursor: null })}
      loadCreditOffers={async () => []}
      loadCreditHistory={async () => ({ items: [], next_cursor: null })}
      loadBillingPurchases={async () => []}
      startCheckout={async (quantityGb, idempotencyKey) => {
        checkoutRequest = { quantityGb, idempotencyKey };
        return { checkout_url: 'https://checkout.stripe.com/c/pay/test' };
      }}
      openCheckout={(url) => { checkoutUrl = url; }}
    />);

    await page.getByRole('button', { name: '10 GB' }).click();
    await page.getByRole('button', { name: 'Buy 10 GB for $50' }).click();
    expect(checkoutRequest.quantityGb).toBe(10);
    expect(checkoutRequest.idempotencyKey).toMatch(/^[a-zA-Z0-9_-]+$/);
    expect(checkoutUrl).toBe('https://checkout.stripe.com/c/pay/test');
  });

  test('hides Checkout when disabled and labels Stripe test mode unmistakably', async () => {
    const credits = { included_monthly_remaining_bytes: 1_024, supplemental_remaining_bytes: 0, total_granted_bytes: 1_024, total_remaining_bytes: 1_024, total_used_bytes: 0, reset_at: 4_102_444_800, next_grant_expiration: null };
    const common = {
      view: 'credits', theme: 'light', onThemeChange: () => {}, onAccountDeleted: () => {},
      loadCliSessions: async () => ({ items: [], next_cursor: null }),
      loadMyShares: async () => ({ items: [], next_cursor: null }),
      loadCreditOffers: async () => [],
      loadCreditHistory: async () => ({ items: [], next_cursor: null }),
      loadBillingPurchases: async () => [],
    };
    render(<Dashboard {...common} user={{ github_login: 'fixture-user', billing: { service_plan: 'free', billing_status: 'active', purchase_mode: 'disabled' }, credits, share_stats: { total: 0, admitted: 0, in_progress: 0 } }} />);
    await expect.element(page.getByRole('heading', { name: 'Purchases unavailable' })).toBeVisible();
    await expect.element(page.getByRole('group', { name: 'Credit quantity' })).not.toBeInTheDocument();

    cleanup();
    render(<Dashboard {...common} user={{ github_login: 'fixture-user', billing: { service_plan: 'free', billing_status: 'active', purchase_mode: 'test' }, credits, share_stats: { total: 0, admitted: 0, in_progress: 0 } }} />);
    await expect.element(page.getByText('Stripe test mode · no real charges')).toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Open test Checkout · 5 GB for $25' })).toBeVisible();
  });

  test('retries Checkout confirmation and keeps a fresher purchase than the initial list', async () => {
    const credits = { included_monthly_remaining_bytes: 1_024, supplemental_remaining_bytes: 0, total_granted_bytes: 1_024, total_remaining_bytes: 1_024, total_used_bytes: 0, reset_at: 4_102_444_800, next_grant_expiration: null };
    let resolveInitialList;
    let pollCalls = 0;
    const purchase = (state) => ({ id: 'purchase-1', state, quantity_gb: 1, amount_cents: 500, created_at: 1_786_000_000 });
    render(<Dashboard
      user={{ github_login: 'fixture-user', billing: { service_plan: 'free', billing_status: 'active', purchase_mode: 'test' }, credits, share_stats: { total: 0, admitted: 0, in_progress: 0 } }}
      view="credits"
      route="credits?checkout=success&purchase_id=purchase-1"
      theme="light"
      onThemeChange={() => {}}
      onAccountDeleted={() => {}}
      loadCliSessions={async () => ({ items: [], next_cursor: null })}
      loadMyShares={async () => ({ items: [], next_cursor: null })}
      loadCreditOffers={async () => []}
      loadCreditHistory={async () => ({ items: [], next_cursor: null })}
      loadBillingPurchases={() => new Promise((resolve) => { resolveInitialList = resolve; })}
      loadBillingPurchase={async () => {
        pollCalls += 1;
        if (pollCalls === 1) throw new Error('temporary network failure');
        return purchase(pollCalls === 2 ? 'checkout_open' : 'paid');
      }}
      loadCurrentUser={async () => ({ billing: { service_plan: 'paid', billing_status: 'active', purchase_mode: 'test' }, credits })}
      checkoutPollBaseDelay={0}
      checkoutPollMaxAttempts={4}
    />);

    await expect.element(page.getByText('Payment confirmed. Your credits are ready.')).toBeVisible();
    resolveInitialList([purchase('checkout_open')]);
    await new Promise((resolve) => window.setTimeout(resolve, 0));
    await expect.element(page.getByText('paid', { exact: true })).toBeVisible();
    await expect.element(page.getByText('checkout open', { exact: true })).not.toBeInTheDocument();
    expect(pollCalls).toBe(3);
  });

  test('shows a bounded timeout when Stripe confirmation stays nonterminal', async () => {
    const credits = { included_monthly_remaining_bytes: 1_024, supplemental_remaining_bytes: 0, total_granted_bytes: 1_024, total_remaining_bytes: 1_024, total_used_bytes: 0, reset_at: 4_102_444_800, next_grant_expiration: null };
    render(<Dashboard
      user={{ github_login: 'fixture-user', billing: { service_plan: 'free', billing_status: 'active', purchase_mode: 'test' }, credits, share_stats: { total: 0, admitted: 0, in_progress: 0 } }}
      view="credits"
      route="credits?checkout=success&purchase_id=purchase-1"
      theme="light"
      onThemeChange={() => {}}
      onAccountDeleted={() => {}}
      loadCliSessions={async () => ({ items: [], next_cursor: null })}
      loadMyShares={async () => ({ items: [], next_cursor: null })}
      loadCreditOffers={async () => []}
      loadCreditHistory={async () => ({ items: [], next_cursor: null })}
      loadBillingPurchases={async () => []}
      loadBillingPurchase={async () => ({ id: 'purchase-1', state: 'checkout_open', quantity_gb: 1, amount_cents: 500, created_at: 1_786_000_000 })}
      checkoutPollBaseDelay={0}
      checkoutPollMaxAttempts={2}
    />);

    await expect.element(page.getByText('We could not confirm the payment yet. Check purchase history or refresh this page.')).toBeVisible();
  });

  test.each([
    ['failed', 'Payment was not completed. No credits were added.'],
    ['refunded', 'This payment was refunded. Its purchased credits are no longer available.'],
    ['disputed', 'This payment is under dispute. Its purchased credits are temporarily unavailable.'],
  ])('renders the %s Checkout terminal state explicitly', async (state, message) => {
    const credits = { included_monthly_remaining_bytes: 1_024, supplemental_remaining_bytes: 0, total_granted_bytes: 1_024, total_remaining_bytes: 1_024, total_used_bytes: 0, reset_at: 4_102_444_800, next_grant_expiration: null };
    render(<Dashboard
      user={{ github_login: 'fixture-user', billing: { service_plan: 'free', billing_status: 'active', purchase_mode: 'test' }, credits, share_stats: { total: 0, admitted: 0, in_progress: 0 } }}
      view="credits"
      route="credits?checkout=success&purchase_id=purchase-1"
      theme="light"
      onThemeChange={() => {}}
      onAccountDeleted={() => {}}
      loadCliSessions={async () => ({ items: [], next_cursor: null })}
      loadMyShares={async () => ({ items: [], next_cursor: null })}
      loadCreditOffers={async () => []}
      loadCreditHistory={async () => ({ items: [], next_cursor: null })}
      loadBillingPurchases={async () => []}
      loadBillingPurchase={async () => ({ id: 'purchase-1', state, quantity_gb: 1, amount_cents: 500, created_at: 1_786_000_000 })}
      loadCurrentUser={async () => ({ billing: { service_plan: 'free', billing_status: 'active', purchase_mode: 'test' }, credits })}
      checkoutPollBaseDelay={0}
    />);

    await expect.element(page.getByText(message)).toBeVisible();
  });

  test('renders every known provider icon and neutral fallbacks beside provider text', async () => {
    render(<div>
      {['openai', 'anthropic', 'deepseek', 'openrouter', 'future-provider'].map((provider) => <ProviderIdentity provider={provider} key={provider} />)}
      <ProviderIdentity provider={null} />
    </div>);

    for (const provider of ['openai', 'anthropic', 'deepseek', 'openrouter']) {
      expect(document.querySelector(`[data-provider-icon="${provider}"]`)).not.toBeNull();
      await expect.element(page.getByText(provider, { exact: true })).toBeVisible();
    }
    expect(document.querySelectorAll('[data-provider-icon="unknown"]')).toHaveLength(2);
    await expect.element(page.getByText('future-provider')).toBeVisible();
    await expect.element(page.getByText('Provider not reported')).toBeVisible();
    expect(document.querySelectorAll('[data-provider-icon] [aria-hidden="true"]')).toHaveLength(6);
  });

  test('keeps an OpenRouter icon when its model slug names an upstream vendor', async () => {
    render(<Library loadShares={async () => ({ items: [{
      id: 'routed-share', provider: 'openrouter', model: 'openai/gpt-5-mini',
      publisher: 'fixture-user', authenticated_at_unix_ms: 1_786_000_000_000,
      input_preview: 'Compare these records.', output_preview: 'The second record is stronger.',
      share_url: 'https://example.test/s/routed-share'
    }], next_cursor: null })} />);

    const row = page.getByRole('link', { name: /openai\/gpt-5-mini/ });
    await expect.element(row).toBeVisible();
    expect(row.element().querySelector('[data-provider-icon="openrouter"]')).not.toBeNull();
    expect(row.element().querySelector('[data-provider-icon="openai"]')).toBeNull();
  });

  test('makes local service authorization a clear two-step decision', async () => {
    window.location.hash = '#/authorize?request_id=request-123&approval_secret=secret-456';
    render(<>
      <Header user={null} hideSignIn />
      <CliApproval route="authorize?request_id=request-123&approval_secret=secret-456" user={null} />
    </>);

    await expect.element(page.getByRole('heading', { name: 'Sign in to continue' })).toBeVisible();
    await expect.element(page.getByRole('link', { name: 'Choose sign-in method' })).toBeVisible();
    await expect.element(page.getByText('Google access')).not.toBeInTheDocument();
    await expect.element(page.getByText('Provider tokens')).not.toBeInTheDocument();
    await expect.element(page.getByText('Review and approve the device')).toBeVisible();
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
      loadKeys={async () => ({ items: [], next_cursor: null })}
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

  test('makes Library rows distinct and uncluttered on a phone', async () => {
    await page.viewport(390, 760);
    render(<Library loadShares={loadLibrary} />);
    await expect.element(page.getByRole('heading', { name: 'Library' })).toBeVisible();
    const row = page.getByRole('link', { name: /claude-sonnet-4-6/ });
    await expect.element(row).toBeVisible();
    expect(row.element().textContent).toContain('Prompt for share-12');
    expect(row.element().textContent).toContain('Response for share-12');
    expect(row.element().textContent).toContain('Open trace');
    expect(document.body.textContent).not.toContain('Verified');
    expect(document.body.textContent).not.toContain('↗');
    expect(document.body.textContent).not.toContain('Listed shares');
  });

  test('shows provider marks in the landing Library preview', async () => {
    let request;
    render(<ListedSharesPreview loadShares={async (options) => { request = options; return { items: [libraryShares[0], libraryShares[11]], next_cursor: null }; }} />);

    const preview = page.getByLabelText('Featured public traces');
    await expect.element(preview).toBeVisible();
    expect(request).toEqual({ limit: 5 });
    expect(preview.element().querySelectorAll('[data-provider-icon="openai"]')).toHaveLength(1);
    expect(preview.element().querySelectorAll('[data-provider-icon="anthropic"]')).toHaveLength(1);
  });

  test('filters the Library by its public session summaries', async () => {
    render(<Library loadShares={loadLibrary} />);
    await expect.element(page.getByLabelText('Browse public sessions')).toBeVisible();
    const search = page.getByPlaceholder('Search conversations or models');
    await search.fill('claude');
    await expect.element(page.getByRole('link', { name: /claude-sonnet-4-6/ })).toBeVisible();
    await expect.element(page.getByRole('link', { name: /gpt-5.2/ })).not.toBeInTheDocument();
  });

  test('keeps Library controls and reports a failed filtered request', async () => {
    const loadShares = async (options) => {
      if (options.search) throw new Error('Search is temporarily unavailable.');
      return { items: [libraryShares[0]], next_cursor: 'old-cursor' };
    };
    render(<Library loadShares={loadShares} />);
    await expect.element(page.getByRole('link', { name: /gpt-5.2/ })).toBeVisible();

    const search = page.getByPlaceholder('Search conversations or models');
    await search.fill('claude');
    await expect.element(search).toBeVisible();
    await expect.element(page.getByText('Search is temporarily unavailable.')).toBeVisible();
    await expect.element(page.getByRole('link', { name: /gpt-5.2/ })).not.toBeInTheDocument();
  });

  test('waits for an indexable Library search term', async () => {
    let requests = 0;
    render(<Library loadShares={async (options) => { requests += 1; return loadLibrary(options); }} />);
    await expect.element(page.getByText('20 traces shown')).toBeVisible();
    const beforeSearch = requests;

    await page.getByPlaceholder('Search conversations or models').fill('ai');
    await expect.element(page.getByText('Search needs three letters or numbers together.')).toBeVisible();
    await new Promise((resolve) => window.setTimeout(resolve, 250));
    expect(requests).toBe(beforeSearch);
  });

  test('keeps Library filters while loading the next page', async () => {
    const requests = [];
    const first = libraryShares[11];
    const second = { ...libraryShares[11], id: 'share-continued', model: 'claude-haiku-4-5' };
    const loadShares = async (options) => {
      requests.push(options);
      return options.cursor
        ? { items: [second], next_cursor: null }
        : { items: [first], next_cursor: 'next-library-page' };
    };
    render(<Library loadShares={loadShares} />);

    const search = page.getByPlaceholder('Search conversations or models');
    await search.fill('claude');
    await expect.element(page.getByRole('link', { name: /claude-sonnet-4-6/ })).toBeVisible();
    await page.getByRole('button', { name: 'Load more traces' }).click();
    await expect.element(page.getByRole('link', { name: /claude-haiku-4-5/ })).toBeVisible();
    expect(requests.at(-1)).toMatchObject({ cursor: 'next-library-page', search: 'claude', limit: 20 });
  });

  test('discards an old Library continuation after filters change', async () => {
    let resolveOldPage;
    let markLoadStarted;
    const loadStarted = new Promise((resolve) => { markLoadStarted = resolve; });
    const initial = libraryShares[0];
    const filtered = libraryShares[11];
    const stale = { ...libraryShares[0], id: 'stale-share', output_preview: 'Stale continuation' };
    const loadShares = async (options) => {
      if (options.cursor) {
        markLoadStarted();
        return new Promise((resolve) => { resolveOldPage = resolve; });
      }
      if (options.search === 'claude') return { items: [filtered], next_cursor: null };
      return { items: [initial], next_cursor: 'old-cursor' };
    };
    render(<Library loadShares={loadShares} />);

    await expect.element(page.getByRole('button', { name: 'Load more traces' })).toBeVisible();
    await page.getByRole('button', { name: 'Load more traces' }).click();
    await loadStarted;
    await page.getByPlaceholder('Search conversations or models').fill('claude');
    await expect.element(page.getByRole('button', { name: 'Load more traces' })).not.toBeInTheDocument();
    await expect.element(page.getByRole('link', { name: /claude-sonnet-4-6/ })).toBeVisible();

    resolveOldPage({ items: [stale], next_cursor: 'stale-cursor' });
    await new Promise((resolve) => window.requestAnimationFrame(resolve));
    await expect.element(page.getByText('Stale continuation')).not.toBeInTheDocument();
    await expect.element(page.getByRole('button', { name: 'Load more traces' })).not.toBeInTheDocument();
  });

  test('loads older API keys without replacing the current page', async () => {
    const key = (id, name) => ({
      id, prefix: `llmn_v1_${id.slice(0, 12)}`, name,
      scopes: ['account:read'], created_at: 1_786_000_000,
      last_used_at: null, expires_at: null, revoked_at: null
    });
    const requests = [];
    render(<ApiKeysPanel
      loadKeys={async (options) => {
        requests.push(options);
        return options.cursor
          ? { items: [key('b'.repeat(32), 'Older key')], next_cursor: null }
          : { items: [key('a'.repeat(32), 'Current key')], next_cursor: 'next-key-page' };
      }}
      createKey={async () => { throw new Error('not used'); }}
      revokeKey={async () => {}}
    />);

    await expect.element(page.getByText('Current key')).toBeVisible();
    await page.getByRole('button', { name: 'Load more API keys' }).click();
    await expect.element(page.getByText('Older key')).toBeVisible();
    await expect.element(page.getByText('Current key')).toBeVisible();
    expect(requests.at(-1)).toEqual({ limit: 20, cursor: 'next-key-page' });
  });

  test('does not treat a bare legacy trace as a package-backed preview', async () => {
    let traceLoads = 0;
    render(<Library
      loadShares={async () => ({ items: [{
        id: 'legacy-share', provider: 'openai', model: 'gpt-4.1', publisher: 'fixture-user',
        authenticated_at_unix_ms: 1_786_000_000_000, share_url: 'https://example.test/s/legacy-share'
      }], next_cursor: null })}
      loadTrace={async (id) => { traceLoads += 1; return loadLibraryTrace(id); }}
    />);

    await expect.element(page.getByText('No prompt or response preview.')).toBeVisible();
    expect(traceLoads).toBe(0);
  });

  test('requires the account identifier before deleting an account', async () => {
    let deleted = false;
    let completed = false;
    render(<DeleteAccountPanel identifier="fixture-user" deleteAccount={async () => { deleted = true; }} onDeleted={() => { completed = true; }} />);

    await page.getByRole('button', { name: 'Delete account' }).click();
    const dialog = page.getByRole('alertdialog');
    const submit = dialog.getByRole('button', { name: 'Delete account' });
    await expect.element(submit).toBeDisabled();
    await dialog.getByLabelText('Type fixture-user to confirm.').fill('fixture-user');
    await expect.element(submit).toBeEnabled();
    await submit.click();
    await new Promise((resolve) => window.requestAnimationFrame(resolve));
    expect(deleted).toBe(true);
    expect(completed).toBe(true);
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
    expect(input.getAttribute('accept')).toBeNull();
    const file = new File(['sanitized fixture'], 'sanitized.llmtrace', { type: 'application/vnd.llmnotary.trace-package+zip' });
    fireEvent.change(input, { target: { files: [file] } });

    await expect.element(page.getByText('Your package may contain sensitive content.')).toBeVisible();
    await expect.element(page.getByText('Headers are hidden by default, but prompts, responses, tool definitions, and tool results may be included. We check the package without saving it.')).toBeVisible();
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
    expect(document.body.textContent).not.toContain('Provider verified');
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
