import { cleanup, fireEvent, render } from '@testing-library/react';
import { afterEach, describe, expect, test } from 'vitest';
import { page } from 'vitest/browser';
import CreditUtilizationChart from './CreditUtilizationChart';
import { ProviderIdentity } from './ProviderIdentity';
import { PlatformApiError } from './platform-api/client';
import { latestMacosDownloadHref } from './releaseDownloads';
import {
  AccountSettings,
  ApiKeysPanel,
  App,
  Dashboard,
  DeleteAccountPanel,
  DeviceAuthorizationApproval,
  Footer,
  Header,
  HostedNotaryRecord,
  Landing,
  Library,
  ListedTracesPreview,
  PublicTracePage,
  SignInPage,
  VerificationPage,
} from './site/SiteApp';
import { initialThemePreference } from './theme';

afterEach(async () => {
  cleanup();
  window.location.hash = '';
  window.localStorage.removeItem('llm-notary-theme');
  await page.viewport(1280, 900);
});

const libraryShares = Array.from({ length: 20 }, (_, index) => ({
  trace_id: `share-${index + 1}`,
  provider: index === 11 ? 'anthropic' : 'openai',
  model: index === 11 ? 'claude-sonnet-4-6' : 'gpt-5.2',
  publisher: 'fixture-user',
  authenticated_at_unix_ms: 1_786_000_000_000 - index,
  input_preview: `Prompt for share-${index + 1}`,
  output_preview: `Response for share-${index + 1}`,
  public_url: `https://example.test/s/share-${index + 1}`,
}));

const loadLibrary = async ({ limit = 20, cursor, search, provider } = {}) => {
  const query = search?.toLowerCase() || '';
  const matches = libraryShares.filter((share) => {
    const text =
      `${share.provider} ${share.model} ${share.publisher} ${share.input_preview} ${share.output_preview}`.toLowerCase();
    return (!query || text.includes(query)) && (!provider || share.provider === provider);
  });
  const offset = cursor ? Number(cursor) : 0;
  const items = matches.slice(offset, offset + limit);
  return {
    items: structuredClone(items),
    next_cursor: offset + limit < matches.length ? String(offset + limit) : null,
  };
};
const loadLibraryTrace = async (id) => ({
  resourceSpans: [
    {
      scopeSpans: [
        {
          spans: [
            {
              name: 'gen_ai.inference',
              spanId: `${id}-span`,
              attributes: [
                {
                  key: 'gen_ai.input.messages',
                  value: {
                    stringValue: JSON.stringify([
                      { role: 'user', parts: [{ type: 'text', content: `Prompt for ${id}` }] },
                    ]),
                  },
                },
                {
                  key: 'gen_ai.output.messages',
                  value: {
                    stringValue: JSON.stringify([
                      {
                        role: 'assistant',
                        parts: [{ type: 'text', content: `Response for ${id}` }],
                      },
                    ]),
                  },
                },
              ],
            },
          ],
        },
      ],
    },
  ],
});

const balanceFixture = (remaining = 1_024) => ({
  included_monthly_remaining_bytes: remaining,
  supplemental_remaining_bytes: 0,
  total_granted_bytes: remaining,
  total_remaining_bytes: remaining,
  total_used_bytes: 0,
  next_grant_expiration: null,
});

const creditsFixture = (remaining = 1_024) => ({
  capture: balanceFixture(remaining),
  notarization: balanceFixture(remaining),
  reset_at: 4_102_444_800,
});

const billingFixture = (overrides = {}) => ({
  plan: 'free',
  billing_status: 'active',
  purchase_mode: 'disabled',
  subscriptions_configured: false,
  entitlements: {
    monthly_capture_bytes: 50_000_000,
    monthly_notarization_bytes: 50_000_000,
    trace_storage_bytes: 1_000_000_000,
  },
  ...overrides,
});

const usageFixture = ({
  credits = creditsFixture(),
  captures = 0,
  notarizations = 0,
  total = 0,
  shared = 0,
  verifying = 0,
  storedBytes = 0,
} = {}) => ({
  credits,
  operations: { captures, notarizations },
  hosted_traces: { total, shared, verifying, stored_bytes: storedBytes },
});

describe('hosted site', () => {
  test('makes the current macOS app the primary landing action', async () => {
    expect(latestMacosDownloadHref('build-123 0.1.0')).toBe(
      '/downloads/cli/builds/build-123/LLM-Notary-macos-arm64.dmg',
    );
    expect(() => latestMacosDownloadHref('../build 0.1.0')).toThrow(
      'latest download pointer is invalid',
    );
    render(<Landing loadLatestPointer={async () => 'build-123 0.1.0'} />);

    const download = page.getByRole('link', { name: /Download for macOS/ });
    await expect
      .element(download)
      .toHaveAttribute('href', '/downloads/cli/builds/build-123/LLM-Notary-macos-arm64.dmg');
    await expect.element(download).toHaveAttribute('download', 'LLM-Notary-macos-arm64.dmg');
    await expect.element(page.getByText('Apple silicon · macOS 12+')).not.toBeInTheDocument();
    await expect
      .element(page.getByRole('link', { name: 'build on the Notary stack' }))
      .toHaveAttribute('href', '#/docs/getting-started');
    expect(document.querySelector('.hero-developer-path')?.textContent).toBe(
      'or, build on the Notary stack',
    );
    await expect.element(page.getByRole('link', { name: 'Get started' })).not.toBeInTheDocument();
    await expect
      .element(page.getByRole('link', { name: 'Browse Library' }))
      .not.toBeInTheDocument();
    expect(document.querySelector('.receipt [data-provider-icon="openai"]')).not.toBeNull();
  });

  test('puts Pricing in the header and product destinations in the footer', async () => {
    render(
      <>
        <Header user={null} onLogout={() => {}} />
        <Footer />
      </>,
    );

    const productNav = document.querySelector('.product-nav');
    await expect
      .element(page.getByRole('link', { name: 'Notary home' }))
      .toHaveAttribute('href', '/#/');
    await expect.element(page.getByText('Notary by Exalto')).toBeVisible();
    expect(Array.from(productNav.querySelectorAll('a'), (link) => link.textContent)).toEqual([
      'Docs',
      'Pricing',
      'Sign in',
    ]);
    await expect
      .element(page.getByRole('link', { name: 'Pricing' }))
      .toHaveAttribute('href', '/#/pricing');
    const footer = page.getByRole('navigation', { name: 'Footer' });
    await expect
      .element(footer.getByRole('link', { name: 'Verify' }))
      .toHaveAttribute('href', '/#/verify');
    await expect
      .element(footer.getByRole('link', { name: 'Library' }))
      .toHaveAttribute('href', '/#/library');
  });

  test('uses the endorsed identity in browser titles', async () => {
    window.location.hash = '#/privacy';
    render(<App loadCurrentUser={async () => null} />);

    await expect.element(page.getByRole('heading', { name: 'Privacy Policy' })).toBeVisible();
    expect(document.title).toBe('Privacy · Notary by Exalto');
  });

  test('explains hosted pricing in plain language on the landing page', async () => {
    render(<Landing loadLatestPointer={async () => 'build-123 0.1.0'} />);

    const pricing = document.getElementById('pricing');
    expect(pricing).not.toBeNull();
    await expect
      .element(page.getByRole('heading', { name: 'A plan for every proof workload.' }))
      .toBeVisible();
    await expect.element(page.getByText('50 MB capture each month')).toBeVisible();
    await expect.element(page.getByText('1 GB notarization each month')).toBeVisible();
    await expect.element(page.getByText('$10 per additional GB')).toBeVisible();
    await expect.element(page.getByText('Credit boundary')).not.toBeInTheDocument();
    await expect
      .element(page.getByRole('link', { name: 'See plan and usage details' }))
      .toHaveAttribute('href', '/#/docs/hosted-credits');
  });

  test('sends the macOS action to install options when the latest pointer is unavailable', async () => {
    render(
      <Landing
        loadLatestPointer={async () => {
          throw new Error('offline');
        }}
      />,
    );

    const download = page.getByRole('link', { name: /Download for macOS/ });
    await expect.element(download).toHaveAttribute('href', '#/docs/getting-started');
    await expect.element(page.getByText('View install options')).toBeVisible();
  });

  test('defaults to light and keeps appearance choices out of the signed-in account menu', async () => {
    expect(initialThemePreference()).toBe('light');
    let signedOut = false;
    render(
      <Header
        user={{ provider_display_name: 'fixture-user' }}
        onLogout={() => {
          signedOut = true;
        }}
      />,
    );

    await page.getByRole('button', { name: 'Account menu for fixture-user' }).click();
    await expect.element(page.getByRole('link', { name: 'Account' })).toBeVisible();
    await page.getByRole('button', { name: 'Sign out' }).click();
    expect(signedOut).toBe(true);
    await expect.element(page.getByRole('group', { name: 'Appearance' })).not.toBeInTheDocument();
  });

  test('reserves the account slot while browser authentication is loading', async () => {
    render(<Header user={null} authPending onLogout={() => {}} />);

    await expect
      .element(page.getByRole('status', { name: 'Checking sign-in status' }))
      .toBeVisible();
    await expect.element(page.getByRole('link', { name: 'Sign in' })).not.toBeInTheDocument();
  });

  test('keeps an Account deep link out of the landing page while authentication loads', async () => {
    window.location.hash = '#/account/settings';
    let resolveCurrentUser;
    const loadCurrentUser = () =>
      new Promise((resolve) => {
        resolveCurrentUser = resolve;
      });
    render(<App loadCurrentUser={loadCurrentUser} />);

    await expect.element(page.getByRole('status', { name: 'Loading Account' })).toBeVisible();
    await expect.element(page.getByText('Loading Account…')).toBeVisible();
    await expect
      .element(page.getByRole('heading', { name: 'Loading your account' }))
      .not.toBeInTheDocument();
    await expect
      .element(page.getByRole('heading', { name: 'Verifiable intelligence' }))
      .not.toBeInTheDocument();

    resolveCurrentUser({
      provider_display_name: 'fixture-user',
      usage: usageFixture(),
    });
    await expect
      .element(page.getByRole('heading', { name: 'Settings', exact: true }))
      .toBeVisible();
    expect(document.title).toBe('Settings · Notary by Exalto');
  });

  test('offers Google first and preserves a local-service return route', async () => {
    render(
      <SignInPage
        route="signin?return_to=%23%2Fauthorize%3Frequest_id%3Drequest-123"
        loadProviders={async () => ({ google: true, github: true })}
      />,
    );

    const google = page.getByRole('link', { name: 'Continue with Google' });
    await expect.element(google).toBeVisible();
    await expect
      .element(google)
      .toHaveAttribute(
        'href',
        '/api/auth/google?return_to=%23%2Fauthorize%3Frequest_id%3Drequest-123',
      );
    await expect.element(page.getByRole('link', { name: 'Continue with GitHub' })).toBeVisible();
    expect(document.querySelectorAll('[data-auth-provider-icon]')).toHaveLength(2);
    expect(document.querySelector('[data-auth-provider-icon="google"]')).not.toBeNull();
    expect(document.querySelector('[data-auth-provider-icon="github"]')).not.toBeNull();
    expect(document.querySelector('.auth-provider')?.textContent).toContain('Google');
    await expect.element(page.getByText('Google access')).not.toBeInTheDocument();
    await expect.element(page.getByText('Provider tokens')).not.toBeInTheDocument();
  });

  test('uses the formal sign-in title and preserves legacy Dashboard deep links', async () => {
    window.location.hash = '#/signin';
    render(<App loadCurrentUser={async () => null} />);
    await expect.element(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
    expect(document.title).toBe('Sign in · Notary by Exalto');

    cleanup();
    window.location.hash = '#/dashboard/settings';
    render(
      <App
        loadCurrentUser={async () => ({
          provider_display_name: 'fixture-user',
          usage: usageFixture(),
        })}
      />,
    );
    await expect
      .element(page.getByRole('heading', { name: 'Settings', exact: true }))
      .toBeVisible();
  });

  test('returns signed-out Account visitors to the requested Account route', async () => {
    render(
      <SignInPage
        route="signin?return_to=%23%2Faccount%2Ftraces"
        loadProviders={async () => ({ google: true, github: true })}
      />,
    );
    await expect
      .element(page.getByRole('link', { name: 'Continue with Google' }))
      .toHaveAttribute('href', '/api/auth/google?return_to=%23%2Faccount%2Ftraces');
  });

  test('shows only the configured sign-in provider', async () => {
    render(<SignInPage loadProviders={async () => ({ google: false, github: true })} />);

    await expect.element(page.getByRole('link', { name: 'Continue with GitHub' })).toBeVisible();
    await expect
      .element(page.getByRole('link', { name: 'Continue with Google' }))
      .not.toBeInTheDocument();
    expect(document.querySelectorAll('[data-auth-provider-icon="github"]')).toHaveLength(1);
  });

  test('shows progress while handing off to an auth provider', async () => {
    render(<SignInPage loadProviders={async () => ({ google: true, github: true })} />);

    const google = page.getByRole('link', { name: 'Continue with Google' });
    await expect.element(google).toBeVisible();
    google.element().addEventListener('click', (event) => event.preventDefault());
    await google.click();

    await expect
      .element(page.getByRole('link', { name: 'Connecting to Google…' }))
      .toHaveAttribute('aria-busy', 'true');
    await expect
      .element(page.getByRole('link', { name: 'Continue with GitHub' }))
      .toHaveAttribute('aria-disabled', 'true');
    expect(document.querySelectorAll('.auth-provider-progress i')).toHaveLength(3);
  });

  test('covers sign-in loading, unavailable, and already-signed-in states', async () => {
    render(<SignInPage loadProviders={() => new Promise(() => {})} />);
    await expect
      .element(page.getByRole('status').getByText('Loading sign-in options'))
      .toBeVisible();
    await expect.element(page.getByText('Continue to Notary', { exact: true })).toBeVisible();

    cleanup();
    render(
      <SignInPage
        loadProviders={async () => {
          throw new Error('Identity providers are offline.');
        }}
      />,
    );
    await expect
      .element(page.getByRole('alert').getByText('Sign-in options are unavailable'))
      .toBeVisible();
    await expect.element(page.getByText('Identity providers are offline.')).toBeVisible();

    cleanup();
    render(
      <SignInPage
        user={{ provider_display_name: 'fixture-user' }}
        loadProviders={async () => ({ google: true, github: true })}
      />,
    );
    await expect.element(page.getByRole('heading', { name: 'Already signed in' })).toBeVisible();
    await expect
      .element(page.getByRole('link', { name: 'Open Account' }))
      .toHaveAttribute('href', '/#/account');
  });

  test('offers Auto, Light, and Dark in Account appearance settings', async () => {
    let selectedTheme;
    render(
      <AccountSettings
        theme="light"
        onThemeChange={(theme) => {
          selectedTheme = theme;
        }}
      />,
    );

    await expect.element(page.getByRole('heading', { name: 'Appearance' })).toBeVisible();
    const appearance = page.getByRole('radiogroup', { name: 'Appearance' });
    await expect
      .element(appearance.getByRole('radio', { name: 'light' }))
      .toHaveAttribute('aria-checked', 'true');
    await appearance.getByRole('radio', { name: 'auto' }).click();
    expect(selectedTheme).toBe('auto');
    await expect.element(appearance.getByRole('radio', { name: 'dark' })).toBeVisible();
  });

  test('collapses Account navigation into a mobile dropdown', async () => {
    await page.viewport(390, 844);
    render(
      <Dashboard
        user={{
          provider_display_name: 'fixture-user',
          usage: usageFixture({ credits: null, total: 3, shared: 2, verifying: 1 }),
        }}
        view="usage"
        theme="light"
        onThemeChange={() => {}}
        onAccountDeleted={() => {}}
        loadConnectedDevices={async () => ({ items: [], next_cursor: null })}
        loadHostedTraces={async () => ({ items: [], next_cursor: null })}
        loadCreditOffers={async () => []}
        loadCreditHistory={async () => ({ items: [], next_cursor: null })}
        loadBillingPurchases={async () => []}
      />,
    );

    const navigation = page.getByRole('navigation', { name: 'Account navigation' });
    const trigger = navigation.getByRole('button', { name: 'Account menu: Plan & usage' });
    await expect.element(trigger).toHaveAttribute('aria-expanded', 'false');
    await trigger.click();
    await expect.element(trigger).toHaveAttribute('aria-expanded', 'true');
    await expect.element(navigation.getByRole('link', { name: /^Traces\s*3$/ })).toBeVisible();
    await expect
      .element(navigation.getByRole('link', { name: 'Plan & usage' }))
      .toHaveAttribute('aria-current', 'page');
    fireEvent.keyDown(window, { key: 'Escape' });
    await expect.element(trigger).toHaveAttribute('aria-expanded', 'false');
  });

  test('uses only the canonical Account routes in desktop navigation', async () => {
    render(
      <Dashboard
        user={{
          provider_display_name: 'fixture-user',
          usage: usageFixture({ total: 3, shared: 2, verifying: 1 }),
        }}
        view="traces"
        theme="light"
        onThemeChange={() => {}}
        onAccountDeleted={() => {}}
        loadConnectedDevices={async () => ({ items: [], next_cursor: null })}
        loadHostedTraces={async () => ({ items: [], next_cursor: null })}
        loadCreditOffers={async () => []}
        loadCreditHistory={async () => ({ items: [], next_cursor: null })}
        loadBillingPurchases={async () => []}
      />,
    );

    const accountRoutes = Array.from(document.querySelectorAll('.dashboard-sidebar a')).map(
      (link) => [link.textContent?.trim(), link.getAttribute('href')],
    );
    expect(accountRoutes).toEqual([
      ['Overview', '#/account'],
      ['Traces3', '#/account/traces'],
      ['Plan & usage', '#/account/usage'],
      ['Settings', '#/account/settings'],
    ]);
    expect(document.querySelector('a[href^="#/dashboard"]')).toBeNull();
  });

  test('summarizes plan, usage, shared traces, and attention in the Account overview', async () => {
    render(
      <Dashboard
        user={{
          provider_display_name: 'fixture-user',
          usage: usageFixture({
            captures: 12,
            notarizations: 7,
            total: 3,
            shared: 2,
            verifying: 1,
          }),
        }}
        view="overview"
        theme="light"
        onThemeChange={() => {}}
        onAccountDeleted={() => {}}
        loadConnectedDevices={async () => ({ items: [], next_cursor: null })}
        loadHostedTraces={async () => ({ items: [], next_cursor: null })}
        loadCreditOffers={async () => []}
        loadCreditHistory={async () => ({ items: [], next_cursor: null })}
        loadBillingPurchases={async () => []}
      />,
    );

    await expect.element(page.getByText('None', { exact: true })).toBeVisible();
    const summary = document.querySelector('.dashboard-summary');
    expect(summary?.textContent).toContain('Current planFree · active');
    expect(summary?.textContent).toContain('Capture usage0 B used');
    expect(summary?.textContent).toContain('Notarization usage0 B used');
    expect(summary?.textContent).toContain('Shared traces2');
    expect(summary?.textContent).toContain('Needs attentionNone');
    expect(summary?.textContent).not.toContain('Completed captures');
    expect(summary?.textContent).not.toContain('Completed notarizations');
  });

  test('discards an old credit-history page after claiming an offer', async () => {
    let rootRequests = 0;
    let resolveOldPage;
    let markOldPageStarted;
    const oldPageStarted = new Promise((resolve) => {
      markOldPageStarted = resolve;
    });
    const entry = (id, label, createdAt) => ({
      id,
      kind: 'grant',
      credit_kind: 'notarization',
      amount_bytes: 1_024,
      display_label: label,
      created_at: createdAt,
    });
    const loadCreditHistory = async (options) => {
      if (options.cursor) {
        markOldPageStarted();
        return new Promise((resolve) => {
          resolveOldPage = resolve;
        });
      }
      rootRequests += 1;
      return rootRequests === 1
        ? { items: [entry('initial', 'Initial credit', 100)], next_cursor: 'old-cursor' }
        : {
            items: [
              entry('claimed', 'Claimed credit', 200),
              entry('initial', 'Initial credit', 100),
            ],
            next_cursor: 'fresh-cursor',
          };
    };
    render(
      <Dashboard
        user={{
          provider_display_name: 'fixture-user',
          billing: billingFixture(),
          usage: usageFixture(),
        }}
        view="usage"
        theme="light"
        onThemeChange={() => {}}
        onAccountDeleted={() => {}}
        loadConnectedDevices={async () => ({ items: [], next_cursor: null })}
        loadHostedTraces={async () => ({ items: [], next_cursor: null })}
        loadCreditOffers={async () => [
          {
            id: 'offer-1',
            title: 'Test credit',
            description: 'One-time test credit.',
            amount_bytes: 1_024,
            claim_expires_at: 4_102_444_800,
            credit_expires_at: 4_102_444_800,
          },
        ]}
        loadCreditHistory={loadCreditHistory}
        loadBillingPurchases={async () => []}
        claimOfferRequest={async () => ({ credits: creditsFixture(2_048) })}
      />,
    );

    await expect.element(page.getByText('Initial credit')).toBeVisible();
    await page.getByRole('button', { name: 'Load older activity' }).click();
    await oldPageStarted;
    await page.getByRole('button', { name: /^Claim / }).click();
    await expect.element(page.getByText('Claimed credit')).toBeVisible();

    resolveOldPage({
      items: [entry('stale', 'Stale older credit', 50)],
      next_cursor: 'stale-cursor',
    });
    await new Promise((resolve) => window.setTimeout(resolve, 0));
    await expect.element(page.getByText('Stale older credit')).not.toBeInTheDocument();
    await expect.element(page.getByText('Claimed credit')).toBeVisible();
  });

  test('starts a fixed-price Stripe Checkout from the credit quantity rail', async () => {
    let checkoutRequest;
    let checkoutUrl;
    render(
      <Dashboard
        user={{
          provider_display_name: 'fixture-user',
          billing: billingFixture({ purchase_mode: 'live' }),
          usage: usageFixture(),
        }}
        view="usage"
        theme="light"
        onThemeChange={() => {}}
        onAccountDeleted={() => {}}
        loadConnectedDevices={async () => ({ items: [], next_cursor: null })}
        loadHostedTraces={async () => ({ items: [], next_cursor: null })}
        loadCreditOffers={async () => []}
        loadCreditHistory={async () => ({ items: [], next_cursor: null })}
        loadBillingPurchases={async () => []}
        startCheckout={async (quantityGb, idempotencyKey) => {
          checkoutRequest = { quantityGb, idempotencyKey };
          return { checkout_url: 'https://checkout.stripe.com/c/pay/test' };
        }}
        openCheckout={(url) => {
          checkoutUrl = url;
        }}
      />,
    );

    await page.getByRole('button', { name: '10 GB', exact: true }).click();
    await page.getByRole('button', { name: 'Buy 10 GB for $100' }).click();
    expect(checkoutRequest.quantityGb).toBe(10);
    expect(checkoutRequest.idempotencyKey).toMatch(/^[a-zA-Z0-9_-]+$/);
    expect(checkoutUrl).toBe('https://checkout.stripe.com/c/pay/test');
  });

  test('opens subscription Checkout for free accounts and the billing portal for subscribers', async () => {
    let checkoutRequest;
    let openedUrl;
    const common = {
      view: 'usage',
      theme: 'light',
      onThemeChange: () => {},
      onAccountDeleted: () => {},
      loadConnectedDevices: async () => ({ items: [], next_cursor: null }),
      loadHostedTraces: async () => ({ items: [], next_cursor: null }),
      loadCreditOffers: async () => [],
      loadCreditHistory: async () => ({ items: [], next_cursor: null }),
      loadBillingPurchases: async () => [],
      openCheckout: (url) => {
        openedUrl = url;
      },
    };
    render(
      <Dashboard
        {...common}
        user={{
          provider_display_name: 'fixture-user',
          billing: billingFixture({ purchase_mode: 'live', subscriptions_configured: true }),
          usage: usageFixture({ credits: creditsFixture(50_000_000) }),
        }}
        startSubscriptionCheckout={async (plan, idempotencyKey) => {
          checkoutRequest = { plan, idempotencyKey };
          return { checkout_url: 'https://checkout.stripe.com/c/pay/subscription' };
        }}
      />,
    );

    expect(document.body.textContent).toContain('50.0 MB');
    expect(document.body.textContent).toContain('of 1.0 GB');
    expect(document.body.textContent).not.toContain('47.7 MB');
    await page.getByRole('button', { name: '1 GB · $9.99/month' }).click();
    expect(checkoutRequest.plan).toBe('one_gb');
    expect(checkoutRequest.idempotencyKey).toMatch(/^[a-zA-Z0-9_-]+$/);
    expect(openedUrl).toBe('https://checkout.stripe.com/c/pay/subscription');

    cleanup();
    render(
      <Dashboard
        {...common}
        user={{
          provider_display_name: 'fixture-user',
          billing: billingFixture({ plan: 'one_gb', purchase_mode: 'live' }),
          usage: usageFixture(),
        }}
        startBillingPortal={async () => ({
          portal_url: 'https://billing.stripe.com/p/session/test',
        })}
      />,
    );
    await page.getByRole('button', { name: 'Manage subscription' }).click();
    expect(openedUrl).toBe('https://billing.stripe.com/p/session/test');
  });

  test('hides Checkout when disabled and labels Stripe test mode unmistakably', async () => {
    const credits = creditsFixture();
    const common = {
      view: 'usage',
      theme: 'light',
      onThemeChange: () => {},
      onAccountDeleted: () => {},
      loadConnectedDevices: async () => ({ items: [], next_cursor: null }),
      loadHostedTraces: async () => ({ items: [], next_cursor: null }),
      loadCreditOffers: async () => [],
      loadCreditHistory: async () => ({ items: [], next_cursor: null }),
      loadBillingPurchases: async () => [],
    };
    render(
      <Dashboard
        {...common}
        user={{
          provider_display_name: 'fixture-user',
          billing: billingFixture(),
          usage: usageFixture({ credits }),
        }}
      />,
    );
    await expect
      .element(page.getByRole('heading', { name: 'Purchases unavailable' }))
      .toBeVisible();
    await expect
      .element(page.getByText('You can’t buy more notarization right now.'))
      .toBeVisible();
    await expect
      .element(page.getByRole('group', { name: 'Credit quantity' }))
      .not.toBeInTheDocument();

    cleanup();
    render(
      <Dashboard
        {...common}
        user={{
          provider_display_name: 'fixture-user',
          billing: billingFixture({ purchase_mode: 'test' }),
          usage: usageFixture({ credits }),
        }}
      />,
    );
    await expect.element(page.getByText('Stripe test mode · no real charges')).toBeVisible();
    await expect
      .element(page.getByRole('button', { name: 'Open test Checkout · 1 GB for $10' }))
      .toBeVisible();
    await expect
      .element(page.getByText('New subscriptions are temporarily unavailable.'))
      .toBeVisible();
    await expect.element(page.getByRole('button', { name: '1 GB · $9.99/month' })).toBeDisabled();
  });

  test('retries Checkout confirmation and keeps a fresher purchase than the initial list', async () => {
    const credits = creditsFixture();
    let resolveInitialList;
    let pollCalls = 0;
    const purchase = (state) => ({
      id: 'purchase-1',
      state,
      quantity_gb: 1,
      amount_cents: 1_000,
      created_at: 1_786_000_000,
    });
    render(
      <Dashboard
        user={{
          provider_display_name: 'fixture-user',
          billing: billingFixture({ purchase_mode: 'test' }),
          usage: usageFixture({ credits }),
        }}
        view="usage"
        route="usage?checkout=success&purchase_id=purchase-1"
        theme="light"
        onThemeChange={() => {}}
        onAccountDeleted={() => {}}
        loadConnectedDevices={async () => ({ items: [], next_cursor: null })}
        loadHostedTraces={async () => ({ items: [], next_cursor: null })}
        loadCreditOffers={async () => []}
        loadCreditHistory={async () => ({ items: [], next_cursor: null })}
        loadBillingPurchases={() =>
          new Promise((resolve) => {
            resolveInitialList = resolve;
          })
        }
        loadBillingPurchase={async () => {
          pollCalls += 1;
          if (pollCalls === 1) throw new Error('temporary network failure');
          return purchase(pollCalls === 2 ? 'checkout_open' : 'paid');
        }}
        loadCurrentUser={async () => ({
          billing: billingFixture({ plan: 'one_gb', purchase_mode: 'test' }),
          usage: usageFixture({ credits }),
        })}
        checkoutPollBaseDelay={0}
        checkoutPollMaxAttempts={4}
      />,
    );

    await expect
      .element(page.getByText('Payment confirmed. Your credits are ready.'))
      .toBeVisible();
    resolveInitialList([purchase('checkout_open')]);
    await new Promise((resolve) => window.setTimeout(resolve, 0));
    await expect.element(page.getByText('paid', { exact: true })).toBeVisible();
    await expect.element(page.getByText('checkout open', { exact: true })).not.toBeInTheDocument();
    expect(pollCalls).toBe(3);
  });

  test('shows a bounded timeout when Stripe confirmation stays nonterminal', async () => {
    const credits = creditsFixture();
    render(
      <Dashboard
        user={{
          provider_display_name: 'fixture-user',
          billing: billingFixture({ purchase_mode: 'test' }),
          usage: usageFixture({ credits }),
        }}
        view="usage"
        route="usage?checkout=success&purchase_id=purchase-1"
        theme="light"
        onThemeChange={() => {}}
        onAccountDeleted={() => {}}
        loadConnectedDevices={async () => ({ items: [], next_cursor: null })}
        loadHostedTraces={async () => ({ items: [], next_cursor: null })}
        loadCreditOffers={async () => []}
        loadCreditHistory={async () => ({ items: [], next_cursor: null })}
        loadBillingPurchases={async () => []}
        loadBillingPurchase={async () => ({
          id: 'purchase-1',
          state: 'checkout_open',
          quantity_gb: 1,
          amount_cents: 1_000,
          created_at: 1_786_000_000,
        })}
        checkoutPollBaseDelay={0}
        checkoutPollMaxAttempts={2}
      />,
    );

    await expect
      .element(
        page.getByText(
          'We could not confirm the payment yet. Check purchase history or refresh this page.',
        ),
      )
      .toBeVisible();
  });

  test.each([
    ['failed', 'Payment was not completed. No credits were added.'],
    ['refunded', 'This payment was refunded. Its purchased credits are no longer available.'],
    [
      'disputed',
      'This payment is under dispute. Its purchased credits are temporarily unavailable.',
    ],
  ])('renders the %s Checkout terminal state explicitly', async (state, message) => {
    const credits = creditsFixture();
    render(
      <Dashboard
        user={{
          provider_display_name: 'fixture-user',
          billing: billingFixture({ purchase_mode: 'test' }),
          usage: usageFixture({ credits }),
        }}
        view="usage"
        route="usage?checkout=success&purchase_id=purchase-1"
        theme="light"
        onThemeChange={() => {}}
        onAccountDeleted={() => {}}
        loadConnectedDevices={async () => ({ items: [], next_cursor: null })}
        loadHostedTraces={async () => ({ items: [], next_cursor: null })}
        loadCreditOffers={async () => []}
        loadCreditHistory={async () => ({ items: [], next_cursor: null })}
        loadBillingPurchases={async () => []}
        loadBillingPurchase={async () => ({
          id: 'purchase-1',
          state,
          quantity_gb: 1,
          amount_cents: 1_000,
          created_at: 1_786_000_000,
        })}
        loadCurrentUser={async () => ({
          billing: billingFixture({ purchase_mode: 'test' }),
          credits,
        })}
        checkoutPollBaseDelay={0}
      />,
    );

    await expect.element(page.getByText(message)).toBeVisible();
  });

  test('renders every known provider icon and neutral fallbacks beside provider text', async () => {
    render(
      <div>
        {['openai', 'anthropic', 'deepseek', 'openrouter', 'future-provider'].map((provider) => (
          <ProviderIdentity provider={provider} key={provider} />
        ))}
        <ProviderIdentity provider={null} />
      </div>,
    );

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
    render(
      <Library
        loadShares={async () => ({
          items: [
            {
              trace_id: 'routed-share',
              provider: 'openrouter',
              model: 'openai/gpt-5-mini',
              publisher: 'fixture-user',
              authenticated_at_unix_ms: 1_786_000_000_000,
              input_preview: 'Compare these records.',
              output_preview: 'The second record is stronger.',
              public_url: 'https://example.test/s/routed-share',
            },
          ],
          next_cursor: null,
        })}
      />,
    );

    const row = page.getByRole('link', { name: /openai\/gpt-5-mini/ });
    await expect.element(row).toBeVisible();
    expect(row.element().querySelector('[data-provider-icon="openrouter"]')).not.toBeNull();
    expect(row.element().querySelector('[data-provider-icon="openai"]')).toBeNull();
  });

  test('makes local service authorization a clear two-step decision', async () => {
    window.location.hash = '#/authorize?request_id=request-123&approval_secret=secret-456';
    render(
      <>
        <Header user={null} hideSignIn />
        <DeviceAuthorizationApproval
          route="authorize?request_id=request-123&approval_secret=secret-456"
          user={null}
        />
      </>,
    );

    await expect.element(page.getByRole('heading', { name: 'Sign in to continue' })).toBeVisible();
    await expect.element(page.getByRole('link', { name: 'Choose sign-in method' })).toBeVisible();
    await expect.element(page.getByText('Google access')).not.toBeInTheDocument();
    await expect.element(page.getByText('Provider tokens')).not.toBeInTheDocument();
    await expect.element(page.getByText('Review and connect the device')).toBeVisible();
    await expect.element(page.getByRole('link', { name: 'Sign in' })).not.toBeInTheDocument();
  });

  test('shows the device, account, and code before approval', async () => {
    const loadApproval = async () => ({
      device_name: 'Research MacBook',
      user_code: 'NOTARY-7K3',
      expires_at: 1_786_000_000,
      capabilities: ['hosted_notarization', 'consume_credits', 'share_notarized_traces'],
    });
    let approved;
    render(
      <DeviceAuthorizationApproval
        route="authorize?request_id=request-123&approval_secret=secret-456"
        user={{ provider_display_name: 'fixture-user' }}
        loadApproval={loadApproval}
        approveRequest={async (...args) => {
          approved = args;
        }}
      />,
    );

    await expect.element(page.getByRole('heading', { name: 'Connect this device?' })).toBeVisible();
    await expect.element(page.getByText('Research MacBook')).toBeVisible();
    await expect.element(page.getByText('fixture-user')).toBeVisible();
    await expect.element(page.getByText('NOTARY-7K3')).toBeVisible();
    await expect.element(page.getByText('Use hosted notarization')).toBeVisible();
    await expect.element(page.getByText('Consume account credits')).toBeVisible();
    await expect.element(page.getByText('Share Notarized traces')).toBeVisible();
    await expect
      .element(page.getByText(/Connecting does not upload existing local traces/))
      .toBeVisible();
    expect(document.body.textContent).not.toContain('secret-456');
    await page.getByRole('button', { name: 'Connect device' }).click();

    expect(approved).toEqual(['request-123', 'secret-456']);
    await expect.element(page.getByRole('heading', { name: 'Device connected' })).toBeVisible();
  });

  test('covers checking, invalid, and unavailable device-connection states', async () => {
    render(
      <DeviceAuthorizationApproval
        route="authorize?request_id=request-123&approval_secret=secret-456"
        user={{ provider_display_name: 'fixture-user' }}
        loadApproval={() => new Promise(() => {})}
      />,
    );
    await expect
      .element(page.getByRole('heading', { name: 'Checking this request' }))
      .toBeVisible();
    await expect.element(page.getByText('None until you approve')).toBeVisible();

    cleanup();
    render(
      <DeviceAuthorizationApproval
        route="authorize"
        user={{ provider_display_name: 'fixture-user' }}
      />,
    );
    await expect
      .element(page.getByRole('heading', { name: 'Invalid authorization link' }))
      .toBeVisible();
    await expect.element(page.getByText('Restart from the local Notary app')).toBeVisible();

    cleanup();
    render(
      <DeviceAuthorizationApproval
        route="authorize?request_id=request-123&approval_secret=secret-456"
        user={{ provider_display_name: 'fixture-user' }}
        loadApproval={async () => {
          throw new Error('This request expired.');
        }}
      />,
    );
    await expect
      .element(page.getByRole('heading', { name: 'Connection unavailable' }))
      .toBeVisible();
    await expect.element(page.getByRole('alert').getByText(/This request expired/)).toBeVisible();
  });

  test('groups Account settings and revokes a connected device', async () => {
    let revokedId;
    render(
      <Dashboard
        user={{ provider_display_name: 'fixture-user', usage: usageFixture({ credits: null }) }}
        view="settings"
        theme="light"
        onThemeChange={() => {}}
        onAccountDeleted={() => {}}
        loadConnectedDevices={async () => ({
          items: [
            {
              device_id: 'device-1',
              device_name: 'Research MacBook',
              created_at: 1_786_000_000,
              last_used_at: 1_786_000_100,
              expires_at: 1_796_000_000,
              revoked_at: null,
            },
          ],
          next_cursor: null,
        })}
        revokeDeviceRequest={async (id) => {
          revokedId = id;
        }}
        loadHostedTraces={async () => ({ items: [], next_cursor: null })}
        loadCreditOffers={async () => []}
        loadCreditHistory={async () => ({ items: [], next_cursor: null })}
        loadBillingPurchases={async () => []}
      />,
    );

    await expect.element(page.getByRole('heading', { name: 'Appearance' })).toBeVisible();
    await expect.element(page.getByRole('heading', { name: 'API access' })).toBeVisible();
    await expect.element(page.getByRole('heading', { name: 'Connected devices' })).toBeVisible();
    await expect.element(page.getByRole('heading', { name: 'Delete account' })).toBeVisible();
    await expect.element(page.getByText('Research MacBook')).toBeVisible();
    await page.getByRole('button', { name: 'Revoke' }).click();
    await page.getByRole('alertdialog').getByRole('button', { name: 'Revoke device' }).click();
    expect(revokedId).toBe('device-1');
    await expect.element(page.getByText('No devices are connected.')).toBeVisible();
  });

  test('shows a new API key once and revokes it from the account list', async () => {
    const secret = `notary_key_${'a'.repeat(32)}_${'b'.repeat(64)}`;
    let createRequest;
    let revokedId;
    render(
      <ApiKeysPanel
        loadKeys={async () => ({ items: [], next_cursor: null })}
        createKey={async (request) => {
          createRequest = request;
          return {
            secret,
            api_key: {
              id: 'a'.repeat(32),
              prefix: `notary_key_${'a'.repeat(12)}`,
              name: request.name,
              scopes: request.scopes,
              created_at: 1_786_000_000,
              last_used_at: null,
              expires_at: request.expires_at,
              revoked_at: null,
            },
          };
        }}
        revokeKey={async (id) => {
          revokedId = id;
        }}
      />,
    );

    await expect.element(page.getByText('No API keys')).toBeVisible();
    await page.getByRole('button', { name: 'Create API key' }).click();
    await page.getByLabelText('Name').fill('Nightly CI');
    await page.getByRole('dialog').getByRole('button', { name: 'Create API key' }).click();

    await expect.element(page.getByText(secret)).toBeVisible();
    expect(createRequest.name).toBe('Nightly CI');
    expect(createRequest.scopes).toEqual([
      'account:read',
      'traces:read',
      'traces:share',
      'capture:request',
      'notarization:request',
    ]);
    await page.getByRole('button', { name: 'I stored the key' }).click();
    await expect.element(page.getByText(secret)).not.toBeInTheDocument();
    await expect.element(page.getByText('Nightly CI')).toBeVisible();

    await page.getByRole('button', { name: 'Revoke' }).click();
    await page.getByRole('button', { name: 'Revoke API key' }).click();
    expect(revokedId).toBe('a'.repeat(32));
    await expect.element(page.getByText('Revoked')).toBeVisible();
  });

  test('renders a zero notary lower bound as an unbounded interval', async () => {
    render(
      <HostedNotaryRecord
        record={{
          name: 'Alice',
          operator: 'Exalto',
          host: 'notary.example',
          port: 7047,
          transport: 'tls',
          status: 'active',
          key_id: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          valid_from_unix_ms: 0,
          valid_until_unix_ms: null,
          notarize_until_unix_ms: null,
        }}
        activeKeyId="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        copiedKeyId={null}
        onCopy={() => {}}
      />,
    );

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
    render(
      <ListedTracesPreview
        loadShares={async (options) => {
          request = options;
          return { items: [libraryShares[0], libraryShares[11]], next_cursor: null };
        }}
      />,
    );

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
    render(
      <Library
        loadShares={async (options) => {
          requests += 1;
          return loadLibrary(options);
        }}
      />,
    );
    await expect.element(page.getByText('20 traces shown')).toBeVisible();
    const beforeSearch = requests;

    await page.getByPlaceholder('Search conversations or models').fill('ai');
    await expect
      .element(page.getByText('Search needs three letters or numbers together.'))
      .toBeVisible();
    await new Promise((resolve) => window.setTimeout(resolve, 250));
    expect(requests).toBe(beforeSearch);
  });

  test('keeps Library filters while loading the next page', async () => {
    const requests = [];
    const first = libraryShares[11];
    const second = {
      ...libraryShares[11],
      trace_id: 'share-continued',
      model: 'claude-haiku-4-5',
    };
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
    expect(requests.at(-1)).toMatchObject({
      cursor: 'next-library-page',
      search: 'claude',
      limit: 20,
    });
  });

  test('discards an old Library continuation after filters change', async () => {
    let resolveOldPage;
    let markLoadStarted;
    const loadStarted = new Promise((resolve) => {
      markLoadStarted = resolve;
    });
    const initial = libraryShares[0];
    const filtered = libraryShares[11];
    const stale = {
      ...libraryShares[0],
      trace_id: 'stale-share',
      output_preview: 'Stale continuation',
    };
    const loadShares = async (options) => {
      if (options.cursor) {
        markLoadStarted();
        return new Promise((resolve) => {
          resolveOldPage = resolve;
        });
      }
      if (options.search === 'claude') return { items: [filtered], next_cursor: null };
      return { items: [initial], next_cursor: 'old-cursor' };
    };
    render(<Library loadShares={loadShares} />);

    await expect.element(page.getByRole('button', { name: 'Load more traces' })).toBeVisible();
    await page.getByRole('button', { name: 'Load more traces' }).click();
    await loadStarted;
    await page.getByPlaceholder('Search conversations or models').fill('claude');
    await expect
      .element(page.getByRole('button', { name: 'Load more traces' }))
      .not.toBeInTheDocument();
    await expect.element(page.getByRole('link', { name: /claude-sonnet-4-6/ })).toBeVisible();

    resolveOldPage({ items: [stale], next_cursor: 'stale-cursor' });
    await new Promise((resolve) => window.requestAnimationFrame(resolve));
    await expect.element(page.getByText('Stale continuation')).not.toBeInTheDocument();
    await expect
      .element(page.getByRole('button', { name: 'Load more traces' }))
      .not.toBeInTheDocument();
  });

  test('loads older API keys without replacing the current page', async () => {
    const key = (id, name) => ({
      id,
      prefix: `notary_key_${id.slice(0, 12)}`,
      name,
      scopes: ['account:read'],
      created_at: 1_786_000_000,
      last_used_at: null,
      expires_at: null,
      revoked_at: null,
    });
    const requests = [];
    render(
      <ApiKeysPanel
        loadKeys={async (options) => {
          requests.push(options);
          return options.cursor
            ? { items: [key('b'.repeat(32), 'Older key')], next_cursor: null }
            : { items: [key('a'.repeat(32), 'Current key')], next_cursor: 'next-key-page' };
        }}
        createKey={async () => {
          throw new Error('not used');
        }}
        revokeKey={async () => {}}
      />,
    );

    await expect.element(page.getByText('Current key')).toBeVisible();
    await page.getByRole('button', { name: 'Load more API keys' }).click();
    await expect.element(page.getByText('Older key')).toBeVisible();
    await expect.element(page.getByText('Current key')).toBeVisible();
    expect(requests.at(-1)).toEqual({ limit: 20, cursor: 'next-key-page' });
  });

  test('does not treat a bare legacy trace as a package-backed preview', async () => {
    let traceLoads = 0;
    render(
      <Library
        loadShares={async () => ({
          items: [
            {
              trace_id: 'legacy-share',
              provider: 'openai',
              model: 'gpt-4.1',
              publisher: 'fixture-user',
              authenticated_at_unix_ms: 1_786_000_000_000,
              public_url: 'https://example.test/s/legacy-share',
            },
          ],
          next_cursor: null,
        })}
        loadTrace={async (id) => {
          traceLoads += 1;
          return loadLibraryTrace(id);
        }}
      />,
    );

    await expect.element(page.getByText('No prompt or response preview.')).toBeVisible();
    expect(traceLoads).toBe(0);
  });

  test('requires the account identifier before deleting an account', async () => {
    let deleted = false;
    let completed = false;
    render(
      <DeleteAccountPanel
        identifier="fixture-user"
        deleteAccount={async () => {
          deleted = true;
        }}
        onDeleted={() => {
          completed = true;
        }}
      />,
    );

    await expect
      .element(page.getByText(/Local traces and local settings on your devices are not deleted/))
      .toBeVisible();
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
      trace_id: 'share-12',
      title: 'Compare these two evidence trails.',
      visibility: 'unlisted',
      password_protected: false,
      expires_at: null,
      publisher: 'fixture-user',
      shared_at: 1_786_000_001,
      authenticated_at_unix_ms: 1_786_000_000_000,
      provider: 'anthropic',
      host: 'api.anthropic.com',
      model: 'claude-sonnet-4-6',
      notarized_state: 'notarized',
      hosted_verification: 'passed',
      notary_key_id: 'sha256:abc',
      registry_generation: 42,
      trust_source: 'hosted_registry',
      content_sha256: 'b'.repeat(64),
      package_size_bytes: 4096,
      package_sha256: 'c'.repeat(64),
      disclosure_safety_version: 'notary/public-package-safety/v1',
      disclosure_safety_override: false,
      trace_url: '/api/public/traces/share-12/trace.otlp.json',
      package_url: '/api/public/traces/share-12/package.llmtrace',
      public_url: 'https://example.test/s/share-12',
    });
    const loadTrace = async () => ({
      resourceSpans: [
        {
          scopeSpans: [
            {
              spans: [
                {
                  name: 'gen_ai.inference',
                  spanId: 'span-12',
                  attributes: [
                    {
                      key: 'gen_ai.input.messages',
                      value: {
                        stringValue: JSON.stringify([
                          {
                            role: 'user',
                            parts: [
                              { type: 'text', content: 'Compare these two evidence trails.' },
                            ],
                          },
                        ]),
                      },
                    },
                    {
                      key: 'gen_ai.output.messages',
                      value: {
                        stringValue: JSON.stringify([
                          {
                            role: 'assistant',
                            parts: [
                              { type: 'text', content: 'The second trail is stronger.' },
                              {
                                type: 'tool_call',
                                id: 'call-1',
                                name: 'lookup_record',
                                arguments: { id: 42 },
                              },
                              {
                                type: 'tool_call_response',
                                id: 'call-1',
                                result: { source: 'fixture record 42' },
                              },
                            ],
                          },
                        ]),
                      },
                    },
                  ],
                },
              ],
            },
          ],
        },
      ],
    });
    render(<PublicTracePage traceId="share-12" loadShare={loadShare} loadTrace={loadTrace} />);
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
    expect(document.querySelector('meta[name="robots"]')?.getAttribute('content')).toContain(
      'noindex',
    );
  });

  test('opens a protected trace in memory and submits a bounded report', async () => {
    let unlocked = false;
    const required = () => {
      throw new PlatformApiError('Public Trace is unavailable', 404, 'trace_unavailable');
    };
    const loadShare = async () => {
      if (!unlocked) required();
      return {
        trace_id: 'protected-share',
        title: 'Prompt for protected-share',
        visibility: 'listed',
        password_protected: true,
        expires_at: 4_102_444_800,
        publisher: 'fixture-user',
        shared_at: 1_786_000_000,
        authenticated_at_unix_ms: 1_786_000_000_000,
        provider: 'openai',
        host: 'api.openai.com',
        model: 'gpt-5.2',
        notarized_state: 'notarized',
        hosted_verification: 'passed',
        notary_key_id: 'sha256:abc',
        registry_generation: 42,
        trust_source: 'hosted_registry',
        content_sha256: 'b'.repeat(64),
        package_size_bytes: 2048,
        package_sha256: 'c'.repeat(64),
        disclosure_safety_version: 'notary/public-package-safety/v1',
        disclosure_safety_override: false,
        trace_url: '/api/public/traces/protected-share/trace.otlp.json',
        package_url: '/api/public/traces/protected-share/package.llmtrace',
        public_url: 'https://example.test/s/protected-share',
      };
    };
    const loadTrace = async (id) => {
      if (!unlocked) required();
      return loadLibraryTrace(id);
    };
    let report;
    render(
      <PublicTracePage
        traceId="protected-share"
        loadShare={loadShare}
        loadTrace={loadTrace}
        accessTrace={async (_id, password) => {
          if (password !== 'evidence-pass') required();
          unlocked = true;
        }}
        sendReport={async (...args) => {
          report = args;
          return { received: true };
        }}
      />,
    );

    await expect.element(page.getByRole('heading', { name: 'Password required' })).toBeVisible();
    expect(document.querySelector('meta[name="robots"]')?.getAttribute('content')).toContain(
      'noindex',
    );
    await page.getByLabelText('Password').fill('evidence-pass');
    await page.getByRole('button', { name: 'Open trace' }).click();
    await expect.element(page.getByText('Prompt for protected-share')).toBeVisible();
    expect(document.querySelector('meta[name="robots"]')?.getAttribute('content')).toContain(
      'noindex',
    );

    await page.getByRole('button', { name: 'Report this trace' }).click();
    await page.getByRole('combobox', { name: 'Report reason' }).click();
    await page.getByRole('option', { name: 'Spam or misleading content' }).click();
    await page
      .getByPlaceholder('Briefly explain the issue')
      .fill('The listing misrepresents the disclosed response.');
    await page.getByRole('button', { name: 'Send report' }).click();
    expect(report).toEqual([
      'protected-share',
      { reason: 'spam', message: 'The listing misrepresents the disclosed response.' },
    ]);
    await expect.element(page.getByRole('heading', { name: 'Report received' })).toBeVisible();
  });

  test('manages access and unpublishes an admitted trace from the account', async () => {
    let current = {
      trace_id: 'share-managed',
      source_trace_id: 'local-trace-managed',
      status: 'shared',
      access: {
        visibility: 'listed',
        password_protected: false,
        expires_at: null,
      },
      allow_high_entropy: false,
      created_at: 1_786_000_000,
      updated_at: 1_786_000_000,
      verification: {
        verified_at: 1_786_000_000,
        failure_code: null,
      },
      package: {
        format: 'notary/trace-package/v1',
        declared_size_bytes: 4096,
        declared_sha256: 'a'.repeat(64),
        admitted_size_bytes: 4096,
        admitted_sha256: 'a'.repeat(64),
      },
      status_url: '/api/traces/share-managed',
      public_url: 'https://example.test/s/share-managed',
      package_url: '/package.llmtrace',
    };
    const updates = [];
    let stopped = false;
    render(
      <Dashboard
        user={{
          provider_display_name: 'fixture-user',
          usage: usageFixture({ credits: null, total: 1, shared: 1 }),
        }}
        view="traces"
        theme="light"
        onThemeChange={() => {}}
        onAccountDeleted={() => {}}
        loadConnectedDevices={async () => ({ items: [], next_cursor: null })}
        loadHostedTraces={async () => ({ items: [current], next_cursor: null })}
        loadCreditOffers={async () => []}
        loadCreditHistory={async () => ({ items: [], next_cursor: null })}
        loadBillingPurchases={async () => []}
        updateTraceRequest={async (_id, settings) => {
          updates.push(settings);
          current = {
            ...current,
            access: {
              ...current.access,
              visibility: settings.visibility ?? current.access.visibility,
              password_protected: settings.password ? true : current.access.password_protected,
            },
          };
          return current;
        }}
        stopSharingRequest={async () => {
          stopped = true;
          current = { ...current, status: 'stopped', public_url: null };
        }}
      />,
    );

    await expect
      .element(page.getByText('Notarized traces you’ve shared through Notary.'))
      .toBeVisible();
    await expect.element(page.getByRole('link', { name: 'Open' })).toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Copy link' })).toBeVisible();
    await expect.element(page.getByRole('link', { name: 'Export .llmtrace' })).toBeVisible();
    await page.getByRole('button', { name: 'Manage access' }).click();
    const dialogBounds = page.getByRole('dialog').element().getBoundingClientRect();
    const visibilityWidth = page
      .getByRole('combobox', { name: 'Library visibility' })
      .element()
      .getBoundingClientRect().width;
    expect(visibilityWidth).toBeGreaterThan(dialogBounds.width * 0.8);
    expect(
      Math.abs(dialogBounds.left + dialogBounds.width / 2 - window.innerWidth / 2),
    ).toBeLessThan(1);
    expect(
      Math.abs(dialogBounds.top + dialogBounds.height / 2 - window.innerHeight / 2),
    ).toBeLessThan(1);
    await page.viewport(390, 844);
    const mobileDialogBounds = page.getByRole('dialog').element().getBoundingClientRect();
    expect(
      Math.abs(mobileDialogBounds.left + mobileDialogBounds.width / 2 - window.innerWidth / 2),
    ).toBeLessThan(1);
    expect(
      Math.abs(mobileDialogBounds.top + mobileDialogBounds.height / 2 - window.innerHeight / 2),
    ).toBeLessThan(1);
    expect(mobileDialogBounds.left).toBeGreaterThanOrEqual(16);
    expect(mobileDialogBounds.right).toBeLessThanOrEqual(window.innerWidth - 16);
    await page.getByRole('checkbox', { name: /Require a password/ }).click();
    await page.getByRole('textbox', { name: 'Password' }).fill('eight-characters');
    await page.getByRole('button', { name: 'Save changes' }).click();
    expect(updates[0]).toEqual({ visibility: 'listed', password: 'eight-characters' });

    await page.getByRole('button', { name: 'Stop sharing' }).click();
    await page.getByRole('alertdialog').getByRole('button', { name: 'Stop sharing' }).click();
    expect(stopped).toBe(true);
    await expect.element(page.getByText('Stopped', { exact: true })).toBeVisible();
  });

  test('renders every canonical hosted Trace status', async () => {
    const trace = (status, index) => ({
      trace_id: `trace-${status}`,
      source_trace_id: `local-${status}`,
      status,
      access: { visibility: 'unlisted', password_protected: false, expires_at: null },
      allow_high_entropy: false,
      created_at: 1_786_000_000 + index,
      updated_at: 1_786_000_000 + index,
      verification: {
        verified_at: null,
        failure_code: status === 'failed' ? 'worker_failed' : null,
      },
      package: {
        format: 'notary/trace-package/v1',
        declared_size_bytes: 4096,
        declared_sha256: `${index}`.repeat(64),
        admitted_size_bytes: null,
        admitted_sha256: null,
      },
      status_url: `/api/traces/trace-${status}`,
      public_url: status === 'shared' ? `https://example.test/s/trace-${status}` : null,
      package_url: status === 'shared' ? `/api/traces/trace-${status}/package.llmtrace` : null,
    });
    const statuses = ['verifying', 'shared', 'stopped', 'rejected', 'failed'];
    render(
      <Dashboard
        user={{
          provider_display_name: 'fixture-user',
          usage: usageFixture({ credits: null, total: statuses.length, shared: 2, verifying: 1 }),
        }}
        view="traces"
        theme="light"
        onThemeChange={() => {}}
        onAccountDeleted={() => {}}
        loadConnectedDevices={async () => ({ items: [], next_cursor: null })}
        loadHostedTraces={async () => ({
          items: statuses.map(trace),
          next_cursor: null,
        })}
        loadCreditOffers={async () => []}
        loadCreditHistory={async () => ({ items: [], next_cursor: null })}
        loadBillingPurchases={async () => []}
      />,
    );

    for (const status of ['Verifying', 'Shared', 'Stopped', 'Rejected', 'Failed']) {
      await expect.element(page.getByText(status, { exact: true })).toBeVisible();
    }
  });

  test('requires disclosure consent before hosted package verification', async () => {
    const verified = {
      verified: true,
      trace_id: 'sanitized-capture',
      provider: 'openai',
      host: 'api.openai.com',
      authenticated_at_unix_ms: 1_786_000_000_000,
      notary_key_id: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      trust_source: 'hosted_registry',
      registry_generation: 42,
      content_sha256: 'b'.repeat(64),
      package_sha256: 'c'.repeat(64),
      trace: await loadLibraryTrace('verified'),
    };
    let calls = 0;
    render(
      <VerificationPage
        verifyFile={async () => {
          calls += 1;
          return verified;
        }}
      />,
    );
    const input = document.querySelector('input[type="file"]');
    expect(input.getAttribute('accept')).toBeNull();
    const file = new File(['sanitized fixture'], 'sanitized.llmtrace', {
      type: 'application/vnd.exalto.notary.trace-package+zip',
    });
    fireEvent.change(input, { target: { files: [file] } });

    await expect
      .element(page.getByText('Your package may contain sensitive content.'))
      .toBeVisible();
    await expect
      .element(
        page.getByText(
          'Headers are hidden by default, but prompts, responses, tool definitions, and tool results may be included. We check the package without saving it.',
        ),
      )
      .toBeVisible();
    await expect
      .element(page.getByText('I understand that this package may contain sensitive content.'))
      .toBeVisible();
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
    render(
      <VerificationPage
        verifyFile={async () => {
          calls += 1;
        }}
      />,
    );
    const input = document.querySelector('input[type="file"]');
    fireEvent.change(input, { target: { files: [new File(['not a package'], 'notes.zip')] } });

    await expect
      .element(page.getByRole('heading', { name: 'File type is unsupported' }))
      .toBeVisible();
    expect(calls).toBe(0);
  });

  test('ignores an in-flight verification result after the selected file changes', async () => {
    let resolveVerification;
    const pendingVerification = new Promise((resolve) => {
      resolveVerification = resolve;
    });
    render(<VerificationPage verifyFile={() => pendingVerification} />);
    const input = document.querySelector('input[type="file"]');
    fireEvent.change(input, { target: { files: [new File(['first'], 'first.llmtrace')] } });
    await page.getByRole('checkbox').click();
    await page.getByRole('button', { name: 'Verify package' }).click();

    fireEvent.change(input, { target: { files: [new File(['second'], 'second.llmtrace')] } });
    await expect.element(page.getByText('second.llmtrace')).toBeVisible();
    resolveVerification({
      verified: true,
      trace: { resourceSpans: [] },
    });
    await new Promise((resolve) =>
      window.requestAnimationFrame(() => window.requestAnimationFrame(resolve)),
    );

    expect(document.body.textContent).not.toContain('Verification passed.');
    await expect.element(page.getByText('second.llmtrace')).toBeVisible();
  });

  test('renders 30 days of utilization in decimal MB with an accessible summary and overall budget', async () => {
    const today = Date.now() / 1000;
    render(
      <CreditUtilizationChart
        credits={{
          notarization: { total_remaining_bytes: 500_000_000, total_granted_bytes: 750_000_000 },
        }}
        formatBytes={(bytes) => `${bytes / 1_000_000} MB`}
        historyDebits={[
          {
            id: 'd1',
            kind: 'debit',
            amount_bytes: 1_000_000,
            display_label: 'Capture A',
            created_at: today,
          },
          {
            id: 'd2',
            kind: 'debit',
            amount_bytes: 250_000,
            display_label: 'Capture B',
            created_at: today - 86400,
          },
        ]}
      />,
    );

    await expect.element(page.getByRole('heading', { name: 'Last 30 days' })).toBeVisible();
    await expect
      .element(page.getByRole('img', { name: /Daily utilization in MB.*Total 1.25 MB/i }))
      .toBeVisible();
    await expect.element(page.getByText('750 MB')).toBeVisible();
    expect(document.querySelector('.recharts-bar-rectangle path')?.getAttribute('fill')).toBe(
      'var(--action)',
    );
    expect(document.querySelectorAll('.recharts-bar-rectangle')).toHaveLength(2);
  });

  test('distinguishes loading, zero-usage, and unavailable utilization states', async () => {
    const props = {
      credits: {
        notarization: { total_remaining_bytes: 500_000_000, total_granted_bytes: 750_000_000 },
      },
      formatBytes: (bytes) => `${bytes / 1_000_000} MB`,
    };
    const rendered = render(<CreditUtilizationChart {...props} historyDebits={null} />);
    await expect
      .element(page.getByRole('status', { name: 'Loading daily utilization' }))
      .toBeVisible();

    rendered.rerender(<CreditUtilizationChart {...props} historyDebits={[]} />);
    await expect
      .element(page.getByRole('status').getByText('No utilization in the last 30 days'))
      .toBeVisible();

    rendered.rerender(<CreditUtilizationChart {...props} historyDebits={[]} historyError />);
    await expect
      .element(page.getByRole('alert').getByText('Daily utilization unavailable'))
      .toBeVisible();
  });
});
