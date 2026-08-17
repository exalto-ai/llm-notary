import type { MouseEvent as ReactMouseEvent } from 'react';
import { useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import '@fontsource-variable/instrument-sans';
import '@fontsource/ibm-plex-mono/latin-400.css';
import '@fontsource/ibm-plex-mono/latin-ext-400.css';
import '@fontsource/ibm-plex-mono/latin-500.css';
import '@fontsource/ibm-plex-mono/latin-ext-500.css';
import { AuthProviderIcon } from './AuthProviderIcon';
import { ProviderIdentity } from './ProviderIdentity';
import { initialThemePreference, resolvedTheme } from './theme';
import './shadcn.css';
import './action-tokens.css';
import './styles.css';
import './hero-evidence.css';
import './trust-grid.css';
import './commons.css';
import './branding.css';
import './account.css';
import './auth.css';
import './trace.css';
import './docs.css';
import './legal.css';
import './relay-animation.css';
import './landing.css';
import './notaries.css';
import './axis.css';
import './verification.css';
import './sharing.css';
import { getAuthProviders, getCurrentUser, logoutBrowser } from './platform-api/client';
import { RelayAnimation } from './RelayAnimation';
import { latestMacosDownloadHref, loadLatestPointer, macosDmgName } from './releaseDownloads';
import {
  AccountSettings,
  ApiKeysPanel,
  Dashboard,
  DeleteAccountPanel,
} from './site/AccountDashboard';
import {
  DeviceAuthorizationApproval,
  HostedNotaryRecord,
  NotariesPage,
} from './site/AuthorizationPages';
import { Docs } from './site/PublicDocs';
import {
  Library,
  ListedTracesPreview,
  PublicTracePage,
  VerificationPage,
} from './site/PublicTracePages';

const loadCreditUtilizationChart = () => import('./CreditUtilizationChart');
const appleLogoUrl = new URL('./assets/platforms/apple.svg', import.meta.url).href;
const installCommand = 'curl -fsSL https://notary.exalto.ai/install.sh | sh';
type CurrentUser = NonNullable<Awaited<ReturnType<typeof getCurrentUser>>>;
type AccountIdentity = Pick<
  CurrentUser,
  'auth_provider' | 'avatar_url' | 'display_name' | 'provider_display_name'
>;
type AuthProviders = Awaited<ReturnType<typeof getAuthProviders>>;
type AuthProvider = 'github' | 'google';
type Point = readonly [x: number, y: number];

export function MacosDownloadLink({
  loadPointer = loadLatestPointer,
}: {
  loadPointer?: typeof loadLatestPointer;
}) {
  const [downloadHref, setDownloadHref] = useState<string | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  useEffect(() => {
    let cancelled = false;
    loadPointer()
      .then((pointer) => {
        if (!cancelled) setDownloadHref(latestMacosDownloadHref(pointer));
      })
      .catch(() => {
        if (!cancelled) setUnavailable(true);
      });
    return () => {
      cancelled = true;
    };
  }, [loadPointer]);
  return (
    <a
      className="button button-dark hero-download"
      href={downloadHref || '#/docs/getting-started'}
      download={downloadHref ? macosDmgName : undefined}
      aria-busy={!downloadHref && !unavailable}
    >
      <img src={appleLogoUrl} alt="" aria-hidden="true" />
      <span>
        <b>Download for macOS</b>
        {unavailable && <small>View install options</small>}
      </span>
    </a>
  );
}
function PenMark() {
  return (
    <span className="pen-mark" aria-hidden="true">
      <img src="/notary-mark.svg" alt="" />
    </span>
  );
}

function accountName(user: AccountIdentity) {
  return user.display_name || user.provider_display_name;
}

function accountIdentifier(user: AccountIdentity) {
  return user.provider_display_name;
}

function authProviderName(user: AccountIdentity) {
  return user.auth_provider === 'google' ? 'Google' : 'GitHub';
}

function HeroSignalField() {
  const xLines = Array.from({ length: 11 }, (_, index) => -80 + index * 160);
  const yLines = Array.from({ length: 9 }, (_, index) => -30 + index * 120);
  const routes: Point[][] = [
    [
      [-80, 210],
      [400, 210],
      [400, 330],
      [720, 330],
      [720, 570],
      [1040, 570],
      [1040, 690],
      [1520, 690],
    ],
    [
      [-80, 570],
      [240, 570],
      [240, 450],
      [560, 450],
      [560, 210],
      [880, 210],
      [880, 90],
      [1520, 90],
    ],
    [
      [-80, 330],
      [240, 330],
      [240, 90],
      [720, 90],
      [720, 210],
      [1200, 210],
      [1200, 450],
      [1520, 450],
    ],
    [
      [-80, 690],
      [400, 690],
      [400, 570],
      [720, 570],
      [720, 450],
      [1040, 450],
      [1040, 330],
      [1520, 330],
    ],
    [
      [-80, 90],
      [240, 90],
      [240, 210],
      [400, 210],
      [400, 450],
      [880, 450],
      [880, 570],
      [1520, 570],
    ],
    [
      [-80, 450],
      [560, 450],
      [560, 690],
      [880, 690],
      [880, 330],
      [1200, 330],
      [1200, 210],
      [1520, 210],
    ],
  ];
  const pathFor = (points: Point[]) =>
    points
      .map(([x, y], index) => {
        if (!index) return `M${x} ${y}`;
        const [previousX] = points[index - 1];
        return previousX === x ? `V${y}` : `H${x}`;
      })
      .join(' ');
  const tracePaths = routes.map(pathFor);
  const cells: Point[] = [
    [3, 2],
    [5, 3],
    [8, 5],
    [2, 6],
    [6, 1],
    [9, 4],
    [4, 5],
    [7, 6],
    [1, 3],
    [10, 2],
    [5, 6],
    [8, 1],
  ];
  const particles: Array<readonly [routeIndex: number, duration: string, begin: string]> = [
    [0, '3.8s', '-1.1s'],
    [1, '4.4s', '-2.7s'],
    [2, '3.3s', '-.5s'],
    [3, '4.9s', '-3.5s'],
    [4, '3.6s', '-2.1s'],
    [5, '4.2s', '-.8s'],
    [0, '5.1s', '-3.8s'],
    [1, '3.5s', '-1.7s'],
    [2, '4.6s', '-3.1s'],
    [3, '3.9s', '-.2s'],
    [4, '5.4s', '-4.4s'],
    [5, '3.2s', '-2.4s'],
  ];
  return (
    <div className="hero-signal-field" aria-hidden="true">
      <svg viewBox="0 0 1440 840" preserveAspectRatio="xMidYMid slice" aria-hidden="true">
        <g className="signal-grid">
          {yLines.map((y) => (
            <path key={`h-${y}`} d={`M-80 ${y}H1520`} />
          ))}
          {xLines.map((x) => (
            <path key={`v-${x}`} d={`M${x} -30V930`} />
          ))}
        </g>
        <g className="signal-traces">
          {tracePaths.map((path, index) => (
            <path key={path} className={`signal-trace signal-trace--${index + 1}`} d={path} />
          ))}
        </g>
        <g className="signal-cells">
          {cells.map(([xIndex, yIndex]) => (
            <rect
              key={`${xIndex}-${yIndex}`}
              x={xLines[xIndex] - 11}
              y={yLines[yIndex] - 11}
              width="22"
              height="22"
            />
          ))}
        </g>
        <g className="signal-marks">
          {particles.map(([routeIndex, duration, begin], index) => (
            <circle
              key={`${routeIndex}-${begin}`}
              className="signal-mark"
              r={index % 3 === 0 ? 4 : 3.25}
            >
              <animateMotion
                dur={duration}
                begin={begin}
                repeatCount="indefinite"
                path={tracePaths[routeIndex]}
              />
            </circle>
          ))}
        </g>
      </svg>
    </div>
  );
}

function AccountMenu({ user, onLogout }: { user: AccountIdentity; onLogout: () => void }) {
  const [open, setOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const name = accountName(user);
  const identifier = accountIdentifier(user);
  const initials = name.slice(0, 2).toUpperCase();
  useEffect(() => {
    const closeFromPointer = (event: MouseEvent) => {
      if (!(event.target instanceof Node) || !menuRef.current?.contains(event.target))
        setOpen(false);
    };
    const closeFromKeyboard = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', closeFromPointer);
    window.addEventListener('keydown', closeFromKeyboard);
    return () => {
      document.removeEventListener('mousedown', closeFromPointer);
      window.removeEventListener('keydown', closeFromKeyboard);
    };
  }, []);
  return (
    <div className="account-menu" ref={menuRef}>
      <button
        type="button"
        className="account-trigger"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        aria-haspopup="menu"
        aria-label={`Account menu for ${name}`}
      >
        {user.avatar_url ? (
          <img src={user.avatar_url} alt="" referrerPolicy="no-referrer" />
        ) : (
          <span>{initials}</span>
        )}
      </button>
      {open && (
        <nav className="account-popover" aria-label="Account">
          <div className="account-identity">
            <div>
              <b>{name}</b>
              <span>
                {identifier} · {authProviderName(user)}
              </span>
            </div>
          </div>
          <div className="account-actions">
            {/* biome-ignore lint/a11y/useValidAnchor: This root-relative hash URL is SPA navigation, including from direct-share paths. */}
            <a href="/#/dashboard" onClick={() => setOpen(false)}>
              Dashboard
            </a>
            <button
              type="button"
              onClick={() => {
                setOpen(false);
                onLogout();
              }}
            >
              Log out
            </button>
          </div>
        </nav>
      )}
    </div>
  );
}

export function Header({
  user,
  onLogout,
  hideSignIn = false,
  authPending = false,
}: {
  user: AccountIdentity | null;
  onLogout: () => void;
  hideSignIn?: boolean;
  authPending?: boolean;
}) {
  return (
    <header className="nav-wrap">
      <a className="brand" href="/#/">
        <PenMark /> <span>LLM Notary</span>
      </a>
      <nav className="product-nav">
        <a href="/#/docs">Docs</a>
        <a href="/#/pricing">Pricing</a>
        {user ? (
          <AccountMenu user={user} onLogout={onLogout} />
        ) : !hideSignIn && authPending ? (
          <span
            className="account-auth-placeholder"
            role="status"
            aria-label="Checking sign-in status"
          >
            <i />
          </span>
        ) : (
          !hideSignIn && (
            <a className="sign-in-link" href="/#/signin">
              <span>Sign in</span>
            </a>
          )
        )}
      </nav>
    </header>
  );
}

function AuthProviderLink({
  provider,
  href,
  pendingProvider,
  onStart,
}: {
  provider: AuthProvider;
  href: string;
  pendingProvider: AuthProvider | null;
  onStart: (provider: AuthProvider) => void;
}) {
  const name = provider === 'google' ? 'Google' : 'GitHub';
  const pending = pendingProvider === provider;
  const disabled = pendingProvider !== null && !pending;
  const className = `auth-provider${pending ? ' auth-provider--pending' : ''}${disabled ? ' auth-provider--disabled' : ''}`;
  const start = (event: ReactMouseEvent<HTMLAnchorElement>) => {
    if (pendingProvider !== null) {
      event.preventDefault();
      return;
    }
    onStart(provider);
  };
  return (
    <a
      className={className}
      href={href}
      onClick={start}
      aria-busy={pending || undefined}
      aria-disabled={disabled || undefined}
      tabIndex={disabled ? -1 : undefined}
    >
      <AuthProviderIcon provider={provider} />
      <b>{pending ? `Connecting to ${name}…` : `Continue with ${name}`}</b>
      <span className="auth-provider-progress" aria-hidden="true">
        {pending && (
          <>
            <i />
            <i />
            <i />
          </>
        )}
      </span>
    </a>
  );
}

export function SignInPage({
  route = 'signin',
  user = null,
  loadProviders = getAuthProviders,
}: {
  route?: string;
  user?: AccountIdentity | null;
  loadProviders?: typeof getAuthProviders;
}) {
  const [providers, setProviders] = useState<AuthProviders | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pendingProvider, setPendingProvider] = useState<AuthProvider | null>(null);
  useEffect(() => {
    let cancelled = false;
    loadProviders()
      .then((next) => {
        if (!cancelled) setProviders(next);
      })
      .catch((reason) => {
        if (!cancelled)
          setError(reason instanceof Error ? reason.message : 'Could not load sign-in options.');
      });
    return () => {
      cancelled = true;
    };
  }, [loadProviders]);
  const requestedReturn = new URLSearchParams(route.split('?')[1] || '').get('return_to');
  const returnTo = requestedReturn?.startsWith('#/authorize?') ? requestedReturn : null;
  const providerHref = (provider: AuthProvider) =>
    `/api/auth/${provider}${returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : ''}`;
  if (user)
    return (
      <main className="auth-page">
        <section className="auth-panel">
          <h1>Already signed in</h1>
          <p className="auth-intro">
            You’re signed in as <b>{accountName(user)}</b>.
          </p>
          <a className="button button-dark" href="/#/dashboard">
            Open dashboard
          </a>
        </section>
      </main>
    );
  return (
    <main className="auth-page">
      <section className="auth-panel" aria-labelledby="sign-in-title">
        <h1 id="sign-in-title">Sign in</h1>
        <p className="auth-intro">Continue to LLM Notary.</p>
        {error ? (
          <div className="auth-state" role="alert">
            <b>Sign-in options are unavailable</b>
            <span>{error}</span>
          </div>
        ) : providers === null ? (
          <div className="auth-state" role="status">
            <b>Loading sign-in options</b>
          </div>
        ) : (
          <div className="auth-provider-list">
            {providers.google && (
              <AuthProviderLink
                provider="google"
                href={providerHref('google')}
                pendingProvider={pendingProvider}
                onStart={setPendingProvider}
              />
            )}
            {providers.github && (
              <AuthProviderLink
                provider="github"
                href={providerHref('github')}
                pendingProvider={pendingProvider}
                onStart={setPendingProvider}
              />
            )}
            {!providers.google && !providers.github && (
              <div className="auth-state" role="alert">
                <b>No sign-in provider is configured</b>
              </div>
            )}
          </div>
        )}
        <p className="auth-legal">
          By continuing, you agree to the <a href="/#/terms">Terms</a> and acknowledge the{' '}
          <a href="/#/privacy">Privacy Policy</a>.
        </p>
      </section>
    </main>
  );
}

export function Footer() {
  return (
    <footer className="site-footer">
      <span className="footer-copyright">© 2026 LLM Notary</span>
      <nav aria-label="Footer">
        <a href="/#/verify">Verify</a>
        <a href="/#/library">Library</a>
        <a href="/#/notaries">Notaries</a>
        <a href="/#/privacy">Privacy</a>
        <a href="/#/terms">Terms</a>
      </nav>
    </footer>
  );
}

const legalPages = {
  privacy: {
    eyebrow: 'Legal · Privacy',
    title: 'Privacy Policy',
    intro:
      'This policy explains the information handled by the LLM Notary website, session-sharing service, and local tooling.',
    sections: [
      [
        'Local capture stays local',
        'The local proxy handles application plaintext and provider credentials. Within the protocol, the remote notary witnesses encrypted traffic and protocol metadata; it does not receive your API key, prompt, or response plaintext.',
      ],
      [
        'Account information',
        'If you sign in with Google, we use your stable Google account identifier, display name, and profile image to operate your account. We check that Google reports a verified email address but do not retain the address. Google access is limited to openid, email, and profile. If configured, GitHub sign-in remains available for existing accounts and requests identity only, without repository, organization, or email access. Provider access tokens are not retained.',
      ],
      [
        'Shared sessions',
        'Sharing is an explicit action. The service verifies and safety-scans a submitted .llmtrace package before admission, then hosts the disclosed conversation and exact admitted package at a stable link. Header values are hidden by the package’s default disclosure policy, but request and response bodies—including prompts, responses, tool definitions, and tool results—may be accessible. Do not share content you are not permitted to disclose.',
      ],
      [
        'Service processing',
        'One-off verification does not retain an uploaded package. Sharing retains the exact admitted package and its normalized trace so visitors can inspect the session and independently verify the original bytes. Temporary intake objects are removed after admission or rejection.',
      ],
      [
        'Trace reports',
        'A report retains the selected reason and optional note for moderation. Reports are append-only. A keyed network-derived value rate-limits submissions separately, and the application does not store the reporter’s raw IP address in the report record.',
      ],
      [
        'Your choices',
        'You choose whether a shared session is Unlisted or Listed. Both start accessible to anyone with the link; Unlisted only keeps it out of the Library. After admission, you can unpublish it, require a password, or set an expiry. Keep private capture bundles and credentials under your control. For privacy questions or requests, contact the LLM Notary operator through the project’s support channel.',
      ],
      [
        'Updates',
        'We may revise this policy as the service evolves. The current version will always be available on this page.',
      ],
    ],
  },
  terms: {
    eyebrow: 'Legal · Terms',
    title: 'Terms of Service',
    intro:
      'These terms govern your use of the LLM Notary website, local tooling, and session-sharing service.',
    sections: [
      [
        'Using the service',
        'Use LLM Notary lawfully and only with content, credentials, and provider accounts you are authorized to use. Do not interfere with the service, bypass access controls, or submit material that infringes the rights of others.',
      ],
      [
        'Your shared sessions',
        'You are responsible for every package you choose to submit. Sharing is an explicit consent boundary: once admitted, its disclosed conversation and exact package can be accessed by anyone with the link. Unlisted is not private; it only keeps the session out of the Library.',
      ],
      [
        'What verification means',
        'The retained .llmtrace package can be checked against its cryptographic and protocol evidence. The readable conversation is derived from that admitted package, and the download preserves its exact bytes. Neither result establishes that a model output or user interpretation is true, complete, safe, or suitable for a particular purpose.',
      ],
      [
        'Availability',
        'The service is provided on an “as available” basis and may change, be suspended, or be discontinued. Preserve the local materials you need; do not rely on the service as your only record or backup.',
      ],
      [
        'Your responsibilities',
        'You are responsible for maintaining the security of your devices, local captures, API credentials, and account. Do not share confidential, personal, or otherwise protected information unless you have a clear right to do so.',
      ],
      [
        'Changes to these terms',
        'We may update these terms as the product develops. Continued use after an updated version is posted means you accept the revised terms.',
      ],
    ],
  },
} as const;

type LegalPageKey = keyof typeof legalPages;

function isLegalPage(pageKey: string | undefined): pageKey is LegalPageKey {
  return pageKey !== undefined && pageKey in legalPages;
}

function LegalPage({ pageKey }: { pageKey: LegalPageKey }) {
  const page = legalPages[pageKey];
  return (
    <main className="legal-shell">
      <span className="eyebrow">{page.eyebrow}</span>
      <h1>{page.title}</h1>
      <p className="legal-intro">{page.intro}</p>
      <p className="legal-updated">Last updated: August 2026</p>
      <div className="legal-sections">
        {page.sections.map(([heading, copy]) => (
          <section key={heading}>
            <h2>{heading}</h2>
            <p>{copy}</p>
          </section>
        ))}
      </div>
    </main>
  );
}

function TrustColumns() {
  const boundaries = [
    [
      '01',
      'Client',
      'Holds the plaintext',
      'The local proxy sees the request and response. A user cannot change authenticated bytes or invent a provider response and still produce valid finalized evidence.',
    ],
    [
      '02',
      'Notary',
      'Witnesses ciphertext',
      'The notary sees the provider hostname, encrypted traffic, sizes, timing, and protocol metadata—not the API key, prompt, or response plaintext. The provider serves a normal request; origin follows from the authenticated TLS session, not a special provider signature.',
    ],
    [
      '03',
      'Researcher',
      'Checks independently',
      'Researchers can verify the notary signature, provider identity, disclosed transcript, artifact hashes, and deterministic mapping using the trusted notary public key.',
    ],
  ];
  return (
    <div className="trust-columns">
      {boundaries.map(([number, actor, title, copy]) => (
        <article key={actor}>
          <span>{number}</span>
          <b>{actor}</b>
          <h3>{title}</h3>
          <p>{copy}</p>
        </article>
      ))}
    </div>
  );
}

function VerificationArchitecture() {
  return (
    <section className="section architecture" id="how-it-works">
      <div className="section-head">
        <span className="eyebrow">How it works</span>
        <h2>Don’t trust. Verify.</h2>
      </div>
      <TrustColumns />
      <div className="section-link">
        <a href="#/docs/how-it-works">Learn more about the trust model</a>
      </div>
    </section>
  );
}

function MotionStudies() {
  return <RelayAnimation />;
}

function PricingSection() {
  return (
    <section className="section pricing" id="pricing" aria-labelledby="pricing-title">
      <header className="pricing-intro">
        <span className="eyebrow">Pricing</span>
        <h2 id="pricing-title">A plan for every proof workload.</h2>
        <p>
          Every plan includes separate monthly allowances for private capture and notarization, plus
          space for uploaded trace packages.
        </p>
      </header>
      <div className="pricing-ledger">
        <article>
          <header>
            <span>Free</span>
            <div>
              <b>$0</b>
              <small>per month</small>
            </div>
          </header>
          <h3>Explore verifiable traces.</h3>
          <ul>
            <li>50 MB capture each month</li>
            <li>50 MB notarization each month</li>
            <li>Store up to 1 GB of trace packages</li>
          </ul>
        </article>
        <article>
          <header>
            <span>1 GB</span>
            <div>
              <b>$9.99</b>
              <small>per month</small>
            </div>
          </header>
          <h3>For regular research.</h3>
          <ul>
            <li>1 GB capture each month</li>
            <li>1 GB notarization each month</li>
            <li>Store up to 10 GB of trace packages</li>
          </ul>
        </article>
        <article>
          <header>
            <span>10 GB</span>
            <div>
              <b>$49.99</b>
              <small>per month</small>
            </div>
          </header>
          <h3>For sustained workloads.</h3>
          <ul>
            <li>10 GB capture each month</li>
            <li>10 GB notarization each month</li>
            <li>Trace storage without a fixed plan limit*</li>
          </ul>
        </article>
      </div>
      <div className="pricing-addon">
        <span>Need more notarization?</span>
        <b>$10 per additional GB</b>
        <small>Available on every plan · purchased credits do not expire</small>
      </div>
      <p className="pricing-fine-print">
        *No fixed trace-storage limit. Fair-use and abuse controls still apply.
      </p>
      <a className="pricing-details-link" href="/#/docs/hosted-credits">
        See plan and usage details
      </a>
    </section>
  );
}

export function Landing({ loadLatestPointer: loadPointer = loadLatestPointer }) {
  return (
    <main id="top">
      <section className="hero">
        <HeroSignalField />
        <h1>Verifiable intelligence</h1>
        <p>Privacy-preserving LLM trace packages for open research and independent verification.</p>
        <div className="hero-actions">
          <MacosDownloadLink loadPointer={loadPointer} />
          <p className="hero-developer-path">
            or, <a href="#/docs/getting-started">build on the LLM Notary stack</a>
          </p>
        </div>
      </section>
      <MotionStudies />
      <VerificationArchitecture />
      <section className="section install capture">
        <div>
          <span className="eyebrow">Local capture</span>
          <h2>Capture locally.</h2>
          <p>
            Point your existing tools at the local proxy. Provider calls keep streaming normally
            while encrypted bundles stay on your machine.
          </p>
        </div>
        <div className="terminal">
          <div>
            <i />
            <i />
            <i />
          </div>
          <pre>
            <code>
              <b>$</b> {installCommand}
              {'\n\n'}
              <b>$</b> notaryd{'\n\n'}proxy <em>127.0.0.1:8787</em>
              {'\n'}admin <em>127.0.0.1:8788</em>
            </code>
          </pre>
          <a href="#/docs/getting-started">Installation and setup</a>
        </div>
      </section>
      <PricingSection />
      <ListedTracesPreview />
      <section className="section verify" id="verify">
        <div>
          <span className="eyebrow">Independent verification</span>
          <h2>Proof travels with the package.</h2>
          <p>
            A finalized .llmtrace contains the notary-signed TLS evidence, disclosed exchange,
            canonical trace, and hashes needed for portable verification.
          </p>
          <div className="verify-points">
            <span>Notary evidence</span>
            <span>Canonical OTLP</span>
            <span>Portable package</span>
          </div>
          <div className="button-row">
            <a className="button button-dark" href="#/verify">
              Verify a package
            </a>
          </div>
        </div>
        <div className="receipt">
          <header>
            <PenMark />
            <b>Portable package</b>
          </header>
          <h3>Verified</h3>
          <dl>
            <div>
              <dt>Provider</dt>
              <dd>
                <ProviderIdentity provider="OpenAI" detail="api.openai.com" />
              </dd>
            </div>
            <div>
              <dt>Artifact</dt>
              <dd>capture.llmtrace</dd>
            </div>
            <div>
              <dt>Trace hash</dt>
              <dd>9b44f8…c21d</dd>
            </div>
          </dl>
          <div className="receipt-contents">
            <span>
              Notary evidence <i>•••</i>
            </span>
            <span>
              Disclosed exchange <i>•••</i>
            </span>
            <span>
              Canonical trace <i>•••</i>
            </span>
          </div>
          <footer>VERIFIED FROM SOURCE PACKAGE</footer>
        </div>
      </section>
    </main>
  );
}

export {
  AccountSettings,
  ApiKeysPanel,
  Dashboard,
  DeleteAccountPanel,
  DeviceAuthorizationApproval,
  HostedNotaryRecord,
  Library,
  ListedTracesPreview,
  PublicTracePage,
  VerificationPage,
};

export function DashboardAuthLoading() {
  return (
    <main
      className="dashboard-auth-loading"
      role="status"
      aria-live="polite"
      aria-label="Loading dashboard"
    >
      <div className="dashboard-auth-loading-card">
        <span className="dashboard-auth-loading-indicator" aria-hidden="true">
          <i />
        </span>
        <span>Loading dashboard…</span>
      </div>
    </main>
  );
}

export function App({
  loadCurrentUser = getCurrentUser,
}: {
  loadCurrentUser?: typeof getCurrentUser;
} = {}) {
  const [route, setRoute] = useState(window.location.hash || '#/');
  const [user, setUser] = useState<CurrentUser | null>(null);
  const [authPending, setAuthPending] = useState(true);
  const [theme, setTheme] = useState(initialThemePreference);
  useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const applyTheme = () => {
      const activeTheme = resolvedTheme(theme, media.matches);
      document.documentElement.dataset.theme = activeTheme;
      document.documentElement.style.colorScheme = activeTheme;
      document
        .querySelector('meta[name="theme-color"]')
        ?.setAttribute('content', activeTheme === 'dark' ? '#171717' : '#f6f5f2');
    };
    applyTheme();
    window.localStorage.setItem('llm-notary-theme', theme);
    if (theme === 'auto') media.addEventListener('change', applyTheme);
    return () => media.removeEventListener('change', applyTheme);
  }, [theme]);
  useEffect(() => {
    const update = () => setRoute(window.location.hash || '#/');
    window.addEventListener('hashchange', update);
    return () => window.removeEventListener('hashchange', update);
  }, []);
  useEffect(() => {
    const nextSection = route.replace(/^#\/?/, '').split(/[/?]/)[0];
    window.requestAnimationFrame(() => {
      if (nextSection === 'pricing') {
        document.getElementById('pricing')?.scrollIntoView({
          block: 'start',
          behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches
            ? 'auto'
            : 'smooth',
        });
      } else if (nextSection !== 'docs') {
        window.scrollTo({ top: 0, behavior: 'instant' });
      }
    });
  }, [route]);
  useEffect(() => {
    let cancelled = false;
    loadCurrentUser()
      .then((user) => {
        if (!cancelled) {
          setUser(user);
          setAuthPending(false);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setUser(null);
          setAuthPending(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [loadCurrentUser]);
  useEffect(() => {
    if (user) void loadCreditUtilizationChart();
  }, [user]);
  const logout = async () => {
    await logoutBrowser();
    setUser(null);
    if (window.location.hash === '#/dashboard') window.location.hash = '#/';
  };
  const accountDeleted = () => {
    setUser(null);
    setAuthPending(false);
    window.location.hash = '#/';
  };
  const path = route.replace(/^#\/?/, '');
  const directShare = window.location.pathname.match(/^\/s\/([^/]+)\/?$/);
  const directTraceId = directShare ? decodeURIComponent(directShare[1]) : null;
  const routePath = path.split('?')[0];
  const [section, page] = routePath.split('/');
  const sectionAnchor = new URLSearchParams(path.split('?')[1] || '').get('section');
  const isLibrary = section === 'library' || section === 'traces' || section === 'collections';
  const dashboardLoading = section === 'dashboard' && authPending;
  return (
    <>
      <Header
        user={user}
        onLogout={logout}
        hideSignIn={section === 'authorize' || section === 'signin'}
        authPending={authPending}
      />
      {directTraceId ? (
        <PublicTracePage traceId={directTraceId} />
      ) : section === 'authorize' ? (
        <DeviceAuthorizationApproval route={path} user={user} />
      ) : section === 'signin' ? (
        <SignInPage route={path} user={user} />
      ) : section === 'verify' ? (
        <VerificationPage />
      ) : section === 'docs' ? (
        <Docs pageKey={page || 'overview'} section={sectionAnchor ?? undefined} />
      ) : isLibrary ? (
        <Library />
      ) : section === 'notaries' ? (
        <NotariesPage />
      ) : dashboardLoading ? (
        <DashboardAuthLoading />
      ) : section === 'dashboard' && user ? (
        <Dashboard
          user={user}
          view={page}
          route={path}
          theme={theme}
          onThemeChange={setTheme}
          onAccountDeleted={accountDeleted}
        />
      ) : isLegalPage(section) ? (
        <LegalPage pageKey={section} />
      ) : (
        <Landing />
      )}
      {!isLibrary && !dashboardLoading && <Footer />}
    </>
  );
}

const applicationRoot = document.getElementById('root');
if (applicationRoot) createRoot(applicationRoot).render(<App />);
