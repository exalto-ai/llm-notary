import { lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import '@fontsource-variable/instrument-sans';
import '@fontsource-variable/space-grotesk';
import '@fontsource/dm-mono/400.css';
import '@fontsource/dm-mono/500.css';
import { ChevronDown } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Command, CommandDialog, CommandEmpty, CommandInput, CommandItem, CommandList } from '@/components/ui/command';
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '@/components/ui/alert-dialog';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { AuthProviderIcon } from './AuthProviderIcon';
import { ProviderIdentity } from './ProviderIdentity';
import { initialThemePreference, resolvedTheme, themeOptions } from './theme';
import './shadcn.css';
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
import { RelayAnimation } from './RelayAnimation';
import { latestMacosDownloadHref, loadLatestPointer, macosDmgName } from './releaseDownloads';
import {
  approveCli,
  createCheckoutSession,
  createApiKey,
  deleteCurrentAccount,
  getApiKeys,
  getAuthProviders,
  getBillingPurchase,
  getBillingPurchases,
  claimCreditOffer,
  getCliApproval,
  getCliSessions,
  getCurrentUser,
  getCreditOffers,
  getCreditHistory,
  getNotaryDirectory,
  getListedShares,
  getMyShares,
  getPublicShare,
  getSharedTrace,
  logoutBrowser,
  revokeApiKey,
  revokeCliSession,
  verifyTracePackage,
} from './platform-api/client';
import { abbreviatedKeyId, formatNotaryBoundary, notaryLifecycle, orderNotaries } from './notaryLifecycle';

const loadCreditUtilizationChart = () => import('./CreditUtilizationChart');
const CreditUtilizationChart = lazy(loadCreditUtilizationChart);
const appleLogoUrl = new URL('./assets/platforms/apple.svg', import.meta.url).href;
const installCommand = 'curl -fsSL https://llm-notary.exalto.ai/install.sh | sh';
const sourceInstallCommand = `git clone https://github.com/exalto-ai/llm-notary.git
cd llm-notary
cargo install --locked --path crates/llm-notary-client`;
export function MacosDownloadLink({ loadPointer = loadLatestPointer }) {
  const [downloadHref, setDownloadHref] = useState(null);
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
    return () => { cancelled = true; };
  }, [loadPointer]);
  return <a className="button button-dark hero-download" href={downloadHref || '#/docs/getting-started'} download={downloadHref ? macosDmgName : undefined} aria-busy={!downloadHref && !unavailable}>
    <img src={appleLogoUrl} alt="" aria-hidden="true" />
    <span><b>Download for macOS</b>{unavailable && <small>View install options</small>}</span>
  </a>;
}
function PenMark() {
  return <span className="pen-mark" aria-hidden="true"><img src="/notary-mark.svg" alt="" /></span>;
}

function accountName(user) {
  return user.display_name || user.github_login;
}

function accountIdentifier(user) {
  return user.github_login;
}

function authProviderName(user) {
  return user.auth_provider === 'google' ? 'Google' : 'GitHub';
}

function HeroSignalField() {
  const xLines = Array.from({ length: 11 }, (_, index) => -80 + index * 160);
  const yLines = Array.from({ length: 9 }, (_, index) => -30 + index * 120);
  const routes = [
    [[-80, 210], [400, 210], [400, 330], [720, 330], [720, 570], [1040, 570], [1040, 690], [1520, 690]],
    [[-80, 570], [240, 570], [240, 450], [560, 450], [560, 210], [880, 210], [880, 90], [1520, 90]],
    [[-80, 330], [240, 330], [240, 90], [720, 90], [720, 210], [1200, 210], [1200, 450], [1520, 450]],
    [[-80, 690], [400, 690], [400, 570], [720, 570], [720, 450], [1040, 450], [1040, 330], [1520, 330]],
    [[-80, 90], [240, 90], [240, 210], [400, 210], [400, 450], [880, 450], [880, 570], [1520, 570]],
    [[-80, 450], [560, 450], [560, 690], [880, 690], [880, 330], [1200, 330], [1200, 210], [1520, 210]],
  ];
  const pathFor = (points) => points.map(([x, y], index) => {
    if (!index) return `M${x} ${y}`;
    const [previousX] = points[index - 1];
    return previousX === x ? `V${y}` : `H${x}`;
  }).join(' ');
  const tracePaths = routes.map(pathFor);
  const cells = [[3, 2], [5, 3], [8, 5], [2, 6], [6, 1], [9, 4], [4, 5], [7, 6], [1, 3], [10, 2], [5, 6], [8, 1]];
  const particles = [
    [0, '3.8s', '-1.1s'], [1, '4.4s', '-2.7s'], [2, '3.3s', '-.5s'], [3, '4.9s', '-3.5s'],
    [4, '3.6s', '-2.1s'], [5, '4.2s', '-.8s'], [0, '5.1s', '-3.8s'], [1, '3.5s', '-1.7s'],
    [2, '4.6s', '-3.1s'], [3, '3.9s', '-.2s'], [4, '5.4s', '-4.4s'], [5, '3.2s', '-2.4s'],
  ];
  return <div className="hero-signal-field" aria-hidden="true"><svg viewBox="0 0 1440 840" preserveAspectRatio="xMidYMid slice"><g className="signal-grid">{yLines.map((y) => <path key={`h-${y}`} d={`M-80 ${y}H1520`} />)}{xLines.map((x) => <path key={`v-${x}`} d={`M${x} -30V930`} />)}</g><g className="signal-traces">{tracePaths.map((path, index) => <path key={path} className={`signal-trace signal-trace--${index + 1}`} d={path} />)}</g><g className="signal-cells">{cells.map(([xIndex, yIndex]) => <rect key={`${xIndex}-${yIndex}`} x={xLines[xIndex] - 11} y={yLines[yIndex] - 11} width="22" height="22" />)}</g><g className="signal-marks">{particles.map(([routeIndex, duration, begin], index) => <circle key={`${routeIndex}-${begin}`} className="signal-mark" r={index % 3 === 0 ? 4 : 3.25}><animateMotion dur={duration} begin={begin} repeatCount="indefinite" path={tracePaths[routeIndex]} /></circle>)}</g></svg></div>;
}

function LinkIcon() { return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10.6 13.4a4 4 0 0 0 5.7.1l2-2a4 4 0 0 0-5.7-5.7l-1.1 1.1M13.4 10.6a4 4 0 0 0-5.7-.1l-2 2a4 4 0 0 0 5.7 5.7l1.1-1.1" /></svg>; }
function CheckIcon() { return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m5 12 4.2 4.2L19 6.5" /></svg>; }

function AccountMenu({ user, onLogout }) {
  const [open, setOpen] = useState(false);
  const menuRef = useRef(null);
  const name = accountName(user);
  const identifier = accountIdentifier(user);
  const initials = name.slice(0, 2).toUpperCase();
  useEffect(() => {
    const close = (event) => {
      if (event.key === 'Escape' || (event.type === 'mousedown' && !menuRef.current?.contains(event.target))) setOpen(false);
    };
    document.addEventListener('mousedown', close);
    window.addEventListener('keydown', close);
    return () => { document.removeEventListener('mousedown', close); window.removeEventListener('keydown', close); };
  }, []);
  return <div className="account-menu" ref={menuRef}>
    <button type="button" className="account-trigger" onClick={() => setOpen((value) => !value)} aria-expanded={open} aria-haspopup="menu" aria-label={`Account menu for ${name}`}>{user.avatar_url ? <img src={user.avatar_url} alt="" referrerPolicy="no-referrer" /> : <span>{initials}</span>}</button>
    {open && <div className="account-popover" role="menu">
      <div className="account-identity"><div><b>{name}</b><span>{identifier} · {authProviderName(user)}</span></div></div>
      <div className="account-actions"><a href="/#/dashboard" role="menuitem" onClick={() => setOpen(false)}>Dashboard</a><button type="button" role="menuitem" onClick={() => { setOpen(false); onLogout(); }}>Log out</button></div>
    </div>}
  </div>;
}

export function Header({ user, onLogout, hideSignIn = false, authPending = false }) {
  return <header className="nav-wrap"><a className="brand" href="/#/"><PenMark /> <span>LLM Notary</span></a><nav className="product-nav"><a href="/#/docs">Docs</a><a href="/#/verify">Verify</a><a href="/#/library">Library</a>{user ? <AccountMenu user={user} onLogout={onLogout} /> : !hideSignIn && authPending ? <span className="account-auth-placeholder" role="status" aria-label="Checking sign-in status"><i /></span> : !hideSignIn && <a className="sign-in-link" href="/#/signin"><span>Sign in</span></a>}</nav></header>;
}

function AuthProviderLink({ provider, href, pendingProvider, onStart }) {
  const name = provider === 'google' ? 'Google' : 'GitHub';
  const pending = pendingProvider === provider;
  const disabled = pendingProvider !== null && !pending;
  const className = `auth-provider${pending ? ' auth-provider--pending' : ''}${disabled ? ' auth-provider--disabled' : ''}`;
  const start = (event) => {
    if (pendingProvider !== null) {
      event.preventDefault();
      return;
    }
    onStart(provider);
  };
  return <a className={className} href={href} onClick={start} aria-busy={pending || undefined} aria-disabled={disabled || undefined} tabIndex={disabled ? -1 : undefined}>
    <AuthProviderIcon provider={provider} />
    <b>{pending ? `Connecting to ${name}…` : `Continue with ${name}`}</b>
    <span className="auth-provider-progress" aria-hidden="true">{pending && <><i /><i /><i /></>}</span>
  </a>;
}

export function SignInPage({ route = 'signin', user = null, loadProviders = getAuthProviders }) {
  const [providers, setProviders] = useState(null);
  const [error, setError] = useState(null);
  const [pendingProvider, setPendingProvider] = useState(null);
  useEffect(() => {
    let cancelled = false;
    loadProviders()
      .then((next) => { if (!cancelled) setProviders(next); })
      .catch((reason) => { if (!cancelled) setError(reason instanceof Error ? reason.message : 'Could not load sign-in options.'); });
    return () => { cancelled = true; };
  }, [loadProviders]);
  const requestedReturn = new URLSearchParams(route.split('?')[1] || '').get('return_to');
  const returnTo = requestedReturn?.startsWith('#/authorize?') ? requestedReturn : null;
  const providerHref = (provider) => `/api/auth/${provider}${returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : ''}`;
  if (user) return <main className="auth-page"><section className="auth-panel"><h1>Already signed in</h1><p className="auth-intro">You’re signed in as <b>{accountName(user)}</b>.</p><a className="button button-dark" href="/#/dashboard">Open dashboard</a></section></main>;
  return <main className="auth-page"><section className="auth-panel" aria-labelledby="sign-in-title">
    <h1 id="sign-in-title">Sign in</h1><p className="auth-intro">Continue to LLM Notary.</p>
    {error ? <div className="auth-state" role="alert"><b>Sign-in options are unavailable</b><span>{error}</span></div> : providers === null ? <div className="auth-state" role="status"><b>Loading sign-in options</b></div> : <div className="auth-provider-list">
      {providers.google && <AuthProviderLink provider="google" href={providerHref('google')} pendingProvider={pendingProvider} onStart={setPendingProvider} />}
      {providers.github && <AuthProviderLink provider="github" href={providerHref('github')} pendingProvider={pendingProvider} onStart={setPendingProvider} />}
      {!providers.google && !providers.github && <div className="auth-state" role="alert"><b>No sign-in provider is configured</b></div>}
    </div>}
    <p className="auth-legal">By continuing, you agree to the <a href="/#/terms">Terms</a> and acknowledge the <a href="/#/privacy">Privacy Policy</a>.</p>
  </section></main>;
}

function Footer() {
  return <footer className="site-footer"><span className="footer-copyright">© 2026 LLM Notary</span><nav aria-label="Footer"><a href="/#/notaries">Notaries</a><a href="/#/privacy">Privacy</a><a href="/#/terms">Terms</a></nav></footer>;
}

const legalPages = {
  privacy: {
    eyebrow: 'Legal · Privacy',
    title: 'Privacy Policy',
    intro: 'This policy explains the information handled by the LLM Notary website, session-sharing service, and local tooling.',
    sections: [
      ['Local capture stays local', 'The local proxy handles application plaintext and provider credentials. Within the protocol, the remote notary witnesses encrypted traffic and protocol metadata; it does not receive your API key, prompt, or response plaintext.'],
      ['Account information', 'If you sign in with Google, we use your stable Google account identifier, display name, and profile image to operate your account. We check that Google reports a verified email address but do not retain the address. Google access is limited to openid, email, and profile. If configured, GitHub sign-in remains available for existing accounts and requests identity only, without repository, organization, or email access. Provider access tokens are not retained.'],
      ['Shared sessions', 'Sharing is an explicit action. The service verifies and safety-scans a submitted .llmtrace package before admission, then makes the disclosed conversation and exact admitted package public. Header values are hidden by the package’s default disclosure policy, but request and response bodies—including prompts, responses, tool definitions, and tool results—may be public. Do not share content you are not permitted to disclose.'],
      ['Service processing', 'One-off verification does not retain an uploaded package. Sharing retains the exact admitted package and its normalized trace so visitors can inspect the session and independently verify the original bytes. Temporary intake objects are removed after admission or rejection.'],
      ['Your choices', 'You choose whether a shared session is Unlisted or Listed. Both are public to anyone with the link; Unlisted only keeps it out of the Library. Keep private capture bundles and credentials under your control. For privacy questions or requests, contact the LLM Notary operator through the project’s support channel.'],
      ['Updates', 'We may revise this policy as the service evolves. The current version will always be available on this page.'],
    ],
  },
  terms: {
    eyebrow: 'Legal · Terms',
    title: 'Terms of Service',
    intro: 'These terms govern your use of the LLM Notary website, local tooling, and session-sharing service.',
    sections: [
      ['Using the service', 'Use LLM Notary lawfully and only with content, credentials, and provider accounts you are authorized to use. Do not interfere with the service, bypass access controls, or submit material that infringes the rights of others.'],
      ['Your shared sessions', 'You are responsible for every package you choose to submit. Sharing is an explicit consent boundary: once admitted, its disclosed conversation and exact package can be accessed by anyone with the link. Unlisted is not private; it only keeps the session out of the Library.'],
      ['What verification means', 'The retained .llmtrace package can be checked against its cryptographic and protocol evidence. The readable conversation is derived from that admitted package, and the download preserves its exact bytes. Neither result establishes that a model output or user interpretation is true, complete, safe, or suitable for a particular purpose.'],
      ['Availability', 'The service is provided on an “as available” basis and may change, be suspended, or be discontinued. Preserve the local materials you need; do not rely on the service as your only record or backup.'],
      ['Your responsibilities', 'You are responsible for maintaining the security of your devices, local captures, API credentials, and account. Do not share confidential, personal, or otherwise protected information unless you have a clear right to do so.'],
      ['Changes to these terms', 'We may update these terms as the product develops. Continued use after an updated version is posted means you accept the revised terms.'],
    ],
  },
};

function LegalPage({ pageKey }) {
  const page = legalPages[pageKey];
  return <main className="legal-shell"><span className="eyebrow">{page.eyebrow}</span><h1>{page.title}</h1><p className="legal-intro">{page.intro}</p><p className="legal-updated">Last updated: August 2026</p><div className="legal-sections">{page.sections.map(([heading, copy]) => <section key={heading}><h2>{heading}</h2><p>{copy}</p></section>)}</div></main>;
}

function TrustColumns() {
  const boundaries = [
    ['01', 'Client', 'Holds the plaintext', 'The local proxy sees the request and response. A user cannot change authenticated bytes or invent a provider response and still produce valid finalized evidence.'],
    ['02', 'Notary', 'Witnesses ciphertext', 'The notary sees the provider hostname, encrypted traffic, sizes, timing, and protocol metadata—not the API key, prompt, or response plaintext. The provider serves a normal request; origin follows from the authenticated TLS session, not a special provider signature.'],
    ['03', 'Researcher', 'Checks independently', 'Researchers can verify the notary signature, provider identity, disclosed transcript, artifact hashes, and deterministic mapping using the trusted notary public key.'],
  ];
  return <div className="trust-columns" aria-label="How the trust model works">{boundaries.map(([number, actor, title, copy]) => <article key={actor}><span>{number}</span><b>{actor}</b><h3>{title}</h3><p>{copy}</p></article>)}</div>;
}

function VerificationArchitecture() {
  return <section className="section architecture" id="how-it-works"><div className="section-head"><span className="eyebrow">How it works</span><h2>Don’t trust. Verify.</h2></div><TrustColumns /><div className="section-link"><a href="#/docs/how-it-works">Learn more about the trust model</a></div></section>;
}

export function ListedSharesPreview({ loadShares = getListedShares }) {
  const [shares, setShares] = useState(null);
  const [loadError, setLoadError] = useState(false);
  useEffect(() => {
    let cancelled = false;
    loadShares({ limit: 5 })
      .then((payload) => { if (!cancelled) setShares(payload.items); })
      .catch(() => { if (!cancelled) setLoadError(true); });
    return () => { cancelled = true; };
  }, [loadShares]);
  const visible = shares || [];
  return <section className="section library-preview"><div className="trace-heading"><div><span className="eyebrow">Public domain</span><h2>Traces from the community.</h2></div></div>{shares === null && !loadError ? <div className="collection-pending" role="status"><b>Loading the Library…</b><span>Finding the latest public traces.</span></div> : loadError ? <div className="collection-pending" role="alert"><b>The Library couldn’t load.</b><span>Open the Library to try again.</span></div> : visible.length ? <div className="preview-share-list" aria-label="Featured public traces">{visible.map((share) => <a href={`/s/${encodeURIComponent(share.id)}`} key={share.id}><header><b>{share.model}</b><ProviderIdentity provider={share.provider} detail={`shared by ${share.publisher}`} /></header><div className="preview-share-snippets"><p><span>Prompt</span>{share.input_preview || 'No prompt preview.'}</p><p><span>Response</span>{share.output_preview || 'No response preview.'}</p></div></a>)}</div> : <div className="collection-pending"><b>The Library is empty.</b><span>Public traces will appear here after they’re shared.</span></div>}<a className="button button-dark" href="#/library">Browse the Library</a></section>;
}

const MAX_VERIFY_FILE_BYTES = 128 * 1024 * 1024 + 64 * 1024 + 16 * 1024;
const verificationErrors = {
  malformed_package: ['Package could not be read', 'This file is not a well-formed canonical `.llmtrace` package.'],
  tampered_package: ['Package verification failed', 'Authenticated evidence, declared hashes, or the normalized trace did not match.'],
  untrusted_notary: ['Notary key is not trusted', 'The package was signed by a notary key that is not trusted for its authenticated capture time.'],
  unsupported_version: ['Package version is unsupported', 'This verifier does not support one of the package contract versions. Update the verifier or use a compatible package.'],
  verification_in_flight: ['Verification already in progress', 'This network address already has a verification running. Wait for it to finish and try again.'],
  verification_capacity: ['Verifier is at capacity', 'All verification workers are busy. Wait a moment and try again.'],
  package_too_large: ['Package is too large', 'Choose a `.llmtrace` package within the 128 MiB verification limit.'],
  extraction_timeout: ['Package extraction timed out', 'The archive could not be safely extracted within the service limit.'],
  verification_timeout: ['Verification timed out', 'The cryptographic check did not finish within the service limit.'],
  verification_unavailable: ['Verification is unavailable', 'The verification service could not complete this request. Try again later or verify locally.'],
  unsupported_media_type: ['File type is unsupported', 'Choose a finalized file whose name ends in `.llmtrace`.'],
};

function verificationError(code) {
  return verificationErrors[code] || verificationErrors.verification_unavailable;
}

function verificationFileError(file) {
  if (!file.name.toLowerCase().endsWith('.llmtrace')) return 'unsupported_media_type';
  if (file.size < 1) return 'malformed_package';
  if (file.size > MAX_VERIFY_FILE_BYTES) return 'package_too_large';
  return null;
}

function formatVerificationTime(unixMilliseconds) {
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'long' }).format(new Date(unixMilliseconds));
}

function formatTrustSource(source) {
  const words = String(source).replaceAll('_', ' ');
  return `${words.charAt(0).toUpperCase()}${words.slice(1)}`;
}

function VerificationError({ code, onReset = null }) {
  const [title, copy] = verificationError(code);
  return <section className="verification-result verification-result--error" role="alert"><span className="eyebrow">Verification stopped</span><h2>{title}</h2><p>{copy}</p><code>{code}</code>{onReset && <button type="button" className="button" onClick={onReset}>Choose another package</button>}</section>;
}

export function VerificationPage({ verifyFile = verifyTracePackage }) {
  const inputRef = useRef(null);
  const outcomeRef = useRef(null);
  const requestGeneration = useRef(0);
  const [file, setFile] = useState(null);
  const [consent, setConsent] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [status, setStatus] = useState('idle');
  const [errorCode, setErrorCode] = useState(null);
  const [result, setResult] = useState(null);
  const trace = result ? parseSharedTrace(result.trace) : [];
  const chooseFile = (nextFile) => {
    requestGeneration.current += 1;
    setConsent(false);
    setResult(null);
    setStatus('idle');
    const nextError = nextFile ? verificationFileError(nextFile) : null;
    setFile(nextError ? null : nextFile);
    setErrorCode(nextError);
  };
  const submit = async (event) => {
    event.preventDefault();
    if (!file || !consent || status === 'uploading') return;
    setErrorCode(null);
    setResult(null);
    setStatus('uploading');
    const generation = ++requestGeneration.current;
    try {
      const nextResult = await verifyFile(file);
      if (requestGeneration.current !== generation) return;
      setResult(nextResult);
      setStatus('success');
    } catch (error) {
      if (requestGeneration.current !== generation) return;
      setErrorCode(error instanceof Error ? error.message : 'verification_unavailable');
      setStatus('error');
    }
  };
  const resetVerification = () => {
    chooseFile(null);
    if (inputRef.current) inputRef.current.value = '';
  };
  useEffect(() => {
    if (!['success', 'error'].includes(status)) return;
    const frame = window.requestAnimationFrame(() => {
      outcomeRef.current?.focus({ preventScroll: true });
      outcomeRef.current?.scrollIntoView({
        block: 'start',
        behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth',
      });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [status]);
  const completed = status === 'success' || status === 'error';
  return <main className="verification-shell">
    <header className="verification-intro"><span className="eyebrow">Portable verification</span><h1>Verify a .llmtrace package.</h1><p>Check the authenticated provider exchange, notary signature, artifact hashes, and normalized OpenTelemetry trace without signing in.</p></header>
    {!completed && <form className="verification-workspace" onSubmit={submit}>
      <section className="verification-disclosure" aria-labelledby="verification-disclosure-title"><span className="eyebrow">Read before uploading</span><h2 id="verification-disclosure-title">Your package may contain sensitive content.</h2><p>Headers are hidden by default, but prompts, responses, tool definitions, and tool results may be included. We check the package without saving it.</p></section>
      <label
        className={`verification-drop${dragging ? ' verification-drop--active' : ''}`}
        onDragEnter={(event) => { event.preventDefault(); setDragging(true); }}
        onDragOver={(event) => event.preventDefault()}
        onDragLeave={(event) => { if (!(event.relatedTarget instanceof Node) || !event.currentTarget.contains(event.relatedTarget)) setDragging(false); }}
        onDrop={(event) => { event.preventDefault(); setDragging(false); chooseFile(event.dataTransfer.files[0] || null); }}
      >
        <input ref={inputRef} type="file" onChange={(event) => chooseFile(event.target.files[0] || null)} />
        <span>{file ? 'Package selected' : 'Drop one .llmtrace package here'}</span>
        <strong>{file ? file.name : 'or choose a file'}</strong>
        <small>{file ? fileSize(file.size) : 'Maximum package size: 128 MiB'}</small>
      </label>
      {file && <label className="verification-consent"><input type="checkbox" checked={consent} onChange={(event) => setConsent(event.target.checked)} /><span>I understand that this package may contain sensitive content.</span></label>}
      <div className="verification-actions"><button className="button button-dark" type="submit" disabled={!file || !consent || status === 'uploading'}>{status === 'uploading' ? 'Checking package…' : 'Verify package'}</button>{file && <button className="button" type="button" onClick={resetVerification}>Clear</button>}</div>
      {status === 'uploading' && <div className="verification-progress" role="status"><i aria-hidden="true" /><span><b>Checking the evidence</b><small>Keep this page open. Large packages can take a moment.</small></span></div>}
    </form>}
    {!completed && errorCode && <VerificationError code={errorCode} />}
    {completed && <div ref={outcomeRef} className="verification-outcome" tabIndex={-1}>
      {status === 'error' && <VerificationError code={errorCode} onReset={resetVerification} />}
      {result && <section className="verification-result verification-result--success" aria-labelledby="verification-success-title" aria-live="polite"><header><div><span className="eyebrow">Portable package</span><h2 id="verification-success-title">Verification passed.</h2></div><div className="verification-result-actions"><strong>Verified</strong><button type="button" className="button" onClick={resetVerification}>Verify another package</button></div></header><dl className="verification-facts"><div><dt>Provider</dt><dd><ProviderIdentity provider={result.provider} /></dd></div><div><dt>Host</dt><dd>{result.host}</dd></div><div><dt>Capture time</dt><dd>{formatVerificationTime(result.authenticated_at_unix_ms)}</dd></div><div><dt>Notary key</dt><dd><code>{result.notary_key_id}</code></dd></div><div><dt>Trust source</dt><dd>{formatTrustSource(result.trust_source)} · generation {result.directory_generation}</dd></div><div><dt>Trace SHA-256</dt><dd><code>{result.trace_sha256}</code></dd></div><div><dt>Package SHA-256</dt><dd><code>{result.package_sha256}</code></dd></div></dl><section className="verification-trace"><div className="span-panel-head"><span>Normalized trace</span><small>{trace.length} {trace.length === 1 ? 'span' : 'spans'}</small></div>{trace.length ? <SpanTree spans={trace} /> : <p>No normalized spans were present.</p>}</section></section>}
    </div>}
  </main>;
}

function MotionStudies() {
  return <RelayAnimation />;
}

export function Landing({ loadLatestPointer: loadPointer = loadLatestPointer }) {
  return <main id="top">
    <section className="hero">
      <HeroSignalField />
      <h1>Verifiable intelligence</h1>
      <p>Privacy-preserving LLM trace packages for open research and independent verification.</p>
      <div className="hero-actions"><MacosDownloadLink loadPointer={loadPointer} /><p className="hero-developer-path">or, <a href="#/docs/getting-started">build on the LLM Notary stack</a></p></div>
    </section>
    <MotionStudies />
    <VerificationArchitecture />
    <section className="section install capture">
      <div><span className="eyebrow">Local capture</span><h2>Capture locally.</h2><p>Point your existing tools at the local proxy. Provider calls keep streaming normally while encrypted bundles stay on your machine.</p></div>
      <div className="terminal"><div><i /><i /><i /></div><pre><code><b>$</b> {installCommand}{'\n\n'}<b>$</b> llm-notaryd{'\n\n'}proxy  <em>127.0.0.1:8787</em>{'\n'}admin  <em>127.0.0.1:8788</em></code></pre><a href="#/docs/getting-started">Installation and setup</a></div>
    </section>
    <ListedSharesPreview />
    <section className="section verify" id="verify">
      <div><span className="eyebrow">Independent verification</span><h2>Proof travels with the package.</h2><p>A finalized .llmtrace contains the notary-signed TLS evidence, disclosed exchange, canonical trace, and hashes needed for portable verification.</p><div className="verify-points"><span>Notary evidence</span><span>Canonical OTLP</span><span>Portable package</span></div><div className="button-row"><a className="button button-dark" href="#/verify">Verify a package</a></div></div>
      <div className="receipt"><header><PenMark /><b>Portable package</b></header><h3>Verified</h3><dl><div><dt>Provider</dt><dd><ProviderIdentity provider="OpenAI" detail="api.openai.com" /></dd></div><div><dt>Artifact</dt><dd>capture.llmtrace</dd></div><div><dt>Trace hash</dt><dd>9b44f8…c21d</dd></div></dl><div className="receipt-contents"><span>Notary evidence <i>•••</i></span><span>Disclosed exchange <i>•••</i></span><span>Canonical trace <i>•••</i></span></div><footer>VERIFIED FROM SOURCE PACKAGE</footer></div>
    </section>
  </main>;
}

const docPages = {
  overview: {
    title: 'How LLM Notary fits.',
    lead: 'Run your existing model client through a local proxy, keep encrypted evidence on your machine, and turn only the interactions you choose into independently verifiable OpenTelemetry trace packages.',
    blocks: [
      {
        heading: 'The workflow',
        steps: [
          { title: 'Capture', body: 'Point an SDK or agent at the local proxy. Requests and streamed responses continue normally while each completed provider call becomes an encrypted local bundle.' },
          { title: 'Choose', body: 'Bundles wait on your disk. Nothing is shared automatically, and interactive model use does not wait for the expensive proof step.' },
          { title: 'Finalize', body: 'Turn a selected bundle into authenticated TLS evidence and a deterministic OTel GenAI trace. This can happen long after the original model call.' },
          { title: 'Verify or share', body: 'Check the package locally, keep it private, or deliberately share its disclosed conversation and portable proof through a stable link.' },
        ],
      },
      {
        heading: 'Three states, three jobs',
        cards: [
          { meta: 'Private', title: 'Encrypted bundle', body: 'A sensitive local checkpoint that can be finalized later. It is not yet evidence another person can verify.' },
          { meta: 'Portable', title: 'Trace package', body: 'TLSNotary evidence, disclosed authenticated HTTP, canonical OTLP, and a manifest binding the files together.' },
          { meta: 'Public', title: 'Shared session', body: 'A readable conversation plus the exact admitted .llmtrace package. Unlisted stays out of the Library; Listed opts into discovery.' },
        ],
      },
      {
        heading: 'What is automatic',
        items: [
          'The first service start creates or opens the local encrypted-bundle vault. On a desktop OS, its random key is stored in the system credential service.',
          'The service discovers the production notary endpoint and public key from the LLM Notary directory, then pins that trust information locally.',
          'Finalization and verification use the pinned notary identity. Normal hosted use does not require copying a public key into an API request.',
          'Provider credentials remain in your existing SDK or agent environment; LLM Notary does not require a project .env file.',
        ],
      },
      {
        heading: 'A first successful run',
        code: `${installCommand}\n\nllm-notaryd\n# Open http://127.0.0.1:8788 for the local dashboard.\n# Point an OpenAI client at http://127.0.0.1:8787/openai/v1.\n\nllm-notary status\nllm-notary captures list`,
      },
      {
        heading: 'The claim',
        note: 'A trusted notary attests that disclosed bytes came from an authenticated TLS interaction with the named provider, and LLM Notary deterministically binds the OpenTelemetry representation to those bytes.',
      },
    ],
  },
  'how-it-works': {
    title: 'Trust and guarantees',
    lead: 'LLM Notary makes a narrow provenance claim. Understanding who sees what—and what the proof does not establish—is part of using it correctly.',
    blocks: [
      {
        heading: 'Each participant',
        cards: [
          { meta: 'User / client', title: 'Holds the plaintext', body: 'The local proxy sees the request and response. A user cannot change authenticated bytes or invent a provider response and still produce valid finalized evidence.' },
          { meta: 'Notary', title: 'Witnesses ciphertext', body: 'The notary sees the provider hostname, encrypted traffic, sizes, timing, and protocol metadata. It does not receive the API key, prompt, or response plaintext.' },
          { meta: 'Provider', title: 'Serves a normal request', body: 'No provider integration is required. Origin follows from the authenticated provider TLS session, not from a special provider signature.' },
          { meta: 'Verifier', title: 'Checks independently', body: 'A verifier checks the notary signature, provider identity, disclosed transcript, artifact hashes, and deterministic mapping using the trusted notary public key.' },
        ],
      },
      {
        heading: 'Authenticated versus observed',
        items: [
          'A model-emitted tool call is authenticated provider output.',
          'A tool result in the next request proves that the client sent that value—not that the local tool really ran or returned a truthful result.',
          'A session ID is authenticated as client-supplied request metadata. It can correlate calls, but it does not prove one genuine agent process created them.',
          'Each provider call is proved independently. A larger agent run can group those calls without upgrading locally observed activity into provider-authenticated evidence.',
        ],
      },
      {
        heading: 'What this does not prove',
        items: [
          'That a response is correct, safe, complete, or useful.',
          'That a particular human authored the prompt.',
          'That every call from a larger session was disclosed.',
          'That a local tool executed, or that its reported output was accurate.',
          'That the trusted notary private key has never been compromised.',
        ],
      },
      {
        heading: 'How trust is established',
        body: 'The service retrieves the versioned production notary directory over authenticated HTTPS and caches its key history. The JSON directory is not separately signed. Finalized packages identify the notary key that signed their evidence; verification accepts it only if that key was trusted at the package timestamp. A self-hosted deployment pairs `notary.endpoint` with `notary.public_key` in `config.toml`, but that is not part of the normal hosted workflow.',
      },
    ],
  },
  'getting-started': {
    title: 'Choose how to run LLM Notary.',
    lead: 'Use the guided macOS app for everyday capture and review. Use the CLI and local service when you are integrating an SDK, coding agent, server, or automated workflow.',
    blocks: [
      {
        heading: 'Choose an interface',
        cards: [
          { meta: 'Most Mac users', title: 'macOS app', body: 'Guided setup, menu-bar service controls, and the complete capture workspace in one signed application. No terminal is required for normal use.' },
          { meta: 'Developers and operators', title: 'CLI + local service', body: 'Two command-line programs for SDK routing, coding-agent configuration, scripting, automation, and explicit service supervision.' },
        ],
      },
      { heading: 'Install the macOS app', body: 'On the home page, choose Download for macOS. Open the downloaded DMG, move LLM Notary to Applications, then launch it. The app guides first-time setup and supervises its bundled local service.' },
      { heading: 'System requirements', items: ['A Mac with Apple silicon (M1 or newer).', 'macOS 12 Monterey or later.', 'A supported model provider account when you are ready to capture a real interaction.'] },
      { heading: 'What the app manages', body: 'The app configures capture protection, helps connect a provider or coding tool, starts and stops its bundled `llm-notaryd`, and embeds the local capture workspace. Provider credentials stay in the tool that sends the model request; the app does not ask for or store them.' },
      { heading: 'Install the CLI and local service', body: 'The shell installer supports Apple silicon Macs and x86-64 or ARM64 Linux systems. It selects the complete `latest` website build and checks the archive against its published SHA-256 value. This is a moving pre-release pointer. The checksum detects corruption but is not an independent signature because it shares the archive publisher.', code: installCommand },
      { heading: 'Build from source', body: 'To build the same two local programs yourself, use Rust 1.95.0 and the repository toolchain file.', code: sourceInstallCommand },
      { heading: 'Programs', body: '`llm-notaryd` is the long-running local service. `llm-notary` is its short-lived REST client. The website archive installs both together.' },
      { heading: 'Start the service', code: 'llm-notaryd' },
      { heading: 'Open the local dashboard', body: 'Visit `http://127.0.0.1:8788` and use the tabs for captures, finalizations, trace verification, sharing, activity, and settings. The default loopback configuration opens directly. If `admin.auth` is enabled, sign in with its configured username and password; the dashboard exchanges them for an `HttpOnly` session and does not store the password.' },
      { heading: 'Configuration file', body: 'The first service start creates an editable `config.toml` at the standard user location: `~/.config/llm-notary/config.toml` on Linux, `%APPDATA%\\llm-notary\\config.toml` on Windows, and `~/Library/Application Support/llm-notary/config.toml` on macOS. It is written once and never replaced. Start with an explicit file when needed:', code: 'llm-notaryd --config /path/to/config.toml' },
      { heading: 'Use the command client', body: '`llm-notary` is a short-lived client for the daemon\'s versioned loopback API. It checks daemon health and never opens the catalog or vault directly. Add `--json` for automation.', code: 'llm-notary status\nllm-notary captures list --provider openai\nllm-notary operations list --state failed --json\nllm-notary open' },
      { heading: 'What it controls', body: '`config.toml` holds the listener address, optional admin authentication, an optional local or self-hosted notary endpoint, bundle and trace directories, the SQLite catalog path and preview limits, and the enabled provider routes. All built-in providers start enabled. The hostname and API behavior of each provider remain fixed; configuration cannot direct the proxy to an arbitrary upstream host.' },
      { heading: 'Optional admin sign-in', body: 'The loopback administration API is available to local processes without credentials by default. To require sign-in, configure a username and an Argon2id PHC password hash. Store the hash, including its salt and work parameters, rather than the plaintext password. A prompted tool such as caddy hash-password --algorithm argon2id can generate it.', code: '[admin.auth]\nusername = "local-admin"\npassword_hash = "$argon2id$v=19$m=32768,t=2,p=1$..."' },
      { heading: 'Capture encryption is automatic', body: 'On first use, the proxy creates a random capture-encryption key and stores it in Keychain on macOS, Credential Manager on Windows, or the desktop secret service on Linux. The OS may ask you to unlock that credential. You do not need to run a separate initialization command.' },
      { heading: 'Optional passphrase mode', body: 'If you prefer a passphrase instead of the operating-system credential service, point `LLM_NOTARY_VAULT_PASSPHRASE_FILE` at a private UTF-8 file before the first service start. An empty passphrase is accepted for low-friction local testing, but it provides no meaningful protection if someone obtains both your captures and vault configuration.', code: 'export LLM_NOTARY_VAULT_PASSPHRASE_FILE=/private/local/path/vault-passphrase\nllm-notaryd' },
      { heading: 'What happens online', body: 'The local proxy handles plaintext while the notary participates in the provider TLS connection without seeing application data. Provider response bytes stream back to your agent as they arrive.' },
      { heading: 'What happens at end-of-stream', body: 'The proxy seals encrypted deferred state into one `.llmcapture`. It does not perform the expensive final proof before returning control to your workflow.' },
      {
        heading: 'Connect an SDK',
        definitions: [
          { term: 'OpenAI', description: 'Set your SDK base URL to http://127.0.0.1:8787/openai/v1 and continue using the Responses API.' },
          { term: 'Anthropic', description: 'Set the SDK base URL to http://127.0.0.1:8787/anthropic and continue sending Messages API requests to /v1/messages.' },
          { term: 'DeepSeek', description: 'Set the OpenAI-compatible base URL to http://127.0.0.1:8787/deepseek and continue using /chat/completions.' },
          { term: 'OpenRouter', description: 'Set the OpenAI-compatible base URL to http://127.0.0.1:8787/openrouter/api/v1, retain OPENROUTER_API_KEY, and use /chat/completions. Verified origin is openrouter.ai; a namespaced model slug is metadata, not proof of a direct upstream-vendor connection.' },
        ],
      },
      { heading: 'OpenRouter + Chat Completions', body: 'The model slug remains trace metadata. The resulting evidence authenticates OpenRouter—not the vendor named in that slug. The Authorization, HTTP-Referer, and X-Title header values are hidden in a finalized package.', code: 'curl http://127.0.0.1:8787/openrouter/api/v1/chat/completions \\\n  -H "Authorization: Bearer $OPENROUTER_API_KEY" \\\n  -H "Content-Type: application/json" \\\n  -H "HTTP-Referer: https://example.test" \\\n  -H "X-Title: LLM Notary example" \\\n  -d \'{"model":"YOUR_MODEL","stream":true,"messages":[{"role":"user","content":"Reply with exactly: llm-notary"}]}\'' },
      { heading: 'Where the API key comes from', body: 'Keep configuring credentials exactly as your SDK or agent expects—for example, OPENAI_API_KEY in your shell or secret manager. LLM Notary does not create, load, or require a .env file. A .env file is only one optional way your own application might populate environment variables.' },
      { heading: 'Provider boundary', body: 'The first local path segment selects a fixed adapter: /openai, /anthropic, /deepseek, or /openrouter. Each adapter fixes the upstream hostname to an explicit allowlist. The notary—not a caller-supplied URL—resolves and opens the provider connection.' },
      { heading: 'Codex + OpenAI', body: 'Replace YOUR_RESPONSES_MODEL with a model available to the OpenAI API key. The explicit no-WebSocket capability keeps Codex on this prototype\'s supported HTTP transport.', code: 'Add this to ~/.codex/config.toml:\n\nmodel_provider = "llm-notary"\nmodel = "YOUR_RESPONSES_MODEL"\n\n[model_providers.llm-notary]\nname = "LLM Notary local proxy"\nbase_url = "http://127.0.0.1:8787/openai/v1"\nenv_key = "OPENAI_API_KEY"\nwire_api = "responses"\nsupports_websockets = false' },
      { heading: 'Run Codex', code: 'codex exec --ephemeral --skip-git-repo-check \\\n  \'Reply with exactly: hello\'' },
      { heading: 'Claude Code + Anthropic', body: 'Set Claude Code\'s Anthropic base URL to the local route, keep the API key in its normal environment, and choose a model available to that account.', code: 'ANTHROPIC_BASE_URL=http://127.0.0.1:8787/anthropic \\\nclaude --bare --no-session-persistence \\\n  -p --model YOUR_MODEL \\\n  \'Reply with exactly: hello\'' },
      { heading: 'OpenCode + DeepSeek', body: 'Set the provider base URL to http://127.0.0.1:8787/deepseek and retain DEEPSEEK_API_KEY in the OpenCode environment.' },
      { heading: 'Search local captures', body: 'Each completed provider interaction keeps its encrypted bundle and gains a row in the local SQLite catalog. Use the dashboard, or fetch the live OpenAPI document and query the local admin API:', code: 'curl "http://127.0.0.1:8788/v1/captures?query=pricing&provider=openai"' },
      { heading: 'Search punctuation safely', body: 'Capture search treats punctuation as text boundaries instead of raw full-text-search syntax. Hyphenated terms, emphasis marks, multiple words, and double-quoted phrases return matches or an empty list through the normal JSON response.' },
      { heading: 'Filter operations and activity', body: 'The service applies operation state and event severity/type filters before returning bounded results. Coding agents should discover state, kind, capture, event type, severity, and time filters from the live OpenAPI document instead of reimplementing them client-side.', code: 'GET /v1/operations?state=failed&kind=finalization&limit=20\nGET /v1/events?severity=error&event_type=finalization_failed&limit=20' },
      { heading: 'What the catalog records', body: 'A capture records its provider, request and response model when available, HTTP status, request and response sizes, duration, finalization state, and the retained artifact paths. By default, it indexes the first 1,000 characters of the request prompt and output as plain local text. It does not store header values, cookies, or credentials. Change the catalog path, disable full-text search, or set either preview limit to 0 in config.toml.' },
      { heading: 'Stopping and retrying', body: 'Once the end-of-stream bundle is sealed, stopping the proxy does not invalidate it. Finalization can happen later. If finalization is interrupted, the unchanged bundle can be retried, although the interrupted proof computation starts over.' },
    ],
  },
  'hosted-credits': {
    title: 'Credits and utilization',
    lead: 'Signed-in accounts receive included monthly credits and can add purchased or promotional credits for hosted use.',
    blocks: [
      { heading: 'How credits work', body: 'Every signed-in account receives an included monthly grant and can add credits through purchases, promotions, or manual adjustments. Capturing locally, retrying an unchanged finalization, verifying a package, and sharing an already-finalized session do not spend credits.' },
      { heading: 'Monthly and additional grants', body: 'Anonymous use receives 64 MiB each UTC month and a signed-in account receives 512 MiB. During prototype testing, every signed-in account also receives one automatic, non-expiring 128 MiB testing grant. Purchased and promotional credits remain separate grants, and finalization spends the grant that expires soonest before non-expiring credit.' },
      { heading: 'Buy additional credits', body: 'The account dashboard sells one-time increments at $5 USD per decimal GB through Stripe-hosted Checkout. The server fixes the price and grants non-expiring credits only after reconciling a signed webhook with Stripe. Refunds and disputes remove the corresponding credit; a reinstatement restores it.' },
      { heading: 'Anonymous allowances are scoped by network address', body: 'Public hosted use derives a rotating, keyed subject from the connection address: one IPv4 address or one IPv6 /64 prefix. Only explicitly trusted reverse proxies may supply the client address. The raw address is not stored in admission records or sent to a notary worker.' },
      { heading: 'An abuse control, not an identity claim', note: 'Network-address scoping is only a coarse abuse control. People behind the same NAT, corporate gateway, or VPN can share an allowance, while one person may appear under different addresses. The derived subject does not identify a person and is not a privacy guarantee.' },
      { heading: 'Account summary', body: 'The hosted dashboard shows plan and billing status, included and additional balances, the monthly reset, the next expiration, purchases, offers, and paginated credit activity. A connected local service can retrieve the same account summary with `llm-notary whoami --json`.' },
      { heading: 'Evidence is unchanged', body: 'Admission and credit bookkeeping do not change TLSNotary evidence, trace-package verification, local bundle retention, or the trust claim. Self-hosted notaries do not need the hosted credit ledger unless their operator deliberately adopts it.' },
    ],
  },
  'trace-packages': {
    title: 'Finalize and verify.',
    lead: 'Turn one encrypted capture into a portable evidence package, inspect its canonical OpenTelemetry trace, and verify the entire package offline.',
    blocks: [
      { heading: 'Finalize one interaction', body: 'Select a captured interaction in the dashboard or admin API. The service atomically writes storage.finalized_dir/<capture-id>.llmtrace by default, records that package in the catalog, and retains the encrypted source capture.', code: 'curl -X POST http://127.0.0.1:8788/v1/captures/cap-example/finalizations' },
      { heading: 'Notary discovery is automatic', body: 'For hosted use, the service refreshes the production notary directory, selects a worker compatible with the capture, and verifies the resulting evidence against its locally pinned key history. For local or self-hosted use, set `notary.endpoint` and `notary.public_key` together in `config.toml`.' },
      { heading: 'Fresh notary connection', body: 'The original provider stream and proxy no longer need to be running. A new notary worker holding the same notary identity and key can complete finalization without a stored server-side checkpoint.' },
      { heading: 'Expect this step to take time', body: 'Private proof generation is slower than capture. Deferring it keeps the interactive agent response fast and makes proof work an explicit background or batch operation.' },
      { heading: 'Interruption behavior', body: 'The pending bundle is not consumed. If finalization fails or the service stops, retry the failed or interrupted durable operation through `POST /v1/operations/{operation_id}/retry`; proof work from the interrupted attempt is not resumed.' },
      { heading: 'Package layout', code: '<capture-id>.llmtrace (ZIP)\n├── archive-manifest.json\n├── evidence.tlsn\n├── manifest.json\n├── request.disclosed.http\n├── response.disclosed.http\n└── trace.otlp.json' },
      {
        heading: 'Artifact responsibilities',
        definitions: [
          { term: 'archive-manifest.json', description: 'The deterministic archive format, ordered entry sizes and hashes, and package digest.' },
          { term: 'evidence.tlsn', description: 'The cryptographic TLSNotary evidence and notary signature.' },
          { term: 'request.disclosed.http', description: 'Authenticated request bytes selected for disclosure. Every header value is hidden except the exact structural value Transfer-Encoding: chunked; the body remains disclosed.' },
          { term: 'response.disclosed.http', description: 'The authenticated provider response, including streamed events. Header values follow the same default-deny rule and the body remains disclosed.' },
          { term: 'trace.otlp.json', description: 'A deterministic OpenTelemetry GenAI mapping of the authenticated request and response, including text, model-emitted tool calls, correlated tool results, model, and usage.' },
          { term: 'manifest.json', description: 'The versioned source metadata and trace hash. The cryptographic signature lives in evidence.tlsn, not in this JSON file.' },
        ],
      },
      { heading: 'Package versus shared view', body: 'The finalized `.llmtrace` package carries all cryptographic evidence and is independently verifiable. A shared session presents a readable view derived from that package and retains the exact admitted bytes for download and independent verification.' },
      { heading: 'Verify a portable package', code: 'llm-notary traces verify ./capture.llmtrace\nPOST /api/verify', body: 'Use the local CLI to verify locally, or upload the package on the public Verify page. The hosted page checks the package without saving it.' },
      { heading: 'Complete context is intentional', body: 'A `.llmtrace` can include system context, tool definitions, session metadata, prompts, responses, and tool results. All HTTP header values are hidden by default, but request and response bodies remain disclosed. Inspect it before sharing; the encrypted `.llmcapture` is private retry state and must stay local.' },
      { heading: 'Download or verify locally', code: 'GET /v1/captures/{capture_id}/package\nPOST /v1/captures/{capture_id}/trace:verify\nllm-notary traces verify ./capture.llmtrace' },
      {
        heading: 'What verification checks',
        items: [
          'The notary signature and expected notary public key.',
          'The authenticated provider identity and TLS evidence.',
          'The disclosed HTTP bytes against the cryptographic evidence.',
          'Every artifact hash named by the package manifest.',
          'The deterministic, versioned OTLP mapping byte-for-byte.',
        ],
      },
      { heading: 'Offline trust', body: 'Verification does not contact the provider or a live notary. It uses the notary key history already cached by the service, or notary.public_key for a self-hosted endpoint. A hosted service must successfully refresh its directory before it can trust previously unseen evidence.' },
      { heading: 'Tool-use boundary', note: 'Verification proves that the model emitted a tool call and, on a later request, that the client sent a particular tool result. It does not prove the local tool actually executed.' },
    ],
  },
  share: {
    title: 'Share a verified session',
    lead: 'Sharing is a deliberate upload of one already-finalized package. The local service verifies it and shows the full disclosed conversation before it contacts LLM Notary.',
    blocks: [
      { heading: 'Connect the local service', body: 'Use the dashboard Share view, or begin the documented `POST /v1/account` device flow and poll its returned request identifier at the required interval.' },
      { heading: 'Choose visibility', body: 'Unlisted is recommended and stays out of the Library. Listed appears in the Library. Both are public to anyone with the stable link; neither is private access.' },
      { heading: 'Submit one finalized package', code: 'POST /v1/captures/{capture_id}/shares\n{"visibility":"unlisted"}' },
      { heading: 'Script-friendly output', body: 'The status URL stays on the loopback administration API so the browser or agent never receives the vault-held hosted credential.', code: '{"capture_id":"cap-…","share_id":"…","state":"queued","visibility":"unlisted","status_url":"/v1/shares/…"}' },
      {
        heading: 'The upload boundary',
        columns: [
          {
            title: 'Uploaded',
            items: [
              'evidence.tlsn and manifest.json',
              'request.disclosed.http with all header values hidden by default',
              'response.disclosed.http with authenticated provider output',
              'the deterministic trace.otlp.json',
            ],
          },
          {
            title: 'Never uploaded',
            items: [
              'encrypted .llmcapture checkpoints',
              'API-key or cookie values',
              'unselected captures from the same session',
              'extra files or symlink targets',
            ],
          },
        ],
      },
      { heading: 'Admission checks', body: 'The local service and hosted admission service validate the deterministic archive, verify its evidence, require hidden header values, and scan every archive entry and nested disclosed body for credential patterns and high-entropy secrets. After storage, admission downloads the exact public bytes and repeats validation, scanning, and verification before exposing the link.' },
      { heading: 'Current consent boundary', body: 'The admission service inspects disclosed request and response bodies, system context, and tool data to verify and reproduce the shared view. Every HTTP header value is hidden except the exact structural value Transfer-Encoding: chunked.' },
      { heading: 'Exact package retention', body: 'An admitted session keeps the exact verified `.llmtrace` bytes, size, and SHA-256 digest. The session page makes that package available for independent verification; the encrypted `.llmcapture` never leaves the local vault.' },
      { heading: 'Retry behavior', body: 'An upload or API failure does not change or delete the local package. Submitting the same capture with the same visibility reuses the archive-derived idempotency key and resumes the retry-safe share job.' },
    ],
  },
};

const docSubheadings = {
  'getting-started': new Set([
    'System requirements',
    'What the app manages',
    'Build from source',
    'Programs',
    'Start the service',
    'Open the local dashboard',
    'Configuration file',
    'Use the command client',
    'What it controls',
    'Optional admin sign-in',
    'Capture encryption is automatic',
    'Optional passphrase mode',
    'What happens online',
    'What happens at end-of-stream',
    'OpenRouter + Chat Completions',
    'Where the API key comes from',
    'Provider boundary',
    'Codex + OpenAI',
    'Run Codex',
    'Claude Code + Anthropic',
    'OpenCode + DeepSeek',
    'What the catalog records',
    'Stopping and retrying',
  ]),
  'trace-packages': new Set([
    'Notary discovery is automatic',
    'Fresh notary connection',
    'Expect this step to take time',
    'Interruption behavior',
    'Artifact responsibilities',
    'Package versus shared view',
    'Complete context is intentional',
    'What verification checks',
    'Offline trust',
    'Tool-use boundary',
  ]),
  'hosted-credits': new Set([
    'Monthly and supplemental grants',
    'Anonymous allowances are scoped by network address',
    'An abuse control, not an identity claim',
    'Account summary',
    'Evidence is unchanged',
  ]),
  share: new Set([
    'Choose visibility',
    'Submit one finalized package',
    'Script-friendly output',
    'Admission checks',
    'Current consent boundary',
    'Exact package retention',
    'Retry behavior',
  ]),
};

const docNavigation = [
  { label: 'Start', pages: [['overview', 'Overview'], ['getting-started', 'Install options']] },
  { label: 'Understand', pages: [['how-it-works', 'Trust model'], ['hosted-credits', 'Credits and utilization'], ['trace-packages', 'Trace packages']] },
  { label: 'Share', pages: [['share', 'Share a session']] },
];
const docOrder = docNavigation.flatMap((group) => group.pages.map(([key]) => key));
const docAliases = {
  install: 'getting-started',
  proxy: 'getting-started',
  bundles: 'getting-started',
  captures: 'getting-started',
  providers: 'getting-started',
  credits: 'hosted-credits',
  plans: 'hosted-credits',
  harnesses: 'getting-started',
  finalize: 'trace-packages',
  artifacts: 'trace-packages',
  verify: 'trace-packages',
  publish: 'share',
};

function docHref(key, section) {
  const route = key === 'overview' ? '#/docs' : `#/docs/${key}`;
  return section ? `${route}?section=${encodeURIComponent(section)}` : route;
}

function docSlug(value) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
}

function docHeadingLevel(pageKey, block) {
  return docSubheadings[pageKey]?.has(block.heading) ? 3 : 2;
}

function getDocOutline(pageKey, blocks) {
  return blocks.reduce((items, block) => {
    if (docHeadingLevel(pageKey, block) === 3 && items.length) {
      items.at(-1).children.push(block);
    } else {
      items.push({ block, children: [] });
    }
    return items;
  }, []);
}

function getBlockText(block) {
  return [block.heading, block.body, block.code, block.note, ...(block.items || []), ...(block.steps || []).flatMap((step) => [step.title, step.body]), ...(block.cards || []).flatMap((card) => [card.meta, card.title, card.body]), ...(block.definitions || []).flatMap((item) => [item.term, item.description])].filter(Boolean).join(' ');
}

function copyToClipboard(value) {
  return navigator.clipboard?.writeText(value).catch(() => {});
}

function DocsInlineText({ children }) {
  return String(children).split('`').map((part, index) => index % 2
    ? <code className="docs-inline-code" key={`${part}-${index}`}>{part}</code>
    : part);
}

function DocsBlock({ block, pageKey }) {
  const Heading = docHeadingLevel(pageKey, block) === 3 ? 'h3' : 'h2';
  const slug = docSlug(block.heading);
  const headingLink = `${window.location.origin}${window.location.pathname}${docHref(pageKey, slug)}`;
  const [copied, setCopied] = useState(false);
  const copy = (value) => {
    copyToClipboard(value);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };
  return <section id={slug} className={`docs-section docs-section--level-${docHeadingLevel(pageKey, block)}`}><div className="docs-heading-row"><Heading>{block.heading}</Heading><button type="button" className="docs-copy-button docs-anchor" onClick={() => copy(headingLink)} aria-label={`${copied ? 'Copied link to' : 'Copy link to'} ${block.heading}`} title={copied ? 'Copied' : 'Copy link'}>{copied ? <CheckIcon /> : <LinkIcon />}</button></div>{block.body && <p><DocsInlineText>{block.body}</DocsInlineText></p>}{block.code && <div className="docs-code"><button type="button" className="docs-copy-button" onClick={() => copy(block.code)} aria-label={`Copy code for ${block.heading}`}>{copied ? 'Copied' : 'Copy'}</button><pre><code>{block.code}</code></pre></div>}{block.note && <aside className="docs-note"><DocsInlineText>{block.note}</DocsInlineText></aside>}{block.items && <ul className="docs-list">{block.items.map((item) => <li key={item}><DocsInlineText>{item}</DocsInlineText></li>)}</ul>}{block.steps && <ol className="docs-flow">{block.steps.map((step, index) => <li key={step.title}><span>{String(index + 1).padStart(2, '0')}</span><div><b>{step.title}</b><p><DocsInlineText>{step.body}</DocsInlineText></p></div></li>)}</ol>}{block.cards && <div className="docs-card-grid">{block.cards.map((card) => <article key={`${card.meta}-${card.title}`}><span>{card.meta}</span><h3>{card.title}</h3><p><DocsInlineText>{card.body}</DocsInlineText></p></article>)}</div>}{block.columns && <div className="docs-boundary-grid">{block.columns.map((column) => <article key={column.title}><h3>{column.title}</h3><ul>{column.items.map((item) => <li key={item}><DocsInlineText>{item}</DocsInlineText></li>)}</ul></article>)}</div>}{block.definitions && <dl className="docs-definitions">{block.definitions.map((item) => <div key={item.term}><dt>{item.term}</dt><dd><DocsInlineText>{item.description}</DocsInlineText></dd></div>)}</dl>}</section>;
}

function DocsOutline({ page, pageKey, section, onNavigate = undefined }) {
  const linkFor = (block) => docHref(pageKey, docSlug(block.heading));
  return <ol className="docs-toc-list">{getDocOutline(pageKey, page.blocks).map(({ block, children }) => <li key={block.heading}><a className={section === docSlug(block.heading) ? 'active' : ''} href={linkFor(block)} onClick={onNavigate} aria-current={section === docSlug(block.heading) ? 'location' : undefined}>{block.heading}</a>{children.length > 0 && <ol>{children.map((child) => <li key={child.heading}><a className={section === docSlug(child.heading) ? 'active' : ''} href={linkFor(child)} onClick={onNavigate} aria-current={section === docSlug(child.heading) ? 'location' : undefined}>{child.heading}</a></li>)}</ol>}</li>)}</ol>;
}

function DocsSearch({ open, onClose }) {
  const [query, setQuery] = useState('');
  const entries = useMemo(() => Object.entries(docPages).map(([key, page]) => ({ key, title: page.title, lead: page.lead, blocks: page.blocks, text: `${page.title} ${page.lead} ${page.blocks.map(getBlockText).join(' ')}`.toLowerCase() })), []);
  const results = useMemo(() => {
    const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
    if (!terms.length) return entries.slice(0, 7);
    return entries.filter((entry) => terms.every((term) => entry.text.includes(term))).slice(0, 10);
  }, [entries, query]);
  useEffect(() => { if (open) setQuery(''); }, [open]);
  const choose = (result) => { window.location.hash = docHref(result.key); onClose(); };
  return <CommandDialog open={open} onOpenChange={(nextOpen) => { if (!nextOpen) onClose(); }} title="Search documentation" description="Search setup, captures, providers, and sharing." className="docs-command-dialog"><Command shouldFilter={false} className="docs-command"><CommandInput value={query} onValueChange={setQuery} placeholder="Search setup, captures, providers…" /><CommandList><CommandEmpty>No documentation matches “{query}”.</CommandEmpty>{results.map((result) => <CommandItem value={result.key} onSelect={() => choose(result)} key={result.key}><span className="docs-command-copy"><b>{result.title}</b><small>{result.lead}</small></span></CommandItem>)}</CommandList><div className="docs-command-footer"><span>↑↓ navigate</span><span>↵ open</span><span>esc close</span></div></Command></CommandDialog>;
}

function DocsMobileToolbar({ currentKey, page, section, onSearch }) {
  const [panel, setPanel] = useState(null);
  const toolbarRef = useRef(null);
  const currentLabel = docNavigation.flatMap((group) => group.pages).find(([key]) => key === currentKey)?.[1] || page.title;
  useEffect(() => setPanel(null), [currentKey, section]);
  useEffect(() => {
    const close = (event) => {
      if (event.key === 'Escape' || (event.type === 'mousedown' && !toolbarRef.current?.contains(event.target))) setPanel(null);
    };
    document.addEventListener('mousedown', close);
    window.addEventListener('keydown', close);
    return () => {
      document.removeEventListener('mousedown', close);
      window.removeEventListener('keydown', close);
    };
  }, []);
  const toggle = (nextPanel) => setPanel((current) => current === nextPanel ? null : nextPanel);
  return <nav className="docs-mobile-toolbar" aria-label="Documentation navigation" ref={toolbarRef}>
    <button type="button" className="docs-search-trigger" onClick={() => { setPanel(null); onSearch(); }}>Search documentation <kbd>⌘ K</kbd></button>
    <div className="docs-mobile-toolbar-row">
      <button type="button" className={panel === 'docs' ? 'active' : ''} onClick={() => toggle('docs')} aria-expanded={panel === 'docs'} aria-controls="docs-mobile-panel"><span><small>Docs</small>{currentLabel}</span><ChevronDown aria-hidden="true" /></button>
      <button type="button" className={panel === 'toc' ? 'active' : ''} onClick={() => toggle('toc')} aria-expanded={panel === 'toc'} aria-controls="docs-mobile-panel"><span><small>Page</small>On this page</span><ChevronDown aria-hidden="true" /></button>
    </div>
    {panel && <div className="docs-mobile-panel" id="docs-mobile-panel">
      {panel === 'docs' ? docNavigation.map((group) => <div className="docs-mobile-nav-group" key={group.label}><span>{group.label}</span>{group.pages.map(([key, label]) => <a className={currentKey === key ? 'active' : ''} href={docHref(key)} aria-current={currentKey === key ? 'page' : undefined} onClick={() => setPanel(null)} key={key}>{label}</a>)}</div>) : <div className="docs-mobile-toc"><span>{page.title}</span><DocsOutline page={page} pageKey={currentKey} section={section} onNavigate={() => setPanel(null)} /></div>}
    </div>}
  </nav>;
}

function Docs({ pageKey, section }) {
  const currentKey = docPages[pageKey] ? pageKey : docAliases[pageKey] || 'overview';
  const page = docPages[currentKey];
  const currentIndex = docOrder.indexOf(currentKey);
  const previousKey = docOrder[currentIndex - 1];
  const nextKey = docOrder[currentIndex + 1];
  const next = nextKey ? { href: docHref(nextKey), label: docPages[nextKey].title } : null;
  const [searchOpen, setSearchOpen] = useState(false);
  useEffect(() => {
    window.requestAnimationFrame(() => {
      if (section) document.getElementById(section)?.scrollIntoView({ block: 'start' });
      else window.scrollTo({ top: 0, behavior: 'instant' });
    });
  }, [currentKey, section]);
  useEffect(() => {
    const handleShortcut = (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); setSearchOpen(true); }
      if (event.key === 'Escape') setSearchOpen(false);
      if (event.altKey && event.key === 'ArrowLeft' && previousKey) window.location.hash = docHref(previousKey);
      if (event.altKey && event.key === 'ArrowRight' && nextKey) window.location.hash = docHref(nextKey);
    };
    window.addEventListener('keydown', handleShortcut);
    return () => window.removeEventListener('keydown', handleShortcut);
  }, [nextKey, previousKey]);
  return <><DocsMobileToolbar currentKey={currentKey} page={page} section={section} onSearch={() => setSearchOpen(true)} /><main className="docs-shell"><aside className="docs-sidebar"><button type="button" className="docs-search-trigger" onClick={() => setSearchOpen(true)}>Search <kbd>⌘ K</kbd></button>{docNavigation.map((group) => <div className="docs-nav-group" key={group.label}><span className="docs-group">{group.label}</span>{group.pages.map(([key, label]) => <a className={currentKey === key ? 'active' : ''} href={docHref(key)} aria-current={currentKey === key ? 'page' : undefined} key={key}>{label}</a>)}</div>)}</aside><article className="docs-content"><h1>{page.title}</h1><p className="docs-lead">{page.lead}</p>{page.blocks.map((block) => <DocsBlock block={block} pageKey={currentKey} key={block.heading} />)}<div className="docs-page-nav">{previousKey ? <a href={docHref(previousKey)}><span>Previous</span>{docPages[previousKey].title}</a> : <span />}{next && <a href={next.href}><span>Next</span>{next.label}</a>}</div></article><aside className="docs-toc" aria-label="On this page"><span>On this page</span><DocsOutline page={page} pageKey={currentKey} section={section} /><p><kbd>⌥</kbd> <kbd>←</kbd><kbd>→</kbd> pages</p></aside></main><DocsSearch open={searchOpen} onClose={() => setSearchOpen(false)} /></>;
}

function formatTraceValue(value) {
  if (typeof value === 'boolean') return String(value);
  if (typeof value === 'number') return value.toLocaleString('en-US');
  if (typeof value === 'object') return JSON.stringify(value);
  return value;
}

function TraceField({ label, value }) {
  return <span className="trace-field"><b>{label}</b><code>{formatTraceValue(value)}</code></span>;
}

function MessagePart({ part }) {
  if (part.type === 'tool_call') {
    return <div className="message-part message-part--tool"><span>tool call</span><div className="trace-fields"><TraceField label="call ID" value={part.id} /><TraceField label="name" value={part.name} /><TraceField label="arguments" value={part.arguments} /></div></div>;
  }
  if (part.type === 'tool_call_response') {
    return <div className="message-part message-part--tool"><span>tool result</span><div className="trace-fields"><TraceField label="call ID" value={part.id} /><TraceField label="result" value={part.result} /></div></div>;
  }
  return <div className="message-part"><span>text</span><div className="message-markdown"><ReactMarkdown>{String(part.content ?? '')}</ReactMarkdown></div></div>;
}

function MessageGroup({ label, messages }) {
  return <div className="message-group"><span className="message-group-label">{label}</span>{messages.map((message, index) => <div className="trace-message" key={`${message.role}-${index}`}><span className="message-role">{message.role}</span><div>{message.parts.map((part, partIndex) => <MessagePart key={`${part.type}-${partIndex}`} part={part} />)}{message.finishReason && <span className="finish-reason">finish_reason: {message.finishReason}</span>}</div></div>)}</div>;
}

function SpanTree({ spans }) {
  const [expanded, setExpanded] = useState(() => new Set([0]));
  useEffect(() => setExpanded(new Set([0])), [spans]);
  const toggle = (index) => setExpanded((current) => {
    const next = new Set(current);
    if (next.has(index)) next.delete(index);
    else next.add(index);
    return next;
  });
  return <div className="span-tree" aria-label="Trace spans">{spans.map((span, index) => {
    const open = expanded.has(index);
    return <div className="span-row span-row--source" key={`${span.spanId}-${index}`}><button type="button" className="span-summary" aria-expanded={open} onClick={() => toggle(index)}><span className="span-branch" aria-hidden="true" /><span className="span-kind">{span.kind}</span><strong>{span.name}</strong><span className="span-disclosure" aria-hidden="true" /><small>span <code>{span.spanId}</code></small></button>{open && <>{span.attributes && <div className="span-evidence span-attributes"><span className="message-group-label">attributes</span><div className="trace-fields">{span.attributes.map(([name, value]) => <TraceField key={name} label={name} value={value} />)}</div></div>}{span.messages && <div className="span-evidence span-messages"><MessageGroup label="gen_ai.input.messages" messages={span.messages.input} /><MessageGroup label="gen_ai.output.messages" messages={span.messages.output} /></div>}</>}</div>;
  })}</div>;
}

function otlpAttributeValue(value = {}) {
  if ('stringValue' in value) return value.stringValue;
  if ('intValue' in value) return value.intValue;
  if ('doubleValue' in value) return value.doubleValue;
  if ('boolValue' in value) return value.boolValue;
  if (value.arrayValue?.values) return value.arrayValue.values.map(otlpAttributeValue);
  return '';
}

function parseTraceMessages(value) {
  if (typeof value !== 'string') return [];
  try {
    const messages = JSON.parse(value);
    return Array.isArray(messages) ? messages : [];
  } catch {
    return [];
  }
}

function parseSharedTrace(trace) {
  const spans = (trace?.resourceSpans || []).flatMap((resource) => (resource.scopeSpans || []).flatMap((scope) => scope.spans || []));
  return spans.map((span, index) => {
    const attributes = (span.attributes || []).map((attribute) => [attribute.key, otlpAttributeValue(attribute.value)]);
    const attributeMap = Object.fromEntries(attributes);
    return {
      kind: `CLIENT · ${String(index + 1).padStart(2, '0')}`,
      name: span.name || 'gen_ai.inference',
      spanId: span.spanId,
      attributes: attributes.filter(([key]) => key !== 'gen_ai.input.messages' && key !== 'gen_ai.output.messages'),
      messages: {
        input: parseTraceMessages(attributeMap['gen_ai.input.messages']),
        output: parseTraceMessages(attributeMap['gen_ai.output.messages']),
      },
    };
  });
}

function LibraryLoading() {
  return <main className="share-library share-library--loading" aria-busy="true"><header className="share-library-titlebar"><h1>Library</h1></header><div className="share-library-skeleton" role="status" aria-label="Loading the Library">{[1, 2, 3].map((row) => <div key={row}><i /><span><i /><i /></span></div>)}</div></main>;
}

function formatLibraryDate(unixMilliseconds) {
  if (!unixMilliseconds) return null;
  const date = new Date(unixMilliseconds);
  if (Number.isNaN(date.valueOf())) return null;
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }).format(date);
}

function LibraryShareRow({ share }) {
  const captureDate = formatLibraryDate(share.authenticated_at_unix_ms);
  const inputPreview = share.input_preview;
  const outputPreview = share.output_preview;
  return <a className="share-index-row" href={`/s/${encodeURIComponent(share.id)}`}>
    <header><div className="share-index-heading"><b>{share.model}</b><small><ProviderIdentity provider={share.provider} detail={`shared by ${share.publisher}`} />{captureDate && <time dateTime={new Date(share.authenticated_at_unix_ms).toISOString()}>{captureDate}</time>}</small></div><span className="share-index-open">Open trace</span></header>
    <div className="share-index-previews">
      {inputPreview && <p><span>Input</span>{inputPreview}</p>}
      {outputPreview && <p><span>Response</span>{outputPreview}</p>}
      {!inputPreview && !outputPreview && <p className="share-index-preview-missing">No prompt or response preview.</p>}
    </div>
  </a>;
}

export function Library({ loadShares = getListedShares }) {
  const [shares, setShares] = useState(null);
  const [loadingPage, setLoadingPage] = useState(true);
  const [nextCursor, setNextCursor] = useState(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [loadError, setLoadError] = useState('');
  const [query, setQuery] = useState('');
  const [provider, setProvider] = useState('All');
  const [reload, setReload] = useState(0);
  const requestGeneration = useRef(0);
  const normalizedQuery = query.trim();
  const queryIsNotIndexable = normalizedQuery.length > 0 && !/[\p{L}\p{N}]{3}/u.test(normalizedQuery);
  const changeQuery = (value) => {
    requestGeneration.current += 1;
    setLoadingMore(false);
    setNextCursor(null);
    setShares([]);
    setLoadingPage(true);
    setLoadError('');
    setQuery(value);
  };
  const changeProvider = (value) => {
    requestGeneration.current += 1;
    setLoadingMore(false);
    setNextCursor(null);
    setShares([]);
    setLoadingPage(true);
    setLoadError('');
    setProvider(value);
  };
  useEffect(() => {
    let cancelled = false;
    const generation = requestGeneration.current + 1;
    requestGeneration.current = generation;
    setLoadingMore(false);
    if (queryIsNotIndexable) {
      setLoadError('');
      setShares([]);
      setNextCursor(null);
      setLoadingPage(false);
      return () => { cancelled = true; };
    }
    setLoadingPage(true);
    const timeout = window.setTimeout(() => {
      setLoadError('');
      loadShares({ limit: 20, search: normalizedQuery || undefined, provider: provider === 'All' ? undefined : provider })
        .then((payload) => { if (!cancelled && generation === requestGeneration.current) { setShares(payload.items); setNextCursor(payload.next_cursor || null); setLoadingPage(false); } })
        .catch((error) => { if (!cancelled && generation === requestGeneration.current) { setShares(null); setLoadError(error instanceof Error ? error.message : 'Could not load the Library.'); setLoadingPage(false); } });
    }, 200);
    return () => { cancelled = true; window.clearTimeout(timeout); };
  }, [loadShares, normalizedQuery, provider, queryIsNotIndexable, reload]);
  const providers = ['All', ...new Set(['openai', 'anthropic', 'deepseek', 'openrouter', ...(shares || []).map((share) => share.provider)])];
  const loadMore = async () => {
    if (!nextCursor || loadingMore) return;
    const generation = requestGeneration.current;
    setLoadingMore(true);
    setLoadError('');
    try {
      const payload = await loadShares({ limit: 20, cursor: nextCursor, search: normalizedQuery || undefined, provider: provider === 'All' ? undefined : provider });
      if (generation !== requestGeneration.current) return;
      setShares((current) => [...(current || []), ...payload.items]);
      setNextCursor(payload.next_cursor || null);
    } catch (error) {
      if (generation === requestGeneration.current) setLoadError(error instanceof Error ? error.message : 'Could not load more traces.');
    } finally {
      if (generation === requestGeneration.current) setLoadingMore(false);
    }
  };
  if (shares === null && !loadError) return <LibraryLoading />;
  return <main className="share-library">
    <header className="share-library-titlebar"><h1>Library</h1></header>
    <section className="share-library-controls" aria-label="Browse public sessions">
      <label><span>Search</span><Input value={query} onChange={(event) => changeQuery(event.target.value)} placeholder="Search conversations or models" /></label>
      <Select value={provider} onValueChange={changeProvider}><SelectTrigger aria-label="Provider"><SelectValue /></SelectTrigger><SelectContent>{providers.map((value) => <SelectItem value={value} key={value}>{value === 'All' ? 'All providers' : <ProviderIdentity provider={value} />}</SelectItem>)}</SelectContent></Select>
      <span>{shares?.length || 0}{nextCursor ? '+' : ''} {(shares?.length || 0) === 1 ? 'trace' : 'traces'} shown</span>
    </section>
    {queryIsNotIndexable ? <section className="collection-empty"><b>Keep typing.</b><p>Search needs three letters or numbers together.</p></section> : loadingPage ? <div className="share-library-skeleton" role="status" aria-label="Loading filtered traces">{[1, 2, 3].map((row) => <div key={row}><i /><span><i /><i /></span></div>)}</div> : loadError && shares === null ? <section className="collection-empty" role="alert"><b>The Library couldn’t load.</b><p>{loadError}</p><button type="button" onClick={() => setReload((value) => value + 1)}>Try again</button></section> : shares.length ? <><section className="share-index" aria-label="Public traces">{shares.map((share) => <LibraryShareRow share={share} key={share.id} />)}</section>{loadError && <p className="library-page-error" role="alert">{loadError}</p>}{nextCursor && <button className="library-load-more" type="button" onClick={loadMore} disabled={loadingMore}>{loadingMore ? 'Loading…' : 'Load more traces'}</button>}</> : query || provider !== 'All' ? <section className="collection-empty"><b>Nothing matches.</b><p>Try a different search or provider.</p><button type="button" onClick={() => { requestGeneration.current += 1; setLoadingMore(false); setNextCursor(null); setShares([]); setLoadingPage(true); setLoadError(''); setQuery(''); setProvider('All'); }}>Clear filters</button></section> : <section className="collection-empty"><b>The Library is empty.</b><p>Public traces will appear here after they’re shared.</p><a href="#/docs/share">Learn how sharing works</a></section>}
  </main>;
}

function SharedPart({ part }) {
  if (part.type === 'tool_call' || part.type === 'tool_call_response') {
    const call = part.type === 'tool_call';
    return <details className="tool-attachment"><summary><span>{call ? 'Tool call' : 'Tool result'}</span><b>{call ? part.name || 'Unnamed tool' : part.id || 'Returned value'}</b><em>Show</em></summary><div>{part.id && <TraceField label="call ID" value={part.id} />}{call && <TraceField label="arguments" value={part.arguments} />}{!call && <TraceField label="result" value={part.result} />}</div></details>;
  }
  return <div className="shared-message-text"><ReactMarkdown>{String(part.content ?? '')}</ReactMarkdown></div>;
}

function SharedConversation({ spans }) {
  const turns = spans.flatMap((span, spanIndex) => [
    ...(span.messages?.input || []).map((message, messageIndex) => ({ ...message, key: `${spanIndex}-input-${messageIndex}` })),
    ...(span.messages?.output || []).map((message, messageIndex) => ({ ...message, key: `${spanIndex}-output-${messageIndex}` })),
  ]);
  if (!turns.length) return <p className="share-page-state">No messages were disclosed.</p>;
  return <div className="shared-conversation">{turns.map((message, index) => <article className={`shared-message shared-message--${message.role || 'unknown'}`} key={message.key}><aside><span>{String(index + 1).padStart(2, '0')}</span><b>{message.role || 'message'}</b></aside><div>{(message.parts || []).map((part, partIndex) => <SharedPart part={part} key={`${part.type}-${partIndex}`} />)}{message.finishReason && <small className="finish-reason">finish_reason: {message.finishReason}</small>}</div></article>)}</div>;
}

export function SharePage({ shareId, loadShare = getPublicShare, loadTrace = getSharedTrace }) {
  const [share, setShare] = useState(null);
  const [spans, setSpans] = useState(null);
  const [loadError, setLoadError] = useState('');
  useEffect(() => {
    let cancelled = false;
    setShare(null);
    setSpans(null);
    setLoadError('');
    Promise.all([loadShare(shareId), loadTrace(shareId)])
      .then(([detail, trace]) => {
        if (!cancelled) {
          setShare(detail);
          setSpans(parseSharedTrace(trace));
        }
      })
      .catch((error) => { if (!cancelled) setLoadError(error.message); });
    return () => { cancelled = true; };
  }, [loadShare, loadTrace, shareId]);
  useEffect(() => {
    if (!share) return undefined;
    document.title = `${share.model} · LLM Notary`;
    const existingRobots = document.head.querySelector('meta[name="robots"][data-share-page]');
    const robots = existingRobots instanceof HTMLMetaElement ? existingRobots : document.createElement('meta');
    if (!(existingRobots instanceof HTMLMetaElement)) {
      robots.name = 'robots';
      robots.dataset.sharePage = 'true';
      document.head.appendChild(robots);
    }
    robots.content = share.visibility === 'unlisted' ? 'noindex, nofollow, noarchive' : 'index, follow';
    return () => { robots?.remove(); document.title = 'LLM Notary'; };
  }, [share]);
  if (loadError) return <main className="share-page share-page-state" role="alert"><h1>Share unavailable</h1><p>{loadError}</p><a href="#/library">Open Library</a></main>;
  if (!share || spans === null) return <main className="share-page share-page-loading" aria-busy="true" aria-label="Loading shared trace">
    <header className="share-page-header"><div><i className="share-loading-title" /><i className="share-loading-meta" /></div><div className="share-verification-mark"><i aria-hidden="true" /><span><i /><i /></span></div></header>
    <div className="share-page-layout">
      <section className="share-transcript"><header><i className="share-loading-section" /><i className="share-loading-count" /></header><div className="shared-conversation">{[1, 2, 3].map((row) => <article className="shared-message" key={row}><aside><i /><i /></aside><div><i /><i /><i /></div></article>)}</div></section>
      <aside className="share-evidence-rail"><i className="share-loading-label" /><dl>{[1, 2, 3, 4].map((row) => <div key={row}><dt><i /></dt><dd><i /></dd></div>)}</dl><i className="share-loading-package" /></aside>
    </div>
  </main>;
  const authenticated = share.authenticated_at_unix_ms ? new Date(share.authenticated_at_unix_ms).toLocaleString() : 'Not recorded';
  const messageCount = spans.reduce((count, span) => count + (span.messages?.input?.length || 0) + (span.messages?.output?.length || 0), 0);
  return <main className="share-page">
    <header className="share-page-header"><div><h1>{share.model}</h1><p><b>{share.publisher}</b><span><ProviderIdentity provider={share.provider} /></span><span>{share.visibility}</span></p></div><div className="share-verification-mark"><i aria-hidden="true" /><span><b>Verified</b><small>Provider session</small></span></div></header>
    <div className="share-page-layout">
      <section className="share-transcript" aria-labelledby="shared-conversation-title"><header><h2 id="shared-conversation-title">Conversation</h2><span>{messageCount} {messageCount === 1 ? 'message' : 'messages'}</span></header><SharedConversation spans={spans} /></section>
      <aside className="share-evidence-rail"><span className="eyebrow">Verification</span><dl><div><dt>Provider</dt><dd><ProviderIdentity provider={share.provider} /></dd></div><div><dt>Host</dt><dd>{share.host}</dd></div><div><dt>Authenticated</dt><dd>{authenticated}</dd></div><div><dt>Visibility</dt><dd>{share.visibility}</dd></div></dl>
        {share.package_url ? <a className="share-package-download" href={share.package_url}><span>Package</span><b>Download .llmtrace</b><small>{fileSize(share.package_size_bytes || 0)} · SHA-256 included</small></a> : <p className="share-legacy-package">Exact package unavailable for this older share.</p>}
        <details className="share-technical"><summary>Hashes and notary</summary><dl><div><dt>Trace SHA-256</dt><dd><code>{share.trace_sha256}</code></dd></div>{share.package_sha256 && <div><dt>Package SHA-256</dt><dd><code>{share.package_sha256}</code></dd></div>}<div><dt>Notary key</dt><dd><code>{share.notary_key_id || 'Not recorded'}</code></dd></div><div><dt>Directory generation</dt><dd>{share.directory_generation ?? 'Not recorded'}</dd></div><div><dt>Safety contract</dt><dd><code>{share.public_package_safety_version || 'Legacy'}</code></dd></div></dl></details>
      </aside>
    </div>
  </main>;
}

function sessionDate(unixSeconds) {
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(unixSeconds * 1000));
}

function fileSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function shareStateLabel(state) {
  if (state === 'admitted') return { label: 'Admitted', tone: 'verified' };
  if (state === 'queued') return { label: 'Queued', tone: 'pending' };
  if (state === 'verifying') return { label: 'Verifying', tone: 'pending' };
  if (state === 'uploading') return { label: 'Uploading', tone: 'pending' };
  if (state === 'rejected') return { label: 'Rejected', tone: 'attention' };
  if (state === 'expired') return { label: 'Expired', tone: 'attention' };
  if (state === 'failed') return { label: 'Failed', tone: 'attention' };
  return { label: state, tone: 'neutral' };
}

const apiKeyScopeOptions = [
  ['account:read', 'Read account identity'],
  ['notary:admit', 'Request hosted notary admission'],
  ['publish:read', 'Read owned publication status'],
  ['publish:write', 'Create and complete publications'],
];

function apiKeyState(apiKey) {
  if (apiKey.revoked_at) return 'Revoked';
  if (apiKey.expires_at && apiKey.expires_at <= Math.floor(Date.now() / 1000)) return 'Expired';
  return 'Active';
}

export function ApiKeysPanel({ loadKeys = getApiKeys, createKey = createApiKey, revokeKey = revokeApiKey }) {
  const [apiKeys, setApiKeys] = useState(null);
  const [nextCursor, setNextCursor] = useState(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [name, setName] = useState('');
  const [scopes, setScopes] = useState(apiKeyScopeOptions.map(([scope]) => scope));
  const [expiresOn, setExpiresOn] = useState('');
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState(null);
  const [copied, setCopied] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState(null);
  const [revoking, setRevoking] = useState(false);

  useEffect(() => {
    let cancelled = false;
    loadKeys({ limit: 20 })
      .then((page) => { if (!cancelled) { setApiKeys(page.items); setNextCursor(page.next_cursor || null); } })
      .catch((reason) => { if (!cancelled) setError(reason.message); });
    return () => { cancelled = true; };
  }, [loadKeys]);

  const closeDialog = (open) => {
    if (!open && creating) return;
    setDialogOpen(open);
    if (!open) {
      setCreated(null);
      setCopied(false);
      setName('');
      setScopes(apiKeyScopeOptions.map(([scope]) => scope));
      setExpiresOn('');
    }
  };
  const toggleScope = (scope) => setScopes((current) => current.includes(scope)
    ? current.filter((value) => value !== scope)
    : [...current, scope]);
  const create = async (event) => {
    event.preventDefault();
    setCreating(true);
    setError(null);
    try {
      const expiresAt = expiresOn
        ? Math.floor(new Date(`${expiresOn}T23:59:59`).getTime() / 1000)
        : null;
      const response = await createKey({ name, scopes, expires_at: expiresAt });
      setCreated(response);
      setApiKeys((current) => [response.api_key, ...(current || [])]);
    } catch (reason) {
      setError(reason.message);
    } finally {
      setCreating(false);
    }
  };
  const copySecret = async () => {
    await navigator.clipboard.writeText(created.secret);
    setCopied(true);
  };
  const revoke = async () => {
    setRevoking(true);
    setError(null);
    try {
      await revokeKey(revokeTarget.id);
      const revokedAt = Math.floor(Date.now() / 1000);
      setApiKeys((current) => current.map((key) => key.id === revokeTarget.id ? { ...key, revoked_at: key.revoked_at || revokedAt } : key));
    } catch (reason) {
      setError(reason.message);
    } finally {
      setRevoking(false);
      setRevokeTarget(null);
    }
  };
  const loadMore = async () => {
    if (!nextCursor || loadingMore) return;
    setLoadingMore(true);
    setError(null);
    try {
      const page = await loadKeys({ limit: 20, cursor: nextCursor });
      setApiKeys((current) => [...(current || []), ...page.items]);
      setNextCursor(page.next_cursor || null);
    } catch (reason) {
      setError(reason.message);
    } finally {
      setLoadingMore(false);
    }
  };

  return <section className="dashboard-api-keys" aria-labelledby="api-keys-title">
    <header><div><span className="eyebrow">Automation access</span><h2 id="api-keys-title">API keys</h2></div><button type="button" onClick={() => setDialogOpen(true)}>Create API key</button></header>
    {error && <p className="dashboard-session-error" role="alert">{error}</p>}
    {apiKeys === null && !error ? <p className="dashboard-session-empty">Loading API keys…</p> : apiKeys?.length ? <><div className="dashboard-api-key-list">{apiKeys.map((apiKey) => <article key={apiKey.id} className={apiKeyState(apiKey).toLowerCase()}><div className="dashboard-api-key-copy"><div><b>{apiKey.name}</b><span className="dashboard-api-key-state"><i aria-hidden="true" />{apiKeyState(apiKey)}</span></div><code>{apiKey.prefix}</code><span>{apiKey.scopes.join(' · ')}</span><small>Created {sessionDate(apiKey.created_at)} · Last used {apiKey.last_used_at ? sessionDate(apiKey.last_used_at) : 'Never'} · Expires {apiKey.expires_at ? sessionDate(apiKey.expires_at) : 'Never'}</small></div>{!apiKey.revoked_at && <button type="button" onClick={() => setRevokeTarget(apiKey)}>Revoke</button>}</article>)}</div>{nextCursor && <button className="dashboard-load-more" type="button" onClick={loadMore} disabled={loadingMore}>{loadingMore ? 'Loading…' : 'Load more API keys'}</button>}</> : <div className="dashboard-api-key-empty"><b>No API keys</b><p>Create a scoped key for CI, cron jobs, or another unattended host.</p></div>}

    <Dialog open={dialogOpen} onOpenChange={closeDialog}><DialogContent className="axis-api-key-dialog" showCloseButton={!creating}><DialogHeader><DialogTitle>{created ? 'Copy this API key now' : 'Create API key'}</DialogTitle><DialogDescription>{created ? 'The complete key is shown once. Store it in your CI or service secret manager before closing.' : 'Choose only the access this automation needs. The key remains valid until it expires or you revoke it.'}</DialogDescription></DialogHeader>{created ? <div className="api-key-receipt"><span className="eyebrow">API key</span><code>{created.secret}</code><button type="button" onClick={copySecret}>{copied ? 'Copied' : 'Copy API key'}</button></div> : <form id="create-api-key-form" className="api-key-form" onSubmit={create}><label><span>Name</span><Input value={name} onChange={(event) => setName(event.target.value)} maxLength={100} required placeholder="GitHub Actions release" /></label><fieldset><legend>Scopes</legend>{apiKeyScopeOptions.map(([scope, description]) => <label key={scope}><input type="checkbox" checked={scopes.includes(scope)} onChange={() => toggleScope(scope)} /><span><code>{scope}</code><small>{description}</small></span></label>)}</fieldset><label><span>Expiration</span><Input type="date" value={expiresOn} min={new Date(Date.now() + 86400000).toISOString().slice(0, 10)} onChange={(event) => setExpiresOn(event.target.value)} /><small>Leave blank to never expire.</small></label></form>}<DialogFooter>{created ? <button type="button" className="api-key-primary" onClick={() => closeDialog(false)}>I stored the key</button> : <><button type="button" className="api-key-secondary" onClick={() => closeDialog(false)} disabled={creating}>Cancel</button><button type="submit" form="create-api-key-form" className="api-key-primary" disabled={creating || !name.trim() || !scopes.length}>{creating ? 'Creating…' : 'Create API key'}</button></>}</DialogFooter></DialogContent></Dialog>
    <AlertDialog open={Boolean(revokeTarget)} onOpenChange={(open) => { if (!open && !revoking) setRevokeTarget(null); }}><AlertDialogContent className="axis-alert-dialog"><AlertDialogHeader><AlertDialogTitle>Revoke {revokeTarget?.name}?</AlertDialogTitle><AlertDialogDescription>Requests using this key will be rejected immediately. This action does not affect other keys or connected devices.</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel disabled={revoking}>Keep key</AlertDialogCancel><AlertDialogAction disabled={revoking} onClick={revoke}>{revoking ? 'Revoking…' : 'Revoke API key'}</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>
  </section>;
}

export function AccountSettings({ theme, onThemeChange }) {
  return <section className="dashboard-account-settings" aria-labelledby="account-settings-title">
    <header><span className="eyebrow">Preferences</span><h2 id="account-settings-title">Account settings</h2></header>
    <div className="dashboard-account-setting">
      <div><b>Appearance</b><span>Use your device setting, or choose a theme for this browser.</span></div>
      <div className="dashboard-appearance-options" role="radiogroup" aria-label="Appearance">{themeOptions.map((option) => <button type="button" role="radio" aria-checked={theme === option} onClick={() => onThemeChange(option)} key={option}>{option}</button>)}</div>
    </div>
  </section>;
}

export function DeleteAccountPanel({ identifier, onDeleted, deleteAccount = deleteCurrentAccount }) {
  const [open, setOpen] = useState(false);
  const [confirmation, setConfirmation] = useState('');
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState('');
  const close = (nextOpen) => {
    if (deleting) return;
    setOpen(nextOpen);
    if (!nextOpen) {
      setConfirmation('');
      setError('');
    }
  };
  const remove = async (event) => {
    event.preventDefault();
    if (confirmation !== identifier || deleting) return;
    setDeleting(true);
    setError('');
    try {
      await deleteAccount();
      onDeleted();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Could not delete the account.');
      setDeleting(false);
    }
  };
  return <section className="dashboard-delete-account" aria-labelledby="delete-account-title">
    <div><span className="eyebrow">Account deletion</span><h2 id="delete-account-title">Delete account</h2><p>Delete this account and its API keys, devices, credits, traces, and packages.</p></div>
    <button type="button" onClick={() => setOpen(true)}>Delete account</button>
    <AlertDialog open={open} onOpenChange={close}><AlertDialogContent className="axis-alert-dialog axis-delete-account-dialog"><AlertDialogHeader><AlertDialogTitle>Delete {identifier}?</AlertDialogTitle><AlertDialogDescription>This deletes the account, API keys, devices, trace links, and packages. You cannot undo it.</AlertDialogDescription></AlertDialogHeader><form id="delete-account-form" className="delete-account-form" onSubmit={remove}><label htmlFor="delete-account-confirmation">Type <b>{identifier}</b> to confirm.</label><Input id="delete-account-confirmation" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} autoComplete="off" disabled={deleting} />{error && <p role="alert">{error}</p>}</form><AlertDialogFooter><AlertDialogCancel disabled={deleting}>Keep account</AlertDialogCancel><AlertDialogAction type="button" disabled={confirmation !== identifier || deleting} onClick={remove}>{deleting ? 'Deleting…' : 'Delete account'}</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>
  </section>;
}

function CreditUtilizationFallback() {
  return <section className="dashboard-utilization dashboard-utilization--loading" role="status" aria-label="Loading utilization">
    <header><div><span className="eyebrow">Current allocation</span><h2>Utilization</h2></div><i /></header>
    <div className="dashboard-utilization-plot"><i /></div>
    <dl><div><dt><i />Used</dt><dd><i /></dd></div><div><dt><i />Available</dt><dd><i /></dd></div></dl>
  </section>;
}

const dashboardSections = [
  { key: 'overview', label: 'Overview', href: '#/dashboard' },
  { key: 'traces', label: 'Traces', href: '#/dashboard/traces' },
  { key: 'credits', label: 'Credits', href: '#/dashboard/credits' },
  { key: 'settings', label: 'Settings', href: '#/dashboard/settings' },
];

const checkoutReturnMessages = {
  waiting: 'Payment received. Waiting for Stripe confirmation…',
  paid: 'Payment confirmed. Your credits are ready.',
  failed: 'Payment was not completed. No credits were added.',
  refunded: 'This payment was refunded. Its purchased credits are no longer available.',
  disputed: 'This payment is under dispute. Its purchased credits are temporarily unavailable.',
  timeout: 'We could not confirm the payment yet. Check purchase history or refresh this page.',
};

function DashboardMobileNavigation({ activeView, traceCount }) {
  const [open, setOpen] = useState(false);
  const navigationRef = useRef(null);
  const currentLabel = dashboardSections.find(({ key }) => key === activeView)?.label || 'Overview';
  useEffect(() => setOpen(false), [activeView]);
  useEffect(() => {
    const close = (event) => {
      if (event.key === 'Escape' || (event.type === 'mousedown' && !navigationRef.current?.contains(event.target))) setOpen(false);
    };
    document.addEventListener('mousedown', close);
    window.addEventListener('keydown', close);
    return () => {
      document.removeEventListener('mousedown', close);
      window.removeEventListener('keydown', close);
    };
  }, []);
  return <nav className="dashboard-mobile-toolbar" aria-label="Dashboard navigation" ref={navigationRef}>
    <button type="button" className={open ? 'active' : ''} onClick={() => setOpen((current) => !current)} aria-label={`Dashboard menu: ${currentLabel}`} aria-expanded={open} aria-controls="dashboard-mobile-panel">
      <span><small>Dashboard</small>{currentLabel}</span><ChevronDown aria-hidden="true" />
    </button>
    {open && <div className="dashboard-mobile-panel" id="dashboard-mobile-panel"><span>Account</span>{dashboardSections.map(({ key, label, href }) => <a className={activeView === key ? 'active' : ''} href={href} aria-current={activeView === key ? 'page' : undefined} onClick={() => setOpen(false)} key={key}><span>{label}</span>{key === 'traces' && <small>{traceCount}</small>}</a>)}</div>}
  </nav>;
}

export function Dashboard({
  user,
  view,
  theme,
  onThemeChange,
  onAccountDeleted,
  loadCliSessions = getCliSessions,
  loadMyShares = getMyShares,
  loadCreditOffers = getCreditOffers,
  loadCreditHistory = getCreditHistory,
  loadBillingPurchases = getBillingPurchases,
  loadBillingPurchase = getBillingPurchase,
  startCheckout = createCheckoutSession,
  openCheckout = (url) => window.location.assign(url),
  loadCurrentUser = getCurrentUser,
  claimOfferRequest = claimCreditOffer,
  route = '',
  checkoutPollBaseDelay = 1_000,
  checkoutPollMaxAttempts = 8,
}) {
  const [sessions, setSessions] = useState(null);
  const [sessionCursor, setSessionCursor] = useState(null);
  const [loadingMoreSessions, setLoadingMoreSessions] = useState(false);
  const [sessionError, setSessionError] = useState(null);
  const [revoking, setRevoking] = useState(null);
  const [revokeTarget, setRevokeTarget] = useState(null);
  const [shares, setShares] = useState(null);
  const [shareCursor, setShareCursor] = useState(null);
  const [loadingMoreShares, setLoadingMoreShares] = useState(false);
  const [shareError, setShareError] = useState(null);
  const [credits, setCredits] = useState(user.credits);
  const [creditOffers, setCreditOffers] = useState(null);
  const [creditError, setCreditError] = useState(null);
  const [claimingOffer, setClaimingOffer] = useState(null);
  const [creditHistory, setCreditHistory] = useState(null);
  const [creditHistoryCursor, setCreditHistoryCursor] = useState(null);
  const [loadingMoreCreditHistory, setLoadingMoreCreditHistory] = useState(false);
  const [billing, setBilling] = useState(user.billing || { service_plan: 'free', billing_status: 'active', purchase_mode: 'disabled' });
  const [purchases, setPurchases] = useState(null);
  const [purchaseError, setPurchaseError] = useState(null);
  const [checkoutReturnStatus, setCheckoutReturnStatus] = useState(null);
  const [quantityGb, setQuantityGb] = useState(5);
  const [checkoutAttemptKey, setCheckoutAttemptKey] = useState(null);
  const [startingCheckout, setStartingCheckout] = useState(false);
  const creditHistoryGeneration = useRef(0);
  const purchaseListGeneration = useRef(0);
  const checkoutQuery = useMemo(() => new URLSearchParams(route.split('?')[1] || ''), [route]);
  const returnedCheckout = checkoutQuery.get('checkout');
  const returnedPurchaseId = checkoutQuery.get('purchase_id');

  useEffect(() => {
    let cancelled = false;
    loadCliSessions({ limit: 20 })
      .then((page) => { if (!cancelled) { setSessions(page.items); setSessionCursor(page.next_cursor || null); } })
      .catch((reason) => { if (!cancelled) setSessionError(reason.message); });
    return () => { cancelled = true; };
  }, [loadCliSessions]);

  useEffect(() => {
    let cancelled = false;
    const generation = creditHistoryGeneration.current + 1;
    creditHistoryGeneration.current = generation;
    loadCreditHistory({ limit: 20 })
      .then((page) => { if (!cancelled && generation === creditHistoryGeneration.current) { setCreditHistory(page.items); setCreditHistoryCursor(page.next_cursor || null); } })
      .catch((reason) => { if (!cancelled && generation === creditHistoryGeneration.current) setCreditError(reason.message); });
    return () => { cancelled = true; };
  }, [loadCreditHistory]);

  useEffect(() => {
    let cancelled = false;
    const generation = purchaseListGeneration.current;
    loadBillingPurchases()
      .then((items) => { if (!cancelled && generation === purchaseListGeneration.current) setPurchases(items); })
      .catch((reason) => { if (!cancelled && generation === purchaseListGeneration.current) setPurchaseError(reason.message); });
    return () => { cancelled = true; };
  }, [loadBillingPurchases]);

  useEffect(() => {
    if (returnedCheckout !== 'success' || !returnedPurchaseId) {
      setCheckoutReturnStatus(returnedCheckout === 'cancelled' ? 'cancelled' : null);
      return undefined;
    }
    let cancelled = false;
    let timer;
    let attempts = 0;
    setCheckoutReturnStatus('waiting');
    const scheduleNext = (poll) => {
      if (attempts >= checkoutPollMaxAttempts) {
        setCheckoutReturnStatus('timeout');
        return;
      }
      const delay = Math.min(checkoutPollBaseDelay * (2 ** Math.min(attempts - 1, 3)), 5_000);
      timer = window.setTimeout(poll, delay);
    };
    const poll = async () => {
      attempts += 1;
      try {
        const purchase = await loadBillingPurchase(returnedPurchaseId);
        if (cancelled) return;
        setPurchaseError(null);
        purchaseListGeneration.current += 1;
        setPurchases((current) => [purchase, ...(current || []).filter((item) => item.id !== purchase.id)]);
        if (['paid', 'refunded', 'disputed', 'failed'].includes(purchase.state)) {
          setCheckoutReturnStatus(purchase.state);
          try {
            const account = await loadCurrentUser();
            if (!cancelled && account) {
              setCredits(account.credits);
              setBilling(account.billing);
              const generation = creditHistoryGeneration.current + 1;
              creditHistoryGeneration.current = generation;
              const history = await loadCreditHistory({ limit: 20 });
              if (!cancelled && generation === creditHistoryGeneration.current) {
                setCreditHistory(history.items);
                setCreditHistoryCursor(history.next_cursor || null);
              }
            }
          } catch (reason) {
            if (!cancelled) setPurchaseError(reason.message);
          }
          return;
        }
        scheduleNext(poll);
      } catch (reason) {
        if (cancelled) return;
        if (attempts >= checkoutPollMaxAttempts) {
          setCheckoutReturnStatus('timeout');
          setPurchaseError(`Stripe confirmation could not be refreshed: ${reason.message}`);
        } else {
          scheduleNext(poll);
        }
      }
    };
    void poll();
    return () => { cancelled = true; if (timer) window.clearTimeout(timer); };
  }, [checkoutPollBaseDelay, checkoutPollMaxAttempts, loadBillingPurchase, loadCreditHistory, loadCurrentUser, returnedCheckout, returnedPurchaseId]);

  useEffect(() => {
    let cancelled = false;
    loadCreditOffers()
      .then((offers) => { if (!cancelled) setCreditOffers(offers); })
      .catch((reason) => { if (!cancelled) setCreditError(reason.message); });
    return () => { cancelled = true; };
  }, [loadCreditOffers]);

  useEffect(() => {
    if (!revokeTarget) return undefined;
    const closeOnEscape = (event) => { if (event.key === 'Escape' && revoking !== revokeTarget.id) setRevokeTarget(null); };
    window.addEventListener('keydown', closeOnEscape);
    return () => window.removeEventListener('keydown', closeOnEscape);
  }, [revokeTarget, revoking]);

  useEffect(() => {
    let cancelled = false;
    loadMyShares({ limit: 20 })
      .then((page) => { if (!cancelled) { setShares(page.items); setShareCursor(page.next_cursor || null); } })
      .catch((reason) => { if (!cancelled) setShareError(reason.message); });
    return () => { cancelled = true; };
  }, [loadMyShares]);

  const revoke = async (session) => {
    setRevoking(session.id);
    setSessionError(null);
    try {
      await revokeCliSession(session.id);
      setSessions((current) => current?.filter((item) => item.id !== session.id) || []);
    } catch (reason) {
      setSessionError(reason.message);
    } finally {
      setRevoking(null);
      setRevokeTarget(null);
    }
  };

  const claimOffer = async (offer) => {
    let refreshGeneration = null;
    setClaimingOffer(offer.id);
    setCreditError(null);
    try {
      const response = await claimOfferRequest(offer.id);
      setCredits(response.credits);
      setCreditOffers((current) => current?.filter((item) => item.id !== offer.id) || []);
      refreshGeneration = creditHistoryGeneration.current + 1;
      creditHistoryGeneration.current = refreshGeneration;
      setLoadingMoreCreditHistory(true);
      const historyPage = await loadCreditHistory({ limit: 20 });
      if (refreshGeneration === creditHistoryGeneration.current) {
        setCreditHistory(historyPage.items);
        setCreditHistoryCursor(historyPage.next_cursor || null);
      }
    } catch (reason) {
      setCreditError(reason.message);
    } finally {
      if (refreshGeneration === creditHistoryGeneration.current) setLoadingMoreCreditHistory(false);
      setClaimingOffer(null);
    }
  };

  const buyCredits = async () => {
    if (!['test', 'live'].includes(billing.purchase_mode)) return;
    const attemptKey = checkoutAttemptKey || globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    setCheckoutAttemptKey(attemptKey);
    setStartingCheckout(true);
    setPurchaseError(null);
    try {
      const response = await startCheckout(quantityGb, attemptKey);
      openCheckout(response.checkout_url);
    } catch (reason) {
      setPurchaseError(reason.message);
      setStartingCheckout(false);
    }
  };

  const loadMoreSessions = async () => {
    if (!sessionCursor || loadingMoreSessions) return;
    setLoadingMoreSessions(true);
    try {
      const page = await getCliSessions({ limit: 20, cursor: sessionCursor });
      setSessions((current) => [...(current || []), ...page.items]);
      setSessionCursor(page.next_cursor || null);
    } catch (reason) {
      setSessionError(reason.message);
    } finally {
      setLoadingMoreSessions(false);
    }
  };
  const loadMoreShares = async () => {
    if (!shareCursor || loadingMoreShares) return;
    setLoadingMoreShares(true);
    try {
      const page = await getMyShares({ limit: 20, cursor: shareCursor });
      setShares((current) => [...(current || []), ...page.items]);
      setShareCursor(page.next_cursor || null);
    } catch (reason) {
      setShareError(reason.message);
    } finally {
      setLoadingMoreShares(false);
    }
  };
  const loadMoreCreditHistory = async () => {
    if (!creditHistoryCursor || loadingMoreCreditHistory) return;
    const generation = creditHistoryGeneration.current;
    setLoadingMoreCreditHistory(true);
    try {
      const page = await loadCreditHistory({ limit: 20, cursor: creditHistoryCursor });
      if (generation !== creditHistoryGeneration.current) return;
      setCreditHistory((current) => [...(current || []), ...page.items]);
      setCreditHistoryCursor(page.next_cursor || null);
    } catch (reason) {
      if (generation === creditHistoryGeneration.current) setCreditError(reason.message);
    } finally {
      if (generation === creditHistoryGeneration.current) setLoadingMoreCreditHistory(false);
    }
  };

  const admittedCount = user.share_stats?.admitted ?? 0;
  const activeCount = user.share_stats?.in_progress ?? 0;
  const activeView = view === 'shares' ? 'traces' : ['overview', 'traces', 'credits', 'settings'].includes(view) ? view : 'overview';
  const purchaseMode = billing.purchase_mode || 'disabled';
  const checkoutEnabled = purchaseMode === 'test' || purchaseMode === 'live';
  const displayedCheckoutStatus = checkoutReturnStatus || (returnedCheckout === 'success' ? 'waiting' : returnedCheckout === 'cancelled' ? 'cancelled' : null);

  return <main className="dashboard-shell dashboard-shell--account">
    <DashboardMobileNavigation activeView={activeView} traceCount={user.share_stats?.total ?? '—'} />
    <div className="dashboard-layout">
      <aside className="dashboard-sidebar" aria-label="Dashboard navigation">
        <nav>
          <a className={activeView === 'overview' ? 'active' : ''} href="#/dashboard" aria-current={activeView === 'overview' ? 'page' : undefined}><span>Overview</span></a>
          <a className={activeView === 'traces' ? 'active' : ''} href="#/dashboard/traces" aria-current={activeView === 'traces' ? 'page' : undefined}><span>Traces</span><small>{user.share_stats?.total ?? '—'}</small></a>
          <a className={activeView === 'credits' ? 'active' : ''} href="#/dashboard/credits" aria-current={activeView === 'credits' ? 'page' : undefined}><span>Credits</span></a>
          <a className={activeView === 'settings' ? 'active' : ''} href="#/dashboard/settings" aria-current={activeView === 'settings' ? 'page' : undefined}><span>Settings</span></a>
        </nav>
      </aside>
      <div className="dashboard-page">
        {activeView === 'overview' && <>
          <header className="dashboard-page-header"><span className="eyebrow">Account</span><h1>Overview</h1><p>Account details, trace activity, and credit use.</p></header>
          <div className="dashboard-summary">
            <div><span>{authProviderName(user)} account</span><b>{accountIdentifier(user)}</b></div>
            <div><span>Admitted traces</span><b>{shares === null ? '—' : admittedCount}</b></div>
            <div><span>In progress</span><b>{shares === null ? '—' : activeCount}</b></div>
          </div>
          {credits && <Suspense fallback={<CreditUtilizationFallback />}><CreditUtilizationChart credits={credits} formatBytes={fileSize} /></Suspense>}
        </>}
        {activeView === 'credits' && <>
          <header className="dashboard-page-header"><span className="eyebrow">Usage</span><h1>Credits</h1><p>See what you’ve used, what remains, and when credits expire.</p></header>
          {credits && <section className="dashboard-credits" aria-labelledby="credit-balance-title">
            <header><div><span className="eyebrow">Utilization</span><h2 id="credit-balance-title">{fileSize(credits.total_remaining_bytes)} available</h2></div><div className="dashboard-credit-meta"><span>{billing.service_plan} plan · {billing.billing_status}</span><span>Resets {sessionDate(credits.reset_at)}</span></div></header>
            <p className="dashboard-credit-note">Included credits reset monthly. Purchased credits are added separately and do not expire.</p>
            <div className="dashboard-credit-ledger" aria-label="Credit balance breakdown"><div><span>Included this month</span><b>{fileSize(credits.included_monthly_remaining_bytes)}</b></div><div><span>Additional credits</span><b>{fileSize(credits.supplemental_remaining_bytes)}</b></div><div><span>Next expiration</span><b>{credits.next_grant_expiration ? sessionDate(credits.next_grant_expiration) : 'None'}</b></div></div>
            {creditError && <p className="dashboard-session-error" role="alert">{creditError}</p>}
            {creditOffers?.map((offer) => <article className="dashboard-credit-offer" key={offer.id}><div><span className="eyebrow">Available offer</span><b>{offer.title}</b><p>{offer.description} Claim by {sessionDate(offer.claim_expires_at)}.</p></div><button type="button" onClick={() => claimOffer(offer)} disabled={claimingOffer === offer.id}>{claimingOffer === offer.id ? 'Claiming…' : `Claim ${fileSize(offer.amount_bytes)}`}</button></article>)}
            {checkoutEnabled ? <section className="dashboard-credit-purchase" aria-labelledby="buy-credit-title">
              <div className="dashboard-credit-purchase-copy"><span className="eyebrow">Additional credits · $5 per GB</span><h3 id="buy-credit-title">Buy {quantityGb} GB</h3>{purchaseMode === 'test' && <strong className="dashboard-billing-mode" role="status">Stripe test mode · no real charges</strong>}<p>{purchaseMode === 'test' ? `$${quantityGb * 5}.00 USD test purchase · use a Stripe test card` : `$${quantityGb * 5}.00 USD · one-time payment through Stripe`}</p></div>
              <div className="dashboard-credit-quantity" role="group" aria-label="Credit quantity">{[1, 5, 10, 20].map((quantity) => <button key={quantity} type="button" aria-label={`${quantity} GB`} aria-pressed={quantityGb === quantity} onClick={() => { setQuantityGb(quantity); setCheckoutAttemptKey(null); }}>{quantity}<small aria-hidden="true">GB</small></button>)}</div>
              <button className="dashboard-credit-buy" type="button" onClick={buyCredits} disabled={startingCheckout}>{startingCheckout ? 'Opening Checkout…' : purchaseMode === 'test' ? `Open test Checkout · ${quantityGb} GB for $${quantityGb * 5}` : `Buy ${quantityGb} GB for $${quantityGb * 5}`}</button>
            </section> : <section className="dashboard-credit-purchase dashboard-credit-purchase--disabled" aria-labelledby="buy-credit-title"><div className="dashboard-credit-purchase-copy"><span className="eyebrow">Additional credits</span><h3 id="buy-credit-title">Purchases unavailable</h3><p>Hosted credit purchases are not configured for this service.</p></div></section>}
            {displayedCheckoutStatus === 'cancelled' && <p className="dashboard-checkout-state">Checkout was cancelled. No credits were added.</p>}
            {checkoutReturnMessages[displayedCheckoutStatus] && <p className="dashboard-checkout-state" role="status">{checkoutReturnMessages[displayedCheckoutStatus]}</p>}
            {purchaseError && <p className="dashboard-session-error" role="alert">{purchaseError}</p>}
            <div className="dashboard-purchase-history"><h3>Purchases</h3>{purchases === null && !purchaseError ? <p>Loading purchases…</p> : purchases?.length ? purchases.map((purchase) => <div key={purchase.id}><span className={`dashboard-purchase-state dashboard-purchase-state--${purchase.state}`}><i aria-hidden="true" />{purchase.state.replaceAll('_', ' ')}</span><b>{purchase.quantity_gb} GB · ${(purchase.amount_cents / 100).toFixed(2)}</b><time>{sessionDate(purchase.created_at)}</time></div>) : <p>No credit purchases yet.</p>}</div>
            {creditHistory?.length > 0 && <div className="dashboard-credit-history"><h3>Credit activity</h3>{creditHistory.map((entry) => { const addsCredit = entry.kind === 'grant' || (entry.kind === 'adjustment' && entry.amount_bytes > 0); return <div key={`${entry.kind}-${entry.id}`}><span className={`dashboard-credit-sign dashboard-credit-sign--${entry.kind}`}>{addsCredit ? '+' : '−'}{fileSize(Math.abs(entry.amount_bytes))}</span><span>{entry.display_label}</span><time>{sessionDate(entry.created_at)}</time></div>; })}{creditHistoryCursor && <button className="dashboard-load-more" type="button" onClick={loadMoreCreditHistory} disabled={loadingMoreCreditHistory}>{loadingMoreCreditHistory ? 'Loading…' : 'Load older activity'}</button>}</div>}
          </section>}
        </>}
        {activeView === 'settings' && <>
          <header className="dashboard-page-header"><span className="eyebrow">Account</span><h1>Settings</h1><p>Manage appearance, API keys, connected devices, and account deletion.</p></header>
          <AccountSettings theme={theme} onThemeChange={onThemeChange} />
          <ApiKeysPanel />
          <section className="dashboard-sessions" aria-labelledby="connected-services-title"><header><div><span className="eyebrow">Local service access</span><h2 id="connected-services-title">Connected devices</h2></div></header>{sessionError && <p className="dashboard-session-error" role="alert">{sessionError}</p>}{sessions === null && !sessionError ? <p className="dashboard-session-empty">Loading connected devices…</p> : sessions?.length ? <><div className="dashboard-session-list">{sessions.map((session) => <article key={session.id}><div><b>{session.device_name}</b><span>Created {sessionDate(session.created_at)} · Last used {sessionDate(session.last_used_at)} · Expires {sessionDate(session.expires_at)}</span></div><button type="button" onClick={() => setRevokeTarget(session)} disabled={revoking === session.id}>{revoking === session.id ? 'Revoking…' : 'Revoke'}</button></article>)}</div>{sessionCursor && <button className="dashboard-load-more" type="button" onClick={loadMoreSessions} disabled={loadingMoreSessions}>{loadingMoreSessions ? 'Loading…' : 'Load more devices'}</button>}</> : <p className="dashboard-session-empty">No local services are connected.</p>}</section>
          <DeleteAccountPanel identifier={accountIdentifier(user)} onDeleted={onAccountDeleted} />
        </>}
        {activeView === 'traces' && <>
          <header className="dashboard-page-header"><span className="eyebrow">Published evidence</span><h1>Your traces</h1><p>See which traces are live, still processing, or unavailable.</p></header>
          <section className="dashboard-traces" aria-label="Your traces">
            {shareError && <p className="dashboard-session-error" role="alert">{shareError}</p>}
            {shares === null && !shareError ? <p className="dashboard-session-empty">Loading your traces…</p> : shares?.length ? <div className="dashboard-trace-list">{shares.map((share) => {
              const status = shareStateLabel(share.state);
              return <article key={share.id}>
                <div className="dashboard-trace-copy">
                  <div><span className={`dashboard-trace-state dashboard-trace-state--${status.tone}`}><i aria-hidden="true" />{status.label}</span><time>{sessionDate(share.admitted_at || share.updated_at)}</time></div>
                  <h3>Trace {share.id.slice(0, 8)}</h3>
                  <p>{share.visibility} · <code>{share.id}</code></p>
                  {share.failure_code && <p className="dashboard-trace-failure">Reason: {share.failure_code.replaceAll('_', ' ')}</p>}
                </div>
                <div className="dashboard-trace-actions">
                  {share.share_url && <a href={share.share_url} target="_blank" rel="noreferrer">Open trace</a>}
                  {share.package_url && <a href={share.package_url}>Package</a>}
                </div>
              </article>;
            })}</div> : <div className="dashboard-empty dashboard-empty--traces"><span className="eyebrow">No traces</span><b>Publish your first verified trace.</b><p>Finalize a local capture, check the disclosed conversation, then publish it as Unlisted or Listed.</p><a href="#/docs/share">Open the sharing guide</a></div>}
            {shareCursor && <button className="dashboard-load-more" type="button" onClick={loadMoreShares} disabled={loadingMoreShares}>{loadingMoreShares ? 'Loading…' : 'Load more traces'}</button>}
          </section>
        </>}
      </div>
    </div>
    <AlertDialog open={Boolean(revokeTarget)} onOpenChange={(nextOpen) => { if (!nextOpen && !revoking) setRevokeTarget(null); }}><AlertDialogContent className="axis-alert-dialog"><AlertDialogHeader><AlertDialogTitle>Revoke {revokeTarget?.device_name}?</AlertDialogTitle><AlertDialogDescription>This local service will return to public hosted limits and need a new browser approval for account access or sharing.</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel disabled={Boolean(revoking)}>Keep authorization</AlertDialogCancel><AlertDialogAction disabled={Boolean(revoking)} onClick={() => revokeTarget && revoke(revokeTarget)}>{revoking ? 'Revoking…' : 'Revoke device'}</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>
  </main>;
}

function AuthorizationPage({ title, description, action = null, facts, tone = 'neutral' }) {
  return <main className={`cli-approval-shell cli-approval-shell--${tone}`}>
    <section className="cli-approval-workspace" aria-labelledby="cli-approval-title">
      <div className="cli-approval-primary">
        <span className="eyebrow">Local service authorization</span>
        <h1 id="cli-approval-title">{title}</h1>
        <div className="cli-approval-description">{description}</div>
        {action && <div className="cli-approval-action">{action}</div>}
      </div>
      <aside className="cli-approval-context" aria-label="Connection details">
        <header>
          <span className="eyebrow">Connection</span>
          <div className="cli-approval-path" aria-label="Local service connects to an LLM Notary account">
            <span><i aria-hidden="true" />Local service</span>
            <b aria-hidden="true" />
            <span><i aria-hidden="true" />LLM Notary account</span>
          </div>
        </header>
        <dl>{facts.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
      </aside>
    </section>
  </main>;
}

export function CliApproval({ route, user, loadApproval = getCliApproval, approveRequest = approveCli }) {
  const query = new URLSearchParams(route.split('?')[1] || '');
  const requestId = query.get('request_id');
  const approvalSecret = query.get('approval_secret');
  const [details, setDetails] = useState(null);
  const [error, setError] = useState(null);
  const [approved, setApproved] = useState(false);
  useEffect(() => {
    if (!requestId || !approvalSecret || !user) return;
    let cancelled = false;
    loadApproval(requestId, approvalSecret)
      .then((payload) => { if (!cancelled) setDetails(payload); })
      .catch((reason) => { if (!cancelled) setError(reason.message); });
    return () => { cancelled = true; };
  }, [requestId, approvalSecret, user, loadApproval]);
  const approve = async () => {
    setError(null);
    try {
      await approveRequest(requestId, approvalSecret);
      setApproved(true);
    } catch (reason) {
      setError(reason.message);
    }
  };
  if (!requestId || !approvalSecret) return <AuthorizationPage
    tone="attention"
    title="Invalid authorization link"
    description={<p>Return to the local dashboard and begin authorization again.</p>}
    facts={[
      ['Request', 'Invalid or incomplete'],
      ['Next step', 'Start again in the local dashboard'],
    ]}
  />;
  if (!user) return <AuthorizationPage
    title="Sign in to continue"
    description={<p>Sign in to the account that should own this local service. You’ll review the device name and approve the connection next.</p>}
    action={<a className="button button-dark" href={`/#/signin?return_to=${encodeURIComponent(window.location.hash)}`}>Choose sign-in method</a>}
    facts={[
      ['Next step', 'Review and approve the device'],
      ['Control', 'Revoke later from Account'],
    ]}
  />;
  if (approved) return <AuthorizationPage
    tone="success"
    title="Local service approved"
    description={<p>Your local dashboard will finish connecting to this account shortly. You can close this page.</p>}
    facts={[
      ['Device', details?.device_name || 'Local service'],
      ['Account', accountName(user)],
      ['Status', 'Approved'],
    ]}
  />;
  if (error) return <AuthorizationPage
    tone="attention"
    title="Authorization unavailable"
    description={<p role="alert">{error} Return to the local dashboard and start again.</p>}
    facts={[
      ['Request', 'Needs attention'],
      ['Account', accountName(user)],
      ['Next step', 'Start again in the local dashboard'],
    ]}
  />;
  if (!details) return <AuthorizationPage
    title="Checking this request"
    description={<p role="status">Retrieving the device and account details before you approve anything.</p>}
    facts={[
      ['Request', 'Checking'],
      ['Account', accountName(user)],
      ['Changes', 'None until you approve'],
    ]}
  />;
  return <AuthorizationPage
    tone="ready"
    title="Approve this local service?"
    description={<p>This allows the local dashboard to use hosted finalization and create shares under your account.</p>}
    action={<button className="button button-dark" type="button" onClick={approve}>Approve service</button>}
    facts={[
      ['Device', details.device_name],
      ['Account', accountName(user)],
      ['Authorization code', details.user_code],
      ['Expires', sessionDate(details.expires_at)],
    ]}
  />;
}

const hostedNotaryStatuses = new Set(['active', 'retiring', 'retired', 'revoked']);

function normalizeHostedDirectory(payload) {
  if (!payload || typeof payload !== 'object' || payload.format !== 'llm-notary/notary-directory/v3'
    || !Array.isArray(payload.notaries)
    || !Number.isSafeInteger(payload.generation) || payload.generation < 0
    || typeof payload.active_key_id !== 'string') {
    throw new Error('malformed');
  }
  if (!payload.notaries.length) {
    if (payload.active_key_id) throw new Error('malformed');
    return { ...payload, notaries: [] };
  }
  const notaries = payload.notaries.map((record) => {
    if (!record || typeof record !== 'object' || typeof record.host !== 'string' || !record.host
      || !Number.isInteger(record.port) || record.port < 1 || record.port > 65535
      || !['tcp', 'tls'].includes(record.transport) || typeof record.key_id !== 'string' || !record.key_id
      || !hostedNotaryStatuses.has(record.status) || !Number.isSafeInteger(record.valid_from_unix_ms)
      || record.valid_from_unix_ms < 0
      || ![record.valid_until_unix_ms, record.finalize_until_unix_ms]
        .every((value) => value === null || value === undefined || (Number.isSafeInteger(value) && value >= record.valid_from_unix_ms))) {
      throw new Error('malformed');
    }
    return record;
  });
  const active = notaries.find((record) => record.key_id === payload.active_key_id);
  if (!active || active.status !== 'active') throw new Error('malformed');
  return { ...payload, notaries: orderNotaries(notaries, payload.active_key_id) };
}

function notaryEndpoint(record) {
  const host = record.host.includes(':') ? `[${record.host}]` : record.host;
  return `${record.transport}://${host}:${record.port}`;
}

export function HostedNotaryRecord({ record, activeKeyId, copiedKeyId, onCopy, compact = false }) {
  const lifecycle = notaryLifecycle(record.status);
  return <article className={`notary-record notary-record--${record.status}${compact ? ' notary-record--compact' : ''}`}>
    <header><span className={`notary-state notary-state--${record.status}`}><i aria-hidden="true" />{record.status}</span>{record.key_id === activeKeyId && <span className="notary-selected">Selected by active_key_id</span>}</header>
    <h3>{lifecycle.label}</h3>
    <p>{lifecycle.description}</p>
    <dl>
      <div><dt>Endpoint</dt><dd><code>{notaryEndpoint(record)}</code></dd></div>
      <div><dt>Transport</dt><dd>{record.transport.toUpperCase()}</dd></div>
      <div className="notary-key-row"><dt>Key ID / fingerprint</dt><dd><code title={record.key_id}>{abbreviatedKeyId(record.key_id)}</code><button type="button" onClick={() => onCopy(record.key_id)}>{copiedKeyId === record.key_id ? 'Copied' : 'Copy full key ID'}</button></dd></div>
      {!compact && <><div><dt>Valid from</dt><dd>{formatNotaryBoundary(record.valid_from_unix_ms, { kind: 'lower' })}</dd></div><div><dt>Capture cutoff</dt><dd>{formatNotaryBoundary(record.valid_until_unix_ms)}</dd></div><div><dt>Finalization cutoff</dt><dd>{formatNotaryBoundary(record.finalize_until_unix_ms)}</dd></div></>}
    </dl>
  </article>;
}

function NotariesPage() {
  const [directory, setDirectory] = useState(null);
  const [error, setError] = useState(null);
  const [reload, setReload] = useState(0);
  const [copiedKeyId, setCopiedKeyId] = useState(null);
  useEffect(() => {
    let cancelled = false;
    setDirectory(null);
    setError(null);
    getNotaryDirectory()
      .then((payload) => {
        if (cancelled) return;
        try {
          setDirectory(normalizeHostedDirectory(payload));
        } catch {
          setError('malformed');
        }
      })
      .catch(() => { if (!cancelled) setError('unavailable'); });
    return () => { cancelled = true; };
  }, [reload]);
  const copyKeyId = async (keyId) => {
    await navigator.clipboard.writeText(keyId);
    setCopiedKeyId(keyId);
  };
  const available = directory?.notaries.filter((record) => record.key_id === directory.active_key_id || record.status === 'retiring') || [];
  return <main className="notaries-shell">
    <header className="notaries-intro"><span className="eyebrow">Public trust metadata</span><h1>Notaries and trust</h1><p>This is the signing-key lifecycle directory used by verification. It describes permitted protocol work and retained trust records; it does not report endpoint health, uptime, or capacity.</p></header>
    {directory === null && !error ? <div className="notary-loading" role="status" aria-label="Loading notary directory"><i /><i /><i /></div> : error ? <section className="notary-page-state" role="alert"><h2>{error === 'malformed' ? 'The notary directory is malformed' : 'The notary directory is unavailable'}</h2><p>{error === 'malformed' ? 'The response could not be read as a valid signing-key lifecycle directory. No notary is presented as usable.' : 'The public trust metadata could not be loaded. No endpoint status can be inferred from this failure.'}</p><button type="button" onClick={() => setReload((value) => value + 1)}>Try again</button></section> : directory.notaries.length === 0 ? <section className="notary-page-state"><h2>No notary records are published</h2><p>The directory contains no trust records. No capture or finalization endpoint is presented as available.</p></section> : <>
      <section className="notary-section" aria-labelledby="available-notaries"><div className="notary-section-heading"><div><span className="eyebrow">Protocol lifecycle</span><h2 id="available-notaries">Available for protocol work</h2></div><span>Generation {directory.generation}</span></div><p className="notary-section-note">These records describe allowed work within configured time windows. They are not a live availability check.</p><div className="notary-records notary-records--available">{available.length ? available.map((record) => <HostedNotaryRecord key={record.key_id} record={record} activeKeyId={directory.active_key_id} copiedKeyId={copiedKeyId} onCopy={copyKeyId} compact />) : <p>No records are designated for new captures or compatible finalizations.</p>}</div></section>
      <section className="notary-section notary-history" aria-labelledby="notary-history"><div className="notary-section-heading"><div><span className="eyebrow">Pinned signing keys</span><h2 id="notary-history">Trust history</h2></div><span>{directory.notaries.length} {directory.notaries.length === 1 ? 'record' : 'records'}</span></div><div className="notary-records">{directory.notaries.map((record) => <HostedNotaryRecord key={record.key_id} record={record} activeKeyId={directory.active_key_id} copiedKeyId={copiedKeyId} onCopy={copyKeyId} />)}</div></section>
    </>}
  </main>;
}

function App() {
  const [route, setRoute] = useState(window.location.hash || '#/');
  const [user, setUser] = useState(null);
  const [authPending, setAuthPending] = useState(true);
  const [theme, setTheme] = useState(initialThemePreference);
  useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const applyTheme = () => {
      const activeTheme = resolvedTheme(theme, media.matches);
      document.documentElement.dataset.theme = activeTheme;
      document.documentElement.style.colorScheme = activeTheme;
      document.querySelector('meta[name="theme-color"]')?.setAttribute('content', activeTheme === 'dark' ? '#171717' : '#f6f5f2');
    };
    applyTheme();
    window.localStorage.setItem('llm-notary-theme', theme);
    if (theme === 'auto') media.addEventListener('change', applyTheme);
    return () => media.removeEventListener('change', applyTheme);
  }, [theme]);
  useEffect(() => { const update = () => setRoute(window.location.hash || '#/'); window.addEventListener('hashchange', update); return () => window.removeEventListener('hashchange', update); }, []);
  useEffect(() => {
    const nextSection = route.replace(/^#\/?/, '').split(/[/?]/)[0];
    if (nextSection !== 'docs') window.requestAnimationFrame(() => window.scrollTo({ top: 0, behavior: 'instant' }));
  }, [route]);
  useEffect(() => { let cancelled = false; getCurrentUser().then((user) => { if (!cancelled) { setUser(user); setAuthPending(false); } }).catch(() => { if (!cancelled) { setUser(null); setAuthPending(false); } }); return () => { cancelled = true; }; }, []);
  useEffect(() => { if (user) void loadCreditUtilizationChart(); }, [user]);
  const logout = async () => { await logoutBrowser(); setUser(null); if (window.location.hash === '#/dashboard') window.location.hash = '#/'; };
  const accountDeleted = () => { setUser(null); setAuthPending(false); window.location.hash = '#/'; };
  const path = route.replace(/^#\/?/, '');
  const directShare = window.location.pathname.match(/^\/s\/([^/]+)\/?$/);
  const directShareId = directShare ? decodeURIComponent(directShare[1]) : null;
  const routePath = path.split('?')[0];
  const [section, page] = routePath.split('/');
  const sectionAnchor = new URLSearchParams(path.split('?')[1] || '').get('section');
  const isLibrary = section === 'library' || section === 'traces' || section === 'collections';
  return <><Header user={user} onLogout={logout} hideSignIn={section === 'authorize' || section === 'signin'} authPending={authPending} />{directShareId ? <SharePage shareId={directShareId} /> : section === 'authorize' ? <CliApproval route={path} user={user} /> : section === 'signin' ? <SignInPage route={path} user={user} /> : section === 'verify' ? <VerificationPage /> : section === 'docs' ? <Docs pageKey={page || 'overview'} section={sectionAnchor} /> : isLibrary ? <Library /> : section === 'notaries' ? <NotariesPage /> : section === 'dashboard' && user ? <Dashboard user={user} view={page} route={path} theme={theme} onThemeChange={setTheme} onAccountDeleted={accountDeleted} /> : legalPages[section] ? <LegalPage pageKey={section} /> : <Landing />}{!isLibrary && <Footer />}</>;
}

const applicationRoot = document.getElementById('root');
if (applicationRoot) createRoot(applicationRoot).render(<App />);
