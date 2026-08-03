import { useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import '@fontsource-variable/instrument-sans';
import '@fontsource-variable/space-grotesk';
import '@fontsource/dm-mono/400.css';
import '@fontsource/dm-mono/500.css';
import { ChevronDown, Moon, Sun } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Command, CommandDialog, CommandEmpty, CommandInput, CommandItem, CommandList } from '@/components/ui/command';
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '@/components/ui/alert-dialog';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import './shadcn.css';
import './styles.css';
import './hero-evidence.css';
import './trust-grid.css';
import './commons.css';
import './branding.css';
import './account.css';
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
import {
  approveCli,
  changeServicePlan,
  createApiKey,
  getApiKeys,
  getCliApproval,
  getCliSessions,
  getCurrentUser,
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

const installCommand = 'git clone https://github.com/exalto-ai/llm-notary.git\ncd llm-notary\ncargo install --locked --path crates/llm-notary-client';
function PenMark() {
  return <span className="pen-mark" aria-hidden="true"><img src="/notary-mark.svg" alt="" /></span>;
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

function AccountMenu({ user, onLogout, theme, onThemeChange }) {
  const [open, setOpen] = useState(false);
  const menuRef = useRef(null);
  const initials = user.github_login.slice(0, 2).toUpperCase();
  useEffect(() => {
    const close = (event) => {
      if (event.key === 'Escape' || (event.type === 'mousedown' && !menuRef.current?.contains(event.target))) setOpen(false);
    };
    document.addEventListener('mousedown', close);
    window.addEventListener('keydown', close);
    return () => { document.removeEventListener('mousedown', close); window.removeEventListener('keydown', close); };
  }, []);
  const nextTheme = theme === 'dark' ? 'light' : 'dark';
  return <div className="account-menu" ref={menuRef}><button type="button" className="account-trigger" onClick={() => setOpen((value) => !value)} aria-expanded={open} aria-haspopup="menu" aria-label={`Account menu for ${user.github_login}`}>{user.avatar_url ? <img src={user.avatar_url} alt="" referrerPolicy="no-referrer" /> : <span>{initials}</span>}</button>{open && <div className="account-popover" role="menu"><div className="account-identity"><div><b>{user.github_login}</b><span>Signed in with GitHub</span></div><button type="button" className="account-theme" role="menuitemcheckbox" aria-checked={theme === 'dark'} aria-label={`Use ${nextTheme} theme`} title={`Use ${nextTheme} theme`} onClick={() => onThemeChange(nextTheme)}>{theme === 'dark' ? <Sun aria-hidden="true" /> : <Moon aria-hidden="true" />}</button></div><div className="account-actions"><a href="/#/dashboard" role="menuitem" onClick={() => setOpen(false)}>Dashboard</a><button type="button" role="menuitem" onClick={() => { setOpen(false); onLogout(); }}>Log out</button></div></div>}</div>;
}

function Header({ user, onLogout, theme, onThemeChange }) {
  return <header className="nav-wrap"><a className="brand" href="/#/"><PenMark /> <span>LLM Notary</span></a><nav className="product-nav"><a href="/#/docs">Docs</a><a href="/#/verify">Verify</a><a href="/#/library">Library</a>{user ? <AccountMenu user={user} onLogout={onLogout} theme={theme} onThemeChange={onThemeChange} /> : <a className="sign-in-link" href="/api/auth/github">Sign in</a>}</nav></header>;
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
      ['Account information', 'If you sign in with GitHub, we use the identity information required to operate your account, including your GitHub login and account identifier. The GitHub authorization flow is limited to identity and does not request repository, organization, or email access.'],
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

function ListedSharesPreview() {
  const [shares, setShares] = useState(null);
  const [loadError, setLoadError] = useState(false);
  useEffect(() => {
    let cancelled = false;
    getListedShares()
      .then((payload) => { if (!cancelled) setShares(payload); })
      .catch(() => { if (!cancelled) setLoadError(true); });
    return () => { cancelled = true; };
  }, []);
  const visible = (shares || []).slice(0, 5);
  return <section className="section library-preview"><div className="trace-heading"><div><span className="eyebrow">Listed sessions</span><h2>Open the conversation first.</h2></div></div>{shares === null && !loadError ? <div className="collection-pending" role="status"><b>Loading shared sessions…</b><span>Retrieving the public Listed index.</span></div> : loadError ? <div className="collection-pending" role="alert"><b>The Library is temporarily unavailable.</b><span>Open the Library to try again.</span></div> : visible.length ? <div className="preview-share-list" aria-label="Featured shared sessions">{visible.map((share) => <a href={`/s/${encodeURIComponent(share.id)}`} key={share.id}><i aria-hidden="true" /><span><b>{share.model}</b><small>{share.provider} · shared by {share.publisher}</small></span><em>Verified</em></a>)}</div> : <div className="collection-pending"><b>No Listed sessions yet.</b><span>Unlisted links remain accessible without appearing here.</span></div>}<a className="button button-dark" href="#/library">Open Library</a></section>;
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

function VerificationError({ code }) {
  const [title, copy] = verificationError(code);
  return <section className="verification-result verification-result--error" role="alert"><span className="eyebrow">Verification stopped</span><h2>{title}</h2><p>{copy}</p><code>{code}</code></section>;
}

export function VerificationPage({ verifyFile = verifyTracePackage }) {
  const inputRef = useRef(null);
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
  return <main className="verification-shell">
    <header className="verification-intro"><span className="eyebrow">Portable verification</span><h1>Verify a .llmtrace package.</h1><p>Check the authenticated provider exchange, notary signature, artifact hashes, and normalized OpenTelemetry trace without signing in.</p></header>
    <form className="verification-workspace" onSubmit={submit}>
      <section className="verification-disclosure" aria-labelledby="verification-disclosure-title"><span className="eyebrow">Read before uploading</span><h2 id="verification-disclosure-title">Your package may contain sensitive content.</h2><p>Header values are hidden by default, but prompts, responses, tool definitions, and tool results can be present. The service processes the package without durable retention. This live result is not a signed receipt.</p></section>
      <label
        className={`verification-drop${dragging ? ' verification-drop--active' : ''}`}
        onDragEnter={(event) => { event.preventDefault(); setDragging(true); }}
        onDragOver={(event) => event.preventDefault()}
        onDragLeave={(event) => { if (!(event.relatedTarget instanceof Node) || !event.currentTarget.contains(event.relatedTarget)) setDragging(false); }}
        onDrop={(event) => { event.preventDefault(); setDragging(false); chooseFile(event.dataTransfer.files[0] || null); }}
      >
        <input ref={inputRef} type="file" accept=".llmtrace,application/vnd.llmnotary.trace-package+zip" onChange={(event) => chooseFile(event.target.files[0] || null)} />
        <span>{file ? 'Package selected' : 'Drop one .llmtrace package here'}</span>
        <strong>{file ? file.name : 'or choose a file'}</strong>
        <small>{file ? fileSize(file.size) : 'Maximum package size: 128 MiB'}</small>
      </label>
      {file && <label className="verification-consent"><input type="checkbox" checked={consent} onChange={(event) => setConsent(event.target.checked)} /><span>I understand that this package may contain sensitive content.</span></label>}
      <div className="verification-actions"><button className="button button-dark" type="submit" disabled={!file || !consent || status === 'uploading'}>{status === 'uploading' ? 'Verifying package…' : 'Verify package'}</button>{file && <button className="button" type="button" onClick={() => { chooseFile(null); if (inputRef.current) inputRef.current.value = ''; }}>Clear</button>}</div>
      {status === 'uploading' && <p className="verification-progress" role="status">Cryptographic verification is running. Keep this page open.</p>}
    </form>
    {errorCode && <VerificationError code={errorCode} />}
    {result && <section className="verification-result verification-result--success" aria-labelledby="verification-success-title" aria-live="polite"><header><div><span className="eyebrow">Portable package</span><h2 id="verification-success-title">Verification passed.</h2></div><strong>Verified</strong></header><p className="verification-result-note">This result was computed from the uploaded package. It is not a platform signature or durable receipt.</p><dl className="verification-facts"><div><dt>Provider</dt><dd>{result.provider}</dd></div><div><dt>Host</dt><dd>{result.host}</dd></div><div><dt>Capture time</dt><dd>{formatVerificationTime(result.authenticated_at_unix_ms)}</dd></div><div><dt>Notary key</dt><dd><code>{result.notary_key_id}</code></dd></div><div><dt>Trust source</dt><dd>{formatTrustSource(result.trust_source)} · generation {result.directory_generation}</dd></div><div><dt>Trace SHA-256</dt><dd><code>{result.trace_sha256}</code></dd></div><div><dt>Package SHA-256</dt><dd><code>{result.package_sha256}</code></dd></div></dl><section className="verification-trace"><div className="span-panel-head"><span>Normalized trace</span><small>{trace.length} {trace.length === 1 ? 'span' : 'spans'}</small></div>{trace.length ? <SpanTree spans={trace} /> : <p>No normalized spans were present.</p>}</section></section>}
  </main>;
}

function MotionStudies() {
  return <RelayAnimation />;
}

function Landing() {
  return <main id="top">
    <section className="hero">
      <HeroSignalField />
      <h1>Verifiable intelligence</h1>
      <p>Privacy-preserving LLM trace packages for open research and independent verification.</p>
      <div className="hero-actions"><a className="button button-dark" href="#/docs/getting-started">Get started</a><a className="button button-plain" href="#/library">Browse Library</a></div>
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
      <div className="receipt"><header><PenMark /><b>Portable package</b></header><h3>Verified</h3><dl><div><dt>Provider</dt><dd>api.openai.com</dd></div><div><dt>Artifact</dt><dd>capture.llmtrace</dd></div><div><dt>Trace hash</dt><dd>9b44f8…c21d</dd></div></dl><div className="receipt-contents"><span>Notary evidence <i>•••</i></span><span>Disclosed exchange <i>•••</i></span><span>Canonical trace <i>•••</i></span></div><footer>VERIFIED FROM SOURCE PACKAGE</footer></div>
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
    title: 'Install and capture.',
    lead: 'Install one local service, start its foreground process, and point each existing client at its provider path. You keep using the same API key and request shape.',
    blocks: [
      { heading: 'Build from source', body: 'LLM Notary is a pre-release prototype and has no published binary release yet. Build the two local programs from a source checkout with Rust 1.95.0; the repository toolchain file selects that version.', code: installCommand },
      { heading: 'Programs', body: '`llm-notaryd` is the long-running local service. `llm-notary` is its short-lived REST client. The checked-in installer becomes usable only after a version tag publishes matching release assets.' },
      { heading: 'Start the service', code: 'llm-notaryd' },
      { heading: 'Open the local dashboard', body: 'Visit `http://127.0.0.1:8788` and use the tabs for captures, finalizations, trace verification, sharing, activity, and settings. The default loopback configuration opens directly. If `admin.auth` is enabled, sign in with its configured username and password; the dashboard exchanges them for an `HttpOnly` session and does not store the password.' },
      { heading: 'Configuration file', body: 'The first service start creates an editable `config.toml` at the standard user location: `~/.config/llm-notary/config.toml` on Linux, `%APPDATA%\\llm-notary\\config.toml` on Windows, and `~/Library/Application Support/llm-notary/config.toml` on macOS. It is written once and never replaced. Start with an explicit file when needed:', code: 'llm-notaryd --config /path/to/config.toml' },
      { heading: 'Use the command client', body: '`llm-notary` is a short-lived client for the daemon\'s versioned loopback API. It checks daemon health and never opens the catalog or vault directly. Add `--json` for automation.', code: 'llm-notary status\nllm-notary captures list --provider openai\nllm-notary operations list --state failed --json\nllm-notary open' },
      { heading: 'What it controls', body: '`config.toml` holds the listener address, optional admin authentication, an optional local or self-hosted notary endpoint, bundle and trace directories, the SQLite catalog path and preview limits, and the enabled provider routes. All built-in providers start enabled. The hostname and API behavior of each provider remain fixed; configuration cannot direct the proxy to an arbitrary upstream host.' },
      { heading: 'Optional admin sign-in', body: 'The loopback administration API is available to local processes without credentials by default. To require sign-in, configure a username and an Argon2id PHC password hash. Store the hash, including its salt and work parameters, rather than the plaintext password. A prompted tool such as caddy hash-password --algorithm argon2id can generate it.', code: '[admin.auth]\nusername = "local-admin"\npassword_hash = "$argon2id$v=19$m=32768,t=2,p=1$..."' },
      { heading: 'Bundle encryption is automatic', body: 'On first use, the proxy creates a random bundle-encryption key and stores it in Keychain on macOS, Credential Manager on Windows, or the desktop secret service on Linux. The OS may ask you to unlock that credential. You do not need to run a separate initialization command.' },
      { heading: 'Optional passphrase mode', body: 'If you prefer a passphrase instead of the operating-system credential service, point `LLM_NOTARY_VAULT_PASSPHRASE_FILE` at a private UTF-8 file before the first service start. An empty passphrase is accepted for low-friction local testing, but it provides no meaningful protection if someone obtains both your bundles and vault configuration.', code: 'export LLM_NOTARY_VAULT_PASSPHRASE_FILE=/private/local/path/vault-passphrase\nllm-notaryd' },
      { heading: 'What happens online', body: 'The local proxy handles plaintext while the notary participates in the provider TLS connection without seeing application data. Provider response bytes stream back to your agent as they arrive.' },
      { heading: 'What happens at end-of-stream', body: 'The proxy seals encrypted deferred state into one `.llmbundle`. It does not perform the expensive final proof before returning control to your workflow.' },
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
  'trace-packages': {
    title: 'Finalize and verify.',
    lead: 'Turn one encrypted bundle into a portable evidence package, inspect its canonical OpenTelemetry trace, and verify the entire package offline.',
    blocks: [
      { heading: 'Finalize one interaction', body: 'Select a pending capture identifier in the dashboard or admin API. The service atomically writes storage.finalized_dir/<capture-id>.llmtrace by default, records that package in the catalog, and retains the encrypted source bundle.', code: 'curl -X POST http://127.0.0.1:8788/v1/captures/cap-example/finalizations' },
      { heading: 'Notary discovery is automatic', body: 'For hosted use, the service refreshes the production notary directory, selects a worker compatible with the bundle, and verifies the resulting evidence against its locally pinned key history. For local or self-hosted use, set `notary.endpoint` and `notary.public_key` together in `config.toml`.' },
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
      { heading: 'Verify a portable package', code: 'llm-notary traces verify ./capture.llmtrace\nPOST /api/verify', body: 'Use the local CLI for offline verification against pinned trust history, or explicitly upload the package on the public Verify page. The hosted service does not retain the package and its live result is not a signed receipt.' },
      { heading: 'Complete context is intentional', body: 'A `.llmtrace` can include system context, tool definitions, session metadata, prompts, responses, and tool results. All HTTP header values are hidden by default, but request and response bodies remain disclosed. Inspect it before sharing; the encrypted `.llmbundle` is private retry state and must stay local.' },
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
              'encrypted .llmbundle checkpoints',
              'API-key or cookie values',
              'unselected bundles from the same session',
              'extra files or symlink targets',
            ],
          },
        ],
      },
      { heading: 'Admission checks', body: 'The local service and hosted admission service validate the deterministic archive, verify its evidence, require hidden header values, and scan every archive entry and nested disclosed body for credential patterns and high-entropy secrets. After storage, admission downloads the exact public bytes and repeats validation, scanning, and verification before exposing the link.' },
      { heading: 'Current consent boundary', body: 'The admission service inspects disclosed request and response bodies, system context, and tool data to verify and reproduce the shared view. Every HTTP header value is hidden except the exact structural value Transfer-Encoding: chunked.' },
      { heading: 'Exact package retention', body: 'An admitted session keeps the exact verified `.llmtrace` bytes, size, and SHA-256 digest. The session page makes that package available for independent verification; the encrypted `.llmbundle` never leaves the local vault.' },
      { heading: 'Retry behavior', body: 'An upload or API failure does not change or delete the local package. Submitting the same capture with the same visibility reuses the archive-derived idempotency key and resumes the retry-safe share job.' },
    ],
  },
};

const docSubheadings = {
  'getting-started': new Set([
    'Programs',
    'Configuration file',
    'What it controls',
    'Bundle encryption is automatic',
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
  { label: 'Start', pages: [['overview', 'Overview'], ['getting-started', 'Install and capture']] },
  { label: 'Understand', pages: [['how-it-works', 'Trust model'], ['trace-packages', 'Trace packages']] },
  { label: 'Share', pages: [['share', 'Share a session']] },
];
const docOrder = docNavigation.flatMap((group) => group.pages.map(([key]) => key));
const docAliases = {
  install: 'getting-started',
  proxy: 'getting-started',
  bundles: 'getting-started',
  captures: 'getting-started',
  providers: 'getting-started',
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
    return <div className="span-row span-row--source" key={`${span.spanId}-${index}`}><button type="button" className="span-summary" aria-expanded={open} onClick={() => toggle(index)}><span className="span-branch" aria-hidden="true" /><span className="span-kind">{span.kind}</span><strong>{span.name}</strong><span className="span-disclosure" aria-hidden="true" /><small>span <code>{span.spanId}</code></small><em>Provider verified</em></button>{open && <>{span.attributes && <div className="span-evidence span-attributes"><span className="message-group-label">attributes</span><div className="trace-fields">{span.attributes.map(([name, value]) => <TraceField key={name} label={name} value={value} />)}</div></div>}{span.messages && <div className="span-evidence span-messages"><MessageGroup label="gen_ai.input.messages" messages={span.messages.input} /><MessageGroup label="gen_ai.output.messages" messages={span.messages.output} /></div>}</>}</div>;
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

function traceSnippets(spans) {
  const inputMessages = spans.flatMap((span) => span.messages?.input || []);
  const outputMessages = spans.flatMap((span) => span.messages?.output || []);
  const parts = [...inputMessages, ...outputMessages].flatMap((message) => message.parts || []);
  const input = (inputMessages.find((message) => message.role === 'user')?.parts || []).find((part) => part.type === 'text' && part.content)
    || inputMessages.flatMap((message) => message.parts || []).find((part) => part.type === 'text' && part.content);
  const output = (outputMessages.find((message) => message.role === 'assistant')?.parts || []).find((part) => part.type === 'text' && part.content)
    || outputMessages.flatMap((message) => message.parts || []).find((part) => part.type === 'text' && part.content);
  const tool = parts.find((part) => part.type === 'tool_call' || part.type === 'tool_call_response');
  const shorten = (value) => {
    const text = String(value).replace(/\s+/g, ' ').trim();
    return text.length > 150 ? `${text.slice(0, 147)}…` : text;
  };
  return [
    input && { label: 'Input', text: shorten(input.content) },
    output && { label: 'Response', text: shorten(output.content) },
    tool && { label: tool.type === 'tool_call' ? 'Tool call' : 'Tool result', text: tool.type === 'tool_call' ? `${tool.name}(${shorten(JSON.stringify(tool.arguments))})` : shorten(typeof tool.result === 'string' ? tool.result : JSON.stringify(tool.result)) },
  ].filter(Boolean);
}

function LibraryLoading() {
  return <main className="share-library share-library--loading" aria-busy="true"><header className="share-library-titlebar"><h1>Library</h1><span>Listed shares</span></header><div className="share-library-skeleton" role="status"><i /><i /><i /><span>Loading shares</span></div></main>;
}

export function Library({ loadShares = getListedShares }) {
  const [shares, setShares] = useState(null);
  const [loadError, setLoadError] = useState('');
  const [query, setQuery] = useState('');
  const [provider, setProvider] = useState('All');
  useEffect(() => {
    let cancelled = false;
    loadShares()
      .then((payload) => { if (!cancelled) setShares(payload); })
      .catch((error) => { if (!cancelled) setLoadError(error.message); });
    return () => { cancelled = true; };
  }, [loadShares]);
  const providers = ['All', ...new Set((shares || []).map((share) => share.provider))];
  const filtered = useMemo(() => (shares || []).filter((share) => {
    const searchable = `${share.provider} ${share.model} ${share.publisher}`.toLowerCase();
    return searchable.includes(query.toLowerCase()) && (provider === 'All' || share.provider === provider);
  }), [provider, query, shares]);
  if (shares === null && !loadError) return <LibraryLoading />;
  return <main className="share-library">
    <header className="share-library-titlebar"><h1>Library</h1><span>Listed shares</span></header>
    <section className="share-library-controls" aria-label="Browse Listed shares">
      <label><span>Search</span><Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Model, provider, or publisher" /></label>
      <Select value={provider} onValueChange={setProvider}><SelectTrigger aria-label="Provider"><SelectValue /></SelectTrigger><SelectContent>{providers.map((value) => <SelectItem value={value} key={value}>{value}</SelectItem>)}</SelectContent></Select>
      <span>{filtered.length} {filtered.length === 1 ? 'session' : 'sessions'}</span>
    </section>
    {loadError ? <section className="collection-empty" role="alert">{loadError}</section> : filtered.length ? <section className="share-index" aria-label="Listed shares">{filtered.map((share) => <a className="share-index-row" href={`/s/${encodeURIComponent(share.id)}`} key={share.id}><span><b>{share.model}</b><small>{share.provider}</small></span><span><small>Publisher</small>{share.publisher}</span><span className="share-index-state"><i aria-hidden="true" />Verified</span><span aria-hidden="true">↗</span></a>)}</section> : <section className="collection-empty"><b>No matches</b><p>Clear the search or choose another provider.</p></section>}
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
  if (!share || spans === null) return <main className="share-page share-page-state" aria-busy="true"><h1>Loading share</h1></main>;
  const authenticated = share.authenticated_at_unix_ms ? new Date(share.authenticated_at_unix_ms).toLocaleString() : 'Not recorded';
  const messageCount = spans.reduce((count, span) => count + (span.messages?.input?.length || 0) + (span.messages?.output?.length || 0), 0);
  return <main className="share-page">
    <header className="share-page-header"><div><h1>{share.model}</h1><p><b>{share.publisher}</b><span>{share.provider}</span><span>{share.visibility}</span></p></div><div className="share-verification-mark"><i aria-hidden="true" /><span><b>Verified</b><small>Provider session</small></span></div></header>
    <div className="share-page-layout">
      <section className="share-transcript" aria-labelledby="shared-conversation-title"><header><h2 id="shared-conversation-title">Conversation</h2><span>{messageCount} {messageCount === 1 ? 'message' : 'messages'}</span></header><SharedConversation spans={spans} /></section>
      <aside className="share-evidence-rail"><span className="eyebrow">Verification</span><dl><div><dt>Provider</dt><dd>{share.provider}</dd></div><div><dt>Host</dt><dd>{share.host}</dd></div><div><dt>Authenticated</dt><dd>{authenticated}</dd></div><div><dt>Visibility</dt><dd>{share.visibility}</dd></div></dl>
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
    loadKeys()
      .then((keys) => { if (!cancelled) setApiKeys(keys); })
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

  return <section className="dashboard-api-keys" aria-labelledby="api-keys-title">
    <header><div><span className="eyebrow">Automation access</span><h2 id="api-keys-title">API keys</h2></div><button type="button" onClick={() => setDialogOpen(true)}>Create API key</button></header>
    {error && <p className="dashboard-session-error" role="alert">{error}</p>}
    {apiKeys === null && !error ? <p className="dashboard-session-empty">Loading API keys…</p> : apiKeys?.length ? <div className="dashboard-api-key-list">{apiKeys.map((apiKey) => <article key={apiKey.id} className={apiKeyState(apiKey).toLowerCase()}><div className="dashboard-api-key-copy"><div><b>{apiKey.name}</b><span className="dashboard-api-key-state"><i aria-hidden="true" />{apiKeyState(apiKey)}</span></div><code>{apiKey.prefix}</code><span>{apiKey.scopes.join(' · ')}</span><small>Created {sessionDate(apiKey.created_at)} · Last used {apiKey.last_used_at ? sessionDate(apiKey.last_used_at) : 'Never'} · Expires {apiKey.expires_at ? sessionDate(apiKey.expires_at) : 'Never'}</small></div>{!apiKey.revoked_at && <button type="button" onClick={() => setRevokeTarget(apiKey)}>Revoke</button>}</article>)}</div> : <div className="dashboard-api-key-empty"><b>No API keys</b><p>Create a scoped key for CI, cron jobs, or another unattended host.</p></div>}

    <Dialog open={dialogOpen} onOpenChange={closeDialog}><DialogContent className="axis-api-key-dialog" showCloseButton={!creating}><DialogHeader><DialogTitle>{created ? 'Copy this API key now' : 'Create API key'}</DialogTitle><DialogDescription>{created ? 'The complete key is shown once. Store it in your CI or service secret manager before closing.' : 'Choose only the access this automation needs. The key remains valid until it expires or you revoke it.'}</DialogDescription></DialogHeader>{created ? <div className="api-key-receipt"><span className="eyebrow">API key</span><code>{created.secret}</code><button type="button" onClick={copySecret}>{copied ? 'Copied' : 'Copy API key'}</button></div> : <form id="create-api-key-form" className="api-key-form" onSubmit={create}><label><span>Name</span><Input value={name} onChange={(event) => setName(event.target.value)} maxLength={100} required placeholder="GitHub Actions release" /></label><fieldset><legend>Scopes</legend>{apiKeyScopeOptions.map(([scope, description]) => <label key={scope}><input type="checkbox" checked={scopes.includes(scope)} onChange={() => toggleScope(scope)} /><span><code>{scope}</code><small>{description}</small></span></label>)}</fieldset><label><span>Expiration</span><Input type="date" value={expiresOn} min={new Date(Date.now() + 86400000).toISOString().slice(0, 10)} onChange={(event) => setExpiresOn(event.target.value)} /><small>Leave blank to never expire.</small></label></form>}<DialogFooter>{created ? <button type="button" className="api-key-primary" onClick={() => closeDialog(false)}>I stored the key</button> : <><button type="button" className="api-key-secondary" onClick={() => closeDialog(false)} disabled={creating}>Cancel</button><button type="submit" form="create-api-key-form" className="api-key-primary" disabled={creating || !name.trim() || !scopes.length}>{creating ? 'Creating…' : 'Create API key'}</button></>}</DialogFooter></DialogContent></Dialog>
    <AlertDialog open={Boolean(revokeTarget)} onOpenChange={(open) => { if (!open && !revoking) setRevokeTarget(null); }}><AlertDialogContent className="axis-alert-dialog"><AlertDialogHeader><AlertDialogTitle>Revoke {revokeTarget?.name}?</AlertDialogTitle><AlertDialogDescription>Requests using this key will be rejected immediately. This action does not affect other keys or connected devices.</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel disabled={revoking}>Keep key</AlertDialogCancel><AlertDialogAction disabled={revoking} onClick={revoke}>{revoking ? 'Revoking…' : 'Revoke API key'}</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>
  </section>;
}

function Dashboard({ user, view, onPlanChange }) {
  const [sessions, setSessions] = useState(null);
  const [sessionError, setSessionError] = useState(null);
  const [revoking, setRevoking] = useState(null);
  const [revokeTarget, setRevokeTarget] = useState(null);
  const [shares, setShares] = useState(null);
  const [shareError, setShareError] = useState(null);
  const [plan, setPlan] = useState(user.plan);
  const [entitlements, setEntitlements] = useState(user.entitlements);
  const [planChanging, setPlanChanging] = useState(false);
  const [planError, setPlanError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    getCliSessions()
      .then((sessions) => { if (!cancelled) setSessions(sessions); })
      .catch((reason) => { if (!cancelled) setSessionError(reason.message); });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (!revokeTarget) return undefined;
    const closeOnEscape = (event) => { if (event.key === 'Escape' && revoking !== revokeTarget.id) setRevokeTarget(null); };
    window.addEventListener('keydown', closeOnEscape);
    return () => window.removeEventListener('keydown', closeOnEscape);
  }, [revokeTarget, revoking]);

  useEffect(() => {
    let cancelled = false;
    getMyShares()
      .then((payload) => { if (!cancelled) setShares(payload); })
      .catch((reason) => { if (!cancelled) setShareError(reason.message); });
    return () => { cancelled = true; };
  }, []);

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

  const changePlan = async (nextPlan) => {
    setPlanChanging(true);
    setPlanError(null);
    try {
      const response = await changeServicePlan(nextPlan);
      setPlan(response.plan);
      setEntitlements(response.entitlements);
      onPlanChange(response);
    } catch (reason) {
      setPlanError(reason.message);
    } finally {
      setPlanChanging(false);
    }
  };

  const admittedCount = shares?.filter((share) => share.state === 'admitted').length || 0;
  const activeCount = shares?.filter((share) => ['uploading', 'queued', 'verifying'].includes(share.state)).length || 0;
  const activeView = view === 'shares' ? 'shares' : 'account';

  return <main className="dashboard-shell dashboard-shell--account">
    <div className="dashboard-layout">
      <aside className="dashboard-sidebar" aria-label="Dashboard navigation">
        <span className="eyebrow">Dashboard</span>
        <nav>
          <a className={activeView === 'account' ? 'active' : ''} href="#/dashboard" aria-current={activeView === 'account' ? 'page' : undefined}><span>Account</span></a>
          <a className={activeView === 'shares' ? 'active' : ''} href="#/dashboard/shares" aria-current={activeView === 'shares' ? 'page' : undefined}><span>Shares</span><small>{shares === null ? '—' : shares.length}</small></a>
        </nav>
      </aside>
      <div className="dashboard-page">
        {activeView === 'account' ? <>
          <header className="dashboard-page-header"><span className="eyebrow">Account</span><h1>Account</h1><p>Manage hosted service access and the local services connected to your account.</p></header>
          <div className="dashboard-summary">
            <div><span>GitHub account</span><b>{user.github_login}</b></div>
            <div><span>Admitted shares</span><b>{shares === null ? '—' : admittedCount}</b></div>
            <div><span>In progress</span><b>{shares === null ? '—' : activeCount}</b></div>
          </div>
          <section className="dashboard-plan" aria-labelledby="service-plan-title">
            <header><div><span className="eyebrow">Hosted notary access</span><h2 id="service-plan-title">{plan === 'paid_preview' ? 'Paid preview' : 'Free'} plan</h2></div><span className="dashboard-plan-badge">{plan === 'paid_preview' ? 'No charge' : 'Included'}</span></header>
            <p>{plan === 'paid_preview' ? 'Paid preview raises the hosted-service limits while billing is disabled. It creates no charge or payment obligation.' : 'Upgrade to the paid preview to use the higher hosted-service limits. Billing is not enabled and no payment method is required.'}</p>
            {entitlements && <dl><div><dt>Concurrent sessions</dt><dd>{entitlements.account_concurrency ?? 'Shared public pool'}</dd></div><div><dt>Session timeout</dt><dd>{Math.round(entitlements.session_timeout_secs / 60)} min</dd></div><div><dt>Maximum capture</dt><dd>{fileSize(entitlements.max_attestable_http_bytes)}</dd></div><div><dt>Proof credits left</dt><dd>{fileSize(entitlements.remaining_finalization_bytes)}</dd></div><div><dt>Starts per minute</dt><dd>{entitlements.starts_per_minute}</dd></div></dl>}
            {planError && <p className="dashboard-session-error" role="alert">{planError}</p>}
            <button type="button" onClick={() => changePlan(plan === 'paid_preview' ? 'free' : 'paid_preview')} disabled={planChanging}>{planChanging ? 'Updating…' : plan === 'paid_preview' ? 'Return to free' : 'Upgrade to paid preview'}</button>
          </section>
          <section className="dashboard-sessions" aria-labelledby="connected-services-title"><header><div><span className="eyebrow">Local service access</span><h2 id="connected-services-title">Connected devices</h2></div></header>{sessionError && <p className="dashboard-session-error" role="alert">{sessionError}</p>}{sessions === null && !sessionError ? <p className="dashboard-session-empty">Loading connected devices…</p> : sessions?.length ? <div className="dashboard-session-list">{sessions.map((session) => <article key={session.id}><div><b>{session.device_name}</b><span>Created {sessionDate(session.created_at)} · Last used {sessionDate(session.last_used_at)} · Expires {sessionDate(session.expires_at)}</span></div><button type="button" onClick={() => setRevokeTarget(session)} disabled={revoking === session.id}>{revoking === session.id ? 'Revoking…' : 'Revoke'}</button></article>)}</div> : <p className="dashboard-session-empty">No local services are connected.</p>}</section>
          <ApiKeysPanel />
        </> : <>
          <header className="dashboard-page-header"><span className="eyebrow">Shares</span><h1>Your shares</h1><p>Review admission state, visibility, and the stable links created by your local service.</p></header>
          <section className="dashboard-traces" aria-label="Your shares">
            {shareError && <p className="dashboard-session-error" role="alert">{shareError}</p>}
            {shares === null && !shareError ? <p className="dashboard-session-empty">Loading your shares…</p> : shares?.length ? <div className="dashboard-trace-list">{shares.map((share) => {
              const status = shareStateLabel(share.state);
              return <article key={share.id}>
                <div className="dashboard-trace-copy">
                  <div><span className={`dashboard-trace-state dashboard-trace-state--${status.tone}`}><i aria-hidden="true" />{status.label}</span><time>{sessionDate(share.admitted_at || share.updated_at)}</time></div>
                  <h3>Share {share.id.slice(0, 8)}</h3>
                  <p>{share.visibility} · <code>{share.id}</code></p>
                  {share.failure_code && <p className="dashboard-trace-failure">Reason: {share.failure_code.replaceAll('_', ' ')}</p>}
                </div>
                <div className="dashboard-trace-actions">
                  {share.share_url && <a href={share.share_url} target="_blank" rel="noreferrer">Open share</a>}
                  {share.package_url && <a href={share.package_url}>Package</a>}
                </div>
              </article>;
            })}</div> : <div className="dashboard-empty dashboard-empty--traces"><span className="eyebrow">No shares</span><b>Share your first verified session.</b><p>Finalize a capture in the local dashboard, preview its disclosed conversation, then create an Unlisted or Listed link.</p><a href="#/docs/share">Open the sharing guide</a></div>}
          </section>
        </>}
      </div>
    </div>
    <AlertDialog open={Boolean(revokeTarget)} onOpenChange={(nextOpen) => { if (!nextOpen && !revoking) setRevokeTarget(null); }}><AlertDialogContent className="axis-alert-dialog"><AlertDialogHeader><AlertDialogTitle>Revoke {revokeTarget?.device_name}?</AlertDialogTitle><AlertDialogDescription>This local service will return to public hosted limits and need a new browser approval for account access or sharing.</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel disabled={Boolean(revoking)}>Keep authorization</AlertDialogCancel><AlertDialogAction disabled={Boolean(revoking)} onClick={() => revokeTarget && revoke(revokeTarget)}>{revoking ? 'Revoking…' : 'Revoke device'}</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>
  </main>;
}

function CliApproval({ route, user }) {
  const query = new URLSearchParams(route.split('?')[1] || '');
  const requestId = query.get('request_id');
  const approvalSecret = query.get('approval_secret');
  const [details, setDetails] = useState(null);
  const [error, setError] = useState(null);
  const [approved, setApproved] = useState(false);
  useEffect(() => {
    if (!requestId || !approvalSecret || !user) return;
    let cancelled = false;
    getCliApproval(requestId, approvalSecret)
      .then((payload) => { if (!cancelled) setDetails(payload); })
      .catch((reason) => { if (!cancelled) setError(reason.message); });
    return () => { cancelled = true; };
  }, [requestId, approvalSecret, user]);
  const approve = async () => {
    setError(null);
    try {
      await approveCli(requestId, approvalSecret);
      setApproved(true);
    } catch (reason) {
      setError(reason.message);
    }
  };
  if (!requestId || !approvalSecret) return <main className="dashboard-shell"><span className="eyebrow">Local service authorization</span><h1>Invalid authorization link.</h1><p>Return to the local dashboard and begin authorization again.</p></main>;
  if (!user) return <main className="dashboard-shell"><span className="eyebrow">Local service authorization</span><h1>Sign in to approve.</h1><p>This browser must be signed in to the LLM Notary account that should own the local service connection.</p><a className="button button-dark" href={`/api/auth/github?return_to=${encodeURIComponent(window.location.hash)}`}>Sign in with GitHub</a></main>;
  if (approved) return <main className="dashboard-shell"><span className="eyebrow">Local service authorization</span><h1>Service approved.</h1><p>Your local dashboard will finish authorization shortly. You can close this page.</p></main>;
  return <main className="dashboard-shell"><span className="eyebrow">Local service authorization</span><h1>Approve this service?</h1>{error ? <p>{error}</p> : details ? <><p>Connect <b>{details.device_name}</b> to LLM Notary as <b>{user.github_login}</b> for hosted access and sharing?</p><div className="dashboard-card"><span>Authorization code</span><b>{details.user_code}</b><span>Expires {sessionDate(details.expires_at)}</span><button className="button button-dark" onClick={approve}>Approve service</button></div></> : <p>Checking this authorization request…</p>}</main>;
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
  const [theme, setTheme] = useState(() => window.localStorage.getItem('llm-notary-theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
  useEffect(() => { document.documentElement.dataset.theme = theme; document.documentElement.style.colorScheme = theme; window.localStorage.setItem('llm-notary-theme', theme); }, [theme]);
  useEffect(() => { const update = () => setRoute(window.location.hash || '#/'); window.addEventListener('hashchange', update); return () => window.removeEventListener('hashchange', update); }, []);
  useEffect(() => {
    const nextSection = route.replace(/^#\/?/, '').split(/[/?]/)[0];
    if (nextSection !== 'docs') window.requestAnimationFrame(() => window.scrollTo({ top: 0, behavior: 'instant' }));
  }, [route]);
  useEffect(() => { let cancelled = false; getCurrentUser().then((user) => { if (!cancelled) setUser(user); }).catch(() => { if (!cancelled) setUser(null); }); return () => { cancelled = true; }; }, []);
  const logout = async () => { await logoutBrowser(); setUser(null); if (window.location.hash === '#/dashboard') window.location.hash = '#/'; };
  const path = route.replace(/^#\/?/, '');
  const directShare = window.location.pathname.match(/^\/s\/([^/]+)\/?$/);
  const directShareId = directShare ? decodeURIComponent(directShare[1]) : null;
  const routePath = path.split('?')[0];
  const [section, page] = routePath.split('/');
  const sectionAnchor = new URLSearchParams(path.split('?')[1] || '').get('section');
  const isLibrary = section === 'library' || section === 'traces' || section === 'collections';
  const updatePlan = (response) => setUser((current) => current ? { ...current, plan: response.plan, entitlements: response.entitlements } : current);
  return <><Header user={user} onLogout={logout} theme={theme} onThemeChange={setTheme} />{directShareId ? <SharePage shareId={directShareId} /> : section === 'authorize' ? <CliApproval route={path} user={user} /> : section === 'verify' ? <VerificationPage /> : section === 'docs' ? <Docs pageKey={page || 'overview'} section={sectionAnchor} /> : isLibrary ? <Library /> : section === 'notaries' ? <NotariesPage /> : section === 'dashboard' && user ? <Dashboard user={user} view={page} onPlanChange={updatePlan} /> : legalPages[section] ? <LegalPage pageKey={section} /> : <Landing />}{!isLibrary && <Footer />}</>;
}

const applicationRoot = document.getElementById('root');
if (applicationRoot) createRoot(applicationRoot).render(<App />);
