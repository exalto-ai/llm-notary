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
import './shadcn.css';
import './styles.css';
import './hero-evidence.css';
import './trust-grid.css';
import './commons.css';
import './branding.css';
import './account.css';
import './collections.css';
import './docs.css';
import './legal.css';
import './relay-animation.css';
import './landing.css';
import './notaries.css';
import './axis.css';
import { RelayAnimation } from './RelayAnimation';
import {
  approveCli,
  changeServicePlan,
  getCliApproval,
  getCliSessions,
  getCurrentUser,
  getNotaryDirectory,
  getPublishedTrace,
  getPublishJobs,
  getTraceCollection,
  logoutBrowser,
  revokeCliSession,
} from './platform-api/client';
import { abbreviatedKeyId, formatNotaryBoundary, notaryLifecycle, orderNotaries } from './notaryLifecycle';

const publicOrigin = __PUBLIC_ORIGIN__;
const installCommand = `curl -fsSLO ${publicOrigin}/install.sh && sh install.sh`;
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
  return <div className="account-menu" ref={menuRef}><button type="button" className="account-trigger" onClick={() => setOpen((value) => !value)} aria-expanded={open} aria-haspopup="menu" aria-label={`Account menu for ${user.github_login}`}>{user.avatar_url ? <img src={user.avatar_url} alt="" referrerPolicy="no-referrer" /> : <span>{initials}</span>}</button>{open && <div className="account-popover" role="menu"><div className="account-identity"><div><b>{user.github_login}</b><span>Signed in with GitHub</span></div><button type="button" className="account-theme" role="menuitemcheckbox" aria-checked={theme === 'dark'} aria-label={`Use ${nextTheme} theme`} title={`Use ${nextTheme} theme`} onClick={() => onThemeChange(nextTheme)}>{theme === 'dark' ? <Sun aria-hidden="true" /> : <Moon aria-hidden="true" />}</button></div><div className="account-actions"><a href="#/dashboard" role="menuitem" onClick={() => setOpen(false)}>Dashboard</a><button type="button" role="menuitem" onClick={() => { setOpen(false); onLogout(); }}>Log out</button></div></div>}</div>;
}

function Header({ user, onLogout, theme, onThemeChange }) {
  return <header className="nav-wrap"><a className="brand" href="#/"><PenMark /> <span>LLM Notary</span></a><nav className="product-nav"><a href="#/docs">Docs</a><a href="#/library">Library</a>{user ? <AccountMenu user={user} onLogout={onLogout} theme={theme} onThemeChange={onThemeChange} /> : <a className="sign-in-link" href="/api/auth/github">Sign in</a>}</nav></header>;
}

function Footer() {
  return <footer className="site-footer"><span className="footer-copyright">© 2026 LLM Notary</span><nav aria-label="Footer"><a href="#/notaries">Notaries</a><a href="#/privacy">Privacy</a><a href="#/terms">Terms</a></nav></footer>;
}

const legalPages = {
  privacy: {
    eyebrow: 'Legal · Privacy',
    title: 'Privacy Policy',
    intro: 'This policy explains the information handled by the LLM Notary website, publishing service, and local tooling.',
    sections: [
      ['Local capture stays local', 'The local proxy handles application plaintext and provider credentials. Within the protocol, the remote notary witnesses encrypted traffic and protocol metadata; it does not receive your API key, prompt, or response plaintext.'],
      ['Account information', 'If you sign in with GitHub, we use the identity information required to operate your account, including your GitHub login and account identifier. The GitHub authorization flow is limited to identity and does not request repository, organization, or email access.'],
      ['Published evidence', 'Publishing is an explicit action. A submitted package is checked before admission, and an admitted trace, platform stamp, and related public metadata may be available to anyone. Finalized artifacts redact credential and session values, but disclosed trace content may still contain information you choose to publish. Do not publish content you are not permitted to share.'],
      ['Service processing', 'The service processes submissions to verify and publish them. Private intake objects are removed after a successful admission flow; public artifacts remain available as part of the collection.'],
      ['Your choices', 'You choose whether to publish a finalized trace. Keep private capture bundles and credentials under your control, and avoid uploading them to public collections. For privacy questions or requests, contact the LLM Notary operator through the project’s published support channel.'],
      ['Updates', 'We may revise this policy as the service evolves. The current version will always be available on this page.'],
    ],
  },
  terms: {
    eyebrow: 'Legal · Terms',
    title: 'Terms of Service',
    intro: 'These terms govern your use of the LLM Notary website, local tooling, and publishing service.',
    sections: [
      ['Using the service', 'Use LLM Notary lawfully and only with content, credentials, and provider accounts you are authorized to use. Do not interfere with the service, bypass access controls, or submit material that infringes the rights of others.'],
      ['Your publications', 'You are responsible for every trace or artifact you choose to publish. Publishing is an explicit consent boundary: once a submission is admitted, its public trace, stamp, and related metadata can be accessed and independently verified by others.'],
      ['What verification means', 'LLM Notary verification concerns the cryptographic and protocol evidence described in the published artifacts. It does not independently establish that an underlying claim, model output, or user interpretation is true, complete, safe, or suitable for a particular purpose.'],
      ['Availability', 'The service is provided on an “as available” basis and may change, be suspended, or be discontinued. Preserve the local materials you need; do not rely on the service as your only record or backup.'],
      ['Your responsibilities', 'You are responsible for maintaining the security of your devices, local captures, API credentials, and account. Do not publish confidential, personal, or otherwise protected information unless you have a clear right to do so.'],
      ['Changes to these terms', 'We may update these terms as the product develops. Continued use after an updated version is posted means you accept the revised terms.'],
    ],
  },
};

function LegalPage({ pageKey }) {
  const page = legalPages[pageKey];
  return <main className="legal-shell"><span className="eyebrow">{page.eyebrow}</span><h1>{page.title}</h1><p className="legal-intro">{page.intro}</p><p className="legal-updated">Last updated: July 2026</p><div className="legal-sections">{page.sections.map(([heading, copy]) => <section key={heading}><h2>{heading}</h2><p>{copy}</p></section>)}</div></main>;
}

function TrustColumns() {
  const boundaries = [
    ['01', 'Client', 'Holds the plaintext', 'The local proxy sees the request and response. A user cannot change authenticated bytes or invent a provider response and still produce valid finalized evidence.'],
    ['02', 'Notary', 'Witnesses ciphertext', 'The notary sees the provider hostname, encrypted traffic, sizes, timing, and protocol metadata—not the API key, prompt, or response plaintext. The provider serves a normal request; origin follows from the authenticated TLS session, not a special provider signature.'],
    ['03', 'Researcher', 'Checks independently', 'Researchers can verify the notary signature, provider identity, disclosed transcript, artifact hashes, and deterministic mapping using the trusted notary public key.'],
  ];
  return <div className="trust-columns" aria-label="How the trust model works">{boundaries.map(([number, actor, title, copy]) => <article key={actor}><span>{number}</span><b>{actor}</b><h3>{title}</h3><p>{copy}</p></article>)}</div>;
}

function PublishingArchitecture() {
  return <section className="section architecture" id="how-it-works"><div className="section-head"><span className="eyebrow">How it works</span><h2>Don’t trust. Verify.</h2></div><TrustColumns /><div className="section-link"><a href="#/docs/how-it-works">Learn more about the trust model</a></div></section>;
}

function CollectionPreview() {
  const [collection, setCollection] = useState(null);
  const [loadError, setLoadError] = useState(false);
  const [activeId, setActiveId] = useState(null);
  const [tracePreview, setTracePreview] = useState(null);
  useEffect(() => {
    let cancelled = false;
    getTraceCollection()
      .then((payload) => {
        if (!cancelled) {
          setCollection(payload);
          setActiveId(payload.publications[0]?.id || null);
        }
      })
      .catch(() => { if (!cancelled) setLoadError(true); });
    return () => { cancelled = true; };
  }, []);
  const publications = collection?.publications || [];
  const visible = publications.slice(0, 5);
  const active = visible.find((publication) => publication.id === activeId) || visible[0];
  useEffect(() => {
    if (!active) {
      setTracePreview(null);
      return;
    }
    let cancelled = false;
    setTracePreview(null);
    getPublishedTrace(active.id)
      .then((trace) => { if (!cancelled) setTracePreview(parsePublishedTrace(trace)); })
      .catch(() => { if (!cancelled) setTracePreview([]); });
    return () => { cancelled = true; };
  }, [active]);
  const snippets = traceSnippets(tracePreview || []);
  return <section className="section library-preview"><div className="trace-heading"><div><span className="eyebrow">Library</span><h2>Featured traces.</h2></div></div>{collection === null && !loadError ? <div className="collection-pending" role="status"><b>Loading verified traces…</b><span>Retrieving admitted publications.</span></div> : loadError ? <div className="collection-pending" role="alert"><b>The Library is temporarily unavailable.</b><span>Open the Library to try again.</span></div> : visible.length ? <div className="preview-workspace"><div className="preview-records" aria-label="Featured traces">{visible.map((publication) => <button type="button" className={publication.id === active?.id ? 'active' : ''} onClick={() => setActiveId(publication.id)} aria-pressed={publication.id === active?.id} key={publication.id}><i aria-hidden="true" /><span><b>{publication.title}</b><small>{publication.provider} · {publication.model}</small></span><em>{publication.tags[0] || 'trace'}</em></button>)}</div>{active && <article className="preview-inspector"><header><span className="eyebrow">Selected trace</span><span className="inspector-status"><i aria-hidden="true" /> Verified</span></header><h3>{active.title}</h3><p>{active.provider} · {active.model}</p><div className="preview-contents">{snippets.length ? snippets.map((snippet) => <span key={snippet.label}><b>{snippet.label}</b><small>{snippet.text}</small></span>) : <span><b>Trace contents</b><small>Loading preview…</small></span>}</div><div className="preview-command"><span>Verify from the local service</span><code>POST /v1/public-traces/{active.id}/verify</code></div></article>}</div> : <div className="collection-pending"><b>No verified traces yet.</b><span>New publications will appear here as they are admitted.</span></div>}<a className="button button-dark" href="#/library">Open Library</a></section>;
}

function MotionStudies() {
  return <RelayAnimation />;
}

function Landing() {
  return <main id="top">
    <section className="hero">
      <HeroSignalField />
      <h1>Verifiable intelligence</h1>
      <p>Privacy-preserving LLM traces for open research and independent verification.</p>
      <div className="hero-actions"><a className="button button-dark" href="#/docs/getting-started">Get started</a><a className="button button-plain" href="#/library">Browse Library</a></div>
    </section>
    <MotionStudies />
    <PublishingArchitecture />
    <section className="section install capture">
      <div><span className="eyebrow">Local capture</span><h2>Capture locally.</h2><p>Point your existing tools at the local proxy. Provider calls keep streaming normally while encrypted bundles stay on your machine.</p></div>
      <div className="terminal"><div><i /><i /><i /></div><pre><code><b>$</b> {installCommand}{'\n\n'}<b>$</b> llm-notaryd{'\n\n'}proxy  <em>127.0.0.1:8787</em>{'\n'}admin  <em>127.0.0.1:8788</em></code></pre><a href="#/docs/getting-started">Installation and setup</a></div>
    </section>
    <CollectionPreview />
    <section className="section verify" id="verify">
      <div><span className="eyebrow">Independent verification</span><h2>Proof of origin.</h2><p>LLM Notary verifies the provider-authenticated exchange, then signs the exact trace hash. Anyone can check the signature and confirm the published trace has not been altered.</p><div className="verify-points"><span>OTLP JSON</span><span>Signed hash</span><span>Independently verifiable</span></div><div className="button-row"><a className="button button-dark" href="#/docs/trace-packages">Verify with the local API</a></div></div>
      <div className="receipt"><header><PenMark /><b>Publication stamp</b></header><h3>Verified</h3><dl><div><dt>Provider</dt><dd>api.openai.com</dd></div><div><dt>Artifact</dt><dd>trace.otlp.json</dd></div><div><dt>Trace hash</dt><dd>9b44f8…c21d</dd></div></dl><div className="receipt-contents"><span>Input messages <i>•••</i></span><span>Assistant responses <i>•••</i></span><span>Tool calls + results <i>•••</i></span></div><footer>LLM NOTARY / STAMP v1</footer></div>
    </section>
  </main>;
}

const docPages = {
  overview: {
    title: 'How LLM Notary fits.',
    lead: 'Run your existing model client through a local proxy, keep encrypted evidence on your machine, and turn only the interactions you choose into independently verifiable OpenTelemetry traces.',
    blocks: [
      {
        heading: 'The workflow',
        steps: [
          { title: 'Capture', body: 'Point an SDK or agent at the local proxy. Requests and streamed responses continue normally while each completed provider call becomes an encrypted local bundle.' },
          { title: 'Choose', body: 'Bundles wait on your disk. Nothing is published automatically, and interactive model use does not wait for the expensive proof step.' },
          { title: 'Finalize', body: 'Turn a selected bundle into authenticated TLS evidence and a deterministic OTel GenAI trace. This can happen long after the original model call.' },
          { title: 'Verify or publish', body: 'Check the package locally, keep it private, or deliberately publish its normalized trace for other people to inspect.' },
        ],
      },
      {
        heading: 'Three artifacts, three jobs',
        cards: [
          { meta: 'Private', title: 'Encrypted bundle', body: 'A sensitive local checkpoint that can be finalized later. It is not yet evidence another person can verify.' },
          { meta: 'Portable', title: 'Trace package', body: 'TLSNotary evidence, disclosed authenticated HTTP, canonical OTLP, and a manifest binding the files together.' },
          { meta: 'Public', title: 'Published trace', body: 'The canonical OTLP trace paired with an LLM Notary platform stamp and public metadata.' },
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
        body: 'The service retrieves the signed production notary directory over HTTPS and caches its key history. Finalized packages identify the notary key that signed their evidence; verification accepts it only if that key was trusted at the package timestamp. A self-hosted deployment pairs `notary.endpoint` with `notary.public_key` in `config.toml`, but that is not part of the normal hosted workflow.',
      },
    ],
  },
  'getting-started': {
    title: 'Install and capture.',
    lead: 'Install one local service, start its foreground process, and point each existing client at its provider path. You keep using the same API key and request shape.',
    blocks: [
      { heading: 'Install the service', code: installCommand },
      { heading: 'Supported systems', body: 'The installer selects checksum-verified macOS or Linux releases for Apple silicon, Intel, x86_64, and ARM64. Windows x86_64 is available as a ZIP release. Every package contains llm-notaryd for the service and llm-notary for short-lived commands.' },
      { heading: 'Start the service', code: 'llm-notaryd' },
      { heading: 'Open the local dashboard', body: 'Visit `http://127.0.0.1:8788` and use the tabs for captures, finalizations, trace verification, publishing, activity, and settings. The default loopback configuration opens directly. If `admin.auth` is enabled, sign in with its configured username and password; the dashboard exchanges them for an `HttpOnly` session and does not store the password.' },
      { heading: 'Configuration file', body: 'The first service start creates an editable `config.toml` at the standard user location: `~/.config/llm-notary` on Linux, `%APPDATA%\\llm-notary` on Windows, and `~/Library/Application Support/llm-notary` on macOS. It is written once and never replaced. Start with an explicit file when needed:', code: 'llm-notaryd --config /path/to/config.toml' },
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
      { heading: 'OpenRouter + Chat Completions', body: 'The model slug remains trace metadata. The resulting evidence authenticates OpenRouter—not the vendor named in that slug. Authorization is redacted; optional HTTP-Referer and X-Title attribution headers remain in the private capture.', code: 'curl http://127.0.0.1:8787/openrouter/api/v1/chat/completions \\\n  -H "Authorization: Bearer $OPENROUTER_API_KEY" \\\n  -H "Content-Type: application/json" \\\n  -H "HTTP-Referer: https://example.test" \\\n  -H "X-Title: LLM Notary example" \\\n  -d \'{"model":"openai/gpt-4o","stream":true,"messages":[{"role":"user","content":"Reply with exactly: llm-notary"}]}\'' },
      { heading: 'Where the API key comes from', body: 'Keep configuring credentials exactly as your SDK or agent expects—for example, OPENAI_API_KEY in your shell or secret manager. LLM Notary does not create, load, or require a .env file. A .env file is only one optional way your own application might populate environment variables.' },
      { heading: 'Provider boundary', body: 'The first local path segment selects a fixed adapter: /openai, /anthropic, /deepseek, or /openrouter. Each adapter fixes the upstream hostname to an explicit allowlist. The notary—not a caller-supplied URL—resolves and opens the provider connection.' },
      { heading: 'Codex + OpenAI', code: 'Add this to ~/.codex/config.toml:\n\nmodel_provider = "llm-notary"\nmodel = "gpt-5-mini"\nmodel_reasoning_effort = "low"\n\n[model_providers.llm-notary]\nname = "LLM Notary local proxy"\nbase_url = "http://127.0.0.1:8787/openai/v1"\nenv_key = "OPENAI_API_KEY"\nwire_api = "responses"\nsupports_websockets = false' },
      { heading: 'Run Codex', code: 'codex exec --ephemeral --ignore-user-config --skip-git-repo-check \\\n  -m gpt-5-mini \\\n  -c \'model_reasoning_effort="low"\' \\\n  \'Reply with exactly: hello\'' },
      { heading: 'Claude Code + Anthropic', code: 'ANTHROPIC_BASE_URL=http://127.0.0.1:8787/anthropic \\\nclaude --bare --no-session-persistence \\\n  -p --model claude-haiku-4-5-20251001 \\\n  \'Reply with exactly: hello\'' },
      { heading: 'OpenCode + DeepSeek', body: 'Set the provider base URL to http://127.0.0.1:8787/deepseek and retain DEEPSEEK_API_KEY in the OpenCode environment.' },
      { heading: 'Search local captures', body: 'Each completed provider interaction keeps its encrypted bundle and gains a row in the local SQLite catalog. Use the dashboard, or fetch the live OpenAPI document and query the local admin API:', code: 'curl "http://127.0.0.1:8788/v1/captures?query=pricing&model=gpt-5"' },
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
      { heading: 'Finalize one interaction', body: 'Select a pending capture identifier in the dashboard or admin API. The service writes to storage.finalized_dir/<capture-id> by default, records that package in the catalog, and retains the encrypted source bundle.', code: 'curl -X POST http://127.0.0.1:8788/v1/captures/cap-example/finalizations' },
      { heading: 'Notary discovery is automatic', body: 'For hosted use, the service refreshes the production notary directory, selects a worker compatible with the bundle, and verifies the resulting evidence against its locally pinned key history. For local or self-hosted use, set `notary.endpoint` and `notary.public_key` together in `config.toml`.' },
      { heading: 'Fresh notary connection', body: 'The original provider stream and proxy no longer need to be running. A new notary worker holding the same notary identity and key can complete finalization without a stored server-side checkpoint.' },
      { heading: 'Expect this step to take time', body: 'Private proof generation is slower than capture. Deferring it keeps the interactive agent response fast and makes proof work an explicit background or batch operation.' },
      { heading: 'Interruption behavior', body: 'The pending bundle is not consumed. If finalization fails or the service stops, retry the failed or interrupted durable operation through `POST /v1/operations/{operation_id}/retry`; proof work from the interrupted attempt is not resumed.' },
      { heading: 'Package layout', code: 'verified-trace/\n├── evidence.tlsn\n├── manifest.json\n├── request.disclosed.http\n├── response.http\n└── trace.otlp.json' },
      {
        heading: 'Artifact responsibilities',
        definitions: [
          { term: 'evidence.tlsn', description: 'The cryptographic TLSNotary evidence and notary signature.' },
          { term: 'request.disclosed.http', description: 'Authenticated request bytes selected for disclosure. Secret API-key header values remain redacted.' },
          { term: 'response.http', description: 'The authenticated provider response, including streamed events.' },
          { term: 'trace.otlp.json', description: 'A deterministic OpenTelemetry GenAI mapping of the authenticated request and response, including text, model-emitted tool calls, correlated tool results, model, and usage.' },
          { term: 'manifest.json', description: 'The versioned source metadata and trace hash. The cryptographic signature lives in evidence.tlsn, not in this JSON file.' },
        ],
      },
      { heading: 'Package versus publication', body: 'The finalized source package uses `manifest.json`. A later public trace pairs the canonical `trace.otlp.json` with a platform-issued `stamp.json`; that public stamp does not replace the private TLSNotary evidence.' },
      { heading: 'Inspect or verify a Library trace', code: 'GET /v1/public-traces/{publication_id}\nPOST /v1/public-traces/{publication_id}/verify', body: 'The local admin API resolves the publication through the public API and returns its canonical trace and stamp. The verify operation checks canonical bytes, trace hash, contract versions, platform key ID, stamp issuer, and signature without accepting an output path.' },
      { heading: 'Complete context is intentional', body: 'The raw verified package can include system context, tool definitions, session metadata, prompts, responses, and tool results. Inspect it before sharing. A future selective publication format can disclose less without weakening what the private source package proves.' },
      { heading: 'Verify locally', code: 'POST /v1/captures/{capture_id}/trace:verify' },
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
  publish: {
    title: 'Publish a trace package',
    lead: 'Publishing is a deliberate upload of one already-finalized package. The local service verifies it before it contacts LLM Notary.',
    blocks: [
      { heading: 'Authorize publication', body: 'Use the dashboard Publishing view, or begin the documented `POST /v1/publication/auth` device flow and poll its returned request identifier at the required interval.' },
      { heading: 'Submit one finalized package', code: 'POST /v1/captures/{capture_id}/publications' },
      { heading: 'Script-friendly output', code: `{"capture_id":"cap-…","job_id":"…","state":"queued","status_url":"${publicOrigin}/api/publish/jobs/…"}` },
      {
        heading: 'The upload boundary',
        columns: [
          {
            title: 'Uploaded',
            items: [
              'evidence.tlsn and manifest.json',
              'request.disclosed.http with secret header values redacted',
              'response.http with authenticated provider output',
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
      { heading: 'Local checks before upload', body: 'The service creates a deterministic, versioned archive containing exactly the five finalized-package files. It rejects extra files, symlinks, malformed manifests, untrusted evidence, and non-canonical trace bytes before it creates an upload job.' },
      { heading: 'Current consent boundary', body: 'The initial admission service may inspect the disclosed request, response, system context, and tool data in a package to verify and reproduce the public trace. Authentication headers and cookie values remain redacted. A future artifact can add a stronger privacy-preserving verifier under a new format version.' },
      { heading: 'Retry behavior', body: 'An upload or API failure does not change or delete the local package. Submitting the same capture again reuses the archive-derived idempotency key and resumes the retry-safe publication job.' },
    ],
  },
};

const docSubheadings = {
  'getting-started': new Set([
    'Supported systems',
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
    'Package versus publication',
    'Download a Library trace',
    'Complete context is intentional',
    'What verification checks',
    'Offline trust',
    'Tool-use boundary',
  ]),
  publish: new Set([
    'Submit one finalized package',
    'Script-friendly output',
    'Local checks before upload',
    'Current consent boundary',
    'Retry behavior',
  ]),
};

const docNavigation = [
  { label: 'Start', pages: [['overview', 'Overview'], ['getting-started', 'Install and capture']] },
  { label: 'Understand', pages: [['how-it-works', 'Trust model'], ['trace-packages', 'Trace packages']] },
  { label: 'Share', pages: [['publish', 'Publish']] },
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
  return <CommandDialog open={open} onOpenChange={(nextOpen) => { if (!nextOpen) onClose(); }} title="Search documentation" description="Search setup, captures, providers, and publishing." className="docs-command-dialog"><Command shouldFilter={false} className="docs-command"><CommandInput value={query} onValueChange={setQuery} placeholder="Search setup, captures, providers…" /><CommandList><CommandEmpty>No documentation matches “{query}”.</CommandEmpty>{results.map((result) => <CommandItem value={result.key} onSelect={() => choose(result)} key={result.key}><span className="docs-command-copy"><b>{result.title}</b><small>{result.lead}</small></span></CommandItem>)}</CommandList><div className="docs-command-footer"><span>↑↓ navigate</span><span>↵ open</span><span>esc close</span></div></Command></CommandDialog>;
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
  return <div className="span-tree" aria-label="Published trace spans">{spans.map((span, index) => {
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

function parsePublishedTrace(trace) {
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
  return <main className="library-shell library-shell--loading" aria-busy="true">
    <section className="library-controls library-loading-controls" aria-hidden="true">
      <i className="library-loading-control library-loading-control--search" />
      <i className="library-loading-control" />
      <i className="library-loading-control" />
      <i className="library-loading-control" />
    </section>
    <div className="library-browse-meta library-loading-meta"><span role="status">Loading library</span></div>
    <section className="library-results library-loading-results" aria-hidden="true">
      <div className="collection-workspace">
        <div className="collection-list">
          <div className="library-grid">{Array.from({ length: 5 }, (_, index) => <div className={`model-card library-loading-row${index === 0 ? ' is-current' : ''}`} key={index}><i /><span><b /><small /></span></div>)}</div>
        </div>
        <article className="collection-inspector library-loading-inspector">
          <header><i /><i /></header>
          <h2 />
          <div className="library-loading-facts">{Array.from({ length: 4 }, (_, index) => <i key={index} />)}</div>
          <div className="library-loading-document"><i /><i /><i /></div>
        </article>
      </div>
    </section>
  </main>;
}

function Collections() {
  const [collection, setCollection] = useState(null);
  const [loadError, setLoadError] = useState('');
  const [query, setQuery] = useState('');
  const [provider, setProvider] = useState('All');
  const [model, setModel] = useState('All');
  const [tag, setTag] = useState(null);
  const [sort, setSort] = useState('Newest');
  const [activeId, setActiveId] = useState(null);
  const [tracePreview, setTracePreview] = useState(null);
  const [traceError, setTraceError] = useState('');
  useEffect(() => {
    let cancelled = false;
    getTraceCollection()
      .then((payload) => { if (!cancelled) { setCollection(payload); setActiveId(payload.publications[0]?.id || null); } })
      .catch((error) => { if (!cancelled) setLoadError(error.message); });
    return () => { cancelled = true; };
  }, []);
  const publications = collection?.publications || [];
  const providers = ['All', ...new Set(publications.map((item) => item.provider))];
  const models = ['All', ...new Set(publications.map((item) => item.model))];
  const tags = [...new Set(publications.flatMap((item) => item.tags))];
  const filtered = useMemo(() => publications.filter((item) => {
    const searchable = `${item.title} ${item.provider} ${item.model} ${item.tags.join(' ')}`.toLowerCase();
    return searchable.includes(query.toLowerCase()) && (provider === 'All' || item.provider === provider) && (model === 'All' || item.model === model) && (!tag || item.tags.includes(tag));
  }).sort((left, right) => sort === 'Newest' ? right.admitted_at - left.admitted_at : sort === 'Downloads' ? right.recent_downloads - left.recent_downloads || right.admitted_at - left.admitted_at : left.title.localeCompare(right.title)), [publications, query, provider, model, tag, sort]);
  useEffect(() => {
    if (!filtered.length) {
      if (activeId !== null) setActiveId(null);
      return;
    }
    if (!filtered.some((item) => item.id === activeId)) setActiveId(filtered[0].id);
  }, [filtered, activeId]);
  const active = filtered.find((item) => item.id === activeId) || null;
  useEffect(() => {
    if (!active) {
      setTracePreview(null);
      setTraceError('');
      return;
    }
    let cancelled = false;
    setTracePreview(null);
    setTraceError('');
    getPublishedTrace(active.id)
      .then((trace) => { if (!cancelled) setTracePreview(parsePublishedTrace(trace)); })
      .catch((error) => { if (!cancelled) setTraceError(error.message); });
    return () => { cancelled = true; };
  }, [active]);
  if (collection === null && !loadError) return <LibraryLoading />;
  return <main className="library-shell">
    {loadError ? <section className="collection-empty" role="alert">{loadError}</section>
      : collection === null ? null
        : <>
          <section className="library-controls" aria-label="Browse traces">
            <label className="library-search"><span>Search traces</span><Input className="axis-library-input" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search by model, provider, or topic" /></label>
            <Select value={provider} onValueChange={setProvider}><SelectTrigger className="axis-select-trigger" aria-label="Provider"><SelectValue /></SelectTrigger><SelectContent className="axis-select-content">{providers.map((value) => <SelectItem value={value} key={value}>{value}</SelectItem>)}</SelectContent></Select>
            <Select value={model} onValueChange={setModel}><SelectTrigger className="axis-select-trigger" aria-label="Model"><SelectValue /></SelectTrigger><SelectContent className="axis-select-content">{models.map((value) => <SelectItem value={value} key={value}>{value}</SelectItem>)}</SelectContent></Select>
            <Select value={sort} onValueChange={setSort}><SelectTrigger className="axis-select-trigger" aria-label="Sort"><SelectValue /></SelectTrigger><SelectContent className="axis-select-content"><SelectItem value="Newest">Newest</SelectItem><SelectItem value="Downloads">Downloads</SelectItem><SelectItem value="Title">Title</SelectItem></SelectContent></Select>
          </section>
          <div className="library-browse-meta"><nav className="topic-filter" aria-label="Filter by topic">{tags.map((value) => <button key={value} className={tag === value ? 'active' : ''} aria-pressed={tag === value} onClick={() => setTag((current) => current === value ? null : value)}>{value}</button>)}</nav><span className="library-count">{filtered.length} {filtered.length === 1 ? 'trace' : 'traces'}</span></div>
          {publications.length === 0
            ? <section className="collection-empty"><b>Production examples are being prepared.</b><p>This page lists only admitted publications. No illustrative record is labeled verified.</p></section>
            : filtered.length === 0
              ? <section className="collection-empty"><b>No publications match these filters.</b><p>Clear a filter or try a broader search.</p></section>
              : <section className="library-results">
                <div className="collection-workspace">
                  <div className="collection-list">
                    <div className="library-grid">{filtered.map((item) => <button className={`model-card${activeId === item.id ? ' active' : ''}`} onClick={() => setActiveId(item.id)} aria-pressed={activeId === item.id} key={item.id}><span className="model-card-title">{item.title}</span><span className="model-card-model">{item.provider} · {item.model}<time>{new Date(item.admitted_at * 1000).toLocaleDateString()}</time></span>{item.tool_use && <span className="model-card-summary">tool use</span>}<span className="model-card-facts"><span><b>Publisher</b>{item.author}</span></span><span className="tag-list">{item.tags.map((value) => <span key={value}>{value}</span>)}</span></button>)}</div>
                  </div>
                  {active && <article className="collection-inspector"><header><span className="eyebrow">Selected trace</span><span className="inspector-status"><i aria-hidden="true" /> Verified</span></header><h2>{active.title}</h2><dl className="inspector-facts"><div><dt>Provider</dt><dd>{active.host}</dd></div><div><dt>Model</dt><dd>{active.model}</dd></div><div><dt>Publisher</dt><dd>{active.author}</dd></div><div><dt>Published</dt><dd>{new Date(active.admitted_at * 1000).toLocaleDateString()}</dd></div></dl><div className="trace-download"><span>Local verification</span><code>POST /v1/public-traces/{active.id}/verify</code><small>Use the local service to fetch the trace and verify its platform stamp.</small></div><section className="span-panel"><div className="span-panel-head"><span>Trace contents</span><small>{active.span_count} {active.span_count === 1 ? 'span' : 'spans'}</small></div><div className="trace-legend"><span><i className="source" /> Fields derived from verified provider exchanges</span></div>{traceError ? <p className="trace-preview-state">{traceError}</p> : tracePreview === null ? <p className="trace-preview-state">Loading messages…</p> : <SpanTree spans={tracePreview} />}</section></article>}
                </div>
              </section>}
        </>}
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

function publishState(state) {
  if (state === 'admitted') return { label: 'Verified', tone: 'verified' };
  if (state === 'queued') return { label: 'Queued', tone: 'pending' };
  if (state === 'verifying') return { label: 'Verifying', tone: 'pending' };
  if (state === 'uploading') return { label: 'Uploading', tone: 'pending' };
  if (state === 'rejected') return { label: 'Rejected', tone: 'attention' };
  if (state === 'expired') return { label: 'Expired', tone: 'attention' };
  if (state === 'failed') return { label: 'Failed', tone: 'attention' };
  return { label: state, tone: 'neutral' };
}

function Dashboard({ user, view, onPlanChange }) {
  const [sessions, setSessions] = useState(null);
  const [sessionError, setSessionError] = useState(null);
  const [revoking, setRevoking] = useState(null);
  const [revokeTarget, setRevokeTarget] = useState(null);
  const [jobs, setJobs] = useState(null);
  const [jobError, setJobError] = useState(null);
  const [publicationById, setPublicationById] = useState({});
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
    getPublishJobs()
      .then((jobs) => { if (!cancelled) setJobs(jobs); })
      .catch((reason) => { if (!cancelled) setJobError(reason.message); });
    getTraceCollection()
      .then((payload) => {
        if (!cancelled && payload?.publications) {
          setPublicationById(Object.fromEntries(payload.publications.map((publication) => [publication.id, publication])));
        }
      })
      .catch(() => {});
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

  const verifiedCount = jobs?.filter((job) => job.state === 'admitted').length || 0;
  const activeCount = jobs?.filter((job) => ['uploading', 'queued', 'verifying'].includes(job.state)).length || 0;
  const activeView = view === 'traces' ? 'traces' : 'account';

  return <main className="dashboard-shell dashboard-shell--account">
    <div className="dashboard-layout">
      <aside className="dashboard-sidebar" aria-label="Dashboard navigation">
        <span className="eyebrow">Dashboard</span>
        <nav>
          <a className={activeView === 'account' ? 'active' : ''} href="#/dashboard" aria-current={activeView === 'account' ? 'page' : undefined}><span>Account</span></a>
          <a className={activeView === 'traces' ? 'active' : ''} href="#/dashboard/traces" aria-current={activeView === 'traces' ? 'page' : undefined}><span>Traces</span><small>{jobs === null ? '—' : jobs.length}</small></a>
        </nav>
      </aside>
      <div className="dashboard-page">
        {activeView === 'account' ? <>
          <header className="dashboard-page-header"><span className="eyebrow">Account</span><h1>Account</h1><p>Manage hosted service access and the local services connected to your account.</p></header>
          <div className="dashboard-summary">
            <div><span>GitHub account</span><b>{user.github_login}</b></div>
            <div><span>Verified traces</span><b>{jobs === null ? '—' : verifiedCount}</b></div>
            <div><span>In progress</span><b>{jobs === null ? '—' : activeCount}</b></div>
          </div>
          <section className="dashboard-plan" aria-labelledby="service-plan-title">
            <header><div><span className="eyebrow">Hosted notary access</span><h2 id="service-plan-title">{plan === 'paid_preview' ? 'Paid preview' : 'Free'} plan</h2></div><span className="dashboard-plan-badge">{plan === 'paid_preview' ? 'No charge' : 'Included'}</span></header>
            <p>{plan === 'paid_preview' ? 'Paid preview unlocks the higher hosted-service limits while billing is still disabled. It creates no charge or payment obligation.' : 'Upgrade to the paid preview to try the higher hosted-service limits. Billing is not enabled and no payment method is required.'}</p>
            {entitlements && <dl><div><dt>Concurrent sessions</dt><dd>{entitlements.account_concurrency ?? 'Shared public pool'}</dd></div><div><dt>Session timeout</dt><dd>{Math.round(entitlements.session_timeout_secs / 60)} min</dd></div><div><dt>Maximum capture</dt><dd>{fileSize(entitlements.max_attestable_http_bytes)}</dd></div><div><dt>Proof credits left</dt><dd>{fileSize(entitlements.remaining_finalization_bytes)}</dd></div><div><dt>Starts per minute</dt><dd>{entitlements.starts_per_minute}</dd></div></dl>}
            {planError && <p className="dashboard-session-error" role="alert">{planError}</p>}
            <button type="button" onClick={() => changePlan(plan === 'paid_preview' ? 'free' : 'paid_preview')} disabled={planChanging}>{planChanging ? 'Updating…' : plan === 'paid_preview' ? 'Return to free' : 'Upgrade to paid preview'}</button>
          </section>
          <section className="dashboard-sessions" aria-labelledby="publishing-sessions-title"><header><div><span className="eyebrow">Local service access</span><h2 id="publishing-sessions-title">Connected devices</h2></div></header>{sessionError && <p className="dashboard-session-error" role="alert">{sessionError}</p>}{sessions === null && !sessionError ? <p className="dashboard-session-empty">Loading connected devices…</p> : sessions?.length ? <div className="dashboard-session-list">{sessions.map((session) => <article key={session.id}><div><b>{session.device_name}</b><span>Created {sessionDate(session.created_at)} · Last used {sessionDate(session.last_used_at)} · Expires {sessionDate(session.expires_at)}</span></div><button type="button" onClick={() => setRevokeTarget(session)} disabled={revoking === session.id}>{revoking === session.id ? 'Revoking…' : 'Revoke'}</button></article>)}</div> : <p className="dashboard-session-empty">No local services are connected.</p>}</section>
        </> : <>
          <header className="dashboard-page-header"><span className="eyebrow">Traces</span><h1>Your traces</h1><p>Review publication status and download the public evidence attached to your account.</p></header>
          <section className="dashboard-traces" aria-label="Your traces">
            {jobError && <p className="dashboard-session-error" role="alert">{jobError}</p>}
            {jobs === null && !jobError ? <p className="dashboard-session-empty">Loading your traces…</p> : jobs?.length ? <div className="dashboard-trace-list">{jobs.map((job) => {
              const publication = publicationById[job.id];
              const status = publishState(job.state);
              return <article key={job.id}>
                <div className="dashboard-trace-copy">
                  <div><span className={`dashboard-trace-state dashboard-trace-state--${status.tone}`}><i aria-hidden="true" />{status.label}</span><time>{sessionDate(job.admitted_at || job.updated_at)}</time></div>
                  <h3>{publication?.title || `Trace ${job.id.slice(0, 8)}`}</h3>
                  <p>{publication ? `${publication.provider} · ${publication.model}` : `${fileSize(job.size_bytes)} · ${job.id}`}</p>
                  {job.failure_code && <p className="dashboard-trace-failure">Reason: {job.failure_code.replaceAll('_', ' ')}</p>}
                </div>
                <div className="dashboard-trace-actions">
                  {job.trace_url && <a href={job.trace_url} target="_blank" rel="noreferrer">Trace</a>}
                  {job.stamp_url && <a href={job.stamp_url} target="_blank" rel="noreferrer">Stamp</a>}
                </div>
              </article>;
            })}</div> : <div className="dashboard-empty dashboard-empty--traces"><span className="eyebrow">No publications</span><b>Publish your first trace.</b><p>Finalize a capture in the local dashboard, then publish its evidence to make it independently verifiable.</p><a href="#/docs/publish">Open the publishing guide</a></div>}
          </section>
        </>}
      </div>
    </div>
    <AlertDialog open={Boolean(revokeTarget)} onOpenChange={(nextOpen) => { if (!nextOpen && !revoking) setRevokeTarget(null); }}><AlertDialogContent className="axis-alert-dialog"><AlertDialogHeader><AlertDialogTitle>Revoke {revokeTarget?.device_name}?</AlertDialogTitle><AlertDialogDescription>This local service will return to public hosted limits and need a new browser approval for account access or publication.</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel disabled={Boolean(revoking)}>Keep authorization</AlertDialogCancel><AlertDialogAction disabled={Boolean(revoking)} onClick={() => revokeTarget && revoke(revokeTarget)}>{revoking ? 'Revoking…' : 'Revoke device'}</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>
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
  return <main className="dashboard-shell"><span className="eyebrow">Local service authorization</span><h1>Approve this service?</h1>{error ? <p>{error}</p> : details ? <><p>Connect <b>{details.device_name}</b> to LLM Notary as <b>{user.github_login}</b> for hosted access and publication?</p><div className="dashboard-card"><span>Authorization code</span><b>{details.user_code}</b><span>Expires {sessionDate(details.expires_at)}</span><button className="button button-dark" onClick={approve}>Approve service</button></div></> : <p>Checking this authorization request…</p>}</main>;
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
  const routePath = path.split('?')[0];
  const [section, page] = routePath.split('/');
  const sectionAnchor = new URLSearchParams(path.split('?')[1] || '').get('section');
  const isLibrary = section === 'library' || section === 'traces' || section === 'collections';
  const updatePlan = (response) => setUser((current) => current ? { ...current, plan: response.plan, entitlements: response.entitlements } : current);
  return <><Header user={user} onLogout={logout} theme={theme} onThemeChange={setTheme} />{section === 'authorize' ? <CliApproval route={path} user={user} /> : section === 'docs' ? <Docs pageKey={page || 'overview'} section={sectionAnchor} /> : isLibrary ? <Collections /> : section === 'notaries' ? <NotariesPage /> : section === 'dashboard' && user ? <Dashboard user={user} view={page} onPlanChange={updatePlan} /> : legalPages[section] ? <LegalPage pageKey={section} /> : <Landing />}{!isLibrary && <Footer />}</>;
}

const applicationRoot = document.getElementById('root');
if (applicationRoot) createRoot(applicationRoot).render(<App />);
