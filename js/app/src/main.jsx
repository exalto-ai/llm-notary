import { Children, cloneElement, useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';
import './refinements.css';
import './commons.css';
import './theme.css';
import './branding.css';
import './account.css';
import './collections.css';
import './docs.css';
import './relay-animation.css';
import { RelayAnimation } from './RelayAnimation';

const installCommand = 'curl -fsSLO https://llmnotary.exalto.ai/install.sh && sh install.sh';
const publishCommand = 'llm-notary publish verified-trace';
const brandAssetVersion = __BRAND_ASSET_VERSION__;

function PenMark({ inverse = false }) {
  return <span className={`pen-mark${inverse ? ' pen-mark--inverse' : ''}`} aria-hidden="true">{inverse ? <img src={`/logo-light.png?v=${brandAssetVersion}`} alt="" /> : <picture><source media="(prefers-color-scheme: dark)" srcSet={`/logo-light.png?v=${brandAssetVersion}`} /><img src={`/logo-dark.png?v=${brandAssetVersion}`} alt="" /></picture>}</span>;
}

function CloseIcon() { return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18" /></svg>; }
function Arrow() { return <div className="flow-arrow" aria-label="Encrypted connection"><span>encrypted</span><svg viewBox="0 0 68 14" preserveAspectRatio="none" aria-hidden="true"><path d="M1 7h61M56 2l6 5-6 5" /></svg></div>; }
function FlowNode({ type, title, note }) { return <div className={`flow-node flow-node--${type}`}><span className="node-mark" aria-hidden="true" /><strong>{title}</strong><small>{note}</small></div>; }

function AccountMenu({ user, onLogout }) {
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
  return <div className="account-menu" ref={menuRef}><button type="button" className="account-trigger" onClick={() => setOpen((value) => !value)} aria-expanded={open} aria-haspopup="menu" aria-label={`Account menu for ${user.github_login}`}>{user.avatar_url ? <img src={user.avatar_url} alt="" referrerPolicy="no-referrer" /> : <span>{initials}</span>}</button>{open && <div className="account-popover" role="menu"><div className="account-identity"><b>{user.github_login}</b><span>Signed in with GitHub</span></div><a href="#/dashboard" role="menuitem" onClick={() => setOpen(false)}>Dashboard</a><button type="button" role="menuitem" onClick={() => { setOpen(false); onLogout(); }}>Log out</button></div>}</div>;
}

function Header({ user, onLogout }) {
  return <header className="nav-wrap"><a className="brand" href="#/"><PenMark /> <span>LLM Notary</span></a><nav className="product-nav"><a href="#/docs">Docs</a><a href="#/collections">Collections</a>{user ? <AccountMenu user={user} onLogout={onLogout} /> : <a className="sign-in-link" href="/api/auth/github">Sign in</a>}</nav></header>;
}

function Footer() {
  return <footer className="site-footer"><a className="brand" href="#/"><PenMark /> <span>LLM Notary</span></a><span>Verified source. Portable spans.</span><span>© 2026 LLM Notary</span></footer>;
}

function Diagram() {
  return <div className="diagram-card"><div className="diagram-label">Private verification path</div><div className="flow" aria-label="Your machine connects through LLM Notary to the AI provider"><FlowNode type="local" title="Your machine" note="Local capture" /><Arrow /><FlowNode type="notary" title="LLM Notary" note="TLS witness" /><Arrow /><FlowNode type="provider" title="AI provider" note="OpenAI · Anthropic · DeepSeek" /></div><div className="diagram-foot">The provider exchange is used once to verify publication. Collections store the normalized OpenTelemetry trace and the platform stamp—not the raw capture.</div></div>;
}

function MotionStudy({ number, title, description, children }) {
  return <article className="motion-study"><header><span>{number}</span><div><h3>{title}</h3><p>{description}</p></div></header>{children}</article>;
}

function MotionStudiesBase() {
  return <section className="motion-studies" aria-labelledby="motion-studies-title"><div className="motion-studies-head"><div><span className="eyebrow">Motion studies / prototype</span><h2 id="motion-studies-title">Three ways to show one trusted completion.</h2></div><p>Each loop tells the same true story: your local proxy holds plaintext, while LLM Notary witnesses encrypted traffic and issues evidence after the call completes.</p></div><div className="motion-study-grid"><MotionStudy number="01" title="The encrypted relay" description="A direct, systems-level account of the connection."><div className="relay-stage motion-stage" aria-label="An encrypted request and response move between your machine and an AI provider through LLM Notary"><div className="study-node study-node--local"><b>YOUR MACHINE</b><span className="study-lines"><i /><i /><i /></span><small>plaintext here</small></div><div className="study-track"><span className="study-packet study-packet--request">8F3</span><span className="study-packet study-packet--response">2A9</span><em>encrypted TLS</em></div><div className="study-node study-node--notary"><b>LLM NOTARY</b><strong>01 10</strong><small>ciphertext only</small></div><div className="study-track study-track--short"><span className="study-packet study-packet--request">8F3</span><span className="study-packet study-packet--response">2A9</span></div><div className="study-node study-node--provider"><b>AI PROVIDER</b><span className="study-spark">✦</span><small>response</small></div><div className="notary-branch" aria-hidden="true"><i /></div><div className="certificate-ledger"><header><i /> YOUR CERTIFICATE</header><p><span>01</span> 9c7f… encrypted record</p><p><span>02</span> a214… encrypted record</p><footer>SEALS ON FINAL EVENT</footer></div></div><footer><i /> The notary sees ciphertext; your certificate seals after streaming ends</footer></MotionStudy><MotionStudy number="02" title="The receipt assembles" description="Evidence is the hero, created after the stream ends."><div className="receipt-stage motion-stage" aria-label="A streamed completion finishes and its receipt is assembled"><div className="completion-stream"><span>drafting response</span><i /><i /><i /><i /><b>terminal event</b></div><div className="assembly-path" aria-hidden="true"><span /><i /></div><div className="mini-receipt"><header><i /> TRACE PACKAGE</header><dl><div><dt>Provider</dt><dd>api.openai.com</dd></div><div><dt>Evidence</dt><dd>verified</dd></div></dl><footer>LLM NOTARY / v0.1</footer></div></div><footer><i /> A receipt appears only when the call is complete</footer></MotionStudy><MotionStudy number="03" title="The privacy boundary" description="Plaintext and proof are kept visually, and conceptually, separate."><div className="boundary-stage motion-stage" aria-label="Private local prompt is distinct from encrypted traffic and shareable proof"><div className="private-panel"><b>LOCAL ONLY</b><span>Summarize the confidential findings from…</span><i>PRIVATE</i></div><div className="boundary-wall"><span>NOTARY</span><b>ENCRYPTED<br />RECORDS</b></div><div className="proof-panel"><b>SHAREABLE PROOF</b><span><i /> Provider connection verified</span><small>Choose what to disclose</small></div></div><footer><i /> Prompts and responses never appear in the witness lane</footer></MotionStudy></div></section>;
}

function FeaturedRelayStudy() {
  return <article className="featured-relay"><header><span>01</span><div><h3>The encrypted relay</h3><p>Your machine is the plaintext boundary. LLM Notary sees ciphertext only, while encrypted transcript records accumulate into your certificate.</p></div></header><div className="featured-relay-stage" aria-label="Your machine contains a certificate, local TLS proxy, and agent. LLM Notary sees encrypted traffic only."><section className="machine-boundary"><header><b>YOUR MACHINE</b><span>plaintext boundary</span></header><div className="machine-module certificate-module"><b>YOUR CERTIFICATE</b><p><span>01</span> 9c7f… encrypted record</p><p><span>02</span> a214… encrypted record</p><small>seals on final event</small></div><div className="machine-module proxy-module"><b>LOCAL TLS PROXY</b><span><i>8F3</i><em>decrypts here</em><i>2A9</i></span><small>encrypted in / plaintext out</small></div><div className="machine-module agent-module"><b>YOUR AGENT</b><span><i /><i /><i /></span><small>reads the plaintext response</small></div></section><div className="notary-column"><div className="notary-box"><b>LLM NOTARY</b><strong>01 10<br />10 01</strong><small>ciphertext only</small></div><div className="certificate-lane"><i>9C7F</i><span>encrypted record</span></div></div><section className="provider-box"><b>AI PROVIDER</b><strong>✦</strong><small>streaming response</small><div className="provider-packet">2A9</div></section><div className="relay-wire relay-wire--main" aria-hidden="true" /><div className="relay-wire relay-wire--certificate" aria-hidden="true" /></div><footer><i /> Readable prompts and responses exist only inside your machine; the notary witnesses encrypted records and your certificate seals after the final stream event.</footer></article>;
}

function MotionStudies() {
  return <RelayAnimation />;
}

function FeaturedRelayStudyV2() {
  return <article className="relay-v2"><header><span>01</span><div><h3>One completion, two local outcomes.</h3><p>The provider’s encrypted stream travels through the notary to your local TLS proxy. There, it becomes useful model output for your agent and a verifiable certificate for you.</p></div></header><div className="relay-v2-stage" aria-label="AI provider sends encrypted response through LLM Notary to local TLS proxy, which provides plaintext to agent and proof to certificate."><section className="v2-provider"><b>AI PROVIDER</b><strong>OpenAI</strong><small>streaming completion</small><span className="v2-provider-lines"><i /><i /><i /></span></section><div className="v2-link v2-link--provider"><span>2A9</span><small>encrypted response</small></div><section className="v2-notary"><b>LLM NOTARY</b><strong>8F 3C<br />A2 19</strong><small>ciphertext only</small><i>cannot read</i></section><div className="v2-link v2-link--notary"><span>2A9</span></div><section className="v2-proxy"><b>LOCAL TLS PROXY</b><strong><i>2A9</i><span>decrypts<br />locally</span></strong><small>your machine</small></section><div className="v2-fan v2-fan--agent"><span>plaintext</span></div><div className="v2-fan v2-fan--certificate"><span>proof</span></div><section className="v2-agent"><header><b>YOUR AGENT</b><span>plaintext output</span></header><p>I found three concrete changes to improve reliability:</p><ul><li>Retry the failed request</li><li>Record the provider model</li><li>Verify before sharing</li></ul></section><section className="v2-certificate"><header><b>YOUR CERTIFICATE</b><span className="v2-seal">CERTIFIED</span></header><dl><div><dt>Provider</dt><dd>api.openai.com</dd></div><div><dt>Model</dt><dd>gpt-4.1</dd></div><div><dt>Stream</dt><dd>complete</dd></div></dl><footer><i /> notary evidence attached</footer></section></div><footer><i /> The notary never receives plaintext. The local proxy fans the completion into useful output and independently verifiable evidence.</footer></article>;
}

function VerifierDialog({ onClose }) {
  const [fileName, setFileName] = useState('');
  useEffect(() => { const close = (event) => event.key === 'Escape' && onClose(); window.addEventListener('keydown', close); return () => window.removeEventListener('keydown', close); }, [onClose]);
  return <div className="modal-backdrop" role="presentation" onMouseDown={onClose}><section className="verifier-modal" role="dialog" aria-modal="true" aria-labelledby="verifier-title" onMouseDown={(event) => event.stopPropagation()}><button className="icon-button" onClick={onClose} aria-label="Close verifier"><CloseIcon /></button><span className="eyebrow">Stamp verifier</span><h2 id="verifier-title">Inspect a publication</h2><p>Choose an OTLP trace or its accompanying LLM Notary stamp. The verifier checks that the stamp signs this exact standardized trace.</p><label className="drop-zone"><input type="file" accept=".json" onChange={(event) => setFileName(event.target.files?.[0]?.name || '')} /><strong>{fileName || 'Choose a trace or stamp'}</strong><small>{fileName ? 'Selected locally' : 'trace.otlp.json or stamp.json'}</small></label><div className="verification-state"><i /> Use <code>llm-notary verify-public</code> for a cryptographic check</div></section></div>;
}

function LandingBase({ onVerify }) {
// Current landing content.
  return <main id="top"><section className="hero"><span className="eyebrow">LLM Notary</span><h1>Publish model behavior<br />as portable spans.</h1><p>LLM Notary verifies a private provider capture, then publishes a standardized OpenTelemetry trace with a signed platform stamp. The raw exchange stays out of the collection.</p><div className="hero-actions"><a className="button button-dark" href="#/docs/publish">Publish a trace</a><a className="button button-plain" href="#/collections">Browse collections</a></div><div className="hero-metadata"><span>For research, evaluation, and safety work</span><b /><span>Private proof. Public standard.</span></div></section><section className="section architecture" id="how-it-works"><div className="section-head"><span className="eyebrow">How publishing works</span><h2>Verify the source.<br />Keep the standard.</h2></div><div className="architecture-grid"><Diagram /><div className="step-list"><article><span>01</span><div><h3>Capture privately</h3><p>Your local proxy records a provider call and its TLSNotary evidence. API keys and private capture data remain under your control.</p></div></article><article><span>02</span><div><h3>Publish standardized spans</h3><p>The platform checks the capture, then admits a normalized OTLP trace: messages, model spans, tool calls, timing, and usage.</p></div></article><article><span>03</span><div><h3>Verify the platform stamp</h3><p>Readers compare the trace hash with a compact signed stamp. They do not need your raw request, response, or TLS evidence.</p></div></article></div></div><div className="section-link"><a href="#/docs/how-it-works">Read the publishing trust model</a></div></section><section className="privacy"><div><span className="eyebrow">Private by design</span><h2>Proof is not the product.</h2></div><p>The private capture proves the trace is real at publication time. The shared artifact is clean OTLP JSON plus a platform signature, built for reuse rather than archival of raw provider traffic.</p></section><section className="section library-preview"><div className="trace-heading"><div><span className="eyebrow">Collections</span><h2>Traces with a shared language.</h2></div><p>The collection is production-backed: a record appears only after its uploaded source package is admitted and stamped.</p></div><div className="collection-pending"><b>LLM Notary Examples</b><span>Verified examples will appear here after the inaugural production run.</span></div><a className="button button-dark" href="#/collections">Open collections</a></section><section className="section verify" id="verify"><div><span className="eyebrow">Independent verification</span><h2>One small stamp.<br />One exact trace.</h2><p>The stamp binds a trace hash to LLM Notary’s verification result. Download the standardized trace, check the platform signature, and use it in your own tooling.</p><div className="verify-points"><span>OTLP JSON</span><span>Signed hash</span><span>No raw capture</span></div><div className="button-row"><a className="button button-dark" href="#/docs/verify">Verify with the CLI</a><button className="button button-plain" onClick={onVerify}>Preview verifier</button></div></div><div className="receipt"><header><PenMark inverse /><b>Publication stamp</b></header><h3>Verified</h3><dl><div><dt>Artifact</dt><dd>trace.otlp.json</dd></div><div><dt>Schema</dt><dd>OTel GenAI / v1</dd></div><div><dt>Source</dt><dd>Provider capture checked</dd></div><div><dt>Signature</dt><dd>LLM Notary platform key</dd></div></dl><footer>LLM NOTARY / STAMP v1</footer></div></section><section className="section install"><div><span className="eyebrow">Get started</span><h2>Capture locally.<br />Publish clearly.</h2></div><div className="terminal"><div><i /><i /><i /></div><pre><code><b>$</b> {installCommand}{'\n\n'}<b>$</b> {publishCommand}{'\n\n'}published  <em>trace.otlp.json + stamp.json</em></code></pre><a href="#/docs/publish">Publishing and format details</a></div></section></main>;
/* Legacy landing content retained in the historical commit:
  return <main id="top"><section className="hero"><span className="eyebrow">LLM Notary</span><h1>Share evidence of<br />how models behave.</h1><p>Keep model calls on your machine. Retain a trace package with a receipt that others can independently verify.</p><div className="hero-actions"><a className="button button-dark" href="#/docs/install">Install the CLI</a><a className="button button-plain" href="#/library">Browse the Library</a></div><div className="hero-metadata"><span>For research, evaluation, and safety work</span><b /><span>Local capture. Deliberate sharing.</span></div></section><MotionStudies /><section className="section architecture" id="how-it-works"><div className="section-head"><span className="eyebrow">How it works</span><h2>Capture locally. Verify anywhere.</h2></div><div className="architecture-grid"><Diagram /><div className="step-list"><article><span>01</span><div><h3>Run the local proxy</h3><p>Your SDK keeps its normal API shape while the proxy saves a trace package on your machine.</p></div></article><article><span>02</span><div><h3>Keep the evidence</h3><p>The notary signs evidence that the response came from the named provider connection.</p></div></article><article><span>03</span><div><h3>Share a chosen trace</h3><p>Review redactions and reuse terms before adding work to a research or evaluation collection.</p></div></article></div></div><div className="section-link"><a href="#/docs/how-it-works">Read how the trust model works</a></div></section><section className="privacy"><div><span className="eyebrow">Privacy by default</span><h2>Evidence without handing over your work.</h2></div><p>Captures stay local until you choose otherwise. The public Library is for intentionally shared, redacted records with clear reuse terms.</p></section><section className="section library-preview"><div className="trace-heading"><div><span className="eyebrow">Library</span><h2>Trace records with useful context.</h2></div><p>Searchable by provider, model, and topic. The records below are illustrative while the Library service is being built.</p></div><div className="preview-records">{records.slice(0, 3).map((record) => <article key={record.id}><i aria-hidden="true"/><div><h3>{record.title}</h3><p>{record.provider} · {record.model}</p></div><span>{record.tags[0]}</span></article>)}</div><a className="button button-dark" href="#/library">Open Library</a></section><section className="section verify" id="verify"><div><span className="eyebrow">Independent verification</span><h2>Inspect before you use it.</h2><p>Check a trace package and the trusted notary key locally. No account or upload is required for the CLI verifier.</p><div className="verify-points"><span>No account</span><span>No upload</span><span>Open format</span></div><div className="button-row"><a className="button button-dark" href="#/docs/verify">Verify with the CLI</a><button className="button button-plain" onClick={onVerify}>Preview browser flow</button></div></div><div className="receipt"><header><PenMark inverse /><b>Trace package</b></header><h3>Receipt</h3><dl><div><dt>Provider</dt><dd>api.openai.com</dd></div><div><dt>Model</dt><dd>gpt-4.1</dd></div><div><dt>Evidence</dt><dd>TLSNotary presentation</dd></div><div><dt>Reuse</dt><dd>CC BY 4.0</dd></div></dl><footer>LLM NOTARY / v0.1</footer></div></section><section className="section install"><div><span className="eyebrow">Get started</span><h2>Install once.<br />Keep using your tools.</h2></div><div className="terminal"><div><i /><i /><i /></div><pre><code><b>$</b> {installCommand}{'\n\n'}<b>$</b> llm-notary proxy start --provider openai{'\n\n'}listening  <em>127.0.0.1:8787</em>{'\n'}ready</code></pre><a href="#/docs/install">Installation and setup</a></div></section></main>;
*/
}

function Landing({ onVerify }) {
  const landing = LandingBase({ onVerify });
  const children = Children.toArray(landing.props.children);
  return cloneElement(landing, undefined, children[0], <MotionStudies key="relay-animation" />, ...children.slice(1));
}

const docPages = {
  overview: {
    title: 'Capture now. Prove later.',
    lead: 'LLM Notary lets an agent use OpenAI, Anthropic, or DeepSeek normally while saving a private bundle for each provider call. Finalize only the interactions you want to turn into independently verifiable OpenTelemetry traces.',
    blocks: [
      {
        heading: 'The lifecycle',
        steps: [
          { title: 'Run the proxy', body: 'Point your existing agent or SDK at the local LLM Notary endpoint. Requests and streamed responses continue to work normally.' },
          { title: 'Save a bundle', body: 'When a provider stream ends, the proxy writes an encrypted .llmbundle to your machine. Interactive work does not wait for proof generation.' },
          { title: 'Finalize later', body: 'Choose any saved bundle and reconnect to a notary. This is the slower step that creates signed TLSNotary evidence and a normalized trace.' },
          { title: 'Verify offline', body: 'The completed package can be checked with the notary public key, without the original bundle, provider, proxy, or a live notary.' },
        ],
      },
      {
        heading: 'Two artifact states',
        cards: [
          { meta: 'Pending', title: 'Encrypted bundle', body: 'A durable local checkpoint. It can be finalized later, but it is not yet evidence another person can verify.' },
          { meta: 'Finalized', title: 'Verified trace package', body: 'TLSNotary evidence, authenticated HTTP disclosure, deterministic OTLP, and a manifest binding the files together.' },
        ],
      },
      {
        heading: 'The claim',
        note: 'A trusted notary attests that the disclosed bytes came from an authenticated TLS interaction with the named model provider, and the OTLP representation is deterministically bound to those bytes.',
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
    ],
  },
  install: {
    title: 'Install the CLI',
    lead: 'The installer downloads a checksum-verified release for macOS or Linux. Windows releases are available as ZIP archives.',
    blocks: [
      { heading: 'Recommended install', code: installCommand },
      { heading: 'Supported packages', body: 'macOS: Apple silicon and Intel. Linux: x86_64 and ARM64. Windows: x86_64 ZIP release. Each archive contains the llm-notary command.' },
      { heading: 'Initialize bundle encryption', code: 'llm-notary vault init\n# Or choose a passphrase:\nllm-notary vault init --passphrase' },
      { heading: 'Vault behavior', body: 'By default, LLM Notary stores a random bundle key in the operating-system credential vault. Passphrase mode derives a key locally. An empty passphrase is allowed, but it does not provide meaningful protection if someone obtains both the bundle and vault configuration.' },
    ],
  },
  proxy: {
    title: 'Run the local proxy',
    lead: 'Start one provider adapter, point your existing client at it, and keep the provider API key in that client as usual.',
    blocks: [
      { heading: 'Start it', code: 'llm-notary proxy start \\\n  --provider openai \\\n  --bundle-dir bundles' },
      { heading: 'What happens online', body: 'The local proxy handles plaintext while the notary participates in the provider TLS connection without seeing application data. Provider response bytes stream back to your agent as they arrive.' },
      { heading: 'What happens at end-of-stream', body: 'The proxy seals encrypted deferred state into one .llmbundle. It does not perform the expensive final proof before returning control to your workflow.' },
      { heading: 'Compatibility probes', body: 'GET and HEAD probes are answered locally. They do not contact the provider or notary and do not create bundles.' },
    ],
  },
  bundles: {
    title: 'Manage pending bundles',
    lead: 'Bundles are private, encrypted checkpoints. Keep them for as long as you may want to prove an interaction, then finalize or remove them on your schedule.',
    blocks: [
      { heading: 'List bundles', code: 'llm-notary bundles list --bundle-dir bundles' },
      { heading: 'What a bundle is', body: 'A bundle contains encrypted client-side deferred protocol state plus capture metadata. It lets a later notary worker complete the proof without retaining server-side session storage.' },
      { heading: 'What a bundle is not', note: 'A pending bundle is not a signature, certificate, or publicly verifiable claim. Do not present the existence of a bundle as proof of a provider response.' },
      { heading: 'Failure and retry', body: 'If the proxy stops after the bundle is sealed, the bundle remains usable. If finalization is interrupted, retry from the same bundle; the interrupted finalization attempt starts over.' },
    ],
  },
  providers: {
    title: 'Configure a provider client',
    lead: 'Load your existing keys, then change only the provider base URL. The notary never receives the credential value.',
    blocks: [
      { heading: 'Load keys from .env', code: 'set -a\nsource .env\nset +a' },
      { heading: 'OpenAI', body: 'Use http://127.0.0.1:8787/v1 as the Responses API base URL.' },
      { heading: 'Anthropic', body: 'Use http://127.0.0.1:8787 as the Messages API base URL. Continue sending requests to /v1/messages.' },
      { heading: 'DeepSeek', body: 'Use http://127.0.0.1:8787 as the OpenAI-compatible base URL. Continue sending requests to /chat/completions.' },
      { heading: 'Provider boundary', body: 'The selected adapter fixes the upstream hostname to an explicit allowlist. The notary—not a caller-supplied URL—resolves and opens the provider connection.' },
    ],
  },
  harnesses: {
    title: 'Configure an agent',
    lead: 'Start the matching local proxy first, then use one of these recipes. Your provider credential remains in the agent environment.',
    blocks: [
      { heading: 'Codex + OpenAI', code: 'Add this to ~/.codex/config.toml:\n\nmodel_provider = "llm-notary"\n\n[model_providers.llm-notary]\nname = "LLM Notary local proxy"\nbase_url = "http://127.0.0.1:8787/v1"\nenv_key = "OPENAI_API_KEY"\nwire_api = "responses"\nsupports_websockets = false' },
      { heading: 'Run Codex', code: 'codex exec --ephemeral --skip-git-repo-check \\\n  -m gpt-4.1-mini \\\n  \'Reply with exactly: hello\'' },
      { heading: 'Claude Code + Anthropic', code: 'ANTHROPIC_BASE_URL=http://127.0.0.1:8787 \\\nclaude --bare --no-session-persistence \\\n  -p --model claude-haiku-4-5-20251001 \\\n  \'Reply with exactly: hello\'' },
      { heading: 'OpenCode + DeepSeek', body: 'Set the provider base URL to http://127.0.0.1:8787 and retain DEEPSEEK_API_KEY in the OpenCode environment.' },
    ],
  },
  finalize: {
    title: 'Finalize a bundle',
    lead: 'Finalization is the deliberate, computationally expensive step. It turns one pending local bundle into a self-contained verified trace package.',
    blocks: [
      { heading: 'Finalize one interaction', code: 'llm-notary finalize bundles/cap-....llmbundle \\\n  --output verified-trace \\\n  --trusted-notary-key <notary-public-key>' },
      { heading: 'Fresh notary connection', body: 'The original provider stream and proxy no longer need to be running. A new notary worker holding the same notary identity and key can complete finalization without a stored server-side checkpoint.' },
      { heading: 'Expect this step to take time', body: 'Private proof generation is slower than capture. Deferring it keeps the interactive agent response fast and makes proof work an explicit background or batch operation.' },
      { heading: 'Interruption behavior', body: 'The pending bundle is not consumed. If finalization fails or the process stops, run the command again; work from the interrupted attempt is not resumed.' },
    ],
  },
  artifacts: {
    title: 'Inside a trace package',
    lead: 'A finalized package keeps the raw authenticated evidence and its standardized representation together. The files have different jobs.',
    blocks: [
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
      { heading: 'Package versus publication', body: 'The finalized source package uses manifest.json. A later Collection publication can pair the canonical trace.otlp.json with a separate platform-issued stamp.json; that public stamp does not replace the private TLSNotary evidence.' },
      { heading: 'Complete context is intentional', body: 'The raw verified package can include system context, tool definitions, session metadata, prompts, responses, and tool results. Inspect it before sharing. A future selective publication format can disclose less without weakening what the private source package proves.' },
    ],
  },
  verify: {
    title: 'Verify a trace package',
    lead: 'Verification runs offline against the trusted notary public key. It does not need the original encrypted bundle, provider account, proxy, or a live notary.',
    blocks: [
      { heading: 'Verify locally', code: 'llm-notary verify-trace verified-trace \\\n  --trusted-notary-key <notary-public-key>' },
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
      { heading: 'Tool-use boundary', note: 'Verification proves that the model emitted a tool call and, on a later request, that the client sent a particular tool result. It does not prove the local tool actually executed.' },
    ],
  },
  publish: {
    title: 'Publish a trace package',
    lead: 'Publishing is a deliberate upload of one already-finalized package. The CLI verifies it locally before it contacts LLM Notary.',
    blocks: [
      { heading: 'Sign in once', code: 'llm-notary login' },
      { heading: 'Submit one finalized package', code: 'llm-notary publish verified-trace' },
      { heading: 'Script-friendly output', code: 'llm-notary publish verified-trace --json\n\n{"job_id":"…","state":"queued","status_url":"https://llmnotary.exalto.ai/api/publish/jobs/…"}' },
      { heading: 'What is uploaded', body: 'The CLI creates a deterministic, versioned archive containing only the five files in the finalized trace package. It rejects extra files, symlinks, malformed manifests, untrusted evidence, and non-canonical trace bytes before creating an upload job.' },
      { heading: 'What is never uploaded', note: 'Do not publish an encrypted .llmbundle. It contains private retry state and is rejected by the CLI. Finalization remains a separate, local choice.' },
      { heading: 'Current consent boundary', body: 'The initial admission service may inspect the disclosed request, response, system context, and tool data in a package to verify and reproduce the public trace. Authentication headers and cookie values remain redacted. A future artifact can add a stronger privacy-preserving verifier under a new format version.' },
      { heading: 'Retry behavior', body: 'An upload or API failure does not change or delete the local package. Run publish again to create a fresh retry-safe job.' },
    ],
  },
};

const docNavigation = [
  { label: 'Foundation', pages: [['overview', 'Overview'], ['how-it-works', 'Trust model']] },
  { label: 'Capture', pages: [['install', 'Install'], ['proxy', 'Proxy'], ['bundles', 'Bundles']] },
  { label: 'Connect', pages: [['providers', 'Providers'], ['harnesses', 'Agents']] },
  { label: 'Prove', pages: [['finalize', 'Finalize'], ['artifacts', 'Artifacts'], ['verify', 'Verify']] },
  { label: 'Share', pages: [['publish', 'Publish']] },
];
const docOrder = docNavigation.flatMap((group) => group.pages.map(([key]) => key));
const docAliases = {};
const previewDocPages = new Set(['overview', 'install', 'proxy', 'bundles', 'finalize', 'artifacts', 'verify', 'publish']);

function DocsBlock({ block }) {
  return <section><h2>{block.heading}</h2>{block.body && <p>{block.body}</p>}{block.code && <pre><code>{block.code}</code></pre>}{block.note && <aside className="docs-note">{block.note}</aside>}{block.items && <ul className="docs-list">{block.items.map((item) => <li key={item}>{item}</li>)}</ul>}{block.steps && <ol className="docs-flow">{block.steps.map((step, index) => <li key={step.title}><span>{String(index + 1).padStart(2, '0')}</span><div><b>{step.title}</b><p>{step.body}</p></div></li>)}</ol>}{block.cards && <div className="docs-card-grid">{block.cards.map((card) => <article key={`${card.meta}-${card.title}`}><span>{card.meta}</span><h3>{card.title}</h3><p>{card.body}</p></article>)}</div>}{block.definitions && <dl className="docs-definitions">{block.definitions.map((item) => <div key={item.term}><dt>{item.term}</dt><dd>{item.description}</dd></div>)}</dl>}</section>;
}

function Docs({ pageKey }) {
  const currentKey = docPages[pageKey] ? pageKey : docAliases[pageKey] || 'overview';
  const page = docPages[currentKey];
  const currentIndex = docOrder.indexOf(currentKey);
  const nextKey = docOrder[currentIndex + 1];
  const next = nextKey
    ? { href: `#/docs/${nextKey === 'overview' ? '' : nextKey}`, label: docPages[nextKey].title }
    : { href: '#/collections', label: 'Browse collections' };
  return <main className="docs-shell"><aside className="docs-sidebar"><span className="eyebrow">Documentation</span>{docNavigation.map((group) => <div className="docs-nav-group" key={group.label}><span className="docs-group">{group.label}</span>{group.pages.map(([key, label]) => <a className={currentKey === key ? 'active' : ''} href={key === 'overview' ? '#/docs' : `#/docs/${key}`} aria-current={currentKey === key ? 'page' : undefined} key={key}>{label}</a>)}</div>)}<div className="docs-nav-group"><span className="docs-group">Explore</span><a href="#/collections">Collections</a></div></aside><article className="docs-content"><span className="eyebrow">LLM Notary / Docs</span><h1>{page.title}</h1><p className="docs-lead">{page.lead}</p>{previewDocPages.has(currentKey) && <aside className="docs-preview"><b>Product preview</b><span>Deferred bundles, finalization, and <code>verify-trace</code> describe the next CLI release.</span></aside>}{page.blocks.map((block) => <DocsBlock block={block} key={block.heading} />)}<div className="docs-next"><span>Next</span><a href={next.href}>{next.label}</a></div></article></main>;
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
  return <div className="message-part"><span>text</span><p>{part.content}</p></div>;
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

function TraceEnvelope({ trace }) {
  return <section className="trace-envelope" aria-label="OpenTelemetry trace metadata"><div className="trace-envelope-head"><span>OTLP envelope</span><small>Illustrative preview</small></div><div className="trace-envelope-grid"><TraceField label="trace_id" value={trace.id} /><TraceField label="service.name" value={trace.service} /><TraceField label="llmnotary.format" value={trace.format} /><TraceField label="llmnotary.normalizer.version" value={trace.normalizer} /><TraceField label="otel.semconv.version" value={trace.semconv} /><TraceField label="instrumentation_scope" value={trace.scope} /></div></section>;
}

function CollectionCard({ collection, active, onSelect }) {
  return <button className={`model-card${active ? ' active' : ''}`} onClick={onSelect} aria-pressed={active}>
    <span className="model-card-top"><span><i aria-hidden="true" /> VERIFIED</span><time>{collection.date}</time></span>
    <span className="model-card-title">{collection.title}</span>
    <span className="model-card-model">{collection.provider} · {collection.model}</span>
    <span className="model-card-summary">{collection.summary}</span>
    <span className="model-card-facts"><span><b>Coverage</b>{collection.spanCount} spans</span><span><b>Evidence</b>{collection.evidence}</span><span><b>Schema</b>{collection.schema}</span></span>
    <span className="tag-list">{collection.tags.map((item) => <span key={item}>{item}</span>)}</span>
  </button>;
}

function CollectionInspector({ collection, onVerify }) {
  return <article className="collection-inspector">
    <header><span className="eyebrow">Selected publication</span><span className="inspector-status"><i aria-hidden="true" /> Verified</span></header>
    <h2>{collection.title}</h2>
    <p>{collection.summary}</p>
    <div className="publication-files"><span>trace.otlp.json</span><span>stamp.json</span></div>
    <dl className="inspector-facts"><div><dt>Provider</dt><dd>{collection.host}</dd></div><div><dt>Model</dt><dd>{collection.model}</dd></div><div><dt>Source evidence</dt><dd>{collection.evidence}</dd></div><div><dt>Trace hash</dt><dd>{collection.hash}</dd></div><div><dt>Reuse</dt><dd>{collection.license}</dd></div><div><dt>Published</dt><dd>{collection.date}</dd></div></dl>
    <TraceEnvelope trace={collection.trace} />
    <section className="span-panel"><div className="span-panel-head"><span>Trace spans</span><small>{collection.spans.length} of {collection.spanCount} spans shown</small></div><div className="trace-legend"><span><i className="source" /> Fields derived from verified provider exchanges</span></div><SpanTree spans={collection.spans} /></section>
    <div className="trace-actions"><button onClick={onVerify}>Verify platform stamp</button><a href="#/docs/artifacts">Trace format</a></div>
  </article>;
}

function Collections({ onVerify }) {
  const [collection, setCollection] = useState(null);
  const [loadError, setLoadError] = useState('');
  const [query, setQuery] = useState('');
  const [provider, setProvider] = useState('All');
  const [model, setModel] = useState('All');
  const [tag, setTag] = useState('All');
  const [sort, setSort] = useState('Newest');
  const [activeId, setActiveId] = useState(null);
  useEffect(() => {
    let cancelled = false;
    fetch('/api/public/collections/examples')
      .then(async (response) => response.ok ? response.json() : Promise.reject(new Error('Could not load the collection.')))
      .then((payload) => { if (!cancelled) { setCollection(payload); setActiveId(payload.publications[0]?.id || null); } })
      .catch((error) => { if (!cancelled) setLoadError(error.message); });
    return () => { cancelled = true; };
  }, []);
  const publications = collection?.publications || [];
  const providers = ['All', ...new Set(publications.map((item) => item.provider))];
  const models = ['All', ...new Set(publications.map((item) => item.model))];
  const tags = ['All', ...new Set(publications.flatMap((item) => item.tags))];
  const filtered = useMemo(() => publications.filter((item) => {
    const searchable = `${item.title} ${item.provider} ${item.model} ${item.surface} ${item.category} ${item.tags.join(' ')}`.toLowerCase();
    return searchable.includes(query.toLowerCase()) && (provider === 'All' || item.provider === provider) && (model === 'All' || item.model === model) && (tag === 'All' || item.tags.includes(tag));
  }).sort((left, right) => sort === 'Newest' ? right.admitted_at - left.admitted_at : left.title.localeCompare(right.title)), [publications, query, provider, model, tag, sort]);
  useEffect(() => {
    if (!filtered.length) {
      if (activeId !== null) setActiveId(null);
      return;
    }
    if (!filtered.some((item) => item.id === activeId)) setActiveId(filtered[0].id);
  }, [filtered, activeId]);
  const active = filtered.find((item) => item.id === activeId) || null;
  return <main className="library-shell">
    <header className="production-collection-head">
      <span className="eyebrow">Public collection</span>
      <h1>{collection?.title || 'LLM Notary Examples'}</h1>
      <p>{collection?.description || 'Loading admitted publications…'}</p>
    </header>
    {loadError ? <section className="collection-empty" role="alert">{loadError}</section>
      : collection === null ? <section className="collection-empty" role="status"><b>Loading publications…</b><p>Checking the admitted collection and its artifact metadata.</p></section>
        : <>
          <section className="library-controls" aria-label="Browse publications">
            <label className="library-search"><span>Search publications</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search by model, provider, surface, or topic" /></label>
            <label><span>Provider</span><select value={provider} onChange={(event) => setProvider(event.target.value)}>{providers.map((value) => <option key={value}>{value}</option>)}</select></label>
            <label><span>Model</span><select value={model} onChange={(event) => setModel(event.target.value)}>{models.map((value) => <option key={value}>{value}</option>)}</select></label>
            <label><span>Sort</span><select value={sort} onChange={(event) => setSort(event.target.value)}><option>Newest</option><option>Title</option></select></label>
          </section>
          <nav className="topic-filter" aria-label="Topics"><span>Topics</span>{tags.map((value) => <button key={value} className={tag === value ? 'active' : ''} onClick={() => setTag(value)}>{value}</button>)}</nav>
          {publications.length === 0
            ? <section className="collection-empty"><b>Production examples are being prepared.</b><p>This page lists only admitted publications. No illustrative record is labeled verified.</p></section>
            : filtered.length === 0
              ? <section className="collection-empty"><b>No publications match these filters.</b><p>Clear a filter or try a broader search.</p></section>
              : <section className="library-results">
                <div className="collection-workspace">
                  <div className="collection-list">
                    <div className="results-heading"><p><b>{filtered.length}</b> publications</p><span>{collection.consent_label}</span></div>
                    <div className="library-grid">{filtered.map((item) => <button className={`model-card${activeId === item.id ? ' active' : ''}`} onClick={() => setActiveId(item.id)} aria-pressed={activeId === item.id} key={item.id}><span className="model-card-top"><span><i aria-hidden="true" /> VERIFIED</span><time>{new Date(item.admitted_at * 1000).toLocaleDateString()}</time></span><span className="model-card-title">{item.title}</span><span className="model-card-model">{item.provider} · {item.model}</span><span className="model-card-summary">{item.category} · {item.surface}{item.tool_use ? ' · tool use' : ''}</span><span className="model-card-facts"><span><b>Coverage</b>{item.span_count} spans</span><span><b>Publisher</b>{item.author}</span><span><b>Disclosure</b>Consent-based</span></span><span className="tag-list">{item.tags.map((value) => <span key={value}>{value}</span>)}</span></button>)}</div>
                  </div>
                  {active && <article className="collection-inspector"><header><span className="eyebrow">Selected publication</span><span className="inspector-status"><i aria-hidden="true" /> Verified</span></header><h2>{active.title}</h2><p>{active.category} captured through {active.surface}. This record passed server admission and carries the platform stamp linked below.</p><dl className="inspector-facts"><div><dt>Provider</dt><dd>{active.host}</dd></div><div><dt>Model</dt><dd>{active.model}</dd></div><div><dt>Publisher</dt><dd>{active.author}</dd></div><div><dt>Tool use</dt><dd>{active.tool_use ? 'Yes' : 'No'}</dd></div><div><dt>Spans</dt><dd>{active.span_count}</dd></div><div><dt>Published</dt><dd>{new Date(active.admitted_at * 1000).toLocaleString()}</dd></div></dl><div className="trace-actions"><a href={active.trace_url} target="_blank" rel="noreferrer">Download trace</a><a href={active.stamp_url} target="_blank" rel="noreferrer">Download stamp</a><button onClick={onVerify}>Verify files</button></div><p className="consent-label">{collection.consent_label}: the service inspected the finalized disclosed package during admission.</p></article>}
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

function Dashboard({ user }) {
  const [sessions, setSessions] = useState(null);
  const [sessionError, setSessionError] = useState(null);
  const [revoking, setRevoking] = useState(null);
  const [jobs, setJobs] = useState(null);
  const [jobError, setJobError] = useState(null);
  const [publicationById, setPublicationById] = useState({});

  useEffect(() => {
    let cancelled = false;
    fetch('/api/cli/sessions', { credentials: 'same-origin' })
      .then(async (response) => response.ok ? response.json() : Promise.reject(new Error((await response.json().catch(() => ({}))).error || 'Could not load CLI sessions.')))
      .then((payload) => { if (!cancelled) setSessions(payload.sessions); })
      .catch((reason) => { if (!cancelled) setSessionError(reason.message); });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    let cancelled = false;
    fetch('/api/me/publish-jobs', { credentials: 'same-origin' })
      .then(async (response) => response.ok ? response.json() : Promise.reject(new Error((await response.json().catch(() => ({}))).error || 'Could not load your traces.')))
      .then((payload) => { if (!cancelled) setJobs(payload.jobs); })
      .catch((reason) => { if (!cancelled) setJobError(reason.message); });
    fetch('/api/public/collections/examples')
      .then((response) => response.ok ? response.json() : null)
      .then((payload) => {
        if (!cancelled && payload?.publications) {
          setPublicationById(Object.fromEntries(payload.publications.map((publication) => [publication.id, publication])));
        }
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, []);

  const revoke = async (session) => {
    if (!window.confirm(`Revoke ${session.device_name}? This CLI will need to sign in again before it can publish.`)) return;
    setRevoking(session.id);
    setSessionError(null);
    try {
      const response = await fetch(`/api/cli/sessions/${encodeURIComponent(session.id)}`, { method: 'DELETE', credentials: 'same-origin' });
      if (!response.ok) throw new Error((await response.json().catch(() => ({}))).error || 'Could not revoke this CLI session.');
      setSessions((current) => current?.filter((item) => item.id !== session.id) || []);
    } catch (reason) {
      setSessionError(reason.message);
    } finally {
      setRevoking(null);
    }
  };

  const verifiedCount = jobs?.filter((job) => job.state === 'admitted').length || 0;
  const activeCount = jobs?.filter((job) => ['uploading', 'queued', 'verifying'].includes(job.state)).length || 0;

  return <main className="dashboard-shell">
    <span className="eyebrow">Account</span>
    <h1>Your traces.</h1>
    <p>Review publication status and download the public evidence attached to your account.</p>
    <div className="dashboard-summary">
      <div><span>GitHub account</span><b>{user.github_login}</b></div>
      <div><span>Verified</span><b>{jobs === null ? '—' : verifiedCount}</b></div>
      <div><span>In progress</span><b>{jobs === null ? '—' : activeCount}</b></div>
    </div>
    <section className="dashboard-traces" aria-labelledby="published-traces-title">
      <header><div><span className="eyebrow">Publications</span><h2 id="published-traces-title">Your traces</h2></div><a href="#/docs/publish">Publish from the CLI</a></header>
      {jobError && <p className="dashboard-session-error" role="alert">{jobError}</p>}
      {jobs === null && !jobError ? <p className="dashboard-session-empty">Loading your traces…</p> : jobs?.length ? <div className="dashboard-trace-list">{jobs.map((job) => {
        const publication = publicationById[job.id];
        const status = publishState(job.state);
        return <article key={job.id}>
          <div className="dashboard-trace-copy">
            <div><span className={`dashboard-trace-state dashboard-trace-state--${status.tone}`}><i aria-hidden="true" />{status.label}</span><time>{sessionDate(job.admitted_at || job.updated_at)}</time></div>
            <h3>{publication?.title || `Trace ${job.id.slice(0, 8)}`}</h3>
            <p>{publication ? `${publication.provider} · ${publication.model} · ${publication.surface}` : `${fileSize(job.size_bytes)} · ${job.id}`}</p>
            {job.failure_code && <p className="dashboard-trace-failure">Reason: {job.failure_code.replaceAll('_', ' ')}</p>}
          </div>
          <div className="dashboard-trace-actions">
            {job.trace_url && <a href={job.trace_url} target="_blank" rel="noreferrer">Trace</a>}
            {job.stamp_url && <a href={job.stamp_url} target="_blank" rel="noreferrer">Stamp</a>}
          </div>
        </article>;
      })}</div> : <div className="dashboard-empty"><b>No published traces yet.</b><p>Finalize a bundle, then run <code>{publishCommand}</code>.</p><a href="#/docs/publish">Read the publishing guide</a></div>}
    </section>
    <section className="dashboard-sessions" aria-labelledby="cli-sessions-title"><header><div><span className="eyebrow">CLI access</span><h2 id="cli-sessions-title">Authorized devices</h2></div><p>Revoke a device to require a new browser sign-in before it can publish.</p></header>{sessionError && <p className="dashboard-session-error" role="alert">{sessionError}</p>}{sessions === null && !sessionError ? <p className="dashboard-session-empty">Loading authorized devices…</p> : sessions?.length ? <div className="dashboard-session-list">{sessions.map((session) => <article key={session.id}><div><b>{session.device_name}</b><span>Last used {sessionDate(session.last_used_at)} · Expires {sessionDate(session.expires_at)}</span></div><button type="button" onClick={() => revoke(session)} disabled={revoking === session.id}>{revoking === session.id ? 'Revoking…' : 'Revoke'}</button></article>)}</div> : <p className="dashboard-session-empty">No active CLI devices are authorized.</p>}</section>
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
    fetch(`/api/cli/authorizations/${encodeURIComponent(requestId)}/approval?approval_secret=${encodeURIComponent(approvalSecret)}`, { credentials: 'same-origin' })
      .then(async (response) => response.ok ? response.json() : Promise.reject(new Error((await response.json().catch(() => ({}))).error || 'This authorization request is unavailable.')))
      .then((payload) => { if (!cancelled) setDetails(payload); })
      .catch((reason) => { if (!cancelled) setError(reason.message); });
    return () => { cancelled = true; };
  }, [requestId, approvalSecret, user]);
  const approve = async () => {
    setError(null);
    const response = await fetch(`/api/cli/authorizations/${encodeURIComponent(requestId)}/approval?approval_secret=${encodeURIComponent(approvalSecret)}`, { method: 'POST', credentials: 'same-origin' });
    if (response.ok) setApproved(true);
    else setError((await response.json().catch(() => ({}))).error || 'Could not approve this CLI request.');
  };
  if (!requestId || !approvalSecret) return <main className="dashboard-shell"><span className="eyebrow">CLI authorization</span><h1>Invalid authorization link.</h1><p>Return to the CLI and start login again.</p></main>;
  if (!user) return <main className="dashboard-shell"><span className="eyebrow">CLI authorization</span><h1>Sign in to approve.</h1><p>This browser must be signed in to the LLM Notary account that should own the CLI publishing session.</p><a className="button button-dark" href={`/api/auth/github?return_to=${encodeURIComponent(window.location.hash)}`}>Sign in with GitHub</a></main>;
  if (approved) return <main className="dashboard-shell"><span className="eyebrow">CLI authorization</span><h1>CLI approved.</h1><p>Your terminal will finish signing in shortly. You can close this page.</p></main>;
  return <main className="dashboard-shell"><span className="eyebrow">CLI authorization</span><h1>Approve this CLI?</h1>{error ? <p>{error}</p> : details ? <><p>Allow <b>{details.device_name}</b> to publish through LLM Notary as <b>{user.github_login}</b>?</p><div className="dashboard-card"><span>Authorization code</span><b>{details.user_code}</b><button className="button button-dark" onClick={approve}>Approve CLI</button></div></> : <p>Checking this authorization request…</p>}</main>;
}

function App() {
  const [route, setRoute] = useState(window.location.hash || '#/');
  const [showVerifier, setShowVerifier] = useState(false);
  const [user, setUser] = useState(null);
  useEffect(() => { const update = () => setRoute(window.location.hash || '#/'); window.addEventListener('hashchange', update); return () => window.removeEventListener('hashchange', update); }, []);
  useEffect(() => { let cancelled = false; fetch('/api/me', { credentials: 'same-origin' }).then((response) => response.ok ? response.json() : null).then((payload) => { if (!cancelled) setUser(payload?.user || null); }).catch(() => { if (!cancelled) setUser(null); }); return () => { cancelled = true; }; }, []);
  const logout = async () => { const response = await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' }); if (response.ok) { setUser(null); if (window.location.hash === '#/dashboard') window.location.hash = '#/'; } };
  const path = route.replace(/^#\/?/, '');
  const routePath = path.split('?')[0];
  const [section, page] = routePath.split('/');
  return <><Header user={user} onLogout={logout} />{section === 'authorize' ? <CliApproval route={path} user={user} /> : section === 'docs' ? <Docs pageKey={page || 'overview'} /> : (section === 'collections' || section === 'library') ? <Collections onVerify={() => setShowVerifier(true)} /> : section === 'dashboard' && user ? <Dashboard user={user} /> : <Landing onVerify={() => setShowVerifier(true)} />}<Footer />{showVerifier && <VerifierDialog onClose={() => setShowVerifier(false)} />}</>;
}

createRoot(document.getElementById('root')).render(<App />);
