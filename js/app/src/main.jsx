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

const collections = [
  {
    id: 'refusal',
    title: 'Refusal boundary test',
    provider: 'OpenAI',
    host: 'api.openai.com',
    model: 'gpt-4.1',
    date: 'Jul 24, 2026',
    sortDate: 20260724,
    spanCount: 42,
    hash: 'a47e32…ef90',
    schema: 'GenAI trace / v1',
    evidence: '1 provider call checked',
    tags: ['Safety', 'Refusals'],
    license: 'CC BY 4.0',
    summary: 'A refusal-boundary evaluation published as a standardized trace. The platform stamp binds the normalized model span to a verified provider capture.',
    spans: [
      { depth: 0, kind: 'INTERNAL', name: 'invoke_workflow refusal-boundary', detail: '42 model turns', trust: 'runtime' },
      { depth: 1, kind: 'CLIENT', name: 'chat gpt-4.1', detail: 'gen_ai.operation.name = chat · 1,842 tokens', trust: 'source', messages: { input: [{ role: 'user', parts: [{ type: 'text', content: 'Respond to the evaluation prompt.' }] }], output: [{ role: 'assistant', parts: [{ type: 'text', content: 'I can’t help with that request.' }], finishReason: 'stop' }] } },
      { depth: 1, kind: 'INTERNAL', name: 'evaluate refusal classifier', detail: 'evaluation result = pass', trust: 'runtime' },
    ],
  },
  {
    id: 'tool',
    title: 'Tool-use evaluation',
    provider: 'Anthropic',
    host: 'api.anthropic.com',
    model: 'claude-sonnet-4',
    date: 'Jul 23, 2026',
    sortDate: 20260723,
    spanCount: 18,
    hash: 'c18b70…79aa',
    schema: 'GenAI trace / v1',
    evidence: '2 provider calls checked',
    tags: ['Evaluation', 'Tools'],
    license: 'CC BY 4.0',
    summary: 'An agent trace with a provider-verified model request, a declared tool call, and a separately marked runtime tool execution.',
    spans: [
      { depth: 0, kind: 'INTERNAL', name: 'invoke_agent travel-researcher', detail: '18 spans', trust: 'runtime' },
      { depth: 1, kind: 'CLIENT', name: 'chat claude-sonnet-4', detail: 'output tool_call = search_routes · call_01H', trust: 'source', messages: { input: [{ role: 'system', parts: [{ type: 'text', content: 'Plan grounded travel routes.' }] }, { role: 'user', parts: [{ type: 'text', content: 'Find a route from Seattle to Portland.' }] }], output: [{ role: 'assistant', parts: [{ type: 'tool_call', id: 'call_01H', name: 'search_routes', arguments: '{"origin":"Seattle","destination":"Portland"}' }] }] } },
      { depth: 2, kind: 'INTERNAL', name: 'execute_tool search_routes', detail: 'gen_ai.tool.call.id = call_01H · 342 ms', trust: 'runtime', attributes: [['gen_ai.tool.name', 'search_routes'], ['gen_ai.tool.call.id', 'call_01H'], ['gen_ai.tool.call.arguments', '{"origin":"Seattle","destination":"Portland"}'], ['gen_ai.tool.call.result', '{"routes":3}']] },
      { depth: 1, kind: 'CLIENT', name: 'chat claude-sonnet-4', detail: 'gen_ai.response.finish_reasons = stop', trust: 'source', messages: { input: [{ role: 'assistant', parts: [{ type: 'tool_call', id: 'call_01H', name: 'search_routes', arguments: '{"origin":"Seattle","destination":"Portland"}' }] }, { role: 'tool', parts: [{ type: 'tool_call_response', id: 'call_01H', result: '{"routes":3}' }] }], output: [{ role: 'assistant', parts: [{ type: 'text', content: 'The fastest route is Cascades service 507.' }], finishReason: 'stop' }] } },
    ],
  },
  {
    id: 'benchmark',
    title: 'Benchmark run #048',
    provider: 'OpenAI',
    host: 'api.openai.com',
    model: 'gpt-4.1-mini',
    date: 'Jul 19, 2026',
    sortDate: 20260719,
    spanCount: 200,
    hash: 'f10cd2…05b7',
    schema: 'GenAI trace / v1',
    evidence: '200 provider calls checked',
    tags: ['Research', 'Benchmark'],
    license: 'CC BY 4.0',
    summary: 'A portable span collection for one instruction-following benchmark slice, ready to inspect or move into another trace-aware analysis workflow.',
    spans: [
      { depth: 0, kind: 'INTERNAL', name: 'invoke_workflow if-benchmark-048', detail: '200 inference spans', trust: 'runtime' },
      { depth: 1, kind: 'CLIENT', name: 'chat gpt-4.1-mini', detail: 'gen_ai.response.finish_reasons = stop', trust: 'source' },
      { depth: 1, kind: 'INTERNAL', name: 'evaluate instruction-following', detail: 'score = 0.92', trust: 'runtime' },
    ],
  },
  {
    id: 'context',
    title: 'Long-context comparison',
    provider: 'Anthropic',
    host: 'api.anthropic.com',
    model: 'claude-opus-4',
    date: 'Jul 16, 2026',
    sortDate: 20260716,
    spanCount: 24,
    hash: 'd49186…3c4d',
    schema: 'GenAI trace / v1',
    evidence: '24 provider calls checked',
    tags: ['Research', 'Long context'],
    license: 'CC BY 4.0',
    summary: 'A multi-turn comparison with normalized input and output messages, provider/model metadata, timing, and a signed platform verification result.',
    spans: [
      { depth: 0, kind: 'INTERNAL', name: 'invoke_workflow long-context-compare', detail: '24 inference spans', trust: 'runtime' },
      { depth: 1, kind: 'CLIENT', name: 'chat claude-opus-4', detail: 'gen_ai.usage.input_tokens = 24,821', trust: 'source' },
    ],
  },
  {
    id: 'coding',
    title: 'Patch review prompts',
    provider: 'OpenAI',
    host: 'api.openai.com',
    model: 'gpt-4.1-mini',
    date: 'Jul 11, 2026',
    sortDate: 20260711,
    spanCount: 86,
    hash: '0c852e…a14f',
    schema: 'GenAI trace / v1',
    evidence: '86 provider calls checked',
    tags: ['Coding', 'Evaluation'],
    license: 'CC BY 4.0',
    summary: 'A published evaluation collection whose model spans are portable and independently separate from the private capture used to admit it.',
    spans: [
      { depth: 0, kind: 'INTERNAL', name: 'invoke_agent patch-review', detail: '86 spans', trust: 'runtime' },
      { depth: 1, kind: 'CLIENT', name: 'chat gpt-4.1-mini', detail: 'gen_ai.operation.name = chat', trust: 'source' },
      { depth: 1, kind: 'INTERNAL', name: 'evaluate review rubric', detail: 'score = 4 / 5', trust: 'runtime' },
    ],
  },
];

const installCommand = 'curl -fsSLO https://llmnotary.exalto.ai/install.sh && sh install.sh';
const publishCommand = 'llm-notary publish captures/cap-... --title "Refusal boundary test" --license "CC BY 4.0"';
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
  return <main id="top"><section className="hero"><span className="eyebrow">LLM Notary</span><h1>Publish model behavior<br />as portable spans.</h1><p>LLM Notary verifies a private provider capture, then publishes a standardized OpenTelemetry trace with a signed platform stamp. The raw exchange stays out of the collection.</p><div className="hero-actions"><a className="button button-dark" href="#/docs/publish">Publish a trace</a><a className="button button-plain" href="#/collections">Browse collections</a></div><div className="hero-metadata"><span>For research, evaluation, and safety work</span><b /><span>Private proof. Public standard.</span></div></section><section className="section architecture" id="how-it-works"><div className="section-head"><span className="eyebrow">How publishing works</span><h2>Verify the source.<br />Keep the standard.</h2></div><div className="architecture-grid"><Diagram /><div className="step-list"><article><span>01</span><div><h3>Capture privately</h3><p>Your local proxy records a provider call and its TLSNotary evidence. API keys and private capture data remain under your control.</p></div></article><article><span>02</span><div><h3>Publish standardized spans</h3><p>The platform checks the capture, then admits a normalized OTLP trace: messages, model spans, tool calls, timing, and usage.</p></div></article><article><span>03</span><div><h3>Verify the platform stamp</h3><p>Readers compare the trace hash with a compact signed stamp. They do not need your raw request, response, or TLS evidence.</p></div></article></div></div><div className="section-link"><a href="#/docs/how-it-works">Read the publishing trust model</a></div></section><section className="privacy"><div><span className="eyebrow">Private by design</span><h2>Proof is not the product.</h2></div><p>The private capture proves the trace is real at publication time. The shared artifact is clean OTLP JSON plus a platform signature, built for reuse rather than archival of raw provider traffic.</p></section><section className="section library-preview"><div className="trace-heading"><div><span className="eyebrow">Collections</span><h2>Traces with a shared language.</h2></div><p>Filter published work by provider, model, span kind, and topic. Inspect the graph before using a result.</p></div><div className="preview-records">{collections.slice(0, 3).map((collection) => <article key={collection.id}><i aria-hidden="true" /><div><h3>{collection.title}</h3><p>{collection.spanCount} spans · {collection.provider} · {collection.model}</p></div><span>VERIFIED</span></article>)}</div><a className="button button-dark" href="#/collections">Open collections</a></section><section className="section verify" id="verify"><div><span className="eyebrow">Independent verification</span><h2>One small stamp.<br />One exact trace.</h2><p>The stamp binds a trace hash to LLM Notary’s verification result. Download the standardized trace, check the platform signature, and use it in your own tooling.</p><div className="verify-points"><span>OTLP JSON</span><span>Signed hash</span><span>No raw capture</span></div><div className="button-row"><a className="button button-dark" href="#/docs/verify">Verify with the CLI</a><button className="button button-plain" onClick={onVerify}>Preview verifier</button></div></div><div className="receipt"><header><PenMark inverse /><b>Publication stamp</b></header><h3>Verified</h3><dl><div><dt>Artifact</dt><dd>trace.otlp.json</dd></div><div><dt>Schema</dt><dd>OTel GenAI / v1</dd></div><div><dt>Source</dt><dd>Provider capture checked</dd></div><div><dt>Signature</dt><dd>LLM Notary platform key</dd></div></dl><footer>LLM NOTARY / STAMP v1</footer></div></section><section className="section install"><div><span className="eyebrow">Get started</span><h2>Capture locally.<br />Publish clearly.</h2></div><div className="terminal"><div><i /><i /><i /></div><pre><code><b>$</b> {installCommand}{'\n\n'}<b>$</b> {publishCommand}{'\n\n'}published  <em>trace.otlp.json + stamp.json</em></code></pre><a href="#/docs/publish">Publishing and format details</a></div></section></main>;
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
  overview: { title: 'LLM Notary documentation', lead: 'Publish provider-origin model behavior as a portable OpenTelemetry trace. LLM Notary verifies the private capture once, then signs the standardized artifact that everyone can inspect.', blocks: [['What is published?', 'Each publication contains trace.otlp.json and stamp.json. The trace uses OpenTelemetry GenAI spans for model calls, messages, tool calls, timing, and usage. The stamp signs the exact trace hash.'], ['What stays private?', 'The source capture, TLSNotary evidence, raw HTTP request, and raw provider response are verification inputs. They are not part of the collection artifact.'], ['What the stamp means', 'The LLM Notary platform verified valid source evidence for this exact normalized trace at publication time. The stamp is independent of the source proof and is signed by the platform key.']] },
  'how-it-works': { title: 'The publishing trust model', lead: 'Source evidence and published data have different jobs: one proves a provider exchange to LLM Notary; the other is a standardized trace the community can reuse.', blocks: [['1. Capture privately', 'The local proxy records the provider connection and obtains TLSNotary evidence. The notary does not see the API key or application plaintext.'], ['2. Verify on admission', 'When you publish, LLM Notary checks the source capture and confirms that the submitted OTLP trace agrees with the authenticated provider call.'], ['3. Store the standard, not the source', 'The collection keeps normalized OTLP JSON and a signed stamp. Raw source material is not the published format.'], ['4. Verify anywhere', 'A reader checks the trace hash and platform signature locally. They do not need access to a private capture or a TLSNotary implementation.']] },
  install: { title: 'Install the CLI', lead: 'The installer downloads a checksum-verified release for macOS or Linux. Windows releases are available as ZIP archives.', blocks: [['Recommended install', installCommand], ['Supported packages', 'macOS: Apple silicon and Intel. Linux: x86_64 and ARM64. Windows: x86_64 ZIP release. Each archive contains the llm-notary command.'], ['Choose a version', 'Set LLM_NOTARY_VERSION before running the installer to select a specific release. Set LLM_NOTARY_INSTALL_DIR to install somewhere other than ~/.local/bin.']] },
  proxy: { title: 'Run the local proxy', lead: 'Start the proxy, point an OpenAI-compatible client to it, and keep your existing provider API key in that client.', blocks: [['Start it', 'llm-notary proxy start --provider openai --capture-dir captures'], ['Connect your client', 'Use http://127.0.0.1:8787/v1 as the base URL. DeepSeek uses http://127.0.0.1:8787 without a /v1 suffix. The proxy writes each completed capture to the configured directory.'], ['Providers', 'Use --provider openai, --provider anthropic, or --provider deepseek. The current notary allowlist only accepts their API hostnames.']] },
  providers: { title: 'Configure a provider client', lead: 'Load your existing keys, then change only the provider base URL. The API key and request shape stay the same.', blocks: [['Load keys from .env', 'set -a\nsource .env\nset +a'], ['OpenAI', 'Use http://127.0.0.1:8787/v1 as the Responses API base URL.'], ['Anthropic', 'Use http://127.0.0.1:8788 as the Messages API base URL. Continue sending requests to /v1/messages.'], ['DeepSeek', 'Use http://127.0.0.1:8789 as the OpenAI-compatible base URL. Continue sending requests to /chat/completions.']] },
  harnesses: { title: 'Configure a harness', lead: 'Start the matching local proxy first, then use one of these harness recipes. Each recipe keeps your provider credential in the harness environment.', blocks: [['Codex + OpenAI', 'Add this to ~/.codex/config.toml:\n\nmodel_provider = "llm-notary"\n\n[model_providers.llm-notary]\nname = "LLM Notary local proxy"\nbase_url = "http://127.0.0.1:8787/v1"\nenv_key = "OPENAI_API_KEY"\nwire_api = "responses"\nsupports_websockets = false'], ['Run Codex', 'codex exec --ephemeral --skip-git-repo-check -m gpt-4.1-mini \'Reply with exactly: hello\''], ['Claude Code + Anthropic', 'ANTHROPIC_BASE_URL=http://127.0.0.1:8788 claude --bare --no-session-persistence --tools \'\' -p --model claude-haiku-4-5-20251001 \'Reply with exactly: hello\''], ['OpenCode + DeepSeek', 'Set the provider base URL to http://127.0.0.1:8789 and retain DEEPSEEK_API_KEY in the OpenCode environment.']] },
  publish: { title: 'Publish a standardized trace', lead: 'Publishing converts a private capture into an OpenTelemetry GenAI trace, verifies the source once, and returns a portable artifact plus a signed LLM Notary stamp.', blocks: [['Publish a capture', publishCommand], ['What is uploaded', 'The CLI submits the source capture for verification and the normalized trace for admission. Source material is used to check the publication and is not retained as the collection artifact.'], ['What is returned', 'Every publication has trace.otlp.json and stamp.json. The trace carries standard spans; the stamp binds their canonical hash to the platform verification result.']] },
  verify: { title: 'Verify a published trace', lead: 'Verification runs locally. Check that the LLM Notary stamp signs the exact OTLP JSON trace you downloaded.', blocks: [['Verify a publication', 'llm-notary verify-public trace.otlp.json stamp.json --trusted-platform-key <platform-public-key>'], ['What it checks', 'The verifier hashes the standardized trace, validates the platform signature, and reports the source provider, verification time, and normalizer version carried by the stamp.'], ['Source proof versus platform stamp', 'The source proof is used only when LLM Notary admits a publication. The public stamp is a separate platform assertion that the source proof was verified for this exact trace.']] },
};

function Docs({ pageKey }) {
  const page = docPages[pageKey] || docPages.overview;
  const isCommand = (text) => text.includes('\n') || text.startsWith('export ') || text.startsWith('curl ') || text.startsWith('llm-notary ') || text.startsWith('ANTHROPIC_BASE_URL=') || text.startsWith('codex ');
  const next = pageKey === 'verify'
    ? { href: '#/collections', label: 'Browse collections' }
    : pageKey === 'publish'
      ? { href: '#/docs/verify', label: 'Verify a publication' }
      : { href: '#/docs/publish', label: 'Publish a trace' };
  return <main className="docs-shell"><aside className="docs-sidebar"><span className="eyebrow">Documentation</span><a className={!pageKey || pageKey === 'overview' ? 'active' : ''} href="#/docs">Overview</a><a className={pageKey === 'how-it-works' ? 'active' : ''} href="#/docs/how-it-works">Trust model</a><span className="docs-group">Capture</span><a className={pageKey === 'install' ? 'active' : ''} href="#/docs/install">Install</a><a className={pageKey === 'proxy' ? 'active' : ''} href="#/docs/proxy">Proxy</a><span className="docs-group">Connect</span><a className={pageKey === 'providers' ? 'active' : ''} href="#/docs/providers">Providers</a><a className={pageKey === 'harnesses' ? 'active' : ''} href="#/docs/harnesses">Harnesses</a><span className="docs-group">Publish</span><a className={pageKey === 'publish' ? 'active' : ''} href="#/docs/publish">Publish</a><a className={pageKey === 'verify' ? 'active' : ''} href="#/docs/verify">Verify</a><a href="#/collections">Collections</a></aside><article className="docs-content"><span className="eyebrow">LLM Notary / Docs</span><h1>{page.title}</h1><p className="docs-lead">{page.lead}</p>{page.blocks.map(([heading, body]) => <section key={heading}><h2>{heading}</h2>{isCommand(body) ? <pre><code>{body}</code></pre> : <p>{body}</p>}</section>)}<div className="docs-next"><span>Next</span><a href={next.href}>{next.label}</a></div></article></main>;
}

function TraceField({ label, value }) {
  return <span className="trace-field"><b>{label}</b><code>{value}</code></span>;
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
  return <div className="span-tree" aria-label="Published trace spans">{spans.map((span, index) => <div className={`span-row span-row--${span.trust}`} style={{ '--span-depth': span.depth }} key={`${span.name}-${index}`}><div className="span-summary"><span className="span-branch" aria-hidden="true" /><span className="span-kind">{span.kind}</span><strong>{span.name}</strong><small>{span.detail}</small><em>{span.trust === 'source' ? 'Source verified' : 'Runtime reported'}</em></div>{span.messages && <div className="span-evidence"><MessageGroup label="gen_ai.input.messages" messages={span.messages.input} /><MessageGroup label="gen_ai.output.messages" messages={span.messages.output} /></div>}{span.attributes && <div className="span-evidence span-attributes"><span className="message-group-label">span attributes</span>{span.attributes.map(([name, value]) => <TraceField key={name} label={name} value={value} />)}</div>}</div>)}</div>;
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
    <section className="span-panel"><div className="span-panel-head"><span>Trace spans</span><small>Recorded operations and attributes</small></div><SpanTree spans={collection.spans} /></section>
    <div className="trace-actions"><button onClick={onVerify}>Verify platform stamp</button><a href="#/docs/publish">Trace format</a></div>
  </article>;
}

function Collections({ onVerify }) {
  const [query, setQuery] = useState('');
  const [provider, setProvider] = useState('All');
  const [model, setModel] = useState('All');
  const [tag, setTag] = useState('All');
  const [sort, setSort] = useState('Newest');
  const [active, setActive] = useState(collections[0]);
  const providers = ['All', ...new Set(collections.map((collection) => collection.provider))];
  const models = ['All', ...new Set(collections.map((collection) => collection.model))];
  const tags = ['All', ...new Set(collections.flatMap((collection) => collection.tags))];
  const filtered = useMemo(() => collections.filter((collection) => {
    const searchable = `${collection.title} ${collection.provider} ${collection.model} ${collection.tags.join(' ')} ${collection.summary}`.toLowerCase();
    return searchable.includes(query.toLowerCase()) && (provider === 'All' || collection.provider === provider) && (model === 'All' || collection.model === model) && (tag === 'All' || collection.tags.includes(tag));
  }).sort((a, b) => sort === 'Newest' ? b.sortDate - a.sortDate : a.title.localeCompare(b.title)), [query, provider, model, tag, sort]);
  useEffect(() => { if (filtered.length && !filtered.some((collection) => collection.id === active.id)) setActive(filtered[0]); }, [filtered, active]);
  return <main className="library-shell"><section className="library-controls" aria-label="Browse collections"><label className="library-search"><span>Search collections</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search by model, operation, provider, or topic" /></label><label><span>Provider</span><select value={provider} onChange={(event) => setProvider(event.target.value)}>{providers.map((value) => <option key={value}>{value}</option>)}</select></label><label><span>Model</span><select value={model} onChange={(event) => setModel(event.target.value)}>{models.map((value) => <option key={value}>{value}</option>)}</select></label><label><span>Sort</span><select value={sort} onChange={(event) => setSort(event.target.value)}><option>Newest</option><option>Title</option></select></label></section><nav className="topic-filter" aria-label="Topics"><span>Topics</span>{tags.map((value) => <button key={value} className={tag === value ? 'active' : ''} onClick={() => setTag(value)}>{value}</button>)}</nav><section className="library-results"><div className="collection-workspace"><div className="collection-list"><div className="results-heading"><p><b>{filtered.length}</b> collections</p><span>Verified</span></div><div className="library-grid">{filtered.map((collection) => <CollectionCard collection={collection} active={active.id === collection.id} key={collection.id} onSelect={() => setActive(collection)} />)}</div></div><CollectionInspector collection={active} onVerify={onVerify} /></div></section></main>;
}

function Dashboard({ user }) {
  return <main className="dashboard-shell"><span className="eyebrow">Account</span><h1>Welcome, {user.github_login}.</h1><p>Your LLM Notary account is ready to publish standardized traces and manage the platform stamps attached to your collections.</p><div className="dashboard-card"><span>Signed in with GitHub</span><b>{user.github_login}</b><a href="#/collections">Browse collections</a></div></main>;
}

function App() {
  const [route, setRoute] = useState(window.location.hash || '#/');
  const [showVerifier, setShowVerifier] = useState(false);
  const [user, setUser] = useState(null);
  useEffect(() => { const update = () => setRoute(window.location.hash || '#/'); window.addEventListener('hashchange', update); return () => window.removeEventListener('hashchange', update); }, []);
  useEffect(() => { let cancelled = false; fetch('/api/me', { credentials: 'same-origin' }).then((response) => response.ok ? response.json() : null).then((payload) => { if (!cancelled) setUser(payload?.user || null); }).catch(() => { if (!cancelled) setUser(null); }); return () => { cancelled = true; }; }, []);
  const logout = async () => { const response = await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' }); if (response.ok) { setUser(null); if (window.location.hash === '#/dashboard') window.location.hash = '#/'; } };
  const path = route.replace(/^#\/?/, '');
  const [section, page] = path.split('/');
  return <><Header user={user} onLogout={logout} />{section === 'docs' ? <Docs pageKey={page || 'overview'} /> : (section === 'collections' || section === 'library') ? <Collections onVerify={() => setShowVerifier(true)} /> : section === 'dashboard' && user ? <Dashboard user={user} /> : <Landing onVerify={() => setShowVerifier(true)} />}<Footer />{showVerifier && <VerifierDialog onClose={() => setShowVerifier(false)} />}</>;
}

createRoot(document.getElementById('root')).render(<App />);
