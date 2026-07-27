import { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';
import './refinements.css';
import './commons.css';

const samples = [
  { id: 'refusal', title: 'Refusal boundary test', api: 'OpenAI · Responses API', provider: 'api.openai.com', model: 'gpt-4.1', date: 'Jul 24', hash: 'a47e32…ef90', tags: ['Safety', 'Refusals'], license: 'CC BY 4.0', summary: 'A redacted test of a model refusal boundary. The receipt preserves the provider response and model identifier.' },
  { id: 'tool', title: 'Tool-use evaluation', api: 'Anthropic · Messages API', provider: 'api.anthropic.com', model: 'claude-sonnet-4', date: 'Jul 23', hash: 'c18b70…79aa', tags: ['Evaluation', 'Tools'], license: 'CC BY 4.0', summary: 'A redacted tool call and final response. Private runtime context is removed before sharing.' },
  { id: 'benchmark', title: 'Benchmark run #048', api: 'OpenAI · Chat Completions', provider: 'api.openai.com', model: 'gpt-4.1-mini', date: 'Jul 19', hash: 'f10cd2…05b7', tags: ['Research', 'Benchmark'], license: 'CC BY 4.0', summary: 'A prompt-and-response record from an instruction-following benchmark, published with its origin receipt.' },
  { id: 'context', title: 'Long-context comparison', api: 'Anthropic · Messages API', provider: 'api.anthropic.com', model: 'claude-opus-4', date: 'Jul 16', hash: 'd49186…3c4d', tags: ['Research', 'Long context'], license: 'CC BY 4.0', summary: 'A redacted comparison run that records a long-context prompt and the provider’s returned response.' }
];

function PenMark({ inverse = false }) {
  return <span className={`pen-mark${inverse ? ' pen-mark--inverse' : ''}`} aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M5 19l1.7-5.4L15.5 4.8a2.2 2.2 0 0 1 3.1 3.1l-8.8 8.8L5 19Z"/><path d="m13.9 6.4 3.7 3.7M5 19l4.8-2.4"/></svg></span>;
}

function CloseIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18"/></svg>;
}

function Arrow() {
  return <div className="flow-arrow" aria-label="Encrypted connection"><span>encrypted</span><svg viewBox="0 0 68 14" preserveAspectRatio="none" aria-hidden="true"><path d="M1 7h61M56 2l6 5-6 5"/></svg></div>;
}

function FlowNode({ type, title, note }) {
  return <div className={`flow-node flow-node--${type}`}><span className="node-mark" aria-hidden="true"/><strong>{title}</strong><small>{note}</small></div>;
}

function Diagram() {
  return <div className="diagram-card">
    <div className="diagram-label">One model call</div>
    <div className="flow" aria-label="Your machine connects through LLM Notary to the AI provider">
      <FlowNode type="local" title="Your machine" note="Local proxy" />
      <Arrow />
      <FlowNode type="notary" title="LLM Notary" note="TLS witness" />
      <Arrow />
      <FlowNode type="provider" title="AI provider" note="OpenAI · Anthropic" />
    </div>
    <div className="diagram-foot">The notary only relays encrypted TLS traffic. It cannot read your API key, prompt, or response.</div>
  </div>;
}

function VerifierDialog({ onClose }) {
  const [fileName, setFileName] = useState('');
  useEffect(() => {
    const handleKeyDown = (event) => event.key === 'Escape' && onClose();
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);
  return <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
    <section className="verifier-modal" role="dialog" aria-modal="true" aria-labelledby="verifier-title" onMouseDown={(event) => event.stopPropagation()}>
      <button className="icon-button" onClick={onClose} aria-label="Close verifier"><CloseIcon /></button>
      <span className="eyebrow">Local verifier</span>
      <h2 id="verifier-title">Verify a receipt</h2>
      <p>The verifier reads an exported file in your browser. It does not upload the file.</p>
      <label className="drop-zone"><input type="file" accept=".json,.notary" onChange={(event) => setFileName(event.target.files?.[0]?.name || '')} /><strong>{fileName || 'Choose a receipt file'}</strong><small>{fileName ? 'Ready to inspect locally' : 'JSON or .notary'}</small></label>
      <div className="verification-state"><i /> Notary key directory available</div>
    </section>
  </div>;
}

function App() {
  const [activeSample, setActiveSample] = useState(samples[0]);
  const [showVerifier, setShowVerifier] = useState(false);
  return <>
    <header className="nav-wrap"><a className="brand" href="#top"><PenMark /> <span>LLM Notary</span></a><nav><a href="#how-it-works">How it works</a><a href="#samples">Trace Commons</a><a href="#verify">Verify</a></nav><a className="nav-cta" href="#install">Contribute</a></header>
    <main id="top">
      <section className="hero"><span className="eyebrow">Trace Commons</span><h1>Share evidence of<br />how models behave.</h1><p>Capture an API interaction locally, redact it, and publish a receipt others can verify and study.</p><div className="hero-actions"><a className="button button-dark" href="#samples">Browse sample traces</a><a className="button button-plain" href="#how-it-works">How it works</a></div><div className="hero-metadata"><span>For research, evaluation, and safety work</span><b /><span>Local capture. Consent-based sharing.</span></div></section>
      <section className="section architecture" id="how-it-works"><div className="section-head"><span className="eyebrow">How it works</span><h2>Capture once. Share with context.</h2></div><div className="architecture-grid"><Diagram /><div className="step-list"><article><span>01</span><div><h3>Capture locally</h3><p>The proxy records a model call while your tools keep working normally.</p></div></article><article><span>02</span><div><h3>Keep the evidence</h3><p>The notary creates a receipt for the provider-origin interaction.</p></div></article><article><span>03</span><div><h3>Publish by consent</h3><p>Redact the trace, choose a license, and share it for study or evaluation.</p></div></article></div></div></section>
      <section className="privacy"><div><span className="eyebrow">Share on your terms</span><h2>Open by consent.</h2></div><p>Captures stay local by default. Before publishing, you choose the redaction, visibility, and license for each trace.</p></section>
      <section className="section traces" id="samples"><div className="trace-heading"><div><span className="eyebrow">Trace Commons</span><h2>Evidence for research, evaluation, and safety work.</h2></div><p>Sample records only. A shared trace should include clear consent, redaction, and reuse terms.</p></div><div className="trace-layout"><div className="trace-list" role="tablist">{samples.map((sample) => <button key={sample.id} role="tab" aria-selected={activeSample.id === sample.id} className={activeSample.id === sample.id ? 'active' : ''} onClick={() => setActiveSample(sample)}><i aria-label="Receipt verified"/><span><strong>{sample.title}</strong><small>{sample.api}</small></span><time>{sample.date}</time></button>)}</div><article className="trace-detail"><header><div><h3>{activeSample.title}</h3><span>Sample record · ctr_{activeSample.id}_8f1a…290c</span></div><b>Receipt included</b></header><p>{activeSample.summary}</p><div className="tag-list" aria-label="Trace topics">{activeSample.tags.map((tag) => <span key={tag}>{tag}</span>)}</div><dl><div><dt>Provider</dt><dd>{activeSample.provider}</dd></div><div><dt>Model</dt><dd>{activeSample.model}</dd></div><div><dt>Evidence</dt><dd>TLSNotary presentation</dd></div><div><dt>Reuse</dt><dd>{activeSample.license}</dd></div></dl><div className="trace-actions"><a href="#verify">Verify receipt</a><a href="#verify">View JSON</a></div></article></div></section>
      <section className="section verify" id="verify"><div><span className="eyebrow">Independent verification</span><h2>Inspect before you use it.</h2><p>Open a receipt locally, inspect the disclosed data, and check the notary key that signed it.</p><div className="verify-points"><span>No account</span><span>No upload</span><span>Open format</span></div><button className="button button-dark" onClick={() => setShowVerifier(true)}>Open verifier</button></div><div className="receipt"><header><PenMark inverse /><b>Research record</b></header><h3>Receipt</h3><dl><div><dt>Trace</dt><dd>ctr_{activeSample.id}…290c</dd></div><div><dt>Provider</dt><dd>{activeSample.provider}</dd></div><div><dt>Topics</dt><dd>{activeSample.tags.join(', ')}</dd></div><div><dt>Reuse</dt><dd>{activeSample.license}</dd></div></dl><footer>LLM NOTARY / v0.1</footer></div></section>
      <section className="section install" id="install"><div><span className="eyebrow">Contribute</span><h2>Capture a trace.<br />Decide later whether to share it.</h2></div><div className="terminal"><div><i /><i /><i /></div><pre><code><b>$</b> llm-notary proxy start --provider openai{`\n\n`}listening  <em>127.0.0.1:8787</em>{`\n`}notary connected{`\n`}ready</code></pre><a href="#how-it-works">How contribution works</a></div></section>
    </main>
    <footer className="site-footer"><a className="brand" href="#top"><PenMark /> <span>LLM Notary</span></a><span>Verifiable traces for AI research and evaluation.</span><span>© 2026 LLM Notary</span></footer>
    {showVerifier && <VerifierDialog onClose={() => setShowVerifier(false)} />}
  </>;
}

createRoot(document.getElementById('root')).render(<App />);
