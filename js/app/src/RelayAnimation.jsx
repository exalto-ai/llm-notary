import { useEffect, useState } from 'react';
import { LoaderCircle, LockKeyhole, UnlockKeyhole } from 'lucide-react';

const ciphertextFrames = ['8F 3C\nA2 19', 'C1 7A\n04 E6', '19 BE\nF3 8C', '2B D9\nC7 05', 'A8 14\n5E F0'];

function useProviderTyping() {
  const provider = 'OpenAI';
  const [text, setText] = useState(() => window.matchMedia('(prefers-reduced-motion: reduce)').matches ? provider : '');

  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return undefined;
    let characterIndex = 0;
    const timer = window.setInterval(() => {
      characterIndex += 1;
      setText(provider.slice(0, characterIndex));
      if (characterIndex === provider.length) window.clearInterval(timer);
    }, 70);
    return () => window.clearInterval(timer);
  }, []);

  return text;
}

function useCiphertextFrame() {
  const [frame, setFrame] = useState(ciphertextFrames[0]);

  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return undefined;
    let frameIndex = 0;
    const timer = window.setInterval(() => {
      frameIndex = (frameIndex + 1) % ciphertextFrames.length;
      setFrame(ciphertextFrames[frameIndex]);
      if (frameIndex === ciphertextFrames.length - 1) window.clearInterval(timer);
    }, 220);
    return () => window.clearInterval(timer);
  }, []);

  return frame;
}

function LockGlyph() {
  return <LockKeyhole aria-hidden="true" />;
}

function LockPacket({ className, label }) {
  return <span className={`relay-packet ${className}`} aria-label={label}><LockGlyph /></span>;
}

function EncryptedTrack({ className, label }) {
  return <div className={`relay-track ${className}`} aria-label={label}><LockPacket className="relay-packet--lock" label="Encrypted packet" /></div>;
}

function ProviderCard() {
  const provider = useProviderTyping();
  return <section className="relay-node relay-node--provider">
    <b>AI PROVIDER</b>
    <strong><span>{provider}</span><i aria-hidden="true" /></strong>
    <span className="provider-lines" aria-hidden="true"><i /><i /><i /></span>
  </section>;
}

function NotaryCard() {
  const ciphertext = useCiphertextFrame();
  return <section className="relay-node relay-node--notary">
    <b>LLM NOTARY</b>
    <strong aria-label="Encrypted transcript hash">{ciphertext.split('\n').map((line, index) => <span key={line}>{line}{index === 0 && <br />}</span>)}</strong>
    <small>ciphertext witness</small>
  </section>;
}

function ProxyCard() {
  return <section className="relay-node relay-node--proxy">
    <b>LOCAL TLS PROXY</b>
    <div className="decrypt-display" aria-label="Encrypted data is decrypted locally">
      <span className="decrypt-display__waiting"><LoaderCircle aria-hidden="true" /></span>
      <span className="decrypt-display__cipher"><LockGlyph /></span>
      <i className="decrypt-display__arrow" aria-hidden="true" />
      <span className="decrypt-display__unlocked"><UnlockKeyhole aria-hidden="true" /></span>
    </div>
    <small>your machine</small>
  </section>;
}

function AgentCard() {
  return <section className="relay-output relay-output--agent">
    <header><b>YOUR AGENT</b><span>plaintext output</span></header>
    <p>I found three concrete changes to improve reliability:</p>
    <ul>
      <li>Retry the failed request</li>
      <li>Record the provider model</li>
      <li>Verify before sharing</li>
    </ul>
  </section>;
}

function CertificateCard() {
  return <section className="relay-output relay-output--certificate">
    <header><b>YOUR CERTIFICATE</b><span className="certificate-seal">CERTIFIED</span></header>
    <dl>
      <div><dt>Provider</dt><dd>api.openai.com</dd></div>
      <div><dt>Model</dt><dd>gpt-4.1</dd></div>
      <div><dt>Stream</dt><dd>complete</dd></div>
    </dl>
    <footer><i aria-hidden="true" /> notary evidence attached</footer>
  </section>;
}

export function RelayAnimation() {
  return <section className="relay-animation" aria-label="A provider completion travels as encrypted traffic through LLM Notary to a local TLS proxy. The proxy produces plaintext output for your agent and proof for your certificate.">
    <div className="relay-animation__viewport">
      <div className="relay-animation__flow">
        <ProviderCard />
        <EncryptedTrack className="relay-track--provider" label="Encrypted response travels to LLM Notary" />
        <NotaryCard />
        <EncryptedTrack className="relay-track--notary" label="Encrypted response travels to your local TLS proxy" />
        <ProxyCard />
        <div className="relay-branch" aria-hidden="true">
          <svg viewBox="0 0 100 100" preserveAspectRatio="none">
            <line x1="0" y1="37.5" x2="100" y2="37.5" />
            <line x1="0" y1="62.5" x2="100" y2="62.5" />
            <path className="relay-branch__mobile-line" d="M50 0 V50 H25 V100 M50 50 H75 V100" />
          </svg>
          <span className="relay-packet relay-packet--text" aria-label="Plaintext output" />
          <span className="relay-packet relay-packet--proof" aria-label="Proof packet" />
        </div>
        <AgentCard />
        <CertificateCard />
      </div>
    </div>
  </section>;
}
