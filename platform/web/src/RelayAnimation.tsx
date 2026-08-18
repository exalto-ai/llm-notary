import { LoaderCircle, LockKeyhole, UnlockKeyhole } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';

const providerNames = ['OpenAI', 'Anthropic', 'OpenRouter', 'DeepSeek'];
const ciphertextFrames = [
  '8F 3C\nA2 19',
  'C1 7A\n04 E6',
  '19 BE\nF3 8C',
  '2B D9\nC7 05',
  'A8 14\n5E F0',
];

function useProviderTyping() {
  const [text, setText] = useState(providerNames[0]);

  useEffect(() => {
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
    if (reducedMotion.matches) return undefined;

    let providerIndex = 0;
    let characterIndex = providerNames[0].length;
    let direction = 1;
    let timer: number | undefined;

    const tick = () => {
      const provider = providerNames[providerIndex];
      setText(provider.slice(0, characterIndex));

      if (direction === 1 && characterIndex < provider.length) {
        characterIndex += 1;
        timer = window.setTimeout(tick, 70);
      } else if (direction === 1) {
        direction = -1;
        timer = window.setTimeout(tick, 850);
      } else if (characterIndex > 0) {
        characterIndex -= 1;
        timer = window.setTimeout(tick, 45);
      } else {
        providerIndex = (providerIndex + 1) % providerNames.length;
        characterIndex = 1;
        direction = 1;
        timer = window.setTimeout(tick, 360);
      }
    };

    timer = window.setTimeout(tick, 850);
    return () => window.clearTimeout(timer);
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
    }, 220);
    return () => window.clearInterval(timer);
  }, []);

  return frame;
}

function LockGlyph() {
  return <LockKeyhole aria-hidden="true" />;
}

interface RelayPartProps {
  className: string;
}

function LockPacket({ className }: RelayPartProps) {
  return (
    <span className={`relay-packet ${className}`}>
      <LockGlyph />
    </span>
  );
}

function EncryptedTrack({ className }: RelayPartProps) {
  return (
    <div className={`relay-track ${className}`}>
      <LockPacket className="relay-packet--lock" />
    </div>
  );
}

function ProviderCard() {
  const provider = useProviderTyping();
  return (
    <section className="relay-node relay-node--provider">
      <b>AI PROVIDER</b>
      <strong>
        <span>{provider}</span>
        <i aria-hidden="true" />
      </strong>
      <span className="provider-lines" aria-hidden="true">
        <i />
        <i />
        <i />
      </span>
    </section>
  );
}

function NotaryCard() {
  const ciphertext = useCiphertextFrame();
  return (
    <section className="relay-node relay-node--notary">
      <b>REMOTE NOTARY</b>
      <strong>
        {ciphertext.split('\n').map((line, index) => (
          <span key={line}>
            {line}
            {index === 0 && <br />}
          </span>
        ))}
      </strong>
      <small>ciphertext witness</small>
    </section>
  );
}

function ProxyCard() {
  return (
    <section className="relay-node relay-node--proxy">
      <b>LOCAL TLS PROXY</b>
      <div className="decrypt-display">
        <span className="decrypt-display__waiting">
          <LoaderCircle aria-hidden="true" />
        </span>
        <span className="decrypt-display__cipher">
          <LockGlyph />
        </span>
        <i className="decrypt-display__arrow" aria-hidden="true" />
        <span className="decrypt-display__unlocked">
          <UnlockKeyhole aria-hidden="true" />
        </span>
      </div>
      <small>your machine</small>
    </section>
  );
}

function AgentCard() {
  return (
    <section className="relay-output relay-output--agent">
      <header>
        <b>YOUR AGENT</b>
        <span>plaintext output</span>
      </header>
      <p>I found three concrete changes to improve reliability:</p>
      <ul>
        <li>Retry the failed request</li>
        <li>Record the provider model</li>
        <li>Verify before sharing</li>
      </ul>
    </section>
  );
}

function PackageCard() {
  return (
    <section className="relay-output relay-output--package">
      <header>
        <b>YOUR PACKAGE</b>
        <span className="package-ready">PORTABLE</span>
      </header>
      <dl>
        <div>
          <dt>Provider</dt>
          <dd>api.openai.com</dd>
        </div>
        <div>
          <dt>Model</dt>
          <dd>gpt-4.1</dd>
        </div>
        <div>
          <dt>Stream</dt>
          <dd>complete</dd>
        </div>
      </dl>
      <footer>
        <i aria-hidden="true" /> notary evidence included
      </footer>
    </section>
  );
}

function useMobileCamera() {
  const sectionRef = useRef<HTMLElement | null>(null);
  const viewportRef = useRef<HTMLDivElement | null>(null);
  const flowRef = useRef<HTMLDivElement | null>(null);
  const frameRef = useRef<number | null>(null);

  const isMobile = () => window.matchMedia('(max-width: 960px)').matches;
  const prefersReducedMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const cameraStops = () => {
    const viewportWidth = viewportRef.current?.getBoundingClientRect().width || window.innerWidth;
    const center = viewportWidth / 2;
    return [center - 60, center - 229, center - 400, center - 607];
  };

  const positionForProgress = (progress: number): number => {
    const [provider, notary, proxy, outputs] = cameraStops();
    const phase = progress % 1;
    const between = (from: number, to: number, start: number, end: number) =>
      from + (to - from) * ((phase - start) / (end - start));

    if (phase < 0.27) return provider;
    if (phase < 0.32) return between(provider, notary, 0.27, 0.32);
    if (phase < 0.48) return notary;
    if (phase < 0.54) return between(notary, proxy, 0.48, 0.54);
    if (phase < 0.67) return proxy;
    if (phase < 0.73) return between(proxy, outputs, 0.67, 0.73);
    return outputs;
  };

  useEffect(() => {
    const section = sectionRef.current;
    const viewport = viewportRef.current;
    const flow = flowRef.current;
    if (!section || !viewport || !flow) return undefined;

    const updateCamera = () => {
      frameRef.current = null;
      if (!isMobile()) {
        flow.style.removeProperty('--relay-progress');
        flow.style.transform = '';
        return;
      }
      const sectionBounds = section.getBoundingClientRect();
      const viewportHeight = viewport.getBoundingClientRect().height;
      const stickyTop = Math.max(54, (window.innerHeight - viewportHeight) / 2);
      const scrollDistance = Math.max(1, sectionBounds.height - viewportHeight);
      const rawProgress = (stickyTop - sectionBounds.top) / scrollDistance;
      const progress = prefersReducedMotion() ? 0.999 : Math.max(0, Math.min(0.999, rawProgress));
      flow.style.setProperty('--relay-progress', String(progress));
      flow.style.transform = `translateX(${positionForProgress(progress)}px) scale(.8)`;
    };

    const scheduleCameraUpdate = () => {
      if (frameRef.current === null) frameRef.current = window.requestAnimationFrame(updateCamera);
    };

    updateCamera();
    window.addEventListener('scroll', scheduleCameraUpdate, { passive: true });
    window.addEventListener('resize', scheduleCameraUpdate);
    return () => {
      window.removeEventListener('scroll', scheduleCameraUpdate);
      window.removeEventListener('resize', scheduleCameraUpdate);
      if (frameRef.current !== null) window.cancelAnimationFrame(frameRef.current);
    };
  }, []);

  return { flowRef, sectionRef, viewportRef };
}

export function RelayAnimation() {
  const { flowRef, sectionRef, viewportRef } = useMobileCamera();

  return (
    <section
      ref={sectionRef}
      className="relay-animation"
      aria-label="A provider completion travels as encrypted traffic through Notary to a local TLS proxy. The proxy produces plaintext output for your agent and a portable evidence package."
    >
      <div ref={viewportRef} className="relay-animation__viewport" aria-hidden="true">
        <div ref={flowRef} className="relay-animation__flow">
          <ProviderCard />
          <EncryptedTrack className="relay-track--provider" />
          <NotaryCard />
          <EncryptedTrack className="relay-track--notary" />
          <ProxyCard />
          <div className="relay-branch" aria-hidden="true">
            <svg viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
              <line x1="0" y1="37.5" x2="100" y2="37.5" />
              <line x1="0" y1="62.5" x2="100" y2="62.5" />
            </svg>
            <span className="relay-packet relay-packet--text" />
            <span className="relay-packet relay-packet--proof" />
          </div>
          <AgentCard />
          <PackageCard />
        </div>
      </div>
    </section>
  );
}
