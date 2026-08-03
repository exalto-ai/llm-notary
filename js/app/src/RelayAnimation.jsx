import { useEffect, useRef, useState } from 'react';
import { LoaderCircle, LockKeyhole, UnlockKeyhole } from 'lucide-react';

const providerNames = ['OpenAI', 'Anthropic', 'OpenRouter', 'DeepSeek'];
const ciphertextFrames = ['8F 3C\nA2 19', 'C1 7A\n04 E6', '19 BE\nF3 8C', '2B D9\nC7 05', 'A8 14\n5E F0'];

function useProviderTyping() {
  const [text, setText] = useState(providerNames[0]);

  useEffect(() => {
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
    if (reducedMotion.matches) return undefined;

    let providerIndex = 0;
    let characterIndex = providerNames[0].length;
    let direction = 1;
    let timer;

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

function PackageCard() {
  return <section className="relay-output relay-output--package">
    <header><b>YOUR PACKAGE</b><span className="package-ready">PORTABLE</span></header>
    <dl>
      <div><dt>Provider</dt><dd>api.openai.com</dd></div>
      <div><dt>Model</dt><dd>gpt-4.1</dd></div>
      <div><dt>Stream</dt><dd>complete</dd></div>
    </dl>
    <footer><i aria-hidden="true" /> notary evidence included</footer>
  </section>;
}

function useMobileCamera() {
  const viewportRef = useRef(null);
  const flowRef = useRef(null);
  const frameRef = useRef(null);
  const resumeTimerRef = useRef(null);
  const cameraXRef = useRef(0);
  const cycleStartRef = useRef(0);
  const progressRef = useRef(0);
  const manualDragRef = useRef(null);
  const manualRef = useRef(false);
  const inViewRef = useRef(false);

  const duration = 4600;

  const isMobile = () => window.matchMedia('(max-width: 960px)').matches;
  const prefersReducedMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const cameraStops = () => {
    const viewportWidth = viewportRef.current?.getBoundingClientRect().width || window.innerWidth;
    const center = viewportWidth / 2;
    return [center - 60, center - 229, center - 400, center - 607];
  };

  const applyCamera = (position) => {
    cameraXRef.current = position;
    if (flowRef.current) flowRef.current.style.transform = `translateX(${position}px) scale(.8)`;
  };

  const positionForProgress = (progress) => {
    const [provider, notary, proxy, outputs] = cameraStops();
    const phase = progress % 1;
    const between = (from, to, start, end) => from + ((to - from) * ((phase - start) / (end - start)));

    if (phase < .27) return provider;
    if (phase < .32) return between(provider, notary, .27, .32);
    if (phase < .48) return notary;
    if (phase < .54) return between(notary, proxy, .48, .54);
    if (phase < .67) return proxy;
    if (phase < .73) return between(proxy, outputs, .67, .73);
    return outputs;
  };

  const progressForPosition = (position) => {
    const [provider, notary, proxy, outputs] = cameraStops();
    const between = (from, to, start, end) => start + (((position - from) / (to - from)) * (end - start));

    if (position >= provider) return 0;
    if (position >= notary) return between(provider, notary, .27, .32);
    if (position >= proxy) return between(notary, proxy, .48, .54);
    if (position >= outputs) return between(proxy, outputs, .67, .73);
    return .73;
  };

  const stopAnimation = () => {
    window.cancelAnimationFrame(frameRef.current);
    frameRef.current = null;
  };

  const tick = (now) => {
    if (!inViewRef.current || manualRef.current || !isMobile() || prefersReducedMotion()) return;
    const progress = ((now - cycleStartRef.current) % duration) / duration;
    progressRef.current = progress;
    applyCamera(positionForProgress(progress));
    frameRef.current = window.requestAnimationFrame(tick);
  };

  const resumeAnimation = () => {
    if (!inViewRef.current || manualRef.current || !isMobile() || prefersReducedMotion()) return;
    stopAnimation();
    const progress = progressForPosition(cameraXRef.current);
    progressRef.current = progress;
    cycleStartRef.current = window.performance.now() - (progress * duration);
    frameRef.current = window.requestAnimationFrame(tick);
  };

  useEffect(() => {
    const viewport = viewportRef.current;
    if (!viewport) return undefined;

    const resetCamera = () => {
      if (!isMobile()) {
        stopAnimation();
        if (flowRef.current) flowRef.current.style.transform = '';
        return;
      }
      applyCamera(positionForProgress(progressRef.current));
      if (inViewRef.current && !manualRef.current) resumeAnimation();
    };

    resetCamera();
    window.addEventListener('resize', resetCamera);

    if (!('IntersectionObserver' in window)) {
      inViewRef.current = true;
      resumeAnimation();
      return () => {
        window.removeEventListener('resize', resetCamera);
        stopAnimation();
      };
    }

    const observer = new IntersectionObserver(([entry]) => {
      inViewRef.current = entry.isIntersecting;
      if (entry.isIntersecting) resumeAnimation();
      else stopAnimation();
    }, { threshold: 0.35 });
    observer.observe(viewport);
    return () => {
      observer.disconnect();
      window.removeEventListener('resize', resetCamera);
      stopAnimation();
    };
  }, []);

  useEffect(() => () => {
    window.clearTimeout(resumeTimerRef.current);
  }, []);

  const scheduleResume = () => {
    window.clearTimeout(resumeTimerRef.current);
    resumeTimerRef.current = window.setTimeout(() => {
      manualRef.current = false;
      resumeAnimation();
    }, 1800);
  };

  const handlePointerDown = (event) => {
    if (!isMobile()) return;
    manualRef.current = true;
    stopAnimation();
    window.clearTimeout(resumeTimerRef.current);
    manualDragRef.current = { pointerId: event.pointerId, startX: event.clientX, cameraX: cameraXRef.current };
    event.currentTarget.setPointerCapture?.(event.pointerId);
  };

  const handlePointerMove = (event) => {
    const drag = manualDragRef.current;
    if (!drag || drag.pointerId !== event.pointerId || !isMobile()) return;
    const [provider,,, outputs] = cameraStops();
    const next = Math.max(outputs, Math.min(provider, drag.cameraX + event.clientX - drag.startX));
    applyCamera(next);
  };

  const handlePointerEnd = (event) => {
    const drag = manualDragRef.current;
    if (!drag || drag.pointerId !== event.pointerId) return;
    manualDragRef.current = null;
    event.currentTarget.releasePointerCapture?.(event.pointerId);
    scheduleResume();
  };

  return { flowRef, handlePointerDown, handlePointerMove, handlePointerEnd, viewportRef };
}

export function RelayAnimation() {
  const { flowRef, handlePointerDown, handlePointerMove, handlePointerEnd, viewportRef } = useMobileCamera();

  return <section className="relay-animation" aria-label="A provider completion travels as encrypted traffic through LLM Notary to a local TLS proxy. The proxy produces plaintext output for your agent and a portable evidence package.">
    <div ref={viewportRef} className="relay-animation__viewport" onPointerDown={handlePointerDown} onPointerMove={handlePointerMove} onPointerUp={handlePointerEnd} onPointerCancel={handlePointerEnd}>
      <div ref={flowRef} className="relay-animation__flow">
        <ProviderCard />
        <EncryptedTrack className="relay-track--provider" label="Encrypted response travels to LLM Notary" />
        <NotaryCard />
        <EncryptedTrack className="relay-track--notary" label="Encrypted response travels to your local TLS proxy" />
        <ProxyCard />
        <div className="relay-branch" aria-hidden="true">
          <svg viewBox="0 0 100 100" preserveAspectRatio="none">
            <line x1="0" y1="37.5" x2="100" y2="37.5" />
            <line x1="0" y1="62.5" x2="100" y2="62.5" />
          </svg>
          <span className="relay-packet relay-packet--text" aria-label="Plaintext output" />
          <span className="relay-packet relay-packet--proof" aria-label="Proof packet" />
        </div>
        <AgentCard />
        <PackageCard />
      </div>
    </div>
  </section>;
}
