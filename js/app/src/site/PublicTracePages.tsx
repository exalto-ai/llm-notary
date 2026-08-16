import type { FormEvent } from 'react';
import { useEffect, useRef, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { ProviderIdentity } from '../ProviderIdentity';
import {
  downloadSharedPackage,
  getListedShares,
  getPublicShare,
  getSharedTrace,
  reportPublicShare,
  verifyTracePackage,
} from '../platform-api/client';
import { binaryFileSize, sessionDate } from './format';

type ListedSharesResponse = Awaited<ReturnType<typeof getListedShares>>;
type ListedShare = ListedSharesResponse['items'][number];
type VerificationResult = Awaited<ReturnType<typeof verifyTracePackage>>;
type PublicShare = Awaited<ReturnType<typeof getPublicShare>>;
type SharedTrace = Awaited<ReturnType<typeof getSharedTrace>>;
type ReportReason = Parameters<typeof reportPublicShare>[1]['reason'];

type TraceMessagePart = {
  type: string;
  id?: unknown;
  name?: unknown;
  arguments?: unknown;
  result?: unknown;
  content?: unknown;
};

type TraceMessage = {
  role: string;
  parts: TraceMessagePart[];
  finishReason?: string;
};

type ParsedSpan = {
  kind: string;
  name: string;
  spanId: string;
  attributes: Array<[string, unknown]>;
  messages: {
    input: TraceMessage[];
    output: TraceMessage[];
  };
};

function errorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error) return error.message;
  if (
    error &&
    typeof error === 'object' &&
    'message' in error &&
    typeof error.message === 'string'
  ) {
    return error.message;
  }
  return fallback;
}

function errorCode(error: unknown): string | undefined {
  if (error && typeof error === 'object' && 'code' in error && typeof error.code === 'string') {
    return error.code;
  }
  return undefined;
}

export function ListedSharesPreview({
  loadShares = getListedShares,
}: {
  loadShares?: typeof getListedShares;
}) {
  const [shares, setShares] = useState<ListedShare[] | null>(null);
  const [loadError, setLoadError] = useState(false);
  useEffect(() => {
    let cancelled = false;
    loadShares({ limit: 5 })
      .then((payload) => {
        if (!cancelled) setShares(payload.items);
      })
      .catch(() => {
        if (!cancelled) setLoadError(true);
      });
    return () => {
      cancelled = true;
    };
  }, [loadShares]);
  const visible = shares || [];
  return (
    <section className="section library-preview">
      <div className="trace-heading">
        <div>
          <span className="eyebrow">Public domain</span>
          <h2>Traces from the community.</h2>
        </div>
      </div>
      {shares === null && !loadError ? (
        <div className="collection-pending" role="status">
          <b>Loading the Library…</b>
          <span>Finding the latest public traces.</span>
        </div>
      ) : loadError ? (
        <div className="collection-pending" role="alert">
          <b>The Library couldn’t load.</b>
          <span>Open the Library to try again.</span>
        </div>
      ) : visible.length ? (
        <section className="preview-share-list" aria-label="Featured public traces">
          {visible.map((share) => (
            <a href={`/s/${encodeURIComponent(share.id)}`} key={share.id}>
              <header>
                <b>{share.model}</b>
                <ProviderIdentity
                  provider={share.provider}
                  detail={`shared by ${share.publisher}`}
                />
              </header>
              {share.password_protected ? (
                <p className="preview-share-protected">
                  <span>Protected</span>Password required to view disclosed messages.
                </p>
              ) : (
                <div className="preview-share-snippets">
                  <p>
                    <span>Prompt</span>
                    {share.input_preview || 'No prompt preview.'}
                  </p>
                  <p>
                    <span>Response</span>
                    {share.output_preview || 'No response preview.'}
                  </p>
                </div>
              )}
            </a>
          ))}
        </section>
      ) : (
        <div className="collection-pending">
          <b>The Library is empty.</b>
          <span>Public traces will appear here after they’re shared.</span>
        </div>
      )}
      <a className="button button-dark" href="#/library">
        Browse the Library
      </a>
    </section>
  );
}

const MAX_VERIFY_FILE_BYTES = 128 * 1024 * 1024 + 64 * 1024 + 16 * 1024;
const verificationErrors = {
  malformed_package: [
    'Package could not be read',
    'This file is not a well-formed canonical `.llmtrace` package.',
  ],
  tampered_package: [
    'Package verification failed',
    'Authenticated evidence, declared hashes, or the normalized trace did not match.',
  ],
  untrusted_notary: [
    'Notary key is not trusted',
    'The package was signed by a notary key that is not trusted for its authenticated capture time.',
  ],
  unsupported_version: [
    'Package version is unsupported',
    'This verifier does not support one of the package contract versions. Update the verifier or use a compatible package.',
  ],
  verification_in_flight: [
    'Verification already in progress',
    'This network address already has a verification running. Wait for it to finish and try again.',
  ],
  verification_capacity: [
    'Verifier is at capacity',
    'All verification workers are busy. Wait a moment and try again.',
  ],
  package_too_large: [
    'Package is too large',
    'Choose a `.llmtrace` package within the 128 MiB verification limit.',
  ],
  extraction_timeout: [
    'Package extraction timed out',
    'The archive could not be safely extracted within the service limit.',
  ],
  verification_timeout: [
    'Verification timed out',
    'The cryptographic check did not finish within the service limit.',
  ],
  verification_unavailable: [
    'Verification is unavailable',
    'The verification service could not complete this request. Try again later or verify locally.',
  ],
  unsupported_media_type: [
    'File type is unsupported',
    'Choose a finalized file whose name ends in `.llmtrace`.',
  ],
} as const;

type VerificationErrorCode = keyof typeof verificationErrors;

function isVerificationErrorCode(code: string): code is VerificationErrorCode {
  return Object.hasOwn(verificationErrors, code);
}

function verificationError(code: string | null): readonly [string, string] {
  return code && isVerificationErrorCode(code)
    ? verificationErrors[code]
    : verificationErrors.verification_unavailable;
}

function verificationFileError(file: File): VerificationErrorCode | null {
  if (!file.name.toLowerCase().endsWith('.llmtrace')) return 'unsupported_media_type';
  if (file.size < 1) return 'malformed_package';
  if (file.size > MAX_VERIFY_FILE_BYTES) return 'package_too_large';
  return null;
}

function formatVerificationTime(unixMilliseconds: number) {
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'long' }).format(
    new Date(unixMilliseconds),
  );
}

function formatTrustSource(source: string) {
  const words = String(source).replaceAll('_', ' ');
  return `${words.charAt(0).toUpperCase()}${words.slice(1)}`;
}

function VerificationError({
  code,
  onReset = null,
}: {
  code: string | null;
  onReset?: (() => void) | null;
}) {
  const [title, copy] = verificationError(code);
  return (
    <section className="verification-result verification-result--error" role="alert">
      <span className="eyebrow">Verification stopped</span>
      <h2>{title}</h2>
      <p>{copy}</p>
      <code>{code}</code>
      {onReset && (
        <button type="button" className="button" onClick={onReset}>
          Choose another package
        </button>
      )}
    </section>
  );
}

export function VerificationPage({
  verifyFile = verifyTracePackage,
}: {
  verifyFile?: typeof verifyTracePackage;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const outcomeRef = useRef<HTMLDivElement>(null);
  const requestGeneration = useRef(0);
  const [file, setFile] = useState<File | null>(null);
  const [consent, setConsent] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [status, setStatus] = useState<'idle' | 'uploading' | 'success' | 'error'>('idle');
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [result, setResult] = useState<VerificationResult | null>(null);
  const trace = result ? parseSharedTrace(result.trace) : [];
  const chooseFile = (nextFile: File | null) => {
    requestGeneration.current += 1;
    setConsent(false);
    setResult(null);
    setStatus('idle');
    const nextError = nextFile ? verificationFileError(nextFile) : null;
    setFile(nextError ? null : nextFile);
    setErrorCode(nextError);
  };
  const submit = async (event: FormEvent<HTMLFormElement>) => {
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
  return (
    <main className="verification-shell">
      <header className="verification-intro">
        <span className="eyebrow">Portable verification</span>
        <h1>Verify a .llmtrace package.</h1>
        <p>
          Check the authenticated provider exchange, notary signature, artifact hashes, and
          normalized OpenTelemetry trace without signing in.
        </p>
      </header>
      {!completed && (
        <form className="verification-workspace" onSubmit={submit}>
          <section
            className="verification-disclosure"
            aria-labelledby="verification-disclosure-title"
          >
            <span className="eyebrow">Read before uploading</span>
            <h2 id="verification-disclosure-title">Your package may contain sensitive content.</h2>
            <p>
              Headers are hidden by default, but prompts, responses, tool definitions, and tool
              results may be included. We check the package without saving it.
            </p>
          </section>
          <label
            className={`verification-drop${dragging ? ' verification-drop--active' : ''}`}
            onDragEnter={(event) => {
              event.preventDefault();
              setDragging(true);
            }}
            onDragOver={(event) => event.preventDefault()}
            onDragLeave={(event) => {
              if (
                !(event.relatedTarget instanceof Node) ||
                !event.currentTarget.contains(event.relatedTarget)
              )
                setDragging(false);
            }}
            onDrop={(event) => {
              event.preventDefault();
              setDragging(false);
              chooseFile(event.dataTransfer.files[0] || null);
            }}
          >
            <input
              ref={inputRef}
              type="file"
              onChange={(event) => chooseFile(event.currentTarget.files?.[0] || null)}
            />
            <span>{file ? 'Package selected' : 'Drop one .llmtrace package here'}</span>
            <strong>{file ? file.name : 'or choose a file'}</strong>
            <small>{file ? binaryFileSize(file.size) : 'Maximum package size: 128 MiB'}</small>
          </label>
          {file && (
            <label className="verification-consent">
              <input
                type="checkbox"
                checked={consent}
                onChange={(event) => setConsent(event.target.checked)}
              />
              <span>I understand that this package may contain sensitive content.</span>
            </label>
          )}
          <div className="verification-actions">
            <button
              className="button button-dark"
              type="submit"
              disabled={!file || !consent || status === 'uploading'}
            >
              {status === 'uploading' ? 'Checking package…' : 'Verify package'}
            </button>
            {file && (
              <button className="button" type="button" onClick={resetVerification}>
                Clear
              </button>
            )}
          </div>
          {status === 'uploading' && (
            <div className="verification-progress" role="status">
              <i aria-hidden="true" />
              <span>
                <b>Checking the evidence</b>
                <small>Keep this page open. Large packages can take a moment.</small>
              </span>
            </div>
          )}
        </form>
      )}
      {!completed && errorCode && <VerificationError code={errorCode} />}
      {completed && (
        <div ref={outcomeRef} className="verification-outcome" tabIndex={-1}>
          {status === 'error' && <VerificationError code={errorCode} onReset={resetVerification} />}
          {result && (
            <section
              className="verification-result verification-result--success"
              aria-labelledby="verification-success-title"
              aria-live="polite"
            >
              <header>
                <div>
                  <span className="eyebrow">Portable package</span>
                  <h2 id="verification-success-title">Verification passed.</h2>
                </div>
                <div className="verification-result-actions">
                  <strong>Verified</strong>
                  <button type="button" className="button" onClick={resetVerification}>
                    Verify another package
                  </button>
                </div>
              </header>
              <dl className="verification-facts">
                <div>
                  <dt>Provider</dt>
                  <dd>
                    <ProviderIdentity provider={result.provider} />
                  </dd>
                </div>
                <div>
                  <dt>Host</dt>
                  <dd>{result.host}</dd>
                </div>
                <div>
                  <dt>Capture time</dt>
                  <dd>{formatVerificationTime(result.authenticated_at_unix_ms)}</dd>
                </div>
                <div>
                  <dt>Notary key</dt>
                  <dd>
                    <code>{result.notary_key_id}</code>
                  </dd>
                </div>
                <div>
                  <dt>Trust source</dt>
                  <dd>
                    {formatTrustSource(result.trust_source)} · generation{' '}
                    {result.directory_generation}
                  </dd>
                </div>
                <div>
                  <dt>Trace SHA-256</dt>
                  <dd>
                    <code>{result.trace_sha256}</code>
                  </dd>
                </div>
                <div>
                  <dt>Package SHA-256</dt>
                  <dd>
                    <code>{result.package_sha256}</code>
                  </dd>
                </div>
              </dl>
              <section className="verification-trace">
                <div className="span-panel-head">
                  <span>Normalized trace</span>
                  <small>
                    {trace.length} {trace.length === 1 ? 'span' : 'spans'}
                  </small>
                </div>
                {trace.length ? (
                  <SpanTree spans={trace} />
                ) : (
                  <p>No normalized spans were present.</p>
                )}
              </section>
            </section>
          )}
        </div>
      )}
    </main>
  );
}

function formatTraceValue(value: unknown): string {
  if (typeof value === 'boolean') return String(value);
  if (typeof value === 'number') return value.toLocaleString('en-US');
  if (typeof value === 'object') return JSON.stringify(value) ?? '';
  return typeof value === 'string' ? value : '';
}

function TraceField({ label, value }: { label: string; value: unknown }) {
  return (
    <span className="trace-field">
      <b>{label}</b>
      <code>{formatTraceValue(value)}</code>
    </span>
  );
}

function MessagePart({ part }: { part: TraceMessagePart }) {
  if (part.type === 'tool_call') {
    return (
      <div className="message-part message-part--tool">
        <span>tool call</span>
        <div className="trace-fields">
          <TraceField label="call ID" value={part.id} />
          <TraceField label="name" value={part.name} />
          <TraceField label="arguments" value={part.arguments} />
        </div>
      </div>
    );
  }
  if (part.type === 'tool_call_response') {
    return (
      <div className="message-part message-part--tool">
        <span>tool result</span>
        <div className="trace-fields">
          <TraceField label="call ID" value={part.id} />
          <TraceField label="result" value={part.result} />
        </div>
      </div>
    );
  }
  return (
    <div className="message-part">
      <span>text</span>
      <div className="message-markdown">
        <ReactMarkdown>{String(part.content ?? '')}</ReactMarkdown>
      </div>
    </div>
  );
}

function MessageGroup({ label, messages }: { label: string; messages: TraceMessage[] }) {
  return (
    <div className="message-group">
      <span className="message-group-label">{label}</span>
      {messages.map((message, index) => (
        <div className="trace-message" key={`${message.role}-${index}`}>
          <span className="message-role">{message.role}</span>
          <div>
            {message.parts.map((part, partIndex) => (
              <MessagePart key={`${part.type}-${partIndex}`} part={part} />
            ))}
            {message.finishReason && (
              <span className="finish-reason">finish_reason: {message.finishReason}</span>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

function SpanTree({ spans }: { spans: ParsedSpan[] }) {
  const [expanded, setExpanded] = useState(() => new Set<number>([0]));
  useEffect(() => setExpanded(new Set<number>([0])), [spans]);
  const toggle = (index: number) =>
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
  return (
    <section className="span-tree" aria-label="Trace spans">
      {spans.map((span, index) => {
        const open = expanded.has(index);
        return (
          <div className="span-row span-row--source" key={`${span.spanId}-${index}`}>
            <button
              type="button"
              className="span-summary"
              aria-expanded={open}
              onClick={() => toggle(index)}
            >
              <span className="span-branch" aria-hidden="true" />
              <span className="span-kind">{span.kind}</span>
              <strong>{span.name}</strong>
              <span className="span-disclosure" aria-hidden="true" />
              <small>
                span <code>{span.spanId}</code>
              </small>
            </button>
            {open && (
              <>
                {span.attributes && (
                  <div className="span-evidence span-attributes">
                    <span className="message-group-label">attributes</span>
                    <div className="trace-fields">
                      {span.attributes.map(([name, value]) => (
                        <TraceField key={name} label={name} value={value} />
                      ))}
                    </div>
                  </div>
                )}
                {span.messages && (
                  <div className="span-evidence span-messages">
                    <MessageGroup label="gen_ai.input.messages" messages={span.messages.input} />
                    <MessageGroup label="gen_ai.output.messages" messages={span.messages.output} />
                  </div>
                )}
              </>
            )}
          </div>
        );
      })}
    </section>
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function recordArray(value: unknown, key: string): unknown[] {
  if (!isRecord(value)) return [];
  const candidate = value[key];
  return Array.isArray(candidate) ? candidate : [];
}

function otlpAttributeValue(value: unknown): unknown {
  if (!isRecord(value)) return '';
  if ('stringValue' in value) return value.stringValue;
  if ('intValue' in value) return value.intValue;
  if ('doubleValue' in value) return value.doubleValue;
  if ('boolValue' in value) return value.boolValue;
  const arrayValue = value.arrayValue;
  if (isRecord(arrayValue) && Array.isArray(arrayValue.values)) {
    return arrayValue.values.map(otlpAttributeValue);
  }
  return '';
}

function normalizeTracePart(value: unknown): TraceMessagePart {
  if (!isRecord(value)) return { type: 'text', content: value };
  return {
    type: typeof value.type === 'string' ? value.type : 'text',
    id: value.id,
    name: value.name,
    arguments: value.arguments,
    result: value.result,
    content: value.content,
  };
}

function normalizeTraceMessage(value: unknown): TraceMessage {
  if (!isRecord(value)) return { role: 'message', parts: [] };
  return {
    role: typeof value.role === 'string' ? value.role : 'message',
    parts: Array.isArray(value.parts) ? value.parts.map(normalizeTracePart) : [],
    ...(typeof value.finishReason === 'string' ? { finishReason: value.finishReason } : {}),
  };
}

function parseTraceMessages(value: unknown): TraceMessage[] {
  if (typeof value !== 'string') return [];
  try {
    const messages: unknown = JSON.parse(value);
    return Array.isArray(messages) ? messages.map(normalizeTraceMessage) : [];
  } catch {
    return [];
  }
}

function parseSharedTrace(trace: SharedTrace | VerificationResult['trace']): ParsedSpan[] {
  const spans = recordArray(trace, 'resourceSpans').flatMap((resource) =>
    recordArray(resource, 'scopeSpans').flatMap((scope) => recordArray(scope, 'spans')),
  );
  return spans.map((span, index) => {
    const spanRecord = isRecord(span) ? span : {};
    const attributes = recordArray(spanRecord, 'attributes').flatMap((attribute) => {
      if (!isRecord(attribute)) return [];
      const pair: [string, unknown] = [
        typeof attribute.key === 'string' ? attribute.key : '',
        otlpAttributeValue(attribute.value),
      ];
      return [pair];
    });
    const attributeMap = Object.fromEntries(attributes);
    return {
      kind: `CLIENT · ${String(index + 1).padStart(2, '0')}`,
      name: typeof spanRecord.name === 'string' ? spanRecord.name : 'gen_ai.inference',
      spanId: typeof spanRecord.spanId === 'string' ? spanRecord.spanId : '',
      attributes: attributes.filter(
        ([key]) => key !== 'gen_ai.input.messages' && key !== 'gen_ai.output.messages',
      ),
      messages: {
        input: parseTraceMessages(attributeMap['gen_ai.input.messages']),
        output: parseTraceMessages(attributeMap['gen_ai.output.messages']),
      },
    };
  });
}

function LibraryLoading() {
  return (
    <main className="share-library share-library--loading" aria-busy="true">
      <header className="share-library-titlebar">
        <h1>Library</h1>
      </header>
      <div className="share-library-skeleton" role="status" aria-label="Loading the Library">
        {[1, 2, 3].map((row) => (
          <div key={row}>
            <i />
            <span>
              <i />
              <i />
            </span>
          </div>
        ))}
      </div>
    </main>
  );
}

function formatLibraryDate(unixMilliseconds?: number | null) {
  if (!unixMilliseconds) return null;
  const date = new Date(unixMilliseconds);
  if (Number.isNaN(date.valueOf())) return null;
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }).format(date);
}

function LibraryShareRow({ share }: { share: ListedShare }) {
  const captureDate = formatLibraryDate(share.authenticated_at_unix_ms);
  const authenticatedAt = share.authenticated_at_unix_ms;
  const inputPreview = share.input_preview;
  const outputPreview = share.output_preview;
  return (
    <a
      className={`share-index-row${share.password_protected ? ' share-index-row--protected' : ''}`}
      href={`/s/${encodeURIComponent(share.id)}`}
    >
      <header>
        <div className="share-index-heading">
          <b>{share.model}</b>
          <small>
            <ProviderIdentity provider={share.provider} detail={`shared by ${share.publisher}`} />
            {captureDate && authenticatedAt && (
              <time dateTime={new Date(authenticatedAt).toISOString()}>{captureDate}</time>
            )}
          </small>
        </div>
        <span className="share-index-open">
          {share.password_protected ? 'Open protected trace' : 'Open trace'}
        </span>
      </header>
      {share.password_protected ? (
        <p className="share-index-protected">
          <span>Protected</span>Password required to view disclosed messages.
        </p>
      ) : (
        <div className="share-index-previews">
          {inputPreview && (
            <p>
              <span>Input</span>
              {inputPreview}
            </p>
          )}
          {outputPreview && (
            <p>
              <span>Response</span>
              {outputPreview}
            </p>
          )}
          {!inputPreview && !outputPreview && (
            <p className="share-index-preview-missing">No prompt or response preview.</p>
          )}
        </div>
      )}
    </a>
  );
}

export function Library({ loadShares = getListedShares }: { loadShares?: typeof getListedShares }) {
  const [shares, setShares] = useState<ListedShare[] | null>(null);
  const [loadingPage, setLoadingPage] = useState(true);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [loadError, setLoadError] = useState('');
  const [query, setQuery] = useState('');
  const [provider, setProvider] = useState('All');
  const [reload, setReload] = useState(0);
  const requestGeneration = useRef(0);
  const normalizedQuery = query.trim();
  const queryIsNotIndexable =
    normalizedQuery.length > 0 && !/[\p{L}\p{N}]{3}/u.test(normalizedQuery);
  const changeQuery = (value: string) => {
    requestGeneration.current += 1;
    setLoadingMore(false);
    setNextCursor(null);
    setShares([]);
    setLoadingPage(true);
    setLoadError('');
    setQuery(value);
  };
  const changeProvider = (value: string) => {
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
      return () => {
        cancelled = true;
      };
    }
    setLoadingPage(true);
    const timeout = window.setTimeout(() => {
      setLoadError('');
      loadShares({
        limit: 20,
        search: normalizedQuery || undefined,
        provider: provider === 'All' ? undefined : provider,
      })
        .then((payload) => {
          if (!cancelled && generation === requestGeneration.current) {
            setShares(payload.items);
            setNextCursor(payload.next_cursor || null);
            setLoadingPage(false);
          }
        })
        .catch((error) => {
          if (!cancelled && generation === requestGeneration.current) {
            setShares(null);
            setLoadError(error instanceof Error ? error.message : 'Could not load the Library.');
            setLoadingPage(false);
          }
        });
    }, 200);
    return () => {
      cancelled = true;
      window.clearTimeout(timeout);
    };
  }, [loadShares, normalizedQuery, provider, queryIsNotIndexable, reload]);
  const providers = [
    'All',
    ...new Set([
      'openai',
      'anthropic',
      'deepseek',
      'openrouter',
      ...(shares || []).map((share) => share.provider),
    ]),
  ];
  const visibleShares = shares ?? [];
  const loadMore = async () => {
    if (!nextCursor || loadingMore) return;
    const generation = requestGeneration.current;
    setLoadingMore(true);
    setLoadError('');
    try {
      const payload = await loadShares({
        limit: 20,
        cursor: nextCursor,
        search: normalizedQuery || undefined,
        provider: provider === 'All' ? undefined : provider,
      });
      if (generation !== requestGeneration.current) return;
      setShares((current) => [...(current || []), ...payload.items]);
      setNextCursor(payload.next_cursor || null);
    } catch (error) {
      if (generation === requestGeneration.current)
        setLoadError(error instanceof Error ? error.message : 'Could not load more traces.');
    } finally {
      if (generation === requestGeneration.current) setLoadingMore(false);
    }
  };
  if (shares === null && !loadError) return <LibraryLoading />;
  return (
    <main className="share-library">
      <header className="share-library-titlebar">
        <h1>Library</h1>
      </header>
      <section className="share-library-controls" aria-label="Browse public sessions">
        <label htmlFor="library-search">
          <span>Search</span>
          <Input
            id="library-search"
            value={query}
            onChange={(event) => changeQuery(event.target.value)}
            placeholder="Search conversations or models"
          />
        </label>
        <Select value={provider} onValueChange={changeProvider}>
          <SelectTrigger aria-label="Provider">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {providers.map((value) => (
              <SelectItem value={value} key={value}>
                {value === 'All' ? 'All providers' : <ProviderIdentity provider={value} />}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <span>
          {shares?.length || 0}
          {nextCursor ? '+' : ''} {(shares?.length || 0) === 1 ? 'trace' : 'traces'} shown
        </span>
      </section>
      {queryIsNotIndexable ? (
        <section className="collection-empty">
          <b>Keep typing.</b>
          <p>Search needs three letters or numbers together.</p>
        </section>
      ) : loadingPage ? (
        <div className="share-library-skeleton" role="status" aria-label="Loading filtered traces">
          {[1, 2, 3].map((row) => (
            <div key={row}>
              <i />
              <span>
                <i />
                <i />
              </span>
            </div>
          ))}
        </div>
      ) : loadError && shares === null ? (
        <section className="collection-empty" role="alert">
          <b>The Library couldn’t load.</b>
          <p>{loadError}</p>
          <button type="button" onClick={() => setReload((value) => value + 1)}>
            Try again
          </button>
        </section>
      ) : visibleShares.length ? (
        <>
          <section className="share-index" aria-label="Public traces">
            {visibleShares.map((share) => (
              <LibraryShareRow share={share} key={share.id} />
            ))}
          </section>
          {loadError && (
            <p className="library-page-error" role="alert">
              {loadError}
            </p>
          )}
          {nextCursor && (
            <button
              className="library-load-more"
              type="button"
              onClick={loadMore}
              disabled={loadingMore}
            >
              {loadingMore ? 'Loading…' : 'Load more traces'}
            </button>
          )}
        </>
      ) : query || provider !== 'All' ? (
        <section className="collection-empty">
          <b>Nothing matches.</b>
          <p>Try a different search or provider.</p>
          <button
            type="button"
            onClick={() => {
              requestGeneration.current += 1;
              setLoadingMore(false);
              setNextCursor(null);
              setShares([]);
              setLoadingPage(true);
              setLoadError('');
              setQuery('');
              setProvider('All');
            }}
          >
            Clear filters
          </button>
        </section>
      ) : (
        <section className="collection-empty">
          <b>The Library is empty.</b>
          <p>Public traces will appear here after they’re shared.</p>
          <a href="#/docs/share">Learn how sharing works</a>
        </section>
      )}
    </main>
  );
}

function SharedPart({ part }: { part: TraceMessagePart }) {
  if (part.type === 'tool_call' || part.type === 'tool_call_response') {
    const call = part.type === 'tool_call';
    return (
      <details className="tool-attachment">
        <summary>
          <span>{call ? 'Tool call' : 'Tool result'}</span>
          <b>
            {call
              ? formatTraceValue(part.name) || 'Unnamed tool'
              : formatTraceValue(part.id) || 'Returned value'}
          </b>
          <em>Show</em>
        </summary>
        <div>
          {Boolean(part.id) && <TraceField label="call ID" value={part.id} />}
          {call && <TraceField label="arguments" value={part.arguments} />}
          {!call && <TraceField label="result" value={part.result} />}
        </div>
      </details>
    );
  }
  return (
    <div className="shared-message-text">
      <ReactMarkdown>{String(part.content ?? '')}</ReactMarkdown>
    </div>
  );
}

function SharedConversation({ spans }: { spans: ParsedSpan[] }) {
  const turns = spans.flatMap((span, spanIndex) => [
    ...(span.messages?.input || []).map((message, messageIndex) => ({
      ...message,
      key: `${spanIndex}-input-${messageIndex}`,
    })),
    ...(span.messages?.output || []).map((message, messageIndex) => ({
      ...message,
      key: `${spanIndex}-output-${messageIndex}`,
    })),
  ]);
  if (!turns.length) return <p className="share-page-state">No messages were disclosed.</p>;
  return (
    <div className="shared-conversation">
      {turns.map((message, index) => (
        <article
          className={`shared-message shared-message--${message.role || 'unknown'}`}
          key={message.key}
        >
          <aside>
            <span>{String(index + 1).padStart(2, '0')}</span>
            <b>{message.role || 'message'}</b>
          </aside>
          <div>
            {(message.parts || []).map((part, partIndex) => (
              <SharedPart part={part} key={`${part.type}-${partIndex}`} />
            ))}
            {message.finishReason && (
              <small className="finish-reason">finish_reason: {message.finishReason}</small>
            )}
          </div>
        </article>
      ))}
    </div>
  );
}

function ShareReportDialog({
  open,
  onOpenChange,
  shareId,
  password,
  sendReport,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  shareId: string;
  password: string;
  sendReport: typeof reportPublicShare;
}) {
  const [reason, setReason] = useState<ReportReason>('sensitive_information');
  const [message, setMessage] = useState('');
  const [sending, setSending] = useState(false);
  const [error, setError] = useState('');
  const [received, setReceived] = useState(false);
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSending(true);
    setError('');
    try {
      await sendReport(shareId, { reason, message: message.trim() || undefined }, password);
      setReceived(true);
    } catch (failure) {
      setError(errorMessage(failure, 'Could not send this report.'));
    } finally {
      setSending(false);
    }
  };
  const changeOpen = (nextOpen: boolean) => {
    onOpenChange(nextOpen);
    if (!nextOpen) {
      setReason('sensitive_information');
      setMessage('');
      setError('');
      setReceived(false);
    }
  };
  return (
    <Dialog open={open} onOpenChange={changeOpen}>
      <DialogContent className="axis-dialog share-report-dialog">
        <DialogHeader>
          <DialogTitle>{received ? 'Report received' : 'Report this trace'}</DialogTitle>
          <DialogDescription>
            {received
              ? 'This trace has been added to the moderation queue.'
              : 'Choose the issue that best describes this published trace.'}
          </DialogDescription>
        </DialogHeader>
        {received ? (
          <DialogFooter>
            <button type="button" onClick={() => changeOpen(false)}>
              Close
            </button>
          </DialogFooter>
        ) : (
          <form onSubmit={submit}>
            <label htmlFor="share-report-reason">
              <span>Reason</span>
              <Select value={reason} onValueChange={(value) => setReason(value as ReportReason)}>
                <SelectTrigger id="share-report-reason" aria-label="Report reason">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="sensitive_information">Sensitive information</SelectItem>
                  <SelectItem value="harassment">Harassment</SelectItem>
                  <SelectItem value="illegal_content">Illegal content</SelectItem>
                  <SelectItem value="spam">Spam or misleading content</SelectItem>
                  <SelectItem value="other">Other</SelectItem>
                </SelectContent>
              </Select>
            </label>
            <label htmlFor="share-report-note">
              <span>Optional note</span>
              <Textarea
                id="share-report-note"
                value={message}
                onChange={(event) => setMessage(event.target.value)}
                maxLength={500}
                placeholder="Briefly explain the issue"
              />
              <small>{message.length}/500</small>
            </label>
            {error && <p role="alert">{error}</p>}
            <DialogFooter>
              <button type="button" onClick={() => changeOpen(false)} disabled={sending}>
                Cancel
              </button>
              <button type="submit" disabled={sending}>
                {sending ? 'Sending…' : 'Send report'}
              </button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

export function SharePage({
  shareId,
  loadShare = getPublicShare,
  loadTrace = getSharedTrace,
  downloadPackage = downloadSharedPackage,
  sendReport = reportPublicShare,
}: {
  shareId: string;
  loadShare?: typeof getPublicShare;
  loadTrace?: typeof getSharedTrace;
  downloadPackage?: typeof downloadSharedPackage;
  sendReport?: typeof reportPublicShare;
}) {
  const [share, setShare] = useState<PublicShare | null>(null);
  const [spans, setSpans] = useState<ParsedSpan[] | null>(null);
  const [loadError, setLoadError] = useState('');
  const [passwordRequired, setPasswordRequired] = useState(false);
  const [password, setPassword] = useState('');
  const [activePassword, setActivePassword] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const [checkingPassword, setCheckingPassword] = useState(false);
  const [packageError, setPackageError] = useState('');
  const [reportOpen, setReportOpen] = useState(false);
  useEffect(() => {
    let cancelled = false;
    setShare(null);
    setSpans(null);
    setLoadError('');
    setPasswordRequired(false);
    setPassword('');
    setActivePassword('');
    setPasswordError('');
    Promise.all([loadShare(shareId), loadTrace(shareId)])
      .then(([detail, trace]) => {
        if (!cancelled) {
          setShare(detail);
          setSpans(parseSharedTrace(trace));
        }
      })
      .catch((error) => {
        if (cancelled) return;
        if (errorCode(error) === 'share_password_required') setPasswordRequired(true);
        else setLoadError(errorMessage(error, 'Could not load this shared session.'));
      });
    return () => {
      cancelled = true;
    };
  }, [loadShare, loadTrace, shareId]);
  useEffect(() => {
    if (!share && !passwordRequired) return undefined;
    if (share) document.title = `${share.model} · LLM Notary`;
    const existingRobots = document.head.querySelector('meta[name="robots"][data-share-page]');
    const robots =
      existingRobots instanceof HTMLMetaElement ? existingRobots : document.createElement('meta');
    if (!(existingRobots instanceof HTMLMetaElement)) {
      robots.name = 'robots';
      robots.dataset.sharePage = 'true';
      document.head.appendChild(robots);
    }
    robots.content =
      passwordRequired || share?.visibility === 'unlisted' || share?.password_protected
        ? 'noindex, nofollow, noarchive'
        : 'index, follow';
    return () => {
      robots?.remove();
      document.title = 'LLM Notary';
    };
  }, [passwordRequired, share]);
  const unlock = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!password) return;
    setCheckingPassword(true);
    setPasswordError('');
    try {
      const [detail, trace] = await Promise.all([
        loadShare(shareId, password),
        loadTrace(shareId, password),
      ]);
      setShare(detail);
      setSpans(parseSharedTrace(trace));
      setActivePassword(password);
      setPasswordRequired(false);
    } catch (error) {
      const code = errorCode(error);
      if (code === 'share_password_invalid' || code === 'share_password_required')
        setPasswordError('That password did not open this trace.');
      else setPasswordError(errorMessage(error, 'Could not open this trace.'));
    } finally {
      setCheckingPassword(false);
    }
  };
  const saveProtectedPackage = async () => {
    setPackageError('');
    try {
      const blob = await downloadPackage(shareId, activePassword);
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `llm-notary-${shareId}.llmtrace`;
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 0);
    } catch (error) {
      setPackageError(errorMessage(error, 'Could not download this trace package.'));
    }
  };
  if (loadError)
    return (
      <main className="share-page share-page-state" role="alert">
        <h1>Share unavailable</h1>
        <p>{loadError}</p>
        <a href="#/library">Open Library</a>
      </main>
    );
  if (passwordRequired)
    return (
      <main className="share-password-page">
        <form className="share-password-gate" onSubmit={unlock}>
          <span className="eyebrow">Protected trace</span>
          <h1>Password required</h1>
          <p>The publisher limited access to this disclosed conversation.</p>
          <label htmlFor="share-password">Password</label>
          <Input
            id="share-password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoFocus
          />
          {passwordError && (
            <p className="share-password-error" role="alert">
              {passwordError}
            </p>
          )}
          <div>
            <a href="#/library">Back to Library</a>
            <button type="submit" disabled={!password || checkingPassword}>
              {checkingPassword ? 'Opening…' : 'Open trace'}
            </button>
          </div>
        </form>
      </main>
    );
  if (!share || spans === null)
    return (
      <main
        className="share-page share-page-loading"
        aria-busy="true"
        aria-label="Loading shared trace"
      >
        <header className="share-page-header">
          <div>
            <i className="share-loading-title" />
            <i className="share-loading-meta" />
          </div>
          <div className="share-verification-mark">
            <i aria-hidden="true" />
            <span>
              <i />
              <i />
            </span>
          </div>
        </header>
        <div className="share-page-layout">
          <section className="share-transcript">
            <header>
              <i className="share-loading-section" />
              <i className="share-loading-count" />
            </header>
            <div className="shared-conversation">
              {[1, 2, 3].map((row) => (
                <article className="shared-message" key={row}>
                  <aside>
                    <i />
                    <i />
                  </aside>
                  <div>
                    <i />
                    <i />
                    <i />
                  </div>
                </article>
              ))}
            </div>
          </section>
          <aside className="share-evidence-rail">
            <i className="share-loading-label" />
            <dl>
              {[1, 2, 3, 4].map((row) => (
                <div key={row}>
                  <dt>
                    <i />
                  </dt>
                  <dd>
                    <i />
                  </dd>
                </div>
              ))}
            </dl>
            <i className="share-loading-package" />
          </aside>
        </div>
      </main>
    );
  const authenticated = share.authenticated_at_unix_ms
    ? new Date(share.authenticated_at_unix_ms).toLocaleString()
    : 'Not recorded';
  const messageCount = spans.reduce(
    (count, span) =>
      count + (span.messages?.input?.length || 0) + (span.messages?.output?.length || 0),
    0,
  );
  return (
    <main className="share-page">
      <header className="share-page-header">
        <div>
          <h1>{share.model}</h1>
          <p>
            <b>{share.publisher}</b>
            <span>
              <ProviderIdentity provider={share.provider} />
            </span>
            <span>{share.visibility}</span>
          </p>
        </div>
        <div className="share-verification-mark">
          <i aria-hidden="true" />
          <span>
            <b>Verified</b>
            <small>Provider session</small>
          </span>
        </div>
      </header>
      <div className="share-page-layout">
        <section className="share-transcript" aria-labelledby="shared-conversation-title">
          <header>
            <h2 id="shared-conversation-title">Conversation</h2>
            <span>
              {messageCount} {messageCount === 1 ? 'message' : 'messages'}
            </span>
          </header>
          <SharedConversation spans={spans} />
        </section>
        <aside className="share-evidence-rail">
          <span className="eyebrow">Verification</span>
          <dl>
            <div>
              <dt>Provider</dt>
              <dd>
                <ProviderIdentity provider={share.provider} />
              </dd>
            </div>
            <div>
              <dt>Host</dt>
              <dd>{share.host}</dd>
            </div>
            <div>
              <dt>Authenticated</dt>
              <dd>{authenticated}</dd>
            </div>
            <div>
              <dt>Visibility</dt>
              <dd>
                {share.visibility}
                {share.password_protected ? ' · password protected' : ''}
              </dd>
            </div>
            {share.expires_at && (
              <div>
                <dt>Expires</dt>
                <dd>{sessionDate(share.expires_at)}</dd>
              </div>
            )}
          </dl>
          {share.password_protected ? (
            <button className="share-package-download" type="button" onClick={saveProtectedPackage}>
              <span>Package</span>
              <b>Download .llmtrace</b>
              <small>{binaryFileSize(share.package_size_bytes)} · SHA-256 included</small>
            </button>
          ) : (
            <a className="share-package-download" href={share.package_url}>
              <span>Package</span>
              <b>Download .llmtrace</b>
              <small>{binaryFileSize(share.package_size_bytes)} · SHA-256 included</small>
            </a>
          )}
          {packageError && (
            <p className="share-package-error" role="alert">
              {packageError}
            </p>
          )}
          <details className="share-technical">
            <summary>Hashes and notary</summary>
            <dl>
              <div>
                <dt>Trace SHA-256</dt>
                <dd>
                  <code>{share.trace_sha256}</code>
                </dd>
              </div>
              <div>
                <dt>Package SHA-256</dt>
                <dd>
                  <code>{share.package_sha256}</code>
                </dd>
              </div>
              <div>
                <dt>Notary key</dt>
                <dd>
                  <code>{share.notary_key_id || 'Not recorded'}</code>
                </dd>
              </div>
              <div>
                <dt>Directory generation</dt>
                <dd>{share.directory_generation ?? 'Not recorded'}</dd>
              </div>
              <div>
                <dt>Safety contract</dt>
                <dd>
                  <code>{share.public_package_safety_version}</code>
                </dd>
              </div>
            </dl>
          </details>
          <button className="share-report-button" type="button" onClick={() => setReportOpen(true)}>
            Report this trace
          </button>
        </aside>
      </div>
      <ShareReportDialog
        open={reportOpen}
        onOpenChange={setReportOpen}
        shareId={shareId}
        password={activePassword}
        sendReport={sendReport}
      />
    </main>
  );
}
