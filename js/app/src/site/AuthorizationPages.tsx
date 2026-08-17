import type { ReactNode } from 'react';
import { useEffect, useState } from 'react';
import {
  abbreviatedKeyId,
  formatNotaryBoundary,
  notaryLifecycle,
  orderNotaries,
} from '../notaryLifecycle';
import {
  approveCli,
  getCliApproval,
  type getCurrentUser,
  getNotaryDirectory,
} from '../platform-api/client';
import { sessionDate } from './format';

type CurrentUser = NonNullable<Awaited<ReturnType<typeof getCurrentUser>>>;
type AccountIdentity = Pick<CurrentUser, 'display_name' | 'provider_display_name'>;
type CliApprovalDetails = Awaited<ReturnType<typeof getCliApproval>>;
type HostedDirectory = Awaited<ReturnType<typeof getNotaryDirectory>>;
type HostedNotary = HostedDirectory['notaries'][number];
type AuthorizationTone = 'neutral' | 'attention' | 'success' | 'ready';
type AuthorizationFact = readonly [label: string, value: ReactNode];

function accountName(user: AccountIdentity) {
  return user.display_name || user.provider_display_name;
}

function messageFrom(reason: unknown, fallback: string) {
  return reason instanceof Error ? reason.message : fallback;
}

function AuthorizationPage({
  title,
  description,
  action = null,
  facts,
  tone = 'neutral',
}: {
  title: string;
  description: ReactNode;
  action?: ReactNode;
  facts: ReadonlyArray<AuthorizationFact>;
  tone?: AuthorizationTone;
}) {
  return (
    <main className={`cli-approval-shell cli-approval-shell--${tone}`}>
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
            <div
              className="cli-approval-path"
              role="img"
              aria-label="Local service connects to an LLM Notary account"
            >
              <span>
                <i aria-hidden="true" />
                Local service
              </span>
              <b aria-hidden="true" />
              <span>
                <i aria-hidden="true" />
                LLM Notary account
              </span>
            </div>
          </header>
          <dl>
            {facts.map(([label, value]) => (
              <div key={label}>
                <dt>{label}</dt>
                <dd>{value}</dd>
              </div>
            ))}
          </dl>
        </aside>
      </section>
    </main>
  );
}

export function CliApproval({
  route,
  user,
  loadApproval = getCliApproval,
  approveRequest = approveCli,
}: {
  route: string;
  user: AccountIdentity | null;
  loadApproval?: typeof getCliApproval;
  approveRequest?: typeof approveCli;
}) {
  const query = new URLSearchParams(route.split('?')[1] || '');
  const requestId = query.get('request_id');
  const approvalSecret = query.get('approval_secret');
  const [details, setDetails] = useState<CliApprovalDetails | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [approved, setApproved] = useState(false);
  useEffect(() => {
    if (!requestId || !approvalSecret || !user) return;
    let cancelled = false;
    loadApproval(requestId, approvalSecret)
      .then((payload) => {
        if (!cancelled) setDetails(payload);
      })
      .catch((reason) => {
        if (!cancelled) setError(messageFrom(reason, 'This authorization request is unavailable.'));
      });
    return () => {
      cancelled = true;
    };
  }, [requestId, approvalSecret, user, loadApproval]);
  const approve = async () => {
    if (!requestId || !approvalSecret) return;
    setError(null);
    try {
      await approveRequest(requestId, approvalSecret);
      setApproved(true);
    } catch (reason) {
      setError(messageFrom(reason, 'Could not approve this local service request.'));
    }
  };
  if (!requestId || !approvalSecret)
    return (
      <AuthorizationPage
        tone="attention"
        title="Invalid authorization link"
        description={<p>Return to the local dashboard and begin authorization again.</p>}
        facts={[
          ['Request', 'Invalid or incomplete'],
          ['Next step', 'Start again in the local dashboard'],
        ]}
      />
    );
  if (!user)
    return (
      <AuthorizationPage
        title="Sign in to continue"
        description={
          <p>
            Sign in to the account that should own this local service. You’ll review the device name
            and approve the connection next.
          </p>
        }
        action={
          <a
            className="button button-dark"
            href={`/#/signin?return_to=${encodeURIComponent(window.location.hash)}`}
          >
            Choose sign-in method
          </a>
        }
        facts={[
          ['Next step', 'Review and approve the device'],
          ['Control', 'Revoke later from Account'],
        ]}
      />
    );
  if (approved)
    return (
      <AuthorizationPage
        tone="success"
        title="Local service approved"
        description={
          <p>
            Your local dashboard will finish connecting to this account shortly. You can close this
            page.
          </p>
        }
        facts={[
          ['Device', details?.device_name || 'Local service'],
          ['Account', accountName(user)],
          ['Status', 'Approved'],
        ]}
      />
    );
  if (error)
    return (
      <AuthorizationPage
        tone="attention"
        title="Authorization unavailable"
        description={<p role="alert">{error} Return to the local dashboard and start again.</p>}
        facts={[
          ['Request', 'Needs attention'],
          ['Account', accountName(user)],
          ['Next step', 'Start again in the local dashboard'],
        ]}
      />
    );
  if (!details)
    return (
      <AuthorizationPage
        title="Checking this request"
        description={
          <p role="status">
            Retrieving the device and account details before you approve anything.
          </p>
        }
        facts={[
          ['Request', 'Checking'],
          ['Account', accountName(user)],
          ['Changes', 'None until you approve'],
        ]}
      />
    );
  return (
    <AuthorizationPage
      tone="ready"
      title="Approve this local service?"
      description={
        <p>
          This allows the local dashboard to use hosted finalization and create shares under your
          account.
        </p>
      }
      action={
        <button className="button button-dark" type="button" onClick={approve}>
          Approve service
        </button>
      }
      facts={[
        ['Device', details.device_name],
        ['Account', accountName(user)],
        ['Authorization code', details.user_code],
        ['Expires', sessionDate(details.expires_at)],
      ]}
    />
  );
}

const hostedNotaryStatuses: ReadonlySet<HostedNotary['status']> = new Set([
  'active',
  'retiring',
  'retired',
  'revoked',
]);

function normalizeHostedDirectory(payload: HostedDirectory): HostedDirectory {
  if (
    !payload ||
    typeof payload !== 'object' ||
    payload.format !== 'notary/registry/v1' ||
    !Array.isArray(payload.notaries) ||
    !Number.isSafeInteger(payload.generation) ||
    payload.generation < 0 ||
    typeof payload.active_key_id !== 'string'
  ) {
    throw new Error('malformed');
  }
  if (!payload.notaries.length) {
    if (payload.active_key_id) throw new Error('malformed');
    return { ...payload, notaries: [] };
  }
  const notaries = payload.notaries.map((record) => {
    if (
      !record ||
      typeof record !== 'object' ||
      typeof record.name !== 'string' ||
      !record.name ||
      typeof record.operator !== 'string' ||
      !record.operator ||
      typeof record.host !== 'string' ||
      !record.host ||
      !Number.isInteger(record.port) ||
      record.port < 1 ||
      record.port > 65535 ||
      !['tcp', 'tls'].includes(record.transport) ||
      typeof record.key_id !== 'string' ||
      !record.key_id ||
      !hostedNotaryStatuses.has(record.status) ||
      !Number.isSafeInteger(record.valid_from_unix_ms) ||
      record.valid_from_unix_ms < 0 ||
      ![record.valid_until_unix_ms, record.notarize_until_unix_ms].every(
        (value) =>
          value === null ||
          value === undefined ||
          (Number.isSafeInteger(value) && value >= record.valid_from_unix_ms),
      )
    ) {
      throw new Error('malformed');
    }
    return record;
  });
  const active = notaries.find((record) => record.key_id === payload.active_key_id);
  if (active?.status !== 'active') throw new Error('malformed');
  return { ...payload, notaries: orderNotaries(notaries, payload.active_key_id) };
}

function notaryEndpoint(record: HostedNotary) {
  const host = record.host.includes(':') ? `[${record.host}]` : record.host;
  return `${record.transport}://${host}:${record.port}`;
}

export function HostedNotaryRecord({
  record,
  activeKeyId,
  copiedKeyId,
  onCopy,
  compact = false,
}: {
  record: HostedNotary;
  activeKeyId: string;
  copiedKeyId: string | null;
  onCopy: (keyId: string) => void;
  compact?: boolean;
}) {
  const lifecycle = notaryLifecycle(record.status);
  return (
    <article
      className={`notary-record notary-record--${record.status}${compact ? ' notary-record--compact' : ''}`}
    >
      <header>
        <span className={`notary-state notary-state--${record.status}`}>
          <i aria-hidden="true" />
          {record.status}
        </span>
        {record.key_id === activeKeyId && (
          <span className="notary-selected">Selected by active_key_id</span>
        )}
      </header>
      <h3>{lifecycle.label}</h3>
      <p>{lifecycle.description}</p>
      <dl>
        <div>
          <dt>Endpoint</dt>
          <dd>
            <code>{notaryEndpoint(record)}</code>
          </dd>
        </div>
        <div>
          <dt>Transport</dt>
          <dd>{record.transport.toUpperCase()}</dd>
        </div>
        <div className="notary-key-row">
          <dt>Key ID / fingerprint</dt>
          <dd>
            <code title={record.key_id}>{abbreviatedKeyId(record.key_id)}</code>
            <button type="button" onClick={() => onCopy(record.key_id)}>
              {copiedKeyId === record.key_id ? 'Copied' : 'Copy full key ID'}
            </button>
          </dd>
        </div>
        {!compact && (
          <>
            <div>
              <dt>Valid from</dt>
              <dd>{formatNotaryBoundary(record.valid_from_unix_ms, { kind: 'lower' })}</dd>
            </div>
            <div>
              <dt>Capture cutoff</dt>
              <dd>{formatNotaryBoundary(record.valid_until_unix_ms)}</dd>
            </div>
            <div>
              <dt>Finalization cutoff</dt>
              <dd>{formatNotaryBoundary(record.notarize_until_unix_ms)}</dd>
            </div>
          </>
        )}
      </dl>
    </article>
  );
}

export function NotariesPage() {
  const [directory, setDirectory] = useState<HostedDirectory | null>(null);
  const [error, setError] = useState<'malformed' | 'unavailable' | null>(null);
  const [reload, setReload] = useState(0);
  const [copiedKeyId, setCopiedKeyId] = useState<string | null>(null);
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
      .catch(() => {
        if (!cancelled) setError('unavailable');
      });
    return () => {
      cancelled = true;
    };
  }, [reload]);
  const copyKeyId = async (keyId: string) => {
    await navigator.clipboard.writeText(keyId);
    setCopiedKeyId(keyId);
  };
  const available =
    directory?.notaries.filter(
      (record) => record.key_id === directory.active_key_id || record.status === 'retiring',
    ) || [];
  return (
    <main className="notaries-shell">
      <header className="notaries-intro">
        <span className="eyebrow">Public trust metadata</span>
        <h1>Notaries and trust</h1>
        <p>
          This is the signing-key lifecycle directory used by verification. It describes permitted
          protocol work and retained trust records; it does not report endpoint health, uptime, or
          capacity.
        </p>
      </header>
      {directory === null && !error ? (
        <div className="notary-loading" role="status" aria-label="Loading notary directory">
          <i />
          <i />
          <i />
        </div>
      ) : error ? (
        <section className="notary-page-state" role="alert">
          <h2>
            {error === 'malformed'
              ? 'The notary directory is malformed'
              : 'The notary directory is unavailable'}
          </h2>
          <p>
            {error === 'malformed'
              ? 'The response could not be read as a valid signing-key lifecycle directory. No notary is presented as usable.'
              : 'The public trust metadata could not be loaded. No endpoint status can be inferred from this failure.'}
          </p>
          <button type="button" onClick={() => setReload((value) => value + 1)}>
            Try again
          </button>
        </section>
      ) : directory === null ? null : directory.notaries.length === 0 ? (
        <section className="notary-page-state">
          <h2>No notary records are published</h2>
          <p>
            The directory contains no trust records. No capture or finalization endpoint is
            presented as available.
          </p>
        </section>
      ) : (
        <>
          <section className="notary-section" aria-labelledby="available-notaries">
            <div className="notary-section-heading">
              <div>
                <span className="eyebrow">Protocol lifecycle</span>
                <h2 id="available-notaries">Available for protocol work</h2>
              </div>
              <span>Generation {directory.generation}</span>
            </div>
            <p className="notary-section-note">
              These records describe allowed work within configured time windows. They are not a
              live availability check.
            </p>
            <div className="notary-records notary-records--available">
              {available.length ? (
                available.map((record) => (
                  <HostedNotaryRecord
                    key={record.key_id}
                    record={record}
                    activeKeyId={directory.active_key_id}
                    copiedKeyId={copiedKeyId}
                    onCopy={copyKeyId}
                    compact
                  />
                ))
              ) : (
                <p>No records are designated for new captures or compatible finalizations.</p>
              )}
            </div>
          </section>
          <section className="notary-section notary-history" aria-labelledby="notary-history">
            <div className="notary-section-heading">
              <div>
                <span className="eyebrow">Pinned signing keys</span>
                <h2 id="notary-history">Trust history</h2>
              </div>
              <span>
                {directory.notaries.length} {directory.notaries.length === 1 ? 'record' : 'records'}
              </span>
            </div>
            <div className="notary-records">
              {directory.notaries.map((record) => (
                <HostedNotaryRecord
                  key={record.key_id}
                  record={record}
                  activeKeyId={directory.active_key_id}
                  copiedKeyId={copiedKeyId}
                  onCopy={copyKeyId}
                />
              ))}
            </div>
          </section>
        </>
      )}
    </main>
  );
}
