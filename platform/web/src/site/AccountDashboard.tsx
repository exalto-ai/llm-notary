import { ChevronDown } from 'lucide-react';
import type { FormEvent } from 'react';
import { lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
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
import type { CreditHistoryEntry } from '../creditUtilization';
import { loadRecentDebits } from '../creditUtilization';
import {
  claimCreditOffer,
  createApiKey,
  createBillingPortalSession,
  createCheckoutSession,
  createSubscriptionCheckoutSession,
  deleteCurrentAccount,
  getApiKeys,
  getBillingPurchase,
  getBillingPurchases,
  getCreditHistory,
  getCreditOffers,
  getCurrentUser,
  getDevices,
  getHostedTraces,
  revokeApiKey,
  revokeDevice,
  stopHostedTraceSharing,
  updateHostedTrace,
} from '../platform-api/client';
import type { ThemePreference } from '../theme';
import { themeOptions } from '../theme';
import { sessionDate } from './format';

const loadCreditUtilizationChart = () => import('../CreditUtilizationChart');
const CreditUtilizationChart = lazy(loadCreditUtilizationChart);

type CurrentUser = NonNullable<Awaited<ReturnType<typeof getCurrentUser>>>;
type ApiKeyPage = Awaited<ReturnType<typeof getApiKeys>>;
type AccountApiKey = ApiKeyPage['items'][number];
type CreatedApiKey = Awaited<ReturnType<typeof createApiKey>>;
type DevicePage = Awaited<ReturnType<typeof getDevices>>;
type ConnectedDevice = DevicePage['items'][number];
type HostedTracePage = Awaited<ReturnType<typeof getHostedTraces>>;
type HostedTrace = HostedTracePage['items'][number];
type HostedTraceSettings = Parameters<typeof updateHostedTrace>[1];
type CreditHistoryPage = Awaited<ReturnType<typeof getCreditHistory>>;
type AccountCreditHistoryEntry = CreditHistoryPage['items'][number];
type CreditOffer = Awaited<ReturnType<typeof getCreditOffers>>[number];
type BillingPurchase = Awaited<ReturnType<typeof getBillingPurchase>>;
type ServicePlan = CurrentUser['billing']['plan'];
type DashboardView = 'overview' | 'traces' | 'usage' | 'settings';
type DashboardBilling = Omit<CurrentUser['billing'], 'entitlements'> & {
  entitlements?: CurrentUser['billing']['entitlements'];
};
type CheckoutReturnStatus =
  | 'waiting'
  | 'paid'
  | 'failed'
  | 'refunded'
  | 'disputed'
  | 'timeout'
  | 'cancelled';
type SubscriptionStatus = 'waiting' | 'active' | 'review' | 'timeout' | 'cancelled';

function errorMessage(reason: unknown, fallback = 'Something went wrong.'): string {
  return reason instanceof Error ? reason.message : fallback;
}

function accountIdentifier(user: CurrentUser): string {
  return user.provider_display_name;
}

function decimalSize(bytes: number): string {
  if (bytes < 1_000) return `${bytes} B`;
  if (bytes < 1_000_000) return `${(bytes / 1_000).toFixed(1)} KB`;
  if (bytes >= 1_000_000_000) return `${(bytes / 1_000_000_000).toFixed(1)} GB`;
  return `${(bytes / 1_000_000).toFixed(1)} MB`;
}

function shareStateLabel(state: HostedTrace['status']): { label: string; tone: string } {
  if (state === 'shared') return { label: 'Shared', tone: 'verified' };
  if (state === 'stopped') return { label: 'Stopped', tone: 'neutral' };
  if (state === 'verifying') return { label: 'Verifying', tone: 'pending' };
  if (state === 'rejected') return { label: 'Rejected', tone: 'attention' };
  if (state === 'failed') return { label: 'Failed', tone: 'attention' };
  return { label: state, tone: 'neutral' };
}

function shareAccessLabel(share: HostedTrace): string {
  if (share.status === 'stopped') return 'Public access stopped';
  if (share.access.expires_at && share.access.expires_at <= Math.floor(Date.now() / 1000))
    return 'Expired';
  return share.access.visibility === 'listed' ? 'Listed' : 'Unlisted';
}

const apiKeyScopeOptions = [
  ['account:read', 'Read account identity'],
  ['traces:read', 'Read owned Traces'],
  ['traces:share', 'Create and manage shared Traces'],
  ['capture:request', 'Request hosted Capture admission'],
  ['notarization:request', 'Request hosted Notarization admission'],
] as const;

type ApiKeyScope = (typeof apiKeyScopeOptions)[number][0];

function apiKeyState(apiKey: AccountApiKey): 'Revoked' | 'Expired' | 'Active' {
  if (apiKey.revoked_at) return 'Revoked';
  if (apiKey.expires_at && apiKey.expires_at <= Math.floor(Date.now() / 1000)) return 'Expired';
  return 'Active';
}

interface ApiKeysPanelProps {
  loadKeys?: typeof getApiKeys;
  createKey?: typeof createApiKey;
  revokeKey?: typeof revokeApiKey;
}

export function ApiKeysPanel({
  loadKeys = getApiKeys,
  createKey = createApiKey,
  revokeKey = revokeApiKey,
}: ApiKeysPanelProps) {
  const [apiKeys, setApiKeys] = useState<AccountApiKey[] | null>(null);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [name, setName] = useState('');
  const [scopes, setScopes] = useState<ApiKeyScope[]>(apiKeyScopeOptions.map(([scope]) => scope));
  const [expiresOn, setExpiresOn] = useState('');
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<CreatedApiKey | null>(null);
  const [copied, setCopied] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<AccountApiKey | null>(null);
  const [revoking, setRevoking] = useState(false);

  useEffect(() => {
    let cancelled = false;
    loadKeys({ limit: 20 })
      .then((page) => {
        if (!cancelled) {
          setApiKeys(page.items);
          setNextCursor(page.next_cursor || null);
        }
      })
      .catch((reason) => {
        if (!cancelled) setError(errorMessage(reason, 'Could not load API keys.'));
      });
    return () => {
      cancelled = true;
    };
  }, [loadKeys]);

  const closeDialog = (open: boolean) => {
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
  const toggleScope = (scope: ApiKeyScope) =>
    setScopes((current) =>
      current.includes(scope) ? current.filter((value) => value !== scope) : [...current, scope],
    );
  const create = async (event: FormEvent<HTMLFormElement>) => {
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
      setError(errorMessage(reason, 'Could not create the API key.'));
    } finally {
      setCreating(false);
    }
  };
  const copySecret = async () => {
    if (!created) return;
    await navigator.clipboard.writeText(created.secret);
    setCopied(true);
  };
  const revoke = async () => {
    if (!revokeTarget) return;
    setRevoking(true);
    setError(null);
    try {
      await revokeKey(revokeTarget.id);
      const revokedAt = Math.floor(Date.now() / 1000);
      setApiKeys((current) =>
        (current || []).map((key) =>
          key.id === revokeTarget.id ? { ...key, revoked_at: key.revoked_at || revokedAt } : key,
        ),
      );
    } catch (reason) {
      setError(errorMessage(reason, 'Could not revoke the API key.'));
    } finally {
      setRevoking(false);
      setRevokeTarget(null);
    }
  };
  const loadMore = async () => {
    if (!nextCursor || loadingMore) return;
    setLoadingMore(true);
    setError(null);
    try {
      const page = await loadKeys({ limit: 20, cursor: nextCursor });
      setApiKeys((current) => [...(current || []), ...page.items]);
      setNextCursor(page.next_cursor || null);
    } catch (reason) {
      setError(errorMessage(reason, 'Could not load more API keys.'));
    } finally {
      setLoadingMore(false);
    }
  };

  return (
    <section className="dashboard-api-keys" aria-labelledby="api-keys-title">
      <header>
        <div>
          <span className="eyebrow">API keys</span>
          <h2 id="api-keys-title">API access</h2>
        </div>
        <button type="button" onClick={() => setDialogOpen(true)}>
          Create API key
        </button>
      </header>
      {error && (
        <p className="dashboard-session-error" role="alert">
          {error}
        </p>
      )}
      {apiKeys === null && !error ? (
        <p className="dashboard-session-empty">Loading API keys…</p>
      ) : apiKeys?.length ? (
        <>
          <div className="dashboard-api-key-list">
            {apiKeys.map((apiKey) => (
              <article key={apiKey.id} className={apiKeyState(apiKey).toLowerCase()}>
                <div className="dashboard-api-key-copy">
                  <div>
                    <b>{apiKey.name}</b>
                    <span className="dashboard-api-key-state">
                      <i aria-hidden="true" />
                      {apiKeyState(apiKey)}
                    </span>
                  </div>
                  <code>{apiKey.prefix}</code>
                  <span>{apiKey.scopes.join(' · ')}</span>
                  <small>
                    Created {sessionDate(apiKey.created_at)} · Last used{' '}
                    {apiKey.last_used_at ? sessionDate(apiKey.last_used_at) : 'Never'} · Expires{' '}
                    {apiKey.expires_at ? sessionDate(apiKey.expires_at) : 'Never'}
                  </small>
                </div>
                {!apiKey.revoked_at && (
                  <button type="button" onClick={() => setRevokeTarget(apiKey)}>
                    Revoke
                  </button>
                )}
              </article>
            ))}
          </div>
          {nextCursor && (
            <button
              className="dashboard-load-more"
              type="button"
              onClick={loadMore}
              disabled={loadingMore}
            >
              {loadingMore ? 'Loading…' : 'Load more API keys'}
            </button>
          )}
        </>
      ) : (
        <div className="dashboard-api-key-empty">
          <b>No API keys</b>
          <p>Create a scoped key for CI, cron jobs, or another unattended host.</p>
        </div>
      )}

      <Dialog open={dialogOpen} onOpenChange={closeDialog}>
        <DialogContent className="axis-api-key-dialog" showCloseButton={!creating}>
          <DialogHeader>
            <DialogTitle>{created ? 'Copy this API key now' : 'Create API key'}</DialogTitle>
            <DialogDescription>
              {created
                ? 'The complete key is shown once. Store it in your CI or service secret manager before closing.'
                : 'Choose only the access this automation needs. The key remains valid until it expires or you revoke it.'}
            </DialogDescription>
          </DialogHeader>
          {created ? (
            <div className="api-key-receipt">
              <span className="eyebrow">API key</span>
              <code>{created.secret}</code>
              <button type="button" onClick={copySecret}>
                {copied ? 'Copied' : 'Copy API key'}
              </button>
            </div>
          ) : (
            <form id="create-api-key-form" className="api-key-form" onSubmit={create}>
              <label htmlFor="api-key-name">
                <span>Name</span>
                <Input
                  id="api-key-name"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  maxLength={100}
                  required
                  placeholder="GitHub Actions release"
                />
              </label>
              <fieldset>
                <legend>Scopes</legend>
                {apiKeyScopeOptions.map(([scope, description]) => (
                  <label key={scope}>
                    <input
                      type="checkbox"
                      checked={scopes.includes(scope)}
                      onChange={() => toggleScope(scope)}
                    />
                    <span>
                      <code>{scope}</code>
                      <small>{description}</small>
                    </span>
                  </label>
                ))}
              </fieldset>
              <label htmlFor="api-key-expiration">
                <span>Expiration</span>
                <Input
                  id="api-key-expiration"
                  type="date"
                  value={expiresOn}
                  min={new Date(Date.now() + 86400000).toISOString().slice(0, 10)}
                  onChange={(event) => setExpiresOn(event.target.value)}
                />
                <small>Leave blank to never expire.</small>
              </label>
            </form>
          )}
          <DialogFooter>
            {created ? (
              <button type="button" className="api-key-primary" onClick={() => closeDialog(false)}>
                I stored the key
              </button>
            ) : (
              <>
                <button
                  type="button"
                  className="api-key-secondary"
                  onClick={() => closeDialog(false)}
                  disabled={creating}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  form="create-api-key-form"
                  className="api-key-primary"
                  disabled={creating || !name.trim() || !scopes.length}
                >
                  {creating ? 'Creating…' : 'Create API key'}
                </button>
              </>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <AlertDialog
        open={Boolean(revokeTarget)}
        onOpenChange={(open) => {
          if (!open && !revoking) setRevokeTarget(null);
        }}
      >
        <AlertDialogContent className="axis-alert-dialog">
          <AlertDialogHeader>
            <AlertDialogTitle>Revoke {revokeTarget?.name}?</AlertDialogTitle>
            <AlertDialogDescription>
              Requests using this key will be rejected immediately. This action does not affect
              other keys or connected devices.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={revoking}>Keep key</AlertDialogCancel>
            <AlertDialogAction disabled={revoking} onClick={revoke}>
              {revoking ? 'Revoking…' : 'Revoke API key'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </section>
  );
}

interface AccountSettingsProps {
  theme: ThemePreference;
  onThemeChange: (theme: ThemePreference) => void;
}

export function AccountSettings({ theme, onThemeChange }: AccountSettingsProps) {
  return (
    <section className="dashboard-account-settings" aria-labelledby="account-settings-title">
      <header>
        <span className="eyebrow">Theme</span>
        <h2 id="account-settings-title">Appearance</h2>
      </header>
      <div className="dashboard-account-setting">
        <div>
          <b>Browser theme</b>
          <span>Use your device setting, or choose a theme for this browser.</span>
        </div>
        <div className="dashboard-appearance-options" role="radiogroup" aria-label="Appearance">
          {themeOptions.map((option) => (
            <button
              type="button"
              role="radio"
              aria-checked={theme === option}
              onClick={() => onThemeChange(option)}
              key={option}
            >
              {option}
            </button>
          ))}
        </div>
      </div>
    </section>
  );
}

interface DeleteAccountPanelProps {
  identifier: string;
  onDeleted: () => void;
  deleteAccount?: typeof deleteCurrentAccount;
}

export function DeleteAccountPanel({
  identifier,
  onDeleted,
  deleteAccount = deleteCurrentAccount,
}: DeleteAccountPanelProps) {
  const [open, setOpen] = useState(false);
  const [confirmation, setConfirmation] = useState('');
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState('');
  const close = (nextOpen: boolean) => {
    if (deleting) return;
    setOpen(nextOpen);
    if (!nextOpen) {
      setConfirmation('');
      setError('');
    }
  };
  const remove = async (event: FormEvent) => {
    event.preventDefault();
    if (confirmation !== identifier || deleting) return;
    setDeleting(true);
    setError('');
    try {
      await deleteAccount();
      onDeleted();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Could not delete the account.');
      setDeleting(false);
    }
  };
  return (
    <section className="dashboard-delete-account" aria-labelledby="delete-account-title">
      <div>
        <span className="eyebrow">Account deletion</span>
        <h2 id="delete-account-title">Delete account</h2>
        <p>
          Delete hosted traces, active share access, API keys, devices, billing and account data,
          and hosted settings according to the retention policy. Local traces and local settings on
          your devices are not deleted.
        </p>
      </div>
      <button type="button" onClick={() => setOpen(true)}>
        Delete account
      </button>
      <AlertDialog open={open} onOpenChange={close}>
        <AlertDialogContent className="axis-alert-dialog axis-delete-account-dialog">
          <AlertDialogHeader>
            <AlertDialogTitle>Delete {identifier}?</AlertDialogTitle>
            <AlertDialogDescription>
              This deletes hosted traces, active share access, API keys, devices, billing and
              account data, and hosted settings according to the retention policy. Local traces and
              local settings on your devices are not deleted. You cannot undo it.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <form id="delete-account-form" className="delete-account-form" onSubmit={remove}>
            <label htmlFor="delete-account-confirmation">
              Type <b>{identifier}</b> to confirm.
            </label>
            <Input
              id="delete-account-confirmation"
              value={confirmation}
              onChange={(event) => setConfirmation(event.target.value)}
              autoComplete="off"
              disabled={deleting}
            />
            {error && <p role="alert">{error}</p>}
          </form>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>Keep account</AlertDialogCancel>
            <AlertDialogAction
              type="button"
              disabled={confirmation !== identifier || deleting}
              onClick={remove}
            >
              {deleting ? 'Deleting…' : 'Delete account'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </section>
  );
}

function CreditUtilizationFallback({ credits }: { credits: CurrentUser['usage']['credits'] }) {
  const notarization = credits.notarization;
  return (
    <section
      className="dashboard-utilization dashboard-utilization--loading"
      role="status"
      aria-label="Loading daily utilization"
    >
      <header>
        <div>
          <span className="eyebrow">Notarization usage</span>
          <h2>Last 30 days</h2>
        </div>
        <span>MB · UTC</span>
      </header>
      <div className="dashboard-utilization-plot dashboard-utilization-plot--loading">
        <i />
      </div>
      <dl>
        <div>
          <dt>
            <i className="dashboard-utilization-period" />
            30-day use
          </dt>
          <dd>—</dd>
        </div>
        <div>
          <dt>Available</dt>
          <dd>{decimalSize(notarization.total_remaining_bytes)}</dd>
        </div>
        <div>
          <dt>Overall budget</dt>
          <dd>{decimalSize(notarization.total_granted_bytes)}</dd>
        </div>
      </dl>
    </section>
  );
}

const planDetails: Record<ServicePlan, { label: string; price: string }> = {
  free: { label: 'Free', price: '$0' },
  one_gb: { label: '1 GB', price: '$9.99/month' },
  ten_gb: { label: '10 GB', price: '$49.99/month' },
};

function planLabel(plan: ServicePlan): string {
  return planDetails[plan].label;
}

const dashboardSections = [
  { key: 'overview', label: 'Overview', href: '#/account' },
  { key: 'traces', label: 'Traces', href: '#/account/traces' },
  { key: 'usage', label: 'Plan & usage', href: '#/account/usage' },
  { key: 'settings', label: 'Settings', href: '#/account/settings' },
] as const;

const checkoutReturnMessages = {
  waiting: 'Payment received. Waiting for Stripe confirmation…',
  paid: 'Payment confirmed. Your credits are ready.',
  failed: 'Payment was not completed. No credits were added.',
  refunded: 'This payment was refunded. Its purchased credits are no longer available.',
  disputed: 'This payment is under dispute. Its purchased credits are temporarily unavailable.',
  timeout: 'We could not confirm the payment yet. Check purchase history or refresh this page.',
};

function isDashboardView(view: string): view is DashboardView {
  return dashboardSections.some(({ key }) => key === view);
}

function isCompletedPurchaseState(
  state: BillingPurchase['state'],
): state is 'paid' | 'refunded' | 'disputed' | 'failed' {
  return state === 'paid' || state === 'refunded' || state === 'disputed' || state === 'failed';
}

interface DashboardMobileNavigationProps {
  activeView: DashboardView;
  traceCount: number | string;
}

function DashboardMobileNavigation({ activeView, traceCount }: DashboardMobileNavigationProps) {
  const [open, setOpen] = useState(false);
  const navigationRef = useRef<HTMLElement | null>(null);
  const currentLabel = dashboardSections.find(({ key }) => key === activeView)?.label || 'Overview';
  useEffect(() => setOpen(false), [activeView]);
  useEffect(() => {
    const close = (event: MouseEvent | KeyboardEvent) => {
      if (
        ('key' in event && event.key === 'Escape') ||
        (event.type === 'mousedown' &&
          event.target instanceof Node &&
          !navigationRef.current?.contains(event.target))
      )
        setOpen(false);
    };
    document.addEventListener('mousedown', close);
    window.addEventListener('keydown', close);
    return () => {
      document.removeEventListener('mousedown', close);
      window.removeEventListener('keydown', close);
    };
  }, []);
  return (
    <nav className="dashboard-mobile-toolbar" aria-label="Account navigation" ref={navigationRef}>
      <button
        type="button"
        className={open ? 'active' : ''}
        onClick={() => setOpen((current) => !current)}
        aria-label={`Account menu: ${currentLabel}`}
        aria-expanded={open}
        aria-controls="dashboard-mobile-panel"
      >
        <span>
          <small>Account</small>
          {currentLabel}
        </span>
        <ChevronDown aria-hidden="true" />
      </button>
      {open && (
        <div className="dashboard-mobile-panel" id="dashboard-mobile-panel">
          <span>Account</span>
          {dashboardSections.map(({ key, label, href }) => (
            <a
              className={activeView === key ? 'active' : ''}
              href={href}
              aria-current={activeView === key ? 'page' : undefined}
              onClick={() => setOpen(false)}
              key={key}
            >
              <span>{label}</span>
              {key === 'traces' && <small>{traceCount}</small>}
            </a>
          ))}
        </div>
      )}
    </nav>
  );
}

interface HostedTraceSettingsDialogProps {
  share: HostedTrace | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSave: (
    share: HostedTrace,
    settings: HostedTraceSettings,
    closeSettings?: boolean,
  ) => Promise<void>;
  saving: boolean;
  error: string | null;
}

function HostedTraceSettingsDialog({
  share,
  open,
  onOpenChange,
  onSave,
  saving,
  error,
}: HostedTraceSettingsDialogProps) {
  const [visibility, setVisibility] = useState<'unlisted' | 'listed'>('unlisted');
  const [protectedAccess, setProtectedAccess] = useState(false);
  const [password, setPassword] = useState('');
  const [expiryMode, setExpiryMode] = useState<'keep' | 'never' | 'after'>('keep');
  const [expiryDays, setExpiryDays] = useState('7');
  useEffect(() => {
    if (!share || !open) return;
    setVisibility(share.access.visibility);
    setProtectedAccess(share.access.password_protected);
    setPassword('');
    setExpiryMode('keep');
    setExpiryDays('7');
  }, [open, share]);
  if (!share) return null;
  const needsPassword = protectedAccess && !share.access.password_protected;
  const passwordValid = !needsPassword || password.length >= 8;
  const expiryValid =
    expiryMode !== 'after' ||
    (Number.isInteger(Number(expiryDays)) && Number(expiryDays) >= 1 && Number(expiryDays) <= 365);
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const settings: HostedTraceSettings = { visibility };
    if (!protectedAccess && share.access.password_protected) settings.password = '';
    if (protectedAccess && password) settings.password = password;
    if (expiryMode === 'never') settings.expires_in_days = 0;
    if (expiryMode === 'after') settings.expires_in_days = Number(expiryDays);
    onSave(share, settings);
  };
  return (
    <Dialog
      open={open}
      onOpenChange={(nextOpen) => {
        if (!saving) onOpenChange(nextOpen);
      }}
    >
      <DialogContent className="axis-dialog share-settings-dialog">
        <DialogHeader>
          <DialogTitle>Manage Trace {share.trace_id.slice(0, 8)}</DialogTitle>
          <DialogDescription>
            Changes apply to the stable public link immediately.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={submit}>
          <label htmlFor="share-settings-visibility">
            <span>Library visibility</span>
            <Select
              value={visibility}
              onValueChange={(value) => setVisibility(value as 'unlisted' | 'listed')}
            >
              <SelectTrigger id="share-settings-visibility" aria-label="Library visibility">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="unlisted">Unlisted · link only</SelectItem>
                <SelectItem value="listed">Listed · shown in Library</SelectItem>
              </SelectContent>
            </Select>
          </label>
          <label className="share-settings-check">
            <input
              type="checkbox"
              checked={protectedAccess}
              onChange={(event) => setProtectedAccess(event.target.checked)}
            />
            <span>
              <b>Require a password</b>
              <small>
                {share.access.password_protected
                  ? 'Leave the field blank to keep the current password.'
                  : 'People must enter it before any trace content loads.'}
              </small>
            </span>
          </label>
          {protectedAccess && (
            <label htmlFor="share-settings-password">
              <span>
                {share.access.password_protected ? 'New password (optional)' : 'Password'}
              </span>
              <Input
                id="share-settings-password"
                type="password"
                value={password}
                minLength={8}
                maxLength={128}
                autoComplete="new-password"
                onChange={(event) => setPassword(event.target.value)}
                placeholder={
                  share.access.password_protected
                    ? 'Keep current password'
                    : 'At least 8 characters'
                }
              />
            </label>
          )}
          <label htmlFor="share-settings-expiry">
            <span>Expiry</span>
            <Select
              value={expiryMode}
              onValueChange={(value) => setExpiryMode(value as 'keep' | 'never' | 'after')}
            >
              <SelectTrigger id="share-settings-expiry" aria-label="Trace expiry">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="keep">Keep current expiry</SelectItem>
                <SelectItem value="never">Never expires</SelectItem>
                <SelectItem value="after">Expire after a number of days</SelectItem>
              </SelectContent>
            </Select>
          </label>
          {expiryMode === 'after' && (
            <label htmlFor="share-settings-days">
              <span>Days from now</span>
              <Input
                id="share-settings-days"
                type="number"
                min="1"
                max="365"
                step="1"
                value={expiryDays}
                onChange={(event) => setExpiryDays(event.target.value)}
              />
            </label>
          )}
          {share.access.expires_at && expiryMode === 'keep' && (
            <p className="share-settings-current">
              Currently expires {sessionDate(share.access.expires_at)}.
            </p>
          )}
          {error && (
            <p className="share-settings-error" role="alert">
              {error}
            </p>
          )}
          <DialogFooter>
            <button type="button" onClick={() => onOpenChange(false)} disabled={saving}>
              Cancel
            </button>
            <button type="submit" disabled={saving || !passwordValid || !expiryValid}>
              {saving ? 'Saving…' : 'Save changes'}
            </button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

interface DashboardProps {
  user: CurrentUser;
  view: string;
  theme: ThemePreference;
  onThemeChange: (theme: ThemePreference) => void;
  onAccountDeleted: () => void;
  loadConnectedDevices?: typeof getDevices;
  revokeDeviceRequest?: typeof revokeDevice;
  loadHostedTraces?: typeof getHostedTraces;
  loadCreditOffers?: typeof getCreditOffers;
  loadCreditHistory?: typeof getCreditHistory;
  loadBillingPurchases?: typeof getBillingPurchases;
  loadBillingPurchase?: typeof getBillingPurchase;
  startCheckout?: typeof createCheckoutSession;
  startSubscriptionCheckout?: typeof createSubscriptionCheckoutSession;
  startBillingPortal?: typeof createBillingPortalSession;
  openCheckout?: (url: string) => void;
  loadCurrentUser?: typeof getCurrentUser;
  claimOfferRequest?: typeof claimCreditOffer;
  updateTraceRequest?: typeof updateHostedTrace;
  stopSharingRequest?: typeof stopHostedTraceSharing;
  route?: string;
  checkoutPollBaseDelay?: number;
  checkoutPollMaxAttempts?: number;
}

export function Dashboard({
  user,
  view,
  theme,
  onThemeChange,
  onAccountDeleted,
  loadConnectedDevices = getDevices,
  revokeDeviceRequest = revokeDevice,
  loadHostedTraces = getHostedTraces,
  loadCreditOffers = getCreditOffers,
  loadCreditHistory = getCreditHistory,
  loadBillingPurchases = getBillingPurchases,
  loadBillingPurchase = getBillingPurchase,
  startCheckout = createCheckoutSession,
  startSubscriptionCheckout = createSubscriptionCheckoutSession,
  startBillingPortal = createBillingPortalSession,
  openCheckout = (url) => window.location.assign(url),
  loadCurrentUser = getCurrentUser,
  claimOfferRequest = claimCreditOffer,
  updateTraceRequest = updateHostedTrace,
  stopSharingRequest = stopHostedTraceSharing,
  route = '',
  checkoutPollBaseDelay = 1_000,
  checkoutPollMaxAttempts = 8,
}: DashboardProps) {
  const activeView = view === 'shares' ? 'traces' : isDashboardView(view) ? view : 'overview';
  const [sessions, setSessions] = useState<ConnectedDevice[] | null>(null);
  const [sessionCursor, setSessionCursor] = useState<string | null>(null);
  const [loadingMoreSessions, setLoadingMoreSessions] = useState(false);
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<ConnectedDevice | null>(null);
  const [shares, setShares] = useState<HostedTrace[] | null>(null);
  const [shareCursor, setShareCursor] = useState<string | null>(null);
  const [loadingMoreShares, setLoadingMoreShares] = useState(false);
  const [shareError, setShareError] = useState<string | null>(null);
  const [shareSettingsTarget, setHostedTraceSettingsTarget] = useState<HostedTrace | null>(null);
  const [unpublishTarget, setUnpublishTarget] = useState<HostedTrace | null>(null);
  const [copiedTraceId, setCopiedTraceId] = useState<string | null>(null);
  const [savingShare, setSavingShare] = useState<string | null>(null);
  const [credits, setCredits] = useState<CurrentUser['usage']['credits']>(user.usage.credits);
  const [creditOffers, setCreditOffers] = useState<CreditOffer[] | null>(null);
  const [creditError, setCreditError] = useState<string | null>(null);
  const [claimingOffer, setClaimingOffer] = useState<string | null>(null);
  const [creditHistory, setCreditHistory] = useState<AccountCreditHistoryEntry[] | null>(null);
  const [creditHistoryCursor, setCreditHistoryCursor] = useState<string | null>(null);
  const [loadingMoreCreditHistory, setLoadingMoreCreditHistory] = useState(false);
  const [billing, setBilling] = useState<DashboardBilling>(
    user.billing || {
      plan: 'free',
      billing_status: 'active',
      purchase_mode: 'disabled',
      subscriptions_configured: false,
    },
  );
  const [purchases, setPurchases] = useState<BillingPurchase[] | null>(null);
  const [purchaseError, setPurchaseError] = useState<string | null>(null);
  const [checkoutReturnStatus, setCheckoutReturnStatus] = useState<CheckoutReturnStatus | null>(
    null,
  );
  const [quantityGb, setQuantityGb] = useState(1);
  const [checkoutAttemptKey, setCheckoutAttemptKey] = useState<string | null>(null);
  const [startingCheckout, setStartingCheckout] = useState(false);
  const [startingPlan, setStartingPlan] = useState<'one_gb' | 'ten_gb' | 'portal' | null>(null);
  const [subscriptionStatus, setSubscriptionStatus] = useState<SubscriptionStatus | null>(null);
  const [creditUtilizationHistory, setCreditUtilizationHistory] = useState<
    CreditHistoryEntry[] | null
  >(null);
  const [creditUtilizationError, setCreditUtilizationError] = useState(false);
  const creditHistoryGeneration = useRef(0);
  const purchaseListGeneration = useRef(0);
  const checkoutQuery = useMemo(() => new URLSearchParams(route.split('?')[1] || ''), [route]);
  const returnedCheckout = checkoutQuery.get('checkout');
  const returnedPurchaseId = checkoutQuery.get('purchase_id');
  const returnedSubscription = checkoutQuery.get('subscription');

  useEffect(() => {
    let cancelled = false;
    loadConnectedDevices({ limit: 20 })
      .then((page) => {
        if (!cancelled) {
          setSessions(page.items);
          setSessionCursor(page.next_cursor || null);
        }
      })
      .catch((reason) => {
        if (!cancelled) setSessionError(errorMessage(reason, 'Could not load connected devices.'));
      });
    return () => {
      cancelled = true;
    };
  }, [loadConnectedDevices]);

  useEffect(() => {
    let cancelled = false;
    const generation = creditHistoryGeneration.current + 1;
    creditHistoryGeneration.current = generation;
    loadCreditHistory({ limit: 20 })
      .then((page) => {
        if (!cancelled && generation === creditHistoryGeneration.current) {
          setCreditHistory(page.items);
          setCreditHistoryCursor(page.next_cursor || null);
        }
      })
      .catch((reason) => {
        if (!cancelled && generation === creditHistoryGeneration.current)
          setCreditError(errorMessage(reason, 'Could not load credit activity.'));
      });
    return () => {
      cancelled = true;
    };
  }, [loadCreditHistory]);

  useEffect(() => {
    if (activeView !== 'overview') return undefined;
    let cancelled = false;
    setCreditUtilizationHistory(null);
    setCreditUtilizationError(false);
    loadRecentDebits(loadCreditHistory, Date.now(), () => cancelled)
      .then((entries) => {
        if (!cancelled && entries) setCreditUtilizationHistory(entries);
      })
      .catch(() => {
        if (!cancelled) setCreditUtilizationError(true);
      });
    return () => {
      cancelled = true;
    };
  }, [activeView, loadCreditHistory]);

  useEffect(() => {
    let cancelled = false;
    const generation = purchaseListGeneration.current;
    loadBillingPurchases()
      .then((items) => {
        if (!cancelled && generation === purchaseListGeneration.current) setPurchases(items);
      })
      .catch((reason) => {
        if (!cancelled && generation === purchaseListGeneration.current)
          setPurchaseError(errorMessage(reason, 'Could not load credit purchases.'));
      });
    return () => {
      cancelled = true;
    };
  }, [loadBillingPurchases]);

  useEffect(() => {
    if (returnedCheckout !== 'success' || !returnedPurchaseId) {
      setCheckoutReturnStatus(returnedCheckout === 'cancelled' ? 'cancelled' : null);
      return undefined;
    }
    let cancelled = false;
    let timer: number | undefined;
    let attempts = 0;
    setCheckoutReturnStatus('waiting');
    const scheduleNext = (poll: () => Promise<void>) => {
      if (attempts >= checkoutPollMaxAttempts) {
        setCheckoutReturnStatus('timeout');
        return;
      }
      const delay = Math.min(checkoutPollBaseDelay * 2 ** Math.min(attempts - 1, 3), 5_000);
      timer = window.setTimeout(poll, delay);
    };
    const poll = async () => {
      attempts += 1;
      try {
        const purchase = await loadBillingPurchase(returnedPurchaseId);
        if (cancelled) return;
        setPurchaseError(null);
        purchaseListGeneration.current += 1;
        setPurchases((current) => [
          purchase,
          ...(current || []).filter((item) => item.id !== purchase.id),
        ]);
        if (isCompletedPurchaseState(purchase.state)) {
          setCheckoutReturnStatus(purchase.state);
          try {
            const account = await loadCurrentUser();
            if (!cancelled && account) {
              setCredits(account.usage.credits);
              setBilling(account.billing);
              const generation = creditHistoryGeneration.current + 1;
              creditHistoryGeneration.current = generation;
              const history = await loadCreditHistory({ limit: 20 });
              if (!cancelled && generation === creditHistoryGeneration.current) {
                setCreditHistory(history.items);
                setCreditHistoryCursor(history.next_cursor || null);
              }
            }
          } catch (reason) {
            if (!cancelled)
              setPurchaseError(errorMessage(reason, 'Could not refresh account credits.'));
          }
          return;
        }
        scheduleNext(poll);
      } catch (reason) {
        if (cancelled) return;
        if (attempts >= checkoutPollMaxAttempts) {
          setCheckoutReturnStatus('timeout');
          setPurchaseError(`Stripe confirmation could not be refreshed: ${errorMessage(reason)}`);
        } else {
          scheduleNext(poll);
        }
      }
    };
    void poll();
    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [
    checkoutPollBaseDelay,
    checkoutPollMaxAttempts,
    loadBillingPurchase,
    loadCreditHistory,
    loadCurrentUser,
    returnedCheckout,
    returnedPurchaseId,
  ]);

  useEffect(() => {
    if (returnedSubscription !== 'success') {
      setSubscriptionStatus(returnedSubscription === 'cancelled' ? 'cancelled' : null);
      return undefined;
    }
    let cancelled = false;
    let timer: number | undefined;
    let attempts = 0;
    setSubscriptionStatus('waiting');
    const refresh = async () => {
      attempts += 1;
      try {
        const account = await loadCurrentUser();
        if (cancelled || !account) return;
        setCredits(account.usage.credits);
        setBilling(account.billing);
        if (account.billing.plan !== 'free' || account.billing.billing_status === 'review') {
          setSubscriptionStatus(account.billing.billing_status === 'active' ? 'active' : 'review');
          return;
        }
      } catch (reason) {
        if (attempts >= checkoutPollMaxAttempts)
          setPurchaseError(errorMessage(reason, 'Could not refresh the subscription.'));
      }
      if (attempts >= checkoutPollMaxAttempts) {
        setSubscriptionStatus('timeout');
        return;
      }
      const delay = Math.min(checkoutPollBaseDelay * 2 ** Math.min(attempts - 1, 3), 5_000);
      timer = window.setTimeout(refresh, delay);
    };
    void refresh();
    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [checkoutPollBaseDelay, checkoutPollMaxAttempts, loadCurrentUser, returnedSubscription]);

  useEffect(() => {
    let cancelled = false;
    loadCreditOffers()
      .then((offers) => {
        if (!cancelled) setCreditOffers(offers);
      })
      .catch((reason) => {
        if (!cancelled) setCreditError(errorMessage(reason, 'Could not load credit offers.'));
      });
    return () => {
      cancelled = true;
    };
  }, [loadCreditOffers]);

  useEffect(() => {
    if (!revokeTarget) return undefined;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && revoking !== revokeTarget.device_id) setRevokeTarget(null);
    };
    window.addEventListener('keydown', closeOnEscape);
    return () => window.removeEventListener('keydown', closeOnEscape);
  }, [revokeTarget, revoking]);

  useEffect(() => {
    let cancelled = false;
    loadHostedTraces({ limit: 20 })
      .then((page) => {
        if (!cancelled) {
          setShares(page.items);
          setShareCursor(page.next_cursor || null);
        }
      })
      .catch((reason) => {
        if (!cancelled) setShareError(errorMessage(reason, 'Could not load your traces.'));
      });
    return () => {
      cancelled = true;
    };
  }, [loadHostedTraces]);

  const revoke = async (session: ConnectedDevice) => {
    setRevoking(session.device_id);
    setSessionError(null);
    try {
      await revokeDeviceRequest(session.device_id);
      setSessions(
        (current) => current?.filter((item) => item.device_id !== session.device_id) || [],
      );
    } catch (reason) {
      setSessionError(errorMessage(reason, 'Could not revoke this connected device.'));
    } finally {
      setRevoking(null);
      setRevokeTarget(null);
    }
  };

  const saveHostedTraceSettings = async (
    share: HostedTrace,
    settings: HostedTraceSettings,
    closeSettings = true,
  ) => {
    setSavingShare(share.trace_id);
    setShareError(null);
    try {
      const updated = await updateTraceRequest(share.trace_id, settings);
      setShares(
        (current) =>
          current?.map((item) => (item.trace_id === updated.trace_id ? updated : item)) || [],
      );
      if (closeSettings) setHostedTraceSettingsTarget(null);
      setUnpublishTarget(null);
    } catch (reason) {
      setShareError(errorMessage(reason, 'Could not update this trace.'));
    } finally {
      setSavingShare(null);
    }
  };

  const stopSharing = async (trace: HostedTrace) => {
    setSavingShare(trace.trace_id);
    setShareError(null);
    try {
      await stopSharingRequest(trace.trace_id);
      setShares(
        (current) =>
          current?.map((item) =>
            item.trace_id === trace.trace_id
              ? { ...item, status: 'stopped', public_url: null, package_url: null }
              : item,
          ) || [],
      );
      setUnpublishTarget(null);
    } catch (reason) {
      setShareError(errorMessage(reason, 'Could not stop sharing this Trace.'));
    } finally {
      setSavingShare(null);
    }
  };

  const copyShareLink = async (trace: HostedTrace) => {
    if (!trace.public_url) return;
    setShareError(null);
    try {
      await navigator.clipboard.writeText(trace.public_url);
      setCopiedTraceId(trace.trace_id);
    } catch (reason) {
      setShareError(errorMessage(reason, 'Could not copy this share link.'));
    }
  };

  const claimOffer = async (offer: CreditOffer) => {
    let refreshGeneration: number | null = null;
    setClaimingOffer(offer.id);
    setCreditError(null);
    try {
      const response = await claimOfferRequest(offer.id);
      setCredits(response.credits);
      setCreditOffers((current) => current?.filter((item) => item.id !== offer.id) || []);
      refreshGeneration = creditHistoryGeneration.current + 1;
      creditHistoryGeneration.current = refreshGeneration;
      setLoadingMoreCreditHistory(true);
      const historyPage = await loadCreditHistory({ limit: 20 });
      if (refreshGeneration === creditHistoryGeneration.current) {
        setCreditHistory(historyPage.items);
        setCreditHistoryCursor(historyPage.next_cursor || null);
      }
    } catch (reason) {
      setCreditError(errorMessage(reason, 'Could not claim this credit offer.'));
    } finally {
      if (refreshGeneration === creditHistoryGeneration.current) setLoadingMoreCreditHistory(false);
      setClaimingOffer(null);
    }
  };

  const buyCredits = async () => {
    if (!['test', 'live'].includes(billing.purchase_mode)) return;
    const attemptKey =
      checkoutAttemptKey ||
      globalThis.crypto?.randomUUID?.() ||
      `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    setCheckoutAttemptKey(attemptKey);
    setStartingCheckout(true);
    setPurchaseError(null);
    try {
      const response = await startCheckout(quantityGb, attemptKey);
      openCheckout(response.checkout_url);
    } catch (reason) {
      setPurchaseError(errorMessage(reason, 'Could not start checkout.'));
      setStartingCheckout(false);
    }
  };

  const choosePlan = async (plan: 'one_gb' | 'ten_gb') => {
    if (!['test', 'live'].includes(billing.purchase_mode)) return;
    const attemptKey =
      globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    setStartingPlan(plan);
    setPurchaseError(null);
    try {
      const response = await startSubscriptionCheckout(plan, attemptKey);
      openCheckout(response.checkout_url);
    } catch (reason) {
      setPurchaseError(errorMessage(reason, 'Could not start subscription checkout.'));
      setStartingPlan(null);
    }
  };

  const manageSubscription = async () => {
    setStartingPlan('portal');
    setPurchaseError(null);
    try {
      const response = await startBillingPortal();
      openCheckout(response.portal_url);
    } catch (reason) {
      setPurchaseError(errorMessage(reason, 'Could not open subscription management.'));
      setStartingPlan(null);
    }
  };

  const loadMoreSessions = async () => {
    if (!sessionCursor || loadingMoreSessions) return;
    setLoadingMoreSessions(true);
    try {
      const page = await getDevices({ limit: 20, cursor: sessionCursor });
      setSessions((current) => [...(current || []), ...page.items]);
      setSessionCursor(page.next_cursor || null);
    } catch (reason) {
      setSessionError(errorMessage(reason, 'Could not load more connected devices.'));
    } finally {
      setLoadingMoreSessions(false);
    }
  };
  const loadMoreShares = async () => {
    if (!shareCursor || loadingMoreShares) return;
    setLoadingMoreShares(true);
    try {
      const page = await getHostedTraces({ limit: 20, cursor: shareCursor });
      setShares((current) => [...(current || []), ...page.items]);
      setShareCursor(page.next_cursor || null);
    } catch (reason) {
      setShareError(errorMessage(reason, 'Could not load more traces.'));
    } finally {
      setLoadingMoreShares(false);
    }
  };
  const loadMoreCreditHistory = async () => {
    if (!creditHistoryCursor || loadingMoreCreditHistory) return;
    const generation = creditHistoryGeneration.current;
    setLoadingMoreCreditHistory(true);
    try {
      const page = await loadCreditHistory({ limit: 20, cursor: creditHistoryCursor });
      if (generation !== creditHistoryGeneration.current) return;
      setCreditHistory((current) => [...(current || []), ...page.items]);
      setCreditHistoryCursor(page.next_cursor || null);
    } catch (reason) {
      if (generation === creditHistoryGeneration.current)
        setCreditError(errorMessage(reason, 'Could not load older credit activity.'));
    } finally {
      if (generation === creditHistoryGeneration.current) setLoadingMoreCreditHistory(false);
    }
  };

  const sharedCount = user.usage.hosted_traces.shared;
  const traceAttentionCount =
    shares?.filter((trace) => trace.status === 'rejected' || trace.status === 'failed').length || 0;
  const needsAttention =
    billing.billing_status === 'review'
      ? { href: '#/account/usage', value: 'Billing' }
      : shareError
        ? { href: '#/account/traces', value: 'Unavailable' }
        : { href: '#/account/traces', value: traceAttentionCount || 'None' };
  const purchaseMode = billing.purchase_mode || 'disabled';
  const checkoutEnabled = purchaseMode === 'test' || purchaseMode === 'live';
  const subscriptionCheckoutEnabled = checkoutEnabled && billing.subscriptions_configured === true;
  const displayedCheckoutStatus =
    checkoutReturnStatus ||
    (returnedCheckout === 'success'
      ? 'waiting'
      : returnedCheckout === 'cancelled'
        ? 'cancelled'
        : null);
  return (
    <main className="dashboard-shell dashboard-shell--account">
      <DashboardMobileNavigation
        activeView={activeView}
        traceCount={user.usage.hosted_traces.total}
      />
      <div className="dashboard-layout">
        <aside className="dashboard-sidebar" aria-label="Account navigation">
          <nav>
            <a
              className={activeView === 'overview' ? 'active' : ''}
              href="#/account"
              aria-current={activeView === 'overview' ? 'page' : undefined}
            >
              <span>Overview</span>
            </a>
            <a
              className={activeView === 'traces' ? 'active' : ''}
              href="#/account/traces"
              aria-current={activeView === 'traces' ? 'page' : undefined}
            >
              <span>Traces</span>
              <small>{user.usage.hosted_traces.total}</small>
            </a>
            <a
              className={activeView === 'usage' ? 'active' : ''}
              href="#/account/usage"
              aria-current={activeView === 'usage' ? 'page' : undefined}
            >
              <span>Plan & usage</span>
            </a>
            <a
              className={activeView === 'settings' ? 'active' : ''}
              href="#/account/settings"
              aria-current={activeView === 'settings' ? 'page' : undefined}
            >
              <span>Settings</span>
            </a>
          </nav>
        </aside>
        <div className="dashboard-page">
          {activeView === 'overview' && (
            <>
              <header className="dashboard-page-header">
                <span className="eyebrow">Account</span>
                <h1>Overview</h1>
                <p>Plan standing, usage, explicitly shared traces, and anything needing action.</p>
              </header>
              <div className="dashboard-summary">
                <div>
                  <span>Current plan</span>
                  <b>
                    {planLabel(billing.plan)} · {billing.billing_status}
                  </b>
                </div>
                <div>
                  <span>Capture usage</span>
                  <b>{credits ? `${decimalSize(credits.capture.total_used_bytes)} used` : '—'}</b>
                </div>
                <div>
                  <span>Notarization usage</span>
                  <b>
                    {credits ? `${decimalSize(credits.notarization.total_used_bytes)} used` : '—'}
                  </b>
                </div>
                <div>
                  <span>Shared traces</span>
                  <b>{shares === null ? '—' : sharedCount}</b>
                </div>
                <a href={needsAttention.href}>
                  <span>Needs attention</span>
                  <b>{shares === null && !shareError ? '—' : needsAttention.value}</b>
                </a>
              </div>
              {credits && (
                <Suspense fallback={<CreditUtilizationFallback credits={credits} />}>
                  <CreditUtilizationChart
                    credits={credits}
                    formatBytes={decimalSize}
                    historyDebits={creditUtilizationHistory}
                    historyError={creditUtilizationError}
                  />
                </Suspense>
              )}
            </>
          )}
          {activeView === 'usage' && (
            <>
              <header className="dashboard-page-header">
                <span className="eyebrow">Billing</span>
                <h1>Plan & usage</h1>
                <p>
                  Manage your subscription and track capture, notarization, and trace storage
                  separately.
                </p>
              </header>
              {credits && (
                <section className="dashboard-credits" aria-labelledby="credit-balance-title">
                  <header>
                    <div>
                      <span className="eyebrow">Current plan</span>
                      <h2 id="credit-balance-title">{planLabel(billing.plan)}</h2>
                    </div>
                    <div className="dashboard-credit-meta">
                      <span>
                        {billing.billing_status} · {planDetails[billing.plan]?.price}
                      </span>
                      <span>Usage resets {sessionDate(credits.reset_at)}</span>
                    </div>
                  </header>
                  <div className="dashboard-plan-actions">
                    {billing.plan === 'free' ? (
                      <>
                        <div>
                          <b>Increase monthly allowances</b>
                          <span>
                            {subscriptionCheckoutEnabled
                              ? 'Subscription changes are handled securely by Stripe.'
                              : 'New subscriptions are temporarily unavailable.'}
                          </span>
                        </div>
                        <div>
                          {(['one_gb', 'ten_gb'] as const).map((plan) => (
                            <button
                              type="button"
                              key={plan}
                              onClick={() => choosePlan(plan)}
                              disabled={!subscriptionCheckoutEnabled || Boolean(startingPlan)}
                            >
                              {startingPlan === plan
                                ? 'Opening Checkout…'
                                : `${planLabel(plan)} · ${planDetails[plan].price}`}
                            </button>
                          ))}
                        </div>
                      </>
                    ) : (
                      <>
                        <div>
                          <b>{planLabel(billing.plan)} subscription</b>
                          <span>Change plans, update payment details, or cancel in Stripe.</span>
                        </div>
                        <button
                          type="button"
                          onClick={manageSubscription}
                          disabled={!checkoutEnabled || Boolean(startingPlan)}
                        >
                          {startingPlan === 'portal' ? 'Opening portal…' : 'Manage subscription'}
                        </button>
                      </>
                    )}
                  </div>
                  {subscriptionStatus === 'cancelled' && (
                    <p className="dashboard-checkout-state">
                      Subscription Checkout was cancelled. Your plan did not change.
                    </p>
                  )}
                  {subscriptionStatus === 'waiting' && (
                    <p className="dashboard-checkout-state" role="status">
                      Checkout completed. Waiting for Stripe to activate your plan…
                    </p>
                  )}
                  {subscriptionStatus === 'active' && (
                    <p className="dashboard-checkout-state" role="status">
                      Your subscription is active and the new monthly allowances are ready.
                    </p>
                  )}
                  {subscriptionStatus === 'review' && (
                    <p className="dashboard-checkout-state" role="alert">
                      Stripe needs attention before hosted capture, notarization, or uploads can
                      continue. Open subscription management to resolve it.
                    </p>
                  )}
                  {subscriptionStatus === 'timeout' && (
                    <p className="dashboard-checkout-state" role="status">
                      Stripe is still processing the subscription. Refresh this page in a moment.
                    </p>
                  )}
                  {billing.billing_status === 'review' && subscriptionStatus !== 'review' && (
                    <p className="dashboard-checkout-state" role="alert">
                      Billing needs attention. Hosted capture, notarization, and trace uploads are
                      paused until it is resolved.
                    </p>
                  )}
                  <p className="dashboard-credit-note">
                    Capture and notarization have separate monthly allowances. Extra purchases add
                    only notarization and do not expire.
                  </p>
                  <section className="dashboard-usage-ledger" aria-label="Plan usage breakdown">
                    <div>
                      <span>Capture available</span>
                      <b>{decimalSize(credits.capture.total_remaining_bytes)}</b>
                      <small>
                        {decimalSize(credits.capture.included_monthly_remaining_bytes)} included
                        this month
                      </small>
                    </div>
                    <div>
                      <span>Notarization available</span>
                      <b>{decimalSize(credits.notarization.total_remaining_bytes)}</b>
                      <small>
                        {decimalSize(credits.notarization.included_monthly_remaining_bytes)} monthly
                        · {decimalSize(credits.notarization.supplemental_remaining_bytes)} extra
                      </small>
                    </div>
                    <div>
                      <span>Trace storage</span>
                      <b>{decimalSize(user.usage.hosted_traces.stored_bytes)}</b>
                      <small>
                        {billing.entitlements?.trace_storage_bytes == null
                          ? 'No fixed plan limit*'
                          : `of ${decimalSize(billing.entitlements.trace_storage_bytes)}`}
                      </small>
                    </div>
                  </section>
                  {billing.entitlements?.trace_storage_bytes == null && (
                    <p className="dashboard-usage-footnote">
                      *Fair-use and abuse controls still apply. Per-file safety limits remain in
                      place.
                    </p>
                  )}
                  {creditError && (
                    <p className="dashboard-session-error" role="alert">
                      {creditError}
                    </p>
                  )}
                  {creditOffers?.map((offer) => (
                    <article className="dashboard-credit-offer" key={offer.id}>
                      <div>
                        <span className="eyebrow">Available offer</span>
                        <b>{offer.title}</b>
                        <p>
                          {offer.description} Claim by {sessionDate(offer.claim_expires_at)}.
                        </p>
                      </div>
                      <button
                        type="button"
                        onClick={() => claimOffer(offer)}
                        disabled={claimingOffer === offer.id}
                      >
                        {claimingOffer === offer.id
                          ? 'Claiming…'
                          : `Claim ${decimalSize(offer.amount_bytes)}`}
                      </button>
                    </article>
                  ))}
                  {checkoutEnabled ? (
                    <section
                      className="dashboard-credit-purchase"
                      aria-labelledby="buy-credit-title"
                    >
                      <div className="dashboard-credit-purchase-copy">
                        <span className="eyebrow">Extra notarization · $10 per GB</span>
                        <h3 id="buy-credit-title">Buy {quantityGb} GB</h3>
                        {purchaseMode === 'test' && (
                          <strong className="dashboard-billing-mode" role="status">
                            Stripe test mode · no real charges
                          </strong>
                        )}
                        <p>
                          {purchaseMode === 'test'
                            ? `$${quantityGb * 10}.00 USD test purchase · use a Stripe test card`
                            : `$${quantityGb * 10}.00 USD · one-time payment through Stripe`}
                        </p>
                      </div>
                      <div
                        className="dashboard-credit-quantity"
                        role="group"
                        aria-label="Credit quantity"
                      >
                        {[1, 5, 10, 20].map((quantity) => (
                          <button
                            key={quantity}
                            type="button"
                            aria-label={`${quantity} GB`}
                            aria-pressed={quantityGb === quantity}
                            onClick={() => {
                              setQuantityGb(quantity);
                              setCheckoutAttemptKey(null);
                            }}
                          >
                            {quantity}
                            <small aria-hidden="true">GB</small>
                          </button>
                        ))}
                      </div>
                      <button
                        className="dashboard-credit-buy"
                        type="button"
                        onClick={buyCredits}
                        disabled={startingCheckout}
                      >
                        {startingCheckout
                          ? 'Opening Checkout…'
                          : purchaseMode === 'test'
                            ? `Open test Checkout · ${quantityGb} GB for $${quantityGb * 10}`
                            : `Buy ${quantityGb} GB for $${quantityGb * 10}`}
                      </button>
                    </section>
                  ) : (
                    <section
                      className="dashboard-credit-purchase dashboard-credit-purchase--disabled"
                      aria-labelledby="buy-credit-title"
                    >
                      <div className="dashboard-credit-purchase-copy">
                        <span className="eyebrow">Extra notarization</span>
                        <h3 id="buy-credit-title">Purchases unavailable</h3>
                        <p>You can’t buy more notarization right now.</p>
                      </div>
                    </section>
                  )}
                  {displayedCheckoutStatus === 'cancelled' && (
                    <p className="dashboard-checkout-state">
                      Checkout was cancelled. No credits were added.
                    </p>
                  )}
                  {displayedCheckoutStatus &&
                    displayedCheckoutStatus !== 'cancelled' &&
                    checkoutReturnMessages[displayedCheckoutStatus] && (
                      <p className="dashboard-checkout-state" role="status">
                        {checkoutReturnMessages[displayedCheckoutStatus]}
                      </p>
                    )}
                  {purchaseError && (
                    <p className="dashboard-session-error" role="alert">
                      {purchaseError}
                    </p>
                  )}
                  <div className="dashboard-purchase-history">
                    <h3>Purchases</h3>
                    {purchases === null && !purchaseError ? (
                      <p>Loading purchases…</p>
                    ) : purchases?.length ? (
                      purchases.map((purchase) => (
                        <div key={purchase.id}>
                          <span
                            className={`dashboard-purchase-state dashboard-purchase-state--${purchase.state}`}
                          >
                            <i aria-hidden="true" />
                            {purchase.state.replaceAll('_', ' ')}
                          </span>
                          <b>
                            {purchase.quantity_gb} GB · ${(purchase.amount_cents / 100).toFixed(2)}
                          </b>
                          <time>{sessionDate(purchase.created_at)}</time>
                        </div>
                      ))
                    ) : (
                      <p>No credit purchases yet.</p>
                    )}
                  </div>
                  {creditHistory && creditHistory.length > 0 && (
                    <div className="dashboard-credit-history">
                      <h3>Usage activity</h3>
                      {creditHistory.map((entry) => {
                        const addsCredit =
                          entry.kind === 'grant' ||
                          (entry.kind === 'adjustment' && entry.amount_bytes > 0);
                        return (
                          <div key={`${entry.kind}-${entry.id}`}>
                            <span
                              className={`dashboard-credit-sign dashboard-credit-sign--${entry.kind}`}
                            >
                              {addsCredit ? '+' : '−'}
                              {decimalSize(Math.abs(entry.amount_bytes))}
                            </span>
                            <span>
                              <small>{entry.credit_kind}</small>
                              {entry.display_label}
                            </span>
                            <time>{sessionDate(entry.created_at)}</time>
                          </div>
                        );
                      })}
                      {creditHistoryCursor && (
                        <button
                          className="dashboard-load-more"
                          type="button"
                          onClick={loadMoreCreditHistory}
                          disabled={loadingMoreCreditHistory}
                        >
                          {loadingMoreCreditHistory ? 'Loading…' : 'Load older activity'}
                        </button>
                      )}
                    </div>
                  )}
                </section>
              )}
            </>
          )}
          {activeView === 'settings' && (
            <>
              <header className="dashboard-page-header">
                <span className="eyebrow">Account</span>
                <h1>Settings</h1>
                <p>Manage appearance, API keys, connected devices, and account deletion.</p>
              </header>
              <AccountSettings theme={theme} onThemeChange={onThemeChange} />
              <ApiKeysPanel />
              <section className="dashboard-sessions" aria-labelledby="connected-services-title">
                <header>
                  <div>
                    <span className="eyebrow">Account access</span>
                    <h2 id="connected-services-title">Connected devices</h2>
                  </div>
                </header>
                {sessionError && (
                  <p className="dashboard-session-error" role="alert">
                    {sessionError}
                  </p>
                )}
                {sessions === null && !sessionError ? (
                  <p className="dashboard-session-empty">Loading connected devices…</p>
                ) : sessions?.length ? (
                  <>
                    <div className="dashboard-session-list">
                      {sessions.map((session) => (
                        <article key={session.device_id}>
                          <div>
                            <b>{session.device_name}</b>
                            <span>
                              Created {sessionDate(session.created_at)} · Last used{' '}
                              {sessionDate(session.last_used_at)} · Expires{' '}
                              {sessionDate(session.expires_at)}
                            </span>
                          </div>
                          <button
                            type="button"
                            onClick={() => setRevokeTarget(session)}
                            disabled={revoking === session.device_id}
                          >
                            {revoking === session.device_id ? 'Revoking…' : 'Revoke'}
                          </button>
                        </article>
                      ))}
                    </div>
                    {sessionCursor && (
                      <button
                        className="dashboard-load-more"
                        type="button"
                        onClick={loadMoreSessions}
                        disabled={loadingMoreSessions}
                      >
                        {loadingMoreSessions ? 'Loading…' : 'Load more devices'}
                      </button>
                    )}
                  </>
                ) : (
                  <p className="dashboard-session-empty">No devices are connected.</p>
                )}
              </section>
              <DeleteAccountPanel
                identifier={accountIdentifier(user)}
                onDeleted={onAccountDeleted}
              />
            </>
          )}
          {activeView === 'traces' && (
            <>
              <header className="dashboard-page-header">
                <span className="eyebrow">Account</span>
                <h1>Traces</h1>
                <p>Notarized traces you’ve shared through Notary.</p>
              </header>
              <section className="dashboard-traces" aria-label="Your traces">
                {shareError && (
                  <p className="dashboard-session-error" role="alert">
                    {shareError}
                  </p>
                )}
                {shares === null && !shareError ? (
                  <p className="dashboard-session-empty">Loading your traces…</p>
                ) : shares?.length ? (
                  <div className="dashboard-trace-list">
                    {shares.map((share) => {
                      const status = shareStateLabel(share.status);
                      return (
                        <article key={share.trace_id}>
                          <div className="dashboard-trace-copy">
                            <div>
                              <span
                                className={`dashboard-trace-state dashboard-trace-state--${status.tone}`}
                              >
                                <i aria-hidden="true" />
                                {status.label}
                              </span>
                              <time>
                                {sessionDate(share.verification.verified_at || share.updated_at)}
                              </time>
                            </div>
                            <h3>Trace {share.trace_id.slice(0, 8)}</h3>
                            <p>
                              {shareAccessLabel(share)}
                              {share.access.password_protected ? ' · Password protected' : ''}
                              {share.access.expires_at
                                ? ` · Expires ${sessionDate(share.access.expires_at)}`
                                : ''}{' '}
                              · <code>{share.trace_id}</code>
                            </p>
                            {share.verification.failure_code && (
                              <p className="dashboard-trace-failure">
                                Reason: {share.verification.failure_code.replaceAll('_', ' ')}
                              </p>
                            )}
                          </div>
                          <div className="dashboard-trace-actions">
                            {share.public_url && (
                              <a href={share.public_url} target="_blank" rel="noreferrer">
                                Open
                              </a>
                            )}
                            {share.public_url && (
                              <button type="button" onClick={() => copyShareLink(share)}>
                                {copiedTraceId === share.trace_id ? 'Copied' : 'Copy link'}
                              </button>
                            )}
                            {share.package_url && (
                              <a href={share.package_url} download>
                                Export .llmtrace
                              </a>
                            )}
                            {share.status === 'shared' && (
                              <button
                                type="button"
                                onClick={() => {
                                  setShareError(null);
                                  setHostedTraceSettingsTarget(share);
                                }}
                              >
                                Manage access
                              </button>
                            )}
                            {share.status === 'shared' && (
                              <button
                                className="dashboard-trace-unpublish"
                                type="button"
                                onClick={() => setUnpublishTarget(share)}
                              >
                                Stop sharing
                              </button>
                            )}
                          </div>
                        </article>
                      );
                    })}
                  </div>
                ) : (
                  <div className="dashboard-empty dashboard-empty--traces">
                    <span className="eyebrow">No traces</span>
                    <b>No shared traces yet.</b>
                    <p>
                      Notarized local traces appear here only after you explicitly share them as
                      Unlisted or Listed. Connecting a device does not synchronize local traces.
                    </p>
                    <a href="#/docs/share">Open the sharing guide</a>
                  </div>
                )}
                {shareCursor && (
                  <button
                    className="dashboard-load-more"
                    type="button"
                    onClick={loadMoreShares}
                    disabled={loadingMoreShares}
                  >
                    {loadingMoreShares ? 'Loading…' : 'Load more traces'}
                  </button>
                )}
              </section>
            </>
          )}
        </div>
      </div>
      <AlertDialog
        open={Boolean(revokeTarget)}
        onOpenChange={(nextOpen) => {
          if (!nextOpen && !revoking) setRevokeTarget(null);
        }}
      >
        <AlertDialogContent className="axis-alert-dialog">
          <AlertDialogHeader>
            <AlertDialogTitle>Revoke {revokeTarget?.device_name}?</AlertDialogTitle>
            <AlertDialogDescription>
              This device will return to public hosted limits and need a new browser connection for
              account access or sharing.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={Boolean(revoking)}>Keep device</AlertDialogCancel>
            <AlertDialogAction
              disabled={Boolean(revoking)}
              onClick={() => revokeTarget && revoke(revokeTarget)}
            >
              {revoking ? 'Revoking…' : 'Revoke device'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      <HostedTraceSettingsDialog
        share={shareSettingsTarget}
        open={Boolean(shareSettingsTarget)}
        onOpenChange={(nextOpen) => {
          if (!nextOpen) setHostedTraceSettingsTarget(null);
        }}
        onSave={saveHostedTraceSettings}
        saving={savingShare === shareSettingsTarget?.trace_id}
        error={shareError}
      />
      <AlertDialog
        open={Boolean(unpublishTarget)}
        onOpenChange={(nextOpen) => {
          if (!nextOpen && !savingShare) setUnpublishTarget(null);
        }}
      >
        <AlertDialogContent className="axis-alert-dialog">
          <AlertDialogHeader>
            <AlertDialogTitle>
              Stop sharing Trace {unpublishTarget?.trace_id.slice(0, 8)}?
            </AlertDialogTitle>
            <AlertDialogDescription>
              The stable link, trace JSON, and package will stop working immediately. You can share
              this Trace again later from its local device.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={Boolean(savingShare)}>Keep sharing</AlertDialogCancel>
            <AlertDialogAction
              disabled={Boolean(savingShare)}
              onClick={() => unpublishTarget && stopSharing(unpublishTarget)}
            >
              {savingShare ? 'Stopping…' : 'Stop sharing'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </main>
  );
}
