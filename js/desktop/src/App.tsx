import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  Archive,
  BadgeCheck,
  Check,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Clipboard,
  Download,
  FileCheck2,
  Gauge,
  KeyRound,
  ListChecks,
  LockKeyhole,
  Network,
  Play,
  RefreshCw,
  Send,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  Square,
  TerminalSquare,
  UnlockKeyhole,
  UserRound,
} from 'lucide-react';
import {
  completeOnboarding,
  configureVault,
  errorMessage,
  checkForUpdates,
  disconnectAccount,
  getAccountConnection,
  getDesktopState,
  getLaunchAtLogin,
  getUpdateState,
  installUpdateAndRestart,
  openAccountLink,
  pollAccountConnection,
  restartDaemon,
  setCaptureEnabled,
  setLaunchAtLogin,
  startAccountConnection,
  startDaemon,
  stopDaemon,
  unlockVault,
  type DesktopState,
  type DesktopUpdateState,
  type AccountConnection,
  type AccountConnectionStarted,
} from './bridge';
import notaryMark from './notary-mark.svg';

type View =
  | 'home'
  | 'captures'
  | 'notarizations'
  | 'traces'
  | 'sharing'
  | 'activity'
  | 'connections'
  | 'service-details'
  | 'settings';

type WorkspaceView = 'captures' | 'notarizations' | 'traces' | 'sharing' | 'activity' | 'settings';
type OnboardingStep = 'welcome' | 'protection' | 'provider' | 'account' | 'ready';
type VaultSetupMode = 'keychain' | 'passphrase';

const providers = [
  {
    id: 'codex',
    name: 'Codex (ChatGPT plan)',
    operation: 'Responses',
    baseUrl: 'http://127.0.0.1:8787/codex',
    modelExample: 'Use your current Codex model',
  },
  {
    id: 'openrouter',
    name: 'OpenRouter',
    operation: 'Chat Completions',
    baseUrl: 'http://127.0.0.1:8787/openrouter/api/v1',
    modelExample: 'provider/model:free',
  },
  {
    id: 'openai',
    name: 'OpenAI',
    operation: 'Responses',
    baseUrl: 'http://127.0.0.1:8787/openai/v1',
    modelExample: 'gpt-5.4-mini',
  },
  {
    id: 'anthropic',
    name: 'Anthropic / Claude Code',
    operation: 'Messages',
    baseUrl: 'http://127.0.0.1:8787/anthropic',
    modelExample: 'Use your current Claude Code model',
  },
  {
    id: 'deepseek',
    name: 'DeepSeek',
    operation: 'Chat Completions',
    baseUrl: 'http://127.0.0.1:8787/deepseek',
    modelExample: 'deepseek-chat',
  },
] as const;

type Provider = (typeof providers)[number];
type ProviderId = Provider['id'];

const onboardingSteps: OnboardingStep[] = ['welcome', 'protection', 'provider', 'account', 'ready'];

const viewMeta: Record<View, { title: string; subtitle: string }> = {
  home: { title: 'LLM Notary', subtitle: 'Private capture service' },
  captures: { title: 'Captures', subtitle: 'Private evidence on this Mac' },
  notarizations: { title: 'Notarizations', subtitle: 'Notary proof operations' },
  traces: { title: 'Notarized traces', subtitle: 'Portable .llmtrace packages' },
  sharing: { title: 'Share', subtitle: 'Choose exactly what becomes public' },
  activity: { title: 'Activity', subtitle: 'Safe local service events' },
  connections: { title: 'Models & providers', subtitle: 'Connect the tools you already use' },
  'service-details': { title: 'Service details', subtitle: 'Trust, listeners, and privacy policy' },
  settings: { title: 'Settings', subtitle: 'Desktop and background behavior' },
};

const workspaceRoutes: Partial<Record<View, WorkspaceView>> = {
  captures: 'captures',
  notarizations: 'notarizations',
  traces: 'traces',
  sharing: 'sharing',
  activity: 'activity',
  'service-details': 'settings',
};

function vaultProtection(mode: string) {
  if (mode === 'keychain') {
    return {
      label: 'Protected by Keychain',
      detail: 'The vault key is protected by this Mac.',
    };
  }
  if (mode === 'convenience') {
    return {
      label: 'No device protection',
      detail: 'Anyone signed in to this account can open private captures.',
    };
  }
  return {
    label: 'Passphrase vault',
    detail: 'The existing passphrase is required to unlock captures.',
  };
}

function StatusDot({ running, warning = false }: { running: boolean; warning?: boolean }) {
  return <span className={`status-dot ${running ? 'is-running' : ''} ${warning ? 'is-warning' : ''}`} />;
}

function formatBytes(bytes: number) {
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatAccountBytes(bytes: number) {
  if (bytes === 0) return '0 B';
  return formatBytes(bytes);
}

function formatAccountDate(seconds?: number | null) {
  if (!seconds) return '—';
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(seconds * 1000));
}

function accountName(account: AccountConnection) {
  return account.display_name || account.provider_display_name || 'LLM Notary account';
}

function accountProvider(account: AccountConnection) {
  if (account.auth_provider === 'google') return 'Google';
  if (account.auth_provider === 'github') return 'GitHub';
  return 'Hosted account';
}

function DesktopAccountCard({
  compact = false,
  onContinue,
  onSkip
}: {
  compact?: boolean;
  onContinue?: () => void;
  onSkip?: () => void;
}) {
  const [account, setAccount] = useState<AccountConnection | null>(null);
  const [flow, setFlow] = useState<{ value: AccountConnectionStarted; startedAt: number; nextPollAt: number; failures: number } | null>(null);
  const [now, setNow] = useState(Date.now());
  const [busy, setBusy] = useState(false);
  const [polling, setPolling] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = async () => {
    try {
      setAccount(await getAccountConnection());
      setError(null);
    } catch (caught) {
      setError(errorMessage(caught));
    }
  };

  useEffect(() => { void refresh(); }, []);
  useEffect(() => {
    if (!flow) return;
    const timer = window.setInterval(() => setNow(Date.now()), 250);
    return () => window.clearInterval(timer);
  }, [flow]);

  const expired = Boolean(flow && now >= flow.startedAt + flow.value.expires_in_seconds * 1000);
  const pollReady = Boolean(flow && !expired && now >= flow.nextPollAt);

  const poll = async () => {
    if (!flow || !pollReady || polling) return;
    setPolling(true);
    try {
      const next = await pollAccountConnection(flow.value.request_id);
      setAccount(next);
      if (next.signed_in || next.connection_state === 'connected') setFlow(null);
      else setFlow({ ...flow, nextPollAt: Date.now() + flow.value.poll_interval_seconds * 1000, failures: 0 });
      setError(null);
    } catch (caught) {
      setError(errorMessage(caught));
      setFlow((current) => {
        if (!current) return current;
        const failures = current.failures + 1;
        const delay = Math.min(30, Math.max(1, current.value.poll_interval_seconds) * 2 ** Math.min(Math.max(0, failures - 1), 4));
        return { ...current, failures, nextPollAt: Date.now() + delay * 1000 };
      });
    } finally {
      setPolling(false);
    }
  };

  useEffect(() => {
    if (!flow || expired || flow.value.poll_interval_seconds === 0 || !pollReady || polling) return;
    void poll();
  }, [expired, flow, pollReady, polling]);

  const start = async () => {
    setBusy(true);
    setError(null);
    try {
      const value = await startAccountConnection();
      const startedAt = Date.now();
      setFlow({ value, startedAt, nextPollAt: startedAt + value.poll_interval_seconds * 1000, failures: 0 });
      await openAccountLink(value.verification_uri_complete);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  };

  const disconnect = async () => {
    if (!account?.signed_in || account.credential_kind === 'api_key') return;
    if (!window.confirm('Disconnect this device? This revokes only the local browser-approved session.')) return;
    setBusy(true);
    try {
      await disconnectAccount();
      await refresh();
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  };

  const connected = Boolean(account?.signed_in || account?.connection_state === 'connected');
  const state = error ? 'unavailable' : account?.connection_state ?? (connected ? 'connected' : 'disconnected');
  const action = async (url: string) => {
    try { await openAccountLink(url); } catch (caught) { setError(errorMessage(caught)); }
  };

  return <section className={`native-account-card${compact ? ' is-compact' : ''}`}>
    <div className="native-account-heading"><div><span className="section-label">Account</span>{!compact && <h2>Hosted account</h2>}</div><span className={`account-state account-state--${state}`}>{state === 'connected' ? 'Connected' : state === 'reauthorization_required' ? 'Reconnect required' : state === 'unavailable' ? 'Temporarily unavailable' : 'Not connected'}</span></div>
    {account && connected ? <>
      <div className="native-account-identity"><div><strong>{accountName(account)}</strong><span>{accountProvider(account)} · {account.credential_name || account.device_name || 'Connected service'}</span></div>{account.credential_kind === 'api_key' && <small>API key</small>}</div>
      {account.billing && <div className="native-account-facts"><div><span>Plan</span><strong>{account.billing.service_plan}</strong></div><div><span>Billing</span><strong>{account.billing.billing_status}{account.billing.purchase_mode ? ` · ${account.billing.purchase_mode}` : ''}</strong></div>{account.credits && <div><span>Notarization used</span><strong>{formatAccountBytes(account.credits.notarization.total_used_bytes)}</strong></div>}{account.credits && <div><span>Notarization remaining</span><strong>{formatAccountBytes(account.credits.notarization.total_remaining_bytes)}</strong></div>}{account.credits && <div><span>Capture used</span><strong>{formatAccountBytes(account.credits.capture.total_used_bytes)}</strong></div>}{account.credits && <div><span>Capture remaining</span><strong>{formatAccountBytes(account.credits.capture.total_remaining_bytes)}</strong></div>}{account.credits && <div><span>Included monthly</span><strong>{formatAccountBytes(account.credits.notarization.included_monthly_remaining_bytes)}</strong></div>}{account.credits && <div><span>Supplemental</span><strong>{formatAccountBytes(account.credits.notarization.supplemental_remaining_bytes)}</strong></div>}{account.credits && <div><span>Reset</span><strong>{formatAccountDate(account.credits.reset_at)}</strong></div>}{account.credits?.notarization.next_grant_expiration && <div><span>Next expiration</span><strong>{formatAccountDate(account.credits.notarization.next_grant_expiration)}</strong></div>}</div>}
      {account.links && <div className="native-account-links"><button type="button" onClick={() => void action(account.links!.account)}>Open account</button><button type="button" onClick={() => void action(account.links!.usage)}>Usage and credits</button><button type="button" onClick={() => void action(account.links!.plans)}>Plans and pricing</button><button type="button" onClick={() => void action(account.links!.settings)}>{account.credential_kind === 'api_key' ? 'Manage API keys' : 'Account settings'}</button></div>}
      {account.credential_kind !== 'api_key' && <button className="mac-button is-small" type="button" onClick={() => void disconnect()} disabled={busy}>Disconnect this device</button>}
      {onContinue && <button className="mac-button is-primary is-large" type="button" onClick={onContinue}>Continue setup <ChevronRight size={15} /></button>}
    </> : <>
      <p>{state === 'reauthorization_required' ? 'This local authorization expired or was revoked. Reconnect to restore hosted credits and account-owned sharing.' : state === 'unavailable' ? 'The account service is temporarily unavailable. Local capture and verification remain available.' : 'Sign in to see hosted credits, usage, and account-owned sharing. Signing in does not upload or publish local captures.'}</p>
      <div className="wizard-actions"><button className="mac-button is-primary is-large" type="button" onClick={() => void start()} disabled={busy}>{busy ? 'Opening browser…' : state === 'reauthorization_required' ? 'Reconnect' : 'Sign in or create account'} <ChevronRight size={15} /></button>{onSkip && <button className="mac-button is-large" type="button" onClick={onSkip} disabled={busy}>Not now</button>}</div>
    </>}
    {error && <div className="onboarding-error" role="alert">{error}</div>}
    {flow && <div className="native-account-authorization"><span className="section-label">Approval code</span><strong>{flow.value.user_code}</strong>{expired ? <span>Authorization expired. Start again for a fresh request.</span> : <span>{pollReady ? 'Ready to check.' : `Next check in ${Math.max(1, Math.ceil((flow.nextPollAt - now) / 1000))}s.`}</span>}<div><button className="mac-button is-small" type="button" onClick={() => void poll()} disabled={expired || !pollReady || polling}>{polling ? 'Checking…' : 'Check approval'}</button><button className="mac-button is-small" type="button" onClick={() => setFlow(null)}>Cancel</button>{expired && <button className="mac-button is-small" type="button" onClick={() => void start()} disabled={busy}>Try again</button>}</div></div>}
  </section>;
}

function updateChipLabel(update: DesktopUpdateState) {
  if (update.phase === 'checking') return 'Checking for updates';
  if (update.phase === 'downloading') {
    const percent = update.total_bytes
      ? Math.min(100, Math.round((update.downloaded_bytes / update.total_bytes) * 100))
      : 0;
    return `Downloading update${percent ? ` ${percent}%` : ''}`;
  }
  if (update.phase === 'ready') return 'Update ready';
  if (update.phase === 'installing') return 'Installing update';
  if (update.phase === 'error') return 'Update check failed';
  return null;
}

function updateRestartBlockReason(state: DesktopState) {
  if (state.counts.capturing > 0) return 'Finish the active capture before restarting.';
  if (state.counts.notarizing > 0) return 'Finish the active notarization before restarting.';
  if (state.running && !state.managed_by_desktop) return 'Stop or update the separately managed local service first.';
  return null;
}

function App() {
  const query = useMemo(() => new URLSearchParams(window.location.search), []);
  const requestedView = query.get('view') as View | null;
  const [view, setView] = useState<View>(requestedView && requestedView in viewMeta ? requestedView : 'home');
  const [state, setState] = useState<DesktopState | null>(null);
  const [updateState, setUpdateState] = useState<DesktopUpdateState | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setState(await getDesktopState());
    } catch (error) {
      setNotice(errorMessage(error));
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 5000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  useEffect(() => {
    const refreshUpdate = async () => {
      try {
        setUpdateState(await getUpdateState());
      } catch (error) {
        setNotice(errorMessage(error));
      }
    };
    void refreshUpdate();
    const timer = window.setInterval(() => void refreshUpdate(), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const runAction = async (name: string, action: () => Promise<void>, success: string) => {
    setBusy(name);
    setNotice(null);
    try {
      await action();
      await new Promise((resolve) => window.setTimeout(resolve, 500));
      await refresh();
      setNotice(success);
    } catch (error) {
      setNotice(errorMessage(error));
    } finally {
      setBusy(null);
    }
  };

  const checkForDesktopUpdate = async () => {
    setBusy('update-check');
    setNotice(null);
    try {
      setUpdateState(await checkForUpdates());
    } catch (error) {
      setNotice(errorMessage(error));
      setUpdateState(await getUpdateState());
    } finally {
      setBusy(null);
    }
  };

  const restartToUpdate = async () => {
    setBusy('update-install');
    setNotice(null);
    try {
      await installUpdateAndRestart();
    } catch (error) {
      setNotice(errorMessage(error));
      setUpdateState(await getUpdateState());
      setBusy(null);
    }
  };

  if (!state) return <LoadingWindow />;
  if (state.vault_locked) {
    return <VaultUnlock refresh={refresh} />;
  }
  if (!state.onboarding_complete) {
    return <Onboarding state={state} refresh={refresh} onFinish={(next) => setView(next)} />;
  }

  const route = workspaceRoutes[view];
  const meta = viewMeta[view];

  return (
    <div className="native-window">
      <Sidebar state={state} view={view} onNavigate={setView} />
      <section className="window-content">
        <header className="native-toolbar" data-tauri-drag-region="deep">
          <div className="toolbar-title" data-tauri-drag-region="deep">
            <strong>{meta.title}</strong>
            <span>{meta.subtitle}</span>
          </div>
          <div className="toolbar-spacer" data-tauri-drag-region />
          {updateState && updateChipLabel(updateState) && <button
            type="button"
            className={`update-chip is-${updateState.phase}`}
            onClick={() => setView('settings')}
          >
            {updateState.phase === 'downloading' ? <RefreshCw size={11} className="is-spinning" /> : <Download size={11} />}
            {updateChipLabel(updateState)}
          </button>}
          <div className={`service-chip ${state.running ? 'is-running' : ''} ${state.running && !state.capture_enabled ? 'is-direct' : ''}`}>
            <StatusDot running={state.running} warning={!state.running} />
            {state.running ? state.capture_enabled ? 'Ready to capture' : 'Running · Capture off' : 'Service stopped'}
          </div>
        </header>

        <main className={`native-content ${route ? 'has-workspace' : ''}`}>
          {view === 'home' && (
            <HomeView
              state={state}
              busy={busy}
              notice={notice}
              onNavigate={setView}
              onStart={() => void runAction('start', startDaemon, 'LLM Notary started.')}
              onStop={() => void runAction('stop', stopDaemon, 'LLM Notary stopped.')}
              onRestart={() => void runAction('restart', restartDaemon, 'LLM Notary restarted.')}
            />
          )}
          {view === 'connections' && <ConnectionsView state={state} notice={notice} />}
          {view === 'settings' && <SettingsView
            state={state}
            updateState={updateState}
            busy={busy}
            notice={notice}
            onCheckUpdate={() => void checkForDesktopUpdate()}
            onRestartToUpdate={() => void restartToUpdate()}
            onCaptureChange={(enabled) => void runAction(
              'capture-mode',
              async () => { await setCaptureEnabled(enabled); },
              enabled ? 'Capture requests are on.' : 'Capture requests are off.'
            )}
          />}
          {route && (
            <WorkspaceFrame
              route={route}
              running={state.running}
              busy={busy}
              onStart={() => void runAction('start', startDaemon, 'LLM Notary started.')}
            />
          )}
        </main>
      </section>
    </div>
  );
}

function LoadingWindow() {
  return <div className="loading-window"><img src={notaryMark} alt="" /><span>Opening LLM Notary…</span></div>;
}

function VaultUnlock({ refresh }: { refresh: () => Promise<void> }) {
  const [passphrase, setPassphrase] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const unlock = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await unlockVault(passphrase);
      setPassphrase('');
      await startDaemon();
      await new Promise((resolve) => window.setTimeout(resolve, 700));
      await refresh();
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  };

  return <div className="onboarding-window unlock-window">
    <header className="onboarding-toolbar" data-tauri-drag-region="deep">
      <div className="traffic-light-space" data-tauri-drag-region />
      <strong className="onboarding-window-title" data-tauri-drag-region>LLM Notary</strong>
      <span className="onboarding-window-context">Locked</span>
    </header>
    <main className="unlock-body">
      <form className="unlock-card" onSubmit={(event) => void unlock(event)}>
        <span className="unlock-icon"><KeyRound /></span>
        <span className="wizard-kicker">Private capture vault</span>
        <h1>Unlock captures on this Mac</h1>
        <p>Enter the passphrase you chose during setup. LLM Notary keeps it only for this app session.</p>
        <label><span>Vault passphrase</span><input type="password" autoComplete="current-password" autoFocus value={passphrase} aria-invalid={Boolean(error)} aria-describedby={error ? 'vault-unlock-error' : undefined} onChange={(event) => setPassphrase(event.target.value)} /></label>
        {error && <div id="vault-unlock-error" className="onboarding-error" role="alert">{error}</div>}
        <button className="mac-button is-primary is-large" type="submit" disabled={busy}>{busy ? 'Unlocking…' : 'Unlock and start LLM Notary'} <ChevronRight size={15} /></button>
      </form>
    </main>
  </div>;
}

function Sidebar({ state, view, onNavigate }: { state: DesktopState; view: View; onNavigate: (view: View) => void }) {
  const groups: Array<Array<{ view: View; label: string; icon: typeof Gauge; count?: number }>> = [
    [
      { view: 'home', label: 'Home', icon: Gauge },
      { view: 'captures', label: 'Captures', icon: Archive, count: state.counts.captured },
      { view: 'notarizations', label: 'Notarizations', icon: ListChecks, count: state.counts.notarizing },
      { view: 'traces', label: 'Notarized traces', icon: FileCheck2 },
    ],
    [
      { view: 'sharing', label: 'Share', icon: Send },
      { view: 'activity', label: 'Activity', icon: Activity },
    ],
    [
      { view: 'connections', label: 'Models & providers', icon: Network },
      { view: 'service-details', label: 'Service details', icon: TerminalSquare },
      { view: 'settings', label: 'Settings', icon: Settings },
    ],
  ];

  return <aside className="native-sidebar">
    <div className="sidebar-drag-region" data-tauri-drag-region />
    <div className="sidebar-brand">
      <img src={notaryMark} alt="" />
      <span>LLM Notary</span>
    </div>
    <nav aria-label="LLM Notary">
      {groups.map((group, groupIndex) => <div className="sidebar-group" key={groupIndex}>
        {group.map(({ view: itemView, label, icon: Icon, count }) => <button
          key={itemView}
          type="button"
          className={view === itemView ? 'is-selected' : ''}
          onClick={() => onNavigate(itemView)}
        >
          <Icon size={16} strokeWidth={1.8} aria-hidden="true" />
          <span>{label}</span>
          {count ? <b>{count}</b> : null}
        </button>)}
      </div>)}
    </nav>
    <div className="sidebar-footer">
      <StatusDot running={state.running} warning={!state.running} />
      <span>{state.running ? state.capture_enabled ? `Ready on ${state.proxy_listener}` : `Capture off · ${state.proxy_listener}` : 'Service stopped'}</span>
    </div>
  </aside>;
}

function WorkspaceFrame({ route, running, busy, onStart }: {
  route: WorkspaceView;
  running: boolean;
  busy: string | null;
  onStart: () => void;
}) {
  const [loaded, setLoaded] = useState(false);
  const source = `http://127.0.0.1:8788/dashboard?embedded=desktop#/${route}`;

  useEffect(() => setLoaded(false), [source]);

  if (!running) {
    return <EmptyPanel
      icon={Square}
      title="The capture service is stopped"
      copy="Start LLM Notary to open this workspace. Nothing is sent anywhere while the service is stopped."
      action={<button className="mac-button is-primary" onClick={onStart} disabled={busy !== null}>
        <Play size={14} /> {busy === 'start' ? 'Starting…' : 'Start LLM Notary'}
      </button>}
    />;
  }

  return <div className="workspace-frame">
    {!loaded && <div className="workspace-loading"><span className="spinner" />Loading local workspace…</div>}
    <iframe
      key={source}
      src={source}
      title={`${viewMeta[route === 'settings' ? 'service-details' : route].title} workspace`}
      onLoad={() => setLoaded(true)}
    />
  </div>;
}

function HomeView({ state, busy, notice, onNavigate, onStart, onStop, onRestart }: {
  state: DesktopState;
  busy: string | null;
  notice: string | null;
  onNavigate: (view: View) => void;
  onStart: () => void;
  onStop: () => void;
  onRestart: () => void;
}) {
  const vault = vaultProtection(state.vault_mode);
  return <div className="native-page home-page">
    <section className={`status-hero ${state.running ? 'is-running' : ''} ${state.running && !state.capture_enabled ? 'is-direct' : ''}`}>
      <div className="status-orb"><StatusDot running={state.running} warning={!state.running} /></div>
      <div>
        <h1>{state.running ? state.capture_enabled ? 'Ready to capture' : 'Service running with capture off' : 'LLM Notary is stopped'}</h1>
        <p>{state.running
          ? state.capture_enabled
            ? 'Your local proxy is ready. Provider credentials stay in the client that sends each request.'
            : 'Provider requests still pass through this Mac, but go directly to the provider and create no evidence.'
          : 'Start the local service before sending a model request.'}</p>
      </div>
      <div className="hero-actions">
        {state.running ? <>
          <button className="mac-button" onClick={onRestart} disabled={!state.managed_by_desktop || busy !== null}>
            <RefreshCw size={14} /> {busy === 'restart' ? 'Restarting…' : 'Restart'}
          </button>
          <button className="mac-button" onClick={onStop} disabled={!state.managed_by_desktop || busy !== null}>
            <Square size={12} /> {busy === 'stop' ? 'Stopping…' : 'Stop'}
          </button>
        </> : <button className="mac-button is-primary" onClick={onStart} disabled={busy !== null}>
          <Play size={14} /> {busy === 'start' ? 'Starting…' : 'Start LLM Notary'}
        </button>}
      </div>
    </section>

    {(notice || state.message) && <div className="native-notice">{notice ?? state.message}</div>}

    <section className="home-grid">
      <div className="native-card capture-card">
        <header><div><span className="section-label">Capture workspace</span><h2>Private evidence</h2></div><span>{state.counts.captured + state.counts.notarized + state.counts.capturing + state.counts.capture_failed} total</span></header>
        <div className="capture-counts">
          <button onClick={() => onNavigate('captures')}><b>{state.counts.captured}</b><span>Captured</span><ChevronRight size={14} /></button>
          <button onClick={() => onNavigate('traces')}><b>{state.counts.notarized}</b><span>Notarized traces</span><ChevronRight size={14} /></button>
          <button onClick={() => onNavigate('activity')}><b>{state.counts.needs_attention}</b><span>Need attention</span><ChevronRight size={14} /></button>
        </div>
        <button className="card-action" onClick={() => onNavigate(state.counts.captured ? 'captures' : 'connections')}>
          {state.counts.captured ? 'Review private captures' : 'Connect a model client'} <ChevronRight size={15} />
        </button>
      </div>

      <div className="native-card protection-card">
        <header><div><span className="section-label">Protection</span><h2>{vault.label}</h2></div><ShieldCheck size={20} /></header>
        <p>{vault.detail}</p>
        <dl>
          <div><dt>Provider proxy</dt><dd>{state.proxy_listener}</dd></div>
          <div><dt>Notary trust</dt><dd>{state.notary === 'directory' ? 'Signed directory' : state.notary ?? 'Unavailable'}</dd></div>
          <div><dt>Service version</dt><dd>{state.version ?? 'Not running'}</dd></div>
        </dl>
      </div>
    </section>

    <section className="native-card route-card">
      <header><div><span className="section-label">Authenticated route</span><h2>What each part can see</h2></div></header>
      <div className="native-route">
        <RouteStop title="Your client" detail="API key and plaintext" active={state.running} />
        <RouteStop title="This Mac" detail={state.capture_enabled ? 'Plaintext and private capture' : 'Direct HTTPS passthrough'} active={state.running} />
        <RouteStop title="Remote notary" detail={state.capture_enabled ? 'Encrypted protocol only' : 'Bypassed for new requests'} active={state.running && state.capture_enabled} />
        <RouteStop title="Provider" detail="Normal model request" active={state.running} />
      </div>
    </section>
  </div>;
}

function RouteStop({ title, detail, active }: { title: string; detail: string; active: boolean }) {
  return <div className="native-route-stop"><span className={active ? 'is-active' : ''} /><strong>{title}</strong><small>{detail}</small></div>;
}

function ConnectionsView({ state, notice }: { state: DesktopState; notice: string | null }) {
  const [copied, setCopied] = useState<string | null>(null);
  const copy = async (id: string, value: string) => {
    await navigator.clipboard.writeText(value);
    setCopied(id);
    window.setTimeout(() => setCopied(null), 1500);
  };

  return <div className="native-page connections-page">
    <section className="page-intro">
      <h1>Connect a model client</h1>
      <p>Keep the provider API key or subscription login in the app that already uses it. Change only its base URL.</p>
      <span className={`readiness ${state.running ? 'is-ready' : ''}`}><StatusDot running={state.running} warning={!state.running} />{state.running ? state.capture_enabled ? 'Ready to capture requests' : 'Ready for direct requests · Capture off' : 'Start the service first'}</span>
    </section>
    {notice && <div className="native-notice">{notice}</div>}
    <section className="native-list provider-native-list">
      {providers.map((provider) => <div className="native-list-row" key={provider.id}>
        <span className="provider-monogram">{provider.name.slice(0, 1)}</span>
        <div className="row-primary"><strong>{provider.name}</strong><span>{provider.operation}</span></div>
        <code>{provider.baseUrl}</code>
        <button className="mac-button is-small" onClick={() => void copy(provider.id, provider.baseUrl)}>
          {copied === provider.id ? <Check size={13} /> : <Clipboard size={13} />}{copied === provider.id ? 'Copied' : 'Copy'}
        </button>
      </div>)}
    </section>
    <section className="native-card connection-note">
      <KeyRound size={18} />
      <div><strong>LLM Notary does not store provider credentials.</strong><p>The key or subscription token remains in your model client and passes through the local proxy only for the provider request.</p><p>Subscription login is supported with Codex CLI and Claude Code. Native Claude Desktop cannot use this route, and Codex desktop is not yet end-to-end tested or supported.</p></div>
    </section>
  </div>;
}

function SettingsView({
  state,
  updateState,
  busy,
  notice,
  onCheckUpdate,
  onRestartToUpdate,
  onCaptureChange,
}: {
  state: DesktopState;
  updateState: DesktopUpdateState | null;
  busy: string | null;
  notice: string | null;
  onCheckUpdate: () => void;
  onRestartToUpdate: () => void;
  onCaptureChange: (enabled: boolean) => void;
}) {
  const [launch, setLaunch] = useState(false);
  const [ready, setReady] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const vault = vaultProtection(state.vault_mode);
  const requiresSessionUnlock = state.vault_mode === 'passphrase';
  const restartBlock = updateRestartBlockReason(state);
  const updateBusy = updateState?.phase === 'checking'
    || updateState?.phase === 'downloading'
    || updateState?.phase === 'installing'
    || busy === 'update-check'
    || busy === 'update-install';
  const progress = updateState?.total_bytes
    ? Math.min(100, (updateState.downloaded_bytes / updateState.total_bytes) * 100)
    : 0;

  useEffect(() => {
    void getLaunchAtLogin().then((enabled) => { setLaunch(enabled); setReady(true); });
  }, []);

  const changeLaunch = async (enabled: boolean) => {
    setMessage(null);
    try {
      await setLaunchAtLogin(enabled);
      setLaunch(enabled);
      setMessage(enabled
        ? requiresSessionUnlock
          ? 'LLM Notary will open locked when you sign in.'
          : 'LLM Notary will open when you sign in.'
        : 'Launch at sign-in is off.');
    } catch (error) {
      setMessage(errorMessage(error));
    }
  };

  return <div className="native-page preferences-page">
    <DesktopAccountCard />
    <section className="preference-section capture-preference-section">
      <h2>Capture</h2>
      <div className="preference-group">
        <label className="preference-row capture-preference-row">
          <div><strong>Capture requests</strong><span>{state.capture_enabled
            ? 'On — requests use the remote notary and create private captures.'
            : 'Off — requests still pass through the local daemon, go directly to the provider, and create no evidence.'}</span></div>
          <input type="checkbox" role="switch" aria-label="Capture requests" checked={state.capture_enabled} disabled={!state.running || busy !== null} onChange={(event) => onCaptureChange(event.target.checked)} />
        </label>
        {!state.running && <p className="preference-note">Start the local service before changing capture mode.</p>}
      </div>
    </section>
    <section className="preference-section">
      <h2>General</h2>
      <div className="preference-group">
        <label className="preference-row">
          <div><strong>Open LLM Notary at sign-in</strong><span>{requiresSessionUnlock ? 'The app opens locked; enter the vault passphrase to start capture.' : 'Keep capture available from the menu bar.'}</span></div>
          <input type="checkbox" role="switch" checked={launch} disabled={!ready} onChange={(event) => void changeLaunch(event.target.checked)} />
        </label>
        <div className="preference-row"><div><strong>Menu-bar controller</strong><span>Closing the window keeps the background service available.</span></div><span className="value-label"><StatusDot running />Active</span></div>
      </div>
    </section>
    <section className="preference-section">
      <h2>Software updates</h2>
      <div className="preference-group update-preferences">
        <div className="preference-row update-summary-row">
          <div>
            <strong>{updateState?.phase === 'ready'
              ? 'The latest release is ready'
              : updateState?.phase === 'current'
                ? 'LLM Notary is up to date'
                : updateState?.phase === 'downloading'
                  ? 'Downloading the latest release'
                  : updateState?.phase === 'error'
                    ? 'Could not check for updates'
                    : updateState?.enabled === false
                      ? 'Updates are off in this build'
                      : 'Automatically stay on the latest release'}</strong>
            <span>{updateState?.message ?? 'Checking the signed latest release in the background.'}</span>
          </div>
          {updateState?.phase === 'ready'
            ? <button className="mac-button is-primary" onClick={onRestartToUpdate} disabled={Boolean(restartBlock) || updateBusy}>Restart to update</button>
            : <button className="mac-button" onClick={onCheckUpdate} disabled={!updateState?.enabled || updateBusy}>{updateBusy ? 'Working…' : 'Check now'}</button>}
        </div>
        {updateState?.phase === 'downloading' && <div className="update-progress-row">
          <span><i style={{ width: `${progress}%` }} /></span>
          <small>{formatBytes(updateState.downloaded_bytes)} of {updateState.total_bytes ? formatBytes(updateState.total_bytes) : 'the update'}</small>
        </div>}
        {updateState?.phase === 'ready' && restartBlock && <p className="preference-note update-block-note">{restartBlock} The update will stay ready.</p>}
        {updateState?.phase === 'ready' && requiresSessionUnlock && <p className="preference-note">After restart, enter the vault passphrase to resume capture.</p>}
        <p className="preference-note">Signed release builds check about every six hours and download in the background. Installation happens only when you choose Restart to update.</p>
      </div>
    </section>
    <section className="preference-section">
      <h2>Private capture protection</h2>
      <div className="preference-group">
        <div className="preference-row"><div><strong>{vault.label}</strong><span>{vault.detail}</span></div><span className="value-label">Configured</span></div>
        <p className="preference-note">Changing protection requires a guided migration so existing captures are never left with two sources of truth.</p>
      </div>
    </section>
    <section className="preference-section">
      <h2>Local service</h2>
      <div className="preference-group compact-rows">
        <div className="preference-row"><strong>Provider proxy</strong><code>{state.proxy_listener}</code></div>
        <div className="preference-row"><strong>Administration</strong><code>{state.admin_listener}</code></div>
        <div className="preference-row"><strong>Version</strong><code>{state.version ?? 'Not running'}</code></div>
        <div className="preference-row"><strong>App build</strong><code>{state.app_build_id}</code></div>
        <div className="preference-row"><strong>Service build</strong><code>{state.daemon_build_id ?? 'Not running'}</code></div>
      </div>
    </section>
    {(notice || message) && <div className="native-notice">{message ?? notice}</div>}
  </div>;
}

function EmptyPanel({ icon: Icon, title, copy, action }: { icon: typeof Square; title: string; copy: string; action?: React.ReactNode }) {
  return <div className="empty-panel"><span><Icon size={26} /></span><h2>{title}</h2><p>{copy}</p>{action}</div>;
}

function Onboarding({ state, refresh, onFinish }: {
  state: DesktopState;
  refresh: () => Promise<void>;
  onFinish: (view: View) => void;
}) {
  const [step, setStep] = useState<OnboardingStep>('welcome');
  const [protectionMode, setProtectionMode] = useState<VaultSetupMode>('keychain');
  const [passphrase, setPassphrase] = useState('');
  const [passphraseConfirmation, setPassphraseConfirmation] = useState('');
  const [selectedProvider, setSelectedProvider] = useState<ProviderId>('openrouter');
  const [model, setModel] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const provider = providers.find((item) => item.id === selectedProvider) ?? providers[0];
  const stepIndex = onboardingSteps.indexOf(step);

  const goBack = () => {
    setError(null);
    if (step === 'protection') {
      setProtectionMode('keychain');
      setPassphrase('');
      setPassphraseConfirmation('');
    }
    setStep(onboardingSteps[Math.max(0, stepIndex - 1)]);
  };

  const configureProtection = async () => {
    if (protectionMode === 'passphrase' && passphrase !== passphraseConfirmation) {
      setError('The passphrases do not match.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      if (!state.vault_configured) {
        await configureVault(protectionMode, protectionMode === 'passphrase' ? passphrase : undefined);
        setPassphrase('');
        setPassphraseConfirmation('');
        await refresh();
      }
      setStep('provider');
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  };

  const startService = async () => {
    setBusy(true);
    setError(null);
    try {
      await startDaemon();
      await new Promise((resolve) => window.setTimeout(resolve, 700));
      await refresh();
      setStep('account');
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  };

  const finish = async (destination: View) => {
    setBusy(true);
    setError(null);
    try {
      await completeOnboarding();
      await refresh();
      onFinish(destination);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  };

  return <div className="onboarding-window">
    <header className="onboarding-toolbar" data-tauri-drag-region="deep">
      <div className="traffic-light-space" data-tauri-drag-region />
      <strong className="onboarding-window-title" data-tauri-drag-region>LLM Notary</strong>
      <span className="onboarding-window-context">Setup</span>
    </header>
    <div className="onboarding-progress" aria-label={`Setup step ${stepIndex + 1} of ${onboardingSteps.length}`}>
      {onboardingSteps.map((item, index) => <span key={item} className={index <= stepIndex ? 'is-complete' : ''} />)}
    </div>
    <main className="onboarding-body">
      <section className="onboarding-content">
        {step !== 'welcome' && <button className="back-button" type="button" onClick={goBack} disabled={busy}>
          <ChevronLeft size={14} /> Back
        </button>}
        {step === 'welcome' && <WelcomeStep state={state} onContinue={() => setStep('protection')} />}
        {step === 'protection' && <ProtectionStep
          configured={state.vault_configured}
          mode={protectionMode}
          setMode={setProtectionMode}
          passphrase={passphrase}
          setPassphrase={setPassphrase}
          passphraseConfirmation={passphraseConfirmation}
          setPassphraseConfirmation={setPassphraseConfirmation}
          busy={busy}
          onContinue={() => void configureProtection()}
        />}
        {step === 'provider' && <ProviderStep
          provider={provider}
          selectedProvider={selectedProvider}
          setSelectedProvider={setSelectedProvider}
          model={model}
          setModel={setModel}
          busy={busy}
          onContinue={() => void startService()}
        />}
        {step === 'account' && <AccountStep
          onContinue={() => setStep('ready')}
          onSkip={() => setStep('ready')}
        />}
        {step === 'ready' && <ReadyStep
          state={state}
          provider={provider}
          model={model}
          busy={busy}
          onFinish={finish}
        />}
        {error && <div className="onboarding-error" role="alert">{error}</div>}
      </section>
      <OnboardingAside step={step} state={state} provider={provider} />
    </main>
  </div>;
}

function WelcomeStep({ state, onContinue }: { state: DesktopState; onContinue: () => void }) {
  const fresh = !state.agent_configured && !state.vault_configured;
  return <div className="wizard-step welcome-step">
    <span className="wizard-kicker">Welcome to LLM Notary</span>
    <h1>Your model response is readable only where it needs to be.</h1>
    <p>{fresh
      ? 'LLM Notary witnesses an authenticated provider exchange without giving the remote notary your prompt, response, or credentials.'
      : 'This Mac already has some LLM Notary settings. Setup will preserve them while keeping the same privacy boundary.'}</p>
    <SetupTrustDiagram />
    <div className="wizard-actions"><button className="mac-button is-primary is-large" onClick={onContinue}>Continue <ChevronRight size={15} /></button></div>
  </div>;
}

function SetupTrustDiagram() {
  return <figure
    className="setup-trust-diagram"
    role="img"
    aria-label="The model provider sends an encrypted response through the remote notary to LLM Notary on this Mac. The remote notary sees encrypted protocol data, while plaintext is decrypted locally for you and private evidence can be notarized into a portable trace."
  >
    <div className="setup-trust-flow" aria-hidden="true">
      <section className="setup-trust-node setup-provider-node">
        <span>Model provider</span>
        <strong>Authenticated response</strong>
        <small>Serves the normal request</small>
      </section>
      <div className="setup-encrypted-track setup-encrypted-track--provider">
        <i><LockKeyhole /></i>
        <small>Encrypted</small>
      </div>
      <section className="setup-trust-node setup-notary-node">
        <span>Remote notary</span>
        <code>8F 3C<br />A2 19</code>
        <strong>Ciphertext witness</strong>
        <small>No prompt, response, or credentials</small>
      </section>
      <div className="setup-encrypted-track setup-encrypted-track--local">
        <i><LockKeyhole /></i>
        <small>Encrypted</small>
      </div>
      <section className="setup-local-boundary">
        <span className="setup-local-label">On this Mac</span>
        <div className="setup-local-client">
          <img src={notaryMark} alt="" />
          <div><strong>This app</strong><small><UnlockKeyhole /> Decrypts locally</small></div>
        </div>
        <div className="setup-local-branches">
          <span className="setup-local-path setup-local-path--user"><i /></span>
          <span className="setup-local-path setup-local-path--capture"><i /></span>
        </div>
        <div className="setup-local-outputs">
          <div><UserRound /><span><strong>You</strong><small>Readable response</small></span></div>
          <div><FileCheck2 /><span><strong>Notarized trace</strong><small>Only when you notarize</small></span></div>
        </div>
      </section>
    </div>
    <figcaption><LockKeyhole /> Traffic is encrypted in transit. The remote notary never sees plaintext; private captures stay on this Mac.</figcaption>
  </figure>;
}

function ProtectionStep({ configured, mode, setMode, passphrase, setPassphrase, passphraseConfirmation, setPassphraseConfirmation, busy, onContinue }: {
  configured: boolean;
  mode: VaultSetupMode;
  setMode: (value: VaultSetupMode) => void;
  passphrase: string;
  setPassphrase: (value: string) => void;
  passphraseConfirmation: string;
  setPassphraseConfirmation: (value: string) => void;
  busy: boolean;
  onContinue: () => void;
}) {
  const [advancedOpen, setAdvancedOpen] = useState(mode === 'passphrase');
  const passphrasesMatch = passphrase === passphraseConfirmation;
  const mismatchId = 'vault-passphrase-mismatch';
  const chooseKeychain = () => {
    setMode('keychain');
    setPassphrase('');
    setPassphraseConfirmation('');
  };
  const toggleAdvanced = () => {
    if (advancedOpen) chooseKeychain();
    setAdvancedOpen(!advancedOpen);
  };
  return <div className="wizard-step">
    <span className="wizard-kicker">Private captures</span>
    <h1>Protect evidence on this Mac</h1>
    <p>A private capture can reconstruct the original provider request, including credentials. It is always encrypted before it is written.</p>
    {configured ? <div className="configured-protection"><BadgeCheck size={22} /><div><strong>Capture protection is already configured</strong><span>This assistant will keep the existing vault unchanged.</span></div></div> : <div className="protection-options" role="radiogroup" aria-label="Private capture protection">
      <button type="button" role="radio" aria-checked={mode === 'keychain'} className={mode === 'keychain' ? 'is-selected' : ''} onClick={chooseKeychain}>
        <span className="radio-mark">{mode === 'keychain' && <span />}</span><KeyRound size={20} />
        <div><strong>Use Keychain</strong><p>Recommended. macOS protects the vault key; there is no separate password to remember.</p></div>
      </button>
      {advancedOpen && <button type="button" role="radio" aria-checked={mode === 'passphrase'} className={mode === 'passphrase' ? 'is-selected' : ''} onClick={() => setMode('passphrase')}>
        <span className="radio-mark">{mode === 'passphrase' && <span />}</span><SlidersHorizontal size={20} />
        <div><strong>Use a passphrase</strong><p>Enter it whenever the desktop app opens. LLM Notary does not save it.</p></div>
      </button>}
    </div>}
    {!configured && <button type="button" className="advanced-options-toggle" aria-expanded={advancedOpen} onClick={toggleAdvanced}><SlidersHorizontal size={13} /> Advanced options <ChevronDown size={13} /></button>}
    {!configured && advancedOpen && mode === 'passphrase' && <div className="passphrase-fields">
      <label><span>Passphrase</span><input type="password" autoComplete="new-password" value={passphrase} aria-invalid={!passphrasesMatch} aria-describedby={!passphrasesMatch ? mismatchId : undefined} onChange={(event) => setPassphrase(event.target.value)} /></label>
      <label><span>Confirm passphrase</span><input type="password" autoComplete="new-password" value={passphraseConfirmation} aria-invalid={!passphrasesMatch} aria-describedby={!passphrasesMatch ? mismatchId : undefined} onChange={(event) => setPassphraseConfirmation(event.target.value)} /></label>
      {!passphrasesMatch && <small id={mismatchId} className="passphrase-mismatch" role="alert">The passphrases do not match.</small>}
    </div>}
    {!configured && advancedOpen && mode === 'passphrase' && passphrasesMatch && passphrase.length === 0 && <div className="wizard-warning"><ShieldCheck size={16} /><span>An empty passphrase provides no device protection. Anyone with this account's app data can open private captures.</span></div>}
    <div className="wizard-actions"><button className="mac-button is-primary is-large" onClick={onContinue} disabled={busy || (mode === 'passphrase' && (!advancedOpen || !passphrasesMatch))}>{busy ? 'Saving…' : 'Continue'} <ChevronRight size={15} /></button></div>
  </div>;
}

function ProviderStep({ provider, selectedProvider, setSelectedProvider, model, setModel, busy, onContinue }: {
  provider: Provider;
  selectedProvider: ProviderId;
  setSelectedProvider: (id: ProviderId) => void;
  model: string;
  setModel: (value: string) => void;
  busy: boolean;
  onContinue: () => void;
}) {
  return <div className="wizard-step provider-step">
    <span className="wizard-kicker">Models & providers</span>
    <h1>Connect your first provider</h1>
    <p>Choose one to set up now. Every local route remains available, and the provider credential stays in your existing client.</p>
    <div className="provider-picker" role="radiogroup" aria-label="Provider to configure first">
      {providers.map((item) => <button key={item.id} type="button" role="radio" aria-checked={selectedProvider === item.id} className={selectedProvider === item.id ? 'is-selected' : ''} onClick={() => setSelectedProvider(item.id)}>
        <span>{item.name.slice(0, 1)}</span><strong>{item.name}</strong><small>{item.operation}</small>
      </button>)}
    </div>
    <div className="provider-setup-card">
      <label><span>Local base URL</span><code>{provider.baseUrl}</code></label>
      <label><span>Model to try first <em>optional</em></span><input value={model} onChange={(event) => setModel(event.target.value)} placeholder={provider.modelExample} /></label>
      <p>The model name is a setup reminder only. Your client chooses the model on every request.</p>
    </div>
    <div className="wizard-actions"><button className="mac-button is-primary is-large" onClick={onContinue} disabled={busy}>{busy ? 'Starting service…' : 'Start LLM Notary'} <ChevronRight size={15} /></button></div>
  </div>;
}

function ReadyStep({ state, provider, model, busy, onFinish }: {
  state: DesktopState;
  provider: Provider;
  model: string;
  busy: boolean;
  onFinish: (destination: View) => Promise<void>;
}) {
  return <div className="wizard-step ready-step">
    <span className="ready-check"><Check size={26} /></span>
    <span className="wizard-kicker">Setup complete</span>
    <h1>LLM Notary is ready</h1>
    <p>The local service is running. Configure {provider.name} in your model client, then its next request will appear inside this app.</p>
    <div className="ready-summary">
      <div><span><StatusDot running={state.running} /></span><strong>Capture service</strong><small>{state.running ? 'Running' : 'Starting'}</small></div>
      <div><span className="provider-monogram">{provider.name.slice(0, 1)}</span><strong>{provider.name}</strong><small>{model || 'Client chooses model'}</small></div>
      <div><span><ShieldCheck size={16} /></span><strong>Private vault</strong><small>{vaultProtection(state.vault_mode).label}</small></div>
    </div>
    <div className="ready-url"><span>Paste this base URL into your client</span><code>{provider.baseUrl}</code></div>
    <div className="wizard-actions split-actions">
      <button className="mac-button is-primary is-large" onClick={() => void onFinish('captures')} disabled={busy}>Show captures <ChevronRight size={15} /></button>
      <button className="mac-button is-large" onClick={() => void onFinish('home')} disabled={busy}>Go to Home</button>
    </div>
  </div>;
}

function AccountStep({ onContinue, onSkip }: { onContinue: () => void; onSkip: () => void }) {
  return <div className="wizard-step account-step">
    <span className="wizard-kicker">Optional account</span>
    <h1>Connect an LLM Notary account</h1>
    <p>Sign in to see hosted credits and usage, use account-owned sharing, and manage connected devices. This does not upload, publish, or share any local capture.</p>
    <DesktopAccountCard onContinue={onContinue} onSkip={onSkip} />
  </div>;
}

function OnboardingAside({ step, state, provider }: {
  step: OnboardingStep;
  state: DesktopState;
  provider: Provider;
}) {
  const content = {
    welcome: {
      title: 'The notary sees ciphertext, not your conversation',
      copy: 'It participates in the provider connection so the exchange can be authenticated without receiving the application plaintext.',
    },
    protection: {
      title: 'Private before public',
      copy: 'A capture stays on this Mac until you explicitly notarize and share selected evidence.',
    },
    provider: {
      title: `Connect ${provider.name}`,
      copy: 'Only the base URL changes. The API key or subscription login remains in the model client that already holds it.',
    },
    account: {
      title: 'Account connection is optional',
      copy: 'Hosted credits, usage, and account-owned sharing are available when you sign in. Local capture, notarization, and verification work without an account.',
    },
    ready: {
      title: 'One app, end to end',
      copy: 'Review private captures, notarize proof, inspect notarized traces, and choose sharing from this window.',
    },
  }[step];
  return <aside className="onboarding-aside">
    <span className="aside-label">How it works</span>
    <h2>{content.title}</h2>
    <p>{content.copy}</p>
    {step === 'welcome' ? <dl className="aside-trust-facts">
      <div><dt>Remote notary</dt><dd>Provider hostname, encrypted traffic, sizes, timing, and protocol metadata—never plaintext</dd></div>
      <div><dt>This Mac</dt><dd>Provider credentials, prompts, responses, and private captures</dd></div>
      <div><dt>Shared later</dt><dd>Only the evidence you explicitly notarize and choose to share</dd></div>
    </dl> : <div className="aside-route">
      <RouteStop title="Model client" detail="Keeps the credential" active={step === 'ready' || state.running} />
      <RouteStop title="LLM Notary" detail="Captures locally" active={step === 'ready' || state.running} />
      <RouteStop title="Remote notary" detail="Sees encrypted protocol" active={step === 'ready' || state.running} />
      <RouteStop title="Provider" detail="Returns the model response" active={step === 'ready' || state.running} />
    </div>}
    <div className="aside-privacy"><ShieldCheck size={17} /><span>Prompts, responses, and provider credentials are not sent to the remote notary.</span></div>
  </aside>;
}

export default App;
