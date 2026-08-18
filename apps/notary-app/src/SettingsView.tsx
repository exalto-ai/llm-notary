import { useEffect, useState } from 'react';
import {
  errorMessage,
  getLaunchAtLogin,
  setLaunchAtLogin,
  type DesktopState,
  type DesktopUpdateState,
} from './bridge';
import {
  formatBytes,
  StatusDot,
  updateRestartBlockReason,
  vaultProtection,
} from './product';
import { WorkspaceFrame } from './Shell';

export function SettingsView({
  state,
  updateState,
  busy,
  notice,
  onCheckUpdate,
  onRestartToUpdate,
}: {
  state: DesktopState;
  updateState: DesktopUpdateState | null;
  busy: string | null;
  notice: string | null;
  onCheckUpdate: () => void;
  onRestartToUpdate: () => void;
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
          ? 'Notary will open locked when you sign in.'
          : 'Notary will open when you sign in.'
        : 'Launch at sign-in is off.');
    } catch (error) {
      setMessage(errorMessage(error));
    }
  };

  return <div className="native-page preferences-page">
    <section className="preference-section">
      <h2>General</h2>
      <div className="preference-group">
        <label className="preference-row">
          <div><strong>Open Notary at sign-in</strong><span>{requiresSessionUnlock ? 'The app opens locked; enter the vault passphrase to start capture.' : 'Keep capture available from the menu bar.'}</span></div>
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
                ? 'Notary is up to date'
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
      <h2>Private trace protection</h2>
      <div className="preference-group">
        <div className="preference-row"><div><strong>{vault.label}</strong><span>{vault.detail}</span></div><span className="value-label">Configured</span></div>
        <p className="preference-note">Changing protection requires a guided migration so existing private traces are never left with two sources of truth.</p>
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
    <section className="preference-section service-backed-settings">
      <h2>Service settings</h2>
      <p className="preference-note">Account, capture, notary trust, storage, listeners, and developer settings come from the local service.</p>
      <WorkspaceFrame route="settings" running={state.running} />
    </section>
    {(notice || message) && <div className="native-notice">{message ?? notice}</div>}
  </div>;
}
