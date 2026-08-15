import { invoke } from '@tauri-apps/api/core';

export type CaptureCounts = {
  total_captures: number;
  capturing: number;
  ready_to_finalize: number;
  finalized: number;
  failed: number;
  active_operations: number;
};

export type DesktopState = {
  running: boolean;
  managed_by_desktop: boolean;
  vault_configured: boolean;
  agent_configured: boolean;
  onboarding_complete: boolean;
  vault_mode: string;
  vault_locked: boolean;
  version: string | null;
  app_build_id: string;
  daemon_build_id: string | null;
  proxy_listener: string;
  admin_listener: string;
  notary: string | null;
  counts: CaptureCounts;
  message: string | null;
};

export type DesktopUpdateState = {
  enabled: boolean;
  phase: 'disabled' | 'idle' | 'checking' | 'current' | 'downloading' | 'ready' | 'installing' | 'error';
  current_build_id: string;
  latest_build_id: string | null;
  downloaded_bytes: number;
  total_bytes: number | null;
  message: string | null;
};

const emptyCounts: CaptureCounts = {
  total_captures: 0,
  capturing: 0,
  ready_to_finalize: 0,
  finalized: 0,
  failed: 0,
  active_operations: 0,
};

export const isTauri = () => '__TAURI_INTERNALS__' in window;

export const errorMessage = (error: unknown) => error instanceof Error ? error.message : String(error);

function fallbackState(overrides: Partial<DesktopState> = {}): DesktopState {
  return {
    running: false,
    managed_by_desktop: false,
    vault_configured: true,
    agent_configured: true,
    onboarding_complete: true,
    vault_mode: 'keychain',
    vault_locked: false,
    version: null,
    app_build_id: 'dev',
    daemon_build_id: null,
    proxy_listener: '127.0.0.1:8787',
    admin_listener: '127.0.0.1:8788',
    notary: null,
    counts: emptyCounts,
    message: null,
    ...overrides,
  };
}

function forcedState(): DesktopState | null {
  const screen = new URLSearchParams(window.location.search).get('screen');
  if (screen === 'onboarding') {
    return fallbackState({
      vault_configured: false,
      agent_configured: false,
      onboarding_complete: false,
      vault_mode: 'not configured',
      vault_locked: false,
    });
  }
  if (screen === 'unlock') {
    return fallbackState({
      running: false,
      vault_mode: 'passphrase',
      vault_locked: true,
    });
  }
  if (screen === 'offline') {
    return fallbackState({
      message: 'The local service is not responding.',
    });
  }
  return null;
}

export async function getDesktopState(): Promise<DesktopState> {
  const forced = forcedState();
  if (forced) return forced;
  if (isTauri()) return invoke<DesktopState>('get_desktop_state');

  try {
    const response = await fetch('/admin-api/v1/status');
    if (!response.ok) throw new Error(`Local service returned ${response.status}`);
    const status = await response.json();
    return {
      running: true,
      managed_by_desktop: false,
      vault_configured: status.vault !== 'unavailable',
      agent_configured: true,
      onboarding_complete: true,
      vault_mode: status.vault === 'OS vault' ? 'keychain' : 'passphrase',
      vault_locked: false,
      version: status.version,
      app_build_id: 'dev',
      daemon_build_id: status.build_id ?? null,
      proxy_listener: status.proxy_listener,
      admin_listener: status.admin_listener,
      notary: status.notary,
      counts: status.counts,
      message: null,
    };
  } catch (error) {
    return fallbackState({ message: errorMessage(error) });
  }
}

export async function configureVault(mode: 'keychain' | 'passphrase', passphrase?: string): Promise<void> {
  if (!isTauri()) return;
  await invoke('configure_vault', { mode, passphrase });
}

export async function unlockVault(passphrase: string): Promise<void> {
  if (!isTauri()) return;
  await invoke('unlock_vault', { passphrase });
}

export async function completeOnboarding(): Promise<void> {
  if (!isTauri()) return;
  await invoke('complete_onboarding');
}

export async function startDaemon(): Promise<void> {
  if (!isTauri()) return;
  await invoke('start_daemon');
}

export async function stopDaemon(): Promise<void> {
  if (!isTauri()) return;
  await invoke('stop_daemon');
}

export async function restartDaemon(): Promise<void> {
  if (!isTauri()) return;
  await invoke('restart_daemon');
}

export async function getUpdateState(): Promise<DesktopUpdateState> {
  if (!isTauri()) {
    const preview = new URLSearchParams(window.location.search).get('update');
    if (preview === 'ready') {
      return {
        enabled: true,
        phase: 'ready',
        current_build_id: 'preview-build-a',
        latest_build_id: 'preview-build-b',
        downloaded_bytes: 42 * 1024 * 1024,
        total_bytes: 42 * 1024 * 1024,
        message: 'The latest release is ready. Restart when local work is idle.',
      };
    }
    if (preview === 'downloading') {
      return {
        enabled: true,
        phase: 'downloading',
        current_build_id: 'preview-build-a',
        latest_build_id: 'preview-build-b',
        downloaded_bytes: 24 * 1024 * 1024,
        total_bytes: 42 * 1024 * 1024,
        message: 'Downloading the signed update…',
      };
    }
    return {
      enabled: false,
      phase: 'disabled',
      current_build_id: 'dev',
      latest_build_id: null,
      downloaded_bytes: 0,
      total_bytes: null,
      message: 'Automatic updates are available in signed release builds.',
    };
  }
  return invoke<DesktopUpdateState>('get_update_state');
}

export async function checkForUpdates(): Promise<DesktopUpdateState> {
  if (!isTauri()) return getUpdateState();
  return invoke<DesktopUpdateState>('check_for_updates');
}

export async function installUpdateAndRestart(): Promise<void> {
  if (!isTauri()) return;
  await invoke('install_update_and_restart');
}

export async function getLaunchAtLogin(): Promise<boolean> {
  if (!isTauri()) return localStorage.getItem('llm-notary-launch-at-login') === 'true';
  const { isEnabled } = await import('@tauri-apps/plugin-autostart');
  return isEnabled();
}

export async function setLaunchAtLogin(enabled: boolean): Promise<void> {
  if (!isTauri()) {
    localStorage.setItem('llm-notary-launch-at-login', String(enabled));
    return;
  }
  const plugin = await import('@tauri-apps/plugin-autostart');
  if (enabled) await plugin.enable();
  else await plugin.disable();
}
