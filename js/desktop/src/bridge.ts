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
  version: string | null;
  proxy_listener: string;
  admin_listener: string;
  notary: string | null;
  counts: CaptureCounts;
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
    version: null,
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
      version: status.version,
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

export async function configureVault(mode: 'keychain' | 'convenience'): Promise<void> {
  if (!isTauri()) return;
  await invoke('configure_vault', { mode });
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
