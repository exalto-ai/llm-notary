const latestDownloadsRoot = '/downloads/releases';

export const macosDmgName = 'Notary-macos-arm64.dmg';

export function latestMacosDownloadHref(pointer: string): string {
  const fields = String(pointer).trim().split(/\s+/);
  if (fields.length !== 2 || fields.some((field) => !/^[a-zA-Z0-9._-]+$/.test(field))) {
    throw new Error('The latest download pointer is invalid.');
  }
  return `${latestDownloadsRoot}/builds/${fields[0]}/${macosDmgName}`;
}

export async function loadLatestPointer(): Promise<string> {
  const response = await fetch(`${latestDownloadsRoot}/latest`, {
    cache: 'no-store',
    headers: { Accept: 'text/plain' },
  });
  if (!response.ok) throw new Error('The latest download is unavailable.');
  return response.text();
}
