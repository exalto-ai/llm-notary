export const themeOptions = ['auto', 'light', 'dark'] as const;
export type ThemePreference = (typeof themeOptions)[number];
export type ResolvedTheme = Exclude<ThemePreference, 'auto'>;

export function initialThemePreference(): ThemePreference {
  const stored = window.localStorage.getItem('llm-notary-theme');
  return stored && themeOptions.includes(stored as ThemePreference)
    ? (stored as ThemePreference)
    : 'light';
}

export function resolvedTheme(
  preference: ThemePreference,
  prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches,
): ResolvedTheme {
  if (preference === 'auto') return prefersDark ? 'dark' : 'light';
  return preference === 'dark' ? 'dark' : 'light';
}
