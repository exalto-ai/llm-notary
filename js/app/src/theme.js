export const themeOptions = ['auto', 'light', 'dark'];

export function initialThemePreference() {
  const stored = window.localStorage.getItem('llm-notary-theme');
  return themeOptions.includes(stored) ? stored : 'light';
}

export function resolvedTheme(preference, prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches) {
  if (preference === 'auto') return prefersDark ? 'dark' : 'light';
  return preference === 'dark' ? 'dark' : 'light';
}
