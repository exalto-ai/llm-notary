const authProviderIcons = {
  google: new URL('./assets/auth/google-g.svg', import.meta.url).href,
  github: new URL('./assets/auth/github.svg', import.meta.url).href,
} as const;

export type AuthProvider = keyof typeof authProviderIcons;

export function AuthProviderIcon({ provider }: { provider: AuthProvider }) {
  return <img
    className="auth-provider-icon"
    src={authProviderIcons[provider]}
    alt=""
    aria-hidden="true"
    data-auth-provider-icon={provider}
  />;
}
