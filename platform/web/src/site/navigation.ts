export function routeHref(route: string): string {
  const cleanRoute = route.startsWith('#/')
    ? route.slice(2)
    : route.startsWith('/')
      ? route.slice(1)
      : route;
  return `/${cleanRoute.replace(/^\/+/, '')}`;
}

export function currentRoute(): string {
  if (window.location.hash.startsWith('#/')) return window.location.hash.slice(2);
  return `${window.location.pathname.replace(/^\/+/, '')}${window.location.search}`;
}

export function navigateTo(route: string): void {
  window.history.pushState({}, '', routeHref(route));
  window.dispatchEvent(new PopStateEvent('popstate'));
}

export function migrateLegacyRoute(): void {
  if (!window.location.hash.startsWith('#/')) return;
  window.history.replaceState({}, '', routeHref(window.location.hash.slice(1)));
}
