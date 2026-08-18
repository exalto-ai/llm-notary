export const dashboardViews = ['overview', 'traces', 'activity', 'providers', 'settings'] as const;

export type DashboardView = (typeof dashboardViews)[number];

export type DashboardRoute = { view: DashboardView; id?: string };

export function dashboardRouteFromHash(hash: string): DashboardRoute {
  const [candidate = 'overview', id] = hash.replace(/^#\/?/, '').split('/');
  const view = dashboardViews.find((value) => value === candidate);
  return view ? { view, id } : { view: 'overview' };
}

export function dashboardRouteHash(route: DashboardRoute) {
  return `/${route.view}${route.id ? `/${route.id}` : ''}`;
}
