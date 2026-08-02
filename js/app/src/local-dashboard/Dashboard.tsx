import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react';
import {
  ActionIcon, AppShell, Badge, Box, Burger, Button, Center, Divider, Drawer, Group,
  Loader, Menu, Modal, NavLink, Paper, PasswordInput, ScrollArea, Select, SimpleGrid,
  Stack, Table, Tabs, Text, TextInput, ThemeIcon, Title, Tooltip, UnstyledButton,
  useMantineColorScheme
} from '@mantine/core';
import { useDisclosure, useMediaQuery } from '@mantine/hooks';
import { notifications } from '@mantine/notifications';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Activity, AlertTriangle, Archive, ArrowLeft, BookOpenCheck, Check, CheckCircle2, CodeXml,
  ChevronRight, CircleDot, Clock3, Copy, Database, FileCheck2, FileJson2, Gauge,
  KeyRound, ListChecks, Menu as MenuIcon, Moon, PanelLeft, Play, RefreshCw, Search,
  Send, Settings, ShieldCheck, Sun, TerminalSquare, Unplug, XCircle
} from 'lucide-react';
import type {
  Capture, CaptureDetail, Event, LocalApi, LocalApiError, Operation, Status, Verification
} from './api';

export type DashboardView = 'overview' | 'captures' | 'finalizations' | 'traces' | 'publishing' | 'activity' | 'settings';

type Route = { view: DashboardView; id?: string };

const navigation: Array<{ view: DashboardView; label: string; icon: typeof Gauge }> = [
  { view: 'overview', label: 'Overview', icon: Gauge },
  { view: 'captures', label: 'Captures', icon: Archive },
  { view: 'finalizations', label: 'Finalizations', icon: ListChecks },
  { view: 'traces', label: 'Finalized traces', icon: FileCheck2 },
  { view: 'publishing', label: 'Publishing', icon: Send },
  { view: 'activity', label: 'Activity', icon: Activity },
  { view: 'settings', label: 'Settings & API', icon: Settings }
];

function routeFromHash(): Route {
  const [view = 'overview', id] = window.location.hash.replace(/^#\/?/, '').split('/');
  return navigation.some((item) => item.view === view) ? { view: view as DashboardView, id } : { view: 'overview' };
}

function goTo(route: Route) {
  window.location.hash = `/${route.view}${route.id ? `/${route.id}` : ''}`;
}

function useRoute() {
  const [route, setRoute] = useState<Route>(routeFromHash);
  useEffect(() => {
    const change = () => setRoute(routeFromHash());
    window.addEventListener('hashchange', change);
    return () => window.removeEventListener('hashchange', change);
  }, []);
  return route;
}

function formatDate(value?: number | null) {
  if (!value) return 'Not yet';
  return new Intl.DateTimeFormat(undefined, {
    month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit'
  }).format(new Date(value));
}

function formatBytes(value?: number | null) {
  if (value === undefined || value === null) return '—';
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 ** 2).toFixed(1)} MB`;
}

function stateTone(state: string) {
  if (['finalized', 'verified', 'ready', 'success'].includes(state)) return 'ready';
  if (['failed', 'interrupted', 'error', 'unavailable'].includes(state)) return 'danger';
  if (['running', 'capturing', 'queued'].includes(state)) return 'active';
  return 'muted';
}

function StatusLabel({ state }: { state: string }) {
  return <span className={`status-label status-label--${stateTone(state)}`}>
    <span aria-hidden="true" />{state.replaceAll('_', ' ')}
  </span>;
}

function PageHeader({ eyebrow, title, copy, action }: { eyebrow: string; title: string; copy: string; action?: ReactNode }) {
  return <div className="page-header">
    <div><Text className="eyebrow">{eyebrow}</Text><Title order={1}>{title}</Title><Text className="page-copy">{copy}</Text></div>
    {action && <div className="page-action">{action}</div>}
  </div>;
}

function EmptyState({ icon: Icon = Archive, title, copy }: { icon?: typeof Archive; title: string; copy: string }) {
  return <Center className="empty-state"><Stack align="center" gap="sm"><Icon aria-hidden="true" />
    <Title order={3}>{title}</Title><Text>{copy}</Text></Stack></Center>;
}

function ErrorState({ title = 'The local service is unavailable', onRetry }: { title?: string; onRetry?: () => void }) {
  return <Center className="error-state"><Stack align="center" gap="md"><Unplug aria-hidden="true" />
    <Title order={2}>{title}</Title><Text>Check that the foreground service is running on this loopback address.</Text>
    {onRetry && <Button variant="outline" leftSection={<RefreshCw size={15} />} onClick={onRetry}>Try again</Button>}</Stack></Center>;
}

function LoadingState({ label = 'Loading local evidence' }: { label?: string }) {
  return <Center className="loading-state"><Stack align="center" gap="sm"><Loader size="sm" /><Text>{label}</Text></Stack></Center>;
}

function SchemeControl() {
  const { colorScheme, setColorScheme } = useMantineColorScheme();
  const options = [
    { value: 'auto' as const, label: 'System', icon: PanelLeft },
    { value: 'light' as const, label: 'Light', icon: Sun },
    { value: 'dark' as const, label: 'Dark', icon: Moon }
  ];
  return <div className="scheme-control" role="group" aria-label="Color scheme">
    {options.map(({ value, label, icon: Icon }) => <Tooltip key={value} label={label}>
      <button type="button" className={colorScheme === value ? 'is-active' : ''} aria-pressed={colorScheme === value}
        aria-label={`${label} color scheme`} onClick={() => setColorScheme(value)}><Icon size={14} aria-hidden="true" /><span>{label}</span></button>
    </Tooltip>)}
  </div>;
}

function AuthGate({ api, onAuthenticated }: { api: LocalApi; onAuthenticated: () => void }) {
  const [token, setToken] = useState('');
  const mutation = useMutation({
    mutationFn: () => api.session(token),
    onSuccess: () => { setToken(''); onAuthenticated(); },
    onError: () => notifications.show({ color: 'red', title: 'Authentication failed', message: 'Read the private admin token file and try again.' })
  });
  const submit = (event: FormEvent) => { event.preventDefault(); if (token) mutation.mutate(); };
  return <main className="auth-shell">
    <section className="auth-document">
      <Brand />
      <Text className="eyebrow">Local administration</Text>
      <Title order={1}>Open your evidence workspace.</Title>
      <Text className="auth-copy">Exchange the private admin token for an HttpOnly browser session. The token is cleared from this form and is never stored by the dashboard.</Text>
      <form onSubmit={submit}>
        <PasswordInput label="Admin token" description="Read it from the token_path named in your local service configuration."
          value={token} onChange={(event) => setToken(event.currentTarget.value)} autoComplete="off" autoFocus />
        <Button type="submit" loading={mutation.isPending} disabled={!token} rightSection={<ChevronRight size={15} />}>Open dashboard</Button>
      </form>
      <div className="trust-note"><ShieldCheck aria-hidden="true" /><div><b>Loopback only</b><span>This control surface is available only on the local admin listener.</span></div></div>
    </section>
  </main>;
}

function Brand() {
  return <div className="local-brand"><span className="local-mark"><BookOpenCheck size={17} aria-hidden="true" /></span><span>LLM Notary</span></div>;
}

function Sidebar({ route, status, onNavigate, fixture }: {
  route: Route; status: Status; onNavigate: (route: Route) => void; fixture: boolean;
}) {
  const count = (view: DashboardView) => view === 'captures' ? status.counts.pending
    : view === 'finalizations' ? status.counts.active_operations : undefined;
  return <div className="sidebar-inner">
    <nav aria-label="Local dashboard">
      {navigation.map(({ view, label, icon: Icon }) => <NavLink key={view} component="button" type="button" aria-label={label} active={route.view === view}
        label={label} leftSection={<Icon size={17} strokeWidth={1.7} />} rightSection={count(view) ? <Badge size="xs">{count(view)}</Badge> : null}
        onClick={() => onNavigate({ view })} />)}
    </nav>
    <div className="sidebar-foot">
      {fixture && <div className="fixture-flag"><Database size={14} aria-hidden="true" />Documentation fixture</div>}
      <StatusLabel state="online" /><Text>Admin {status.admin_listener}</Text>
    </div>
  </div>;
}

export function Dashboard({ api, fixture = false }: { api: LocalApi; fixture?: boolean }) {
  const route = useRoute();
  const queryClient = useQueryClient();
  const [navOpened, { open: openNav, close: closeNav }] = useDisclosure(false);
  const statusQuery = useQuery({ queryKey: ['status'], queryFn: api.status, retry: false, refetchInterval: fixture ? false : 10_000 });
  const navigate = (next: Route) => { closeNav(); goTo(next); };

  if (statusQuery.isLoading) return <LoadingState label="Connecting to the local service" />;
  if (statusQuery.error && (statusQuery.error as LocalApiError).status === 401) {
    return <AuthGate api={api} onAuthenticated={() => queryClient.invalidateQueries({ queryKey: ['status'] })} />;
  }
  if (!statusQuery.data) return <ErrorState onRetry={() => statusQuery.refetch()} />;
  const status = statusQuery.data;
  return <AppShell
    header={{ height: 64 }} navbar={{ width: 248, breakpoint: 'sm', collapsed: { mobile: !navOpened } }}
    padding={0} className="dashboard-shell">
    <AppShell.Header className="dashboard-header">
      <Group h="100%" justify="space-between" wrap="nowrap">
        <Group gap="sm" wrap="nowrap"><Burger opened={navOpened} onClick={openNav} hiddenFrom="sm" size="sm" aria-label="Open navigation" />
          <Brand /><Divider orientation="vertical" visibleFrom="sm" /><Text className="header-context" visibleFrom="sm">Local evidence</Text></Group>
        <Group gap="md" wrap="nowrap"><div className="header-health"><StatusLabel state="online" /><span>{status.counts.active_operations ? `${status.counts.active_operations} active` : 'Idle'}</span></div><SchemeControl /></Group>
      </Group>
    </AppShell.Header>
    <AppShell.Navbar className="dashboard-navbar"><Sidebar route={route} status={status} onNavigate={navigate} fixture={fixture} /></AppShell.Navbar>
    <Drawer opened={navOpened} onClose={closeNav} title={<Brand />} size="min(88vw, 340px)" hiddenFrom="sm" classNames={{ body: 'mobile-nav-body' }}>
      <Sidebar route={route} status={status} onNavigate={navigate} fixture={fixture} />
    </Drawer>
    <AppShell.Main className="dashboard-main"><View route={route} status={status} api={api} navigate={navigate} /></AppShell.Main>
  </AppShell>;
}

function View({ route, status, api, navigate }: { route: Route; status: Status; api: LocalApi; navigate: (route: Route) => void }) {
  switch (route.view) {
    case 'captures': return <CapturesView api={api} selectedId={route.id} navigate={navigate} />;
    case 'finalizations': return <FinalizationsView api={api} selectedId={route.id} navigate={navigate} />;
    case 'traces': return <TracesView api={api} selectedId={route.id} navigate={navigate} />;
    case 'publishing': return <PublishingView api={api} />;
    case 'activity': return <ActivityView api={api} />;
    case 'settings': return <SettingsView status={status} />;
    default: return <OverviewView api={api} status={status} navigate={navigate} />;
  }
}

function OverviewView({ api, status, navigate }: { api: LocalApi; status: Status; navigate: (route: Route) => void }) {
  const events = useQuery({ queryKey: ['events'], queryFn: api.events });
  const stats = [
    ['Capturing', status.counts.capturing, 'active'], ['Pending', status.counts.pending, 'muted'],
    ['Finalizing', status.counts.active_operations, 'active'], ['Finalized', status.counts.finalized, 'ready'],
    ['Failed', status.counts.failed, 'danger']
  ] as const;
  return <div className="view-page overview-page"><PageHeader eyebrow="Local service" title="Evidence at a glance."
    copy="Capture privately, finalize deliberately, and verify from authenticated provider bytes." />
    <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }} spacing={0} className="service-grid">
      <ServiceFact icon={CheckCircle2} label="Service" value="Online" detail={`v${status.version}`} tone="ready" />
      <ServiceFact icon={KeyRound} label="Vault" value={status.vault} detail="Key material stays local" />
      <ServiceFact icon={ShieldCheck} label="Notary" value={status.notary === 'directory' ? 'Directory pinned' : 'Configured'} detail="Provider connection delegated" />
      <ServiceFact icon={Activity} label="Work queue" value={status.counts.active_operations ? 'Active' : 'Idle'} detail={`${status.counts.active_operations} operation${status.counts.active_operations === 1 ? '' : 's'}`} />
    </SimpleGrid>
    <section className="overview-work"><div><Text className="eyebrow">Capture states</Text><div className="count-strip">{stats.map(([label, value, tone]) => <UnstyledButton key={label} onClick={() => navigate({ view: label === 'Finalizing' ? 'finalizations' : 'captures' })}>
      <span className={`count-marker count-marker--${tone}`} /><b>{value}</b><span>{label}</span></UnstyledButton>)}</div></div>
      <Paper className="next-action"><Text className="eyebrow">Next action</Text><Title order={2}>{status.counts.pending ? 'Finalize pending evidence.' : 'Send a provider request.'}</Title>
        <Text>{status.counts.pending ? `${status.counts.pending} capture${status.counts.pending === 1 ? '' : 's'} can be turned into independently verifiable traces.` : 'Point an SDK at the local provider proxy to create a private capture.'}</Text>
        <Button onClick={() => navigate({ view: status.counts.pending ? 'captures' : 'settings' })}>{status.counts.pending ? 'Review captures' : 'View proxy routes'}</Button></Paper>
    </section>
    <section className="recent-section"><Group justify="space-between"><div><Text className="eyebrow">Recent activity</Text><Title order={2}>What changed</Title></div><Button variant="subtle" onClick={() => navigate({ view: 'activity' })}>All activity</Button></Group>
      {events.isLoading ? <LoadingState /> : <EventList events={events.data?.items.slice(0, 4) ?? []} />}</section>
  </div>;
}

function ServiceFact({ icon: Icon, label, value, detail, tone }: { icon: typeof Gauge; label: string; value: string; detail: string; tone?: string }) {
  return <div className="service-fact"><Group justify="space-between"><Text className="eyebrow">{label}</Text><Icon size={17} aria-hidden="true" /></Group><Title order={3}>{value}</Title><Text>{detail}</Text>{tone && <StatusLabel state={tone} />}</div>;
}

function CapturesView({ api, selectedId, navigate }: { api: LocalApi; selectedId?: string; navigate: (route: Route) => void }) {
  const [query, setQuery] = useState('');
  const [provider, setProvider] = useState<string | null>(null);
  const [finalization, setFinalization] = useState<string | null>(null);
  const mobile = useMediaQuery('(max-width: 820px)');
  const captures = useQuery({ queryKey: ['captures', query, provider, finalization], queryFn: () => api.captures({ query, provider: provider ?? undefined, finalization_state: finalization ?? undefined }) });
  const activeId = selectedId ?? captures.data?.items[0]?.capture_id;
  const active = captures.data?.items.find((capture) => capture.capture_id === activeId);
  const showDetail = Boolean(mobile && selectedId);
  return <div className="view-page capture-page"><PageHeader eyebrow="Private evidence" title="Captures"
    copy="Search privacy-aware previews and move only selected captures into proof generation." />
    {!showDetail && <div className="filter-bar"><TextInput aria-label="Search captures" placeholder="Search prompt and output previews" leftSection={<Search size={15} />} value={query} onChange={(event) => setQuery(event.currentTarget.value)} />
      <Select aria-label="Provider filter" placeholder="All providers" clearable data={['openai', 'anthropic', 'deepseek', 'openrouter']} value={provider} onChange={setProvider} />
      <Select aria-label="Finalization filter" placeholder="All finalization states" clearable data={['not_requested', 'queued', 'running', 'finalized', 'failed', 'interrupted']} value={finalization} onChange={setFinalization} /></div>}
    {captures.isLoading ? <LoadingState /> : captures.error ? <ErrorState onRetry={() => captures.refetch()} /> : !captures.data?.items.length ? <EmptyState title="No captures match" copy="Clear a filter or send a new request through the provider proxy." />
      : <div className={`master-detail ${showDetail ? 'show-detail' : ''}`}>
        <ScrollArea className="master-list" type="auto"><div className="capture-list" role="list" aria-label="Captures">{captures.data.items.map((capture) => <CaptureRow key={capture.capture_id} capture={capture} active={capture.capture_id === activeId} onClick={() => navigate({ view: 'captures', id: capture.capture_id })} />)}</div></ScrollArea>
        <div className="detail-panel">{active ? <CaptureInspector api={api} capture={active} mobile={Boolean(mobile)} onBack={() => navigate({ view: 'captures' })} navigate={navigate} /> : null}</div>
      </div>}
  </div>;
}

function CaptureRow({ capture, active, onClick }: { capture: Capture; active: boolean; onClick: () => void }) {
  return <UnstyledButton className={`capture-row ${active ? 'is-active' : ''}`} onClick={onClick} role="listitem">
    <Group justify="space-between" wrap="nowrap"><Text className="row-provider">{capture.provider}</Text><Text className="mono-time">{formatDate(capture.created_at_unix_ms)}</Text></Group>
    <Title order={3}>{capture.requested_model ?? 'Model not reported'}</Title><Text lineClamp={2}>{capture.prompt_preview || 'Preview disabled for this capture.'}</Text>
    <Group justify="space-between"><StatusLabel state={capture.finalization_state === 'not_requested' ? capture.capture_state : capture.finalization_state} /><Text className="row-size">{formatBytes(capture.response_bytes)}</Text></Group>
  </UnstyledButton>;
}

function CaptureInspector({ api, capture, mobile, onBack, navigate }: { api: LocalApi; capture: Capture; mobile: boolean; onBack: () => void; navigate: (route: Route) => void }) {
  const queryClient = useQueryClient();
  const detail = useQuery({ queryKey: ['capture', capture.capture_id], queryFn: () => api.capture(capture.capture_id) });
  const finalize = useMutation({
    mutationFn: () => api.startFinalization(capture.capture_id),
    onSuccess: (result) => {
      notifications.show({ title: result.deduplicated ? 'Already in the queue' : 'Finalization queued', message: result.deduplicated ? 'The existing operation remains active.' : 'Proof generation will run in the background.' });
      queryClient.invalidateQueries({ queryKey: ['captures'] });
      queryClient.invalidateQueries({ queryKey: ['operations'] });
      navigate({ view: 'finalizations', id: result.operation.operation_id });
    },
    onError: () => notifications.show({ color: 'red', title: 'Could not finalize', message: 'The service returned a safe failure. Review Activity for the failure code.' })
  });
  if (detail.isLoading) return <LoadingState />;
  const value = detail.data;
  if (!value) return <ErrorState title="Capture detail is unavailable" onRetry={() => detail.refetch()} />;
  const canFinalize = capture.capture_state === 'pending' && ['not_requested', 'failed', 'interrupted'].includes(capture.finalization_state);
  return <article className="inspector capture-inspector">
    {mobile && <Button variant="subtle" leftSection={<ArrowLeft size={15} />} onClick={onBack}>All captures</Button>}
    <div className="inspector-head"><div><Text className="eyebrow">Capture detail</Text><Title order={2}>{capture.requested_model ?? 'Unreported model'}</Title><Text className="mono-id">{capture.capture_id}</Text></div>
      {canFinalize && <Button loading={finalize.isPending} leftSection={<Play size={15} />} onClick={() => finalize.mutate()}>Finalize</Button>}</div>
    <Lifecycle capture={capture} />
    <InspectorSection title="Safe metadata"><dl className="metadata-grid"><Fact label="Provider" value={capture.provider} /><Fact label="Operation" value={capture.operation} /><Fact label="HTTP status" value={capture.http_status?.toString() ?? 'In progress'} /><Fact label="Streaming" value={capture.streaming ? 'Yes' : 'No'} /><Fact label="Request" value={formatBytes(capture.request_bytes)} /><Fact label="Response" value={formatBytes(capture.response_bytes)} /></dl></InspectorSection>
    <InspectorSection title="Privacy-aware previews"><div className="preview-block"><Text className="eyebrow">Prompt {capture.prompt_preview_truncated && '· truncated'}</Text><Text>{capture.prompt_preview || 'Preview storage is disabled.'}</Text></div><div className="preview-block"><Text className="eyebrow">Output {capture.output_preview_truncated && '· truncated'}</Text><Text>{capture.output_preview || 'No output preview is available yet.'}</Text></div></InspectorSection>
    <InspectorSection title="Retained artifacts"><ArtifactList detail={value} /></InspectorSection>
  </article>;
}

function Lifecycle({ capture }: { capture: Capture }) {
  const steps = [
    { label: 'Captured', state: capture.capture_state === 'capturing' ? 'active' : 'ready' },
    { label: 'Bundle encrypted', state: capture.capture_state === 'pending' ? 'ready' : capture.capture_state === 'failed' ? 'danger' : 'muted' },
    { label: 'Finalized', state: capture.finalization_state === 'finalized' ? 'ready' : ['running', 'queued'].includes(capture.finalization_state) ? 'active' : capture.finalization_state === 'failed' ? 'danger' : 'muted' }
  ];
  return <ol className="lifecycle" aria-label="Capture lifecycle">{steps.map((step) => <li key={step.label} className={`lifecycle--${step.state}`}><span aria-hidden="true" /><b>{step.label}</b></li>)}</ol>;
}

function InspectorSection({ title, children }: { title: string; children: ReactNode }) {
  return <section className="inspector-section"><Title order={3}>{title}</Title>{children}</section>;
}

function Fact({ label, value }: { label: string; value: string }) { return <div><dt>{label}</dt><dd>{value}</dd></div>; }

function ArtifactList({ detail }: { detail: CaptureDetail }) {
  return <div className="artifact-list">{detail.artifacts.map((artifact) => <div key={artifact.kind}><FileJson2 size={17} aria-hidden="true" /><div><b>{artifact.kind.replaceAll('_', ' ')}</b><span>{formatBytes(artifact.size_bytes)}</span></div><code>{artifact.sha256.slice(0, 12)}…</code></div>)}</div>;
}

function FinalizationsView({ api, selectedId, navigate }: { api: LocalApi; selectedId?: string; navigate: (route: Route) => void }) {
  const operations = useQuery({ queryKey: ['operations'], queryFn: api.operations, refetchInterval: 3_000 });
  const active = operations.data?.items.find((item) => item.operation_id === selectedId) ?? operations.data?.items[0];
  return <div className="view-page"><PageHeader eyebrow="Background work" title="Finalizations" copy="Durable proof operations survive ambiguity: duplicates resolve to one active operation, and interruptions remain retryable." />
    {operations.isLoading ? <LoadingState /> : !operations.data?.items.length ? <EmptyState icon={ListChecks} title="No finalizations yet" copy="Queue one from a pending capture." />
      : <div className="operations-layout"><div className="operations-table"><Table.ScrollContainer minWidth={700}><Table highlightOnHover>
        <Table.Thead><Table.Tr><Table.Th>State</Table.Th><Table.Th>Capture</Table.Th><Table.Th>Attempt</Table.Th><Table.Th>Queued</Table.Th><Table.Th /></Table.Tr></Table.Thead>
        <Table.Tbody>{operations.data.items.map((operation) => <Table.Tr key={operation.operation_id} className={active?.operation_id === operation.operation_id ? 'is-selected' : ''}>
          <Table.Td><StatusLabel state={operation.state} /></Table.Td><Table.Td><code>{operation.capture_id}</code></Table.Td><Table.Td>{operation.attempt}</Table.Td><Table.Td>{formatDate(operation.created_at_unix_ms)}</Table.Td><Table.Td><ActionIcon variant="subtle" aria-label={`Inspect ${operation.operation_id}`} onClick={() => navigate({ view: 'finalizations', id: operation.operation_id })}><ChevronRight size={16} /></ActionIcon></Table.Td>
        </Table.Tr>)}</Table.Tbody></Table></Table.ScrollContainer></div>{active && <OperationInspector api={api} operation={active} />}</div>}
  </div>;
}

function OperationInspector({ api, operation }: { api: LocalApi; operation: Operation }) {
  const queryClient = useQueryClient();
  const retry = useMutation({ mutationFn: () => api.retry(operation.operation_id), onSuccess: () => {
    notifications.show({ title: 'Retry queued', message: 'The same durable operation will make another attempt.' });
    queryClient.invalidateQueries({ queryKey: ['operations'] });
  }});
  const retryable = ['failed', 'interrupted'].includes(operation.state);
  return <Paper className="operation-inspector"><Text className="eyebrow">Selected operation</Text><Group justify="space-between" align="flex-start"><div><Title order={2}>{operation.state === 'running' ? 'Generating private proof' : operation.state.replaceAll('_', ' ')}</Title><Text className="mono-id">{operation.operation_id}</Text></div><StatusLabel state={operation.state} /></Group>
    <div className="operation-stage"><span className={['queued', 'running', 'finalized'].includes(operation.state) ? 'complete' : ''}>Queued</span><i /><span className={['running', 'finalized'].includes(operation.state) ? 'complete' : ''}>Proof generation</span><i /><span className={operation.state === 'finalized' ? 'complete' : ''}>Verified package</span></div>
    <dl className="receipt-list"><Fact label="Capture" value={operation.capture_id ?? '—'} /><Fact label="Attempt" value={String(operation.attempt)} /><Fact label="Started" value={formatDate(operation.started_at_unix_ms)} /><Fact label="Finished" value={formatDate(operation.completed_at_unix_ms)} />{operation.failure_code && <Fact label="Safe failure code" value={operation.failure_code} />}</dl>
    {operation.state === 'running' && <div className="no-progress-note"><Clock3 size={16} /><Text>Proof generation can take several minutes. The service does not report a meaningful percentage.</Text></div>}
    {retryable && <Button leftSection={<RefreshCw size={15} />} loading={retry.isPending} onClick={() => retry.mutate()}>Retry finalization</Button>}
  </Paper>;
}

function TracesView({ api, selectedId, navigate }: { api: LocalApi; selectedId?: string; navigate: (route: Route) => void }) {
  const captures = useQuery({ queryKey: ['captures', 'finalized'], queryFn: () => api.captures({ finalization_state: 'finalized' }) });
  const activeId = selectedId ?? captures.data?.items[0]?.capture_id;
  return <div className="view-page"><PageHeader eyebrow="Portable evidence" title="Finalized traces" copy="Inspect the disclosed document, its evidence receipt, and a fresh independent verification result." />
    {captures.isLoading ? <LoadingState /> : !captures.data?.items.length ? <EmptyState icon={FileCheck2} title="No finalized traces" copy="Finalize a pending capture to create one." />
      : <div className="trace-layout"><div className="trace-list">{captures.data.items.map((capture) => <CaptureRow key={capture.capture_id} capture={capture} active={capture.capture_id === activeId} onClick={() => navigate({ view: 'traces', id: capture.capture_id })} />)}</div>{activeId && <TraceInspector api={api} captureId={activeId} />}</div>}
  </div>;
}

function TraceInspector({ api, captureId }: { api: LocalApi; captureId: string }) {
  const trace = useQuery({ queryKey: ['trace', captureId], queryFn: () => api.trace(captureId) });
  const [verification, setVerification] = useState<Verification | null>(null);
  const verify = useMutation({ mutationFn: () => api.verify(captureId), onSuccess: (result) => {
    setVerification(result); notifications.show({ title: 'Trace verified', message: 'Evidence, disclosure, hashes, and canonical OTLP all match.' });
  }});
  if (trace.isLoading) return <LoadingState />;
  if (!trace.data) return <ErrorState title="Trace package is unavailable" onRetry={() => trace.refetch()} />;
  const manifest = trace.data.manifest as Record<string, unknown>;
  return <article className="trace-inspector"><Group justify="space-between"><div><Text className="eyebrow">Verified trace package</Text><Title order={2}>{captureId}</Title></div><Button leftSection={<ShieldCheck size={15} />} loading={verify.isPending} onClick={() => verify.mutate()}>Verify now</Button></Group>
    <Tabs defaultValue={verification ? 'verification' : 'summary'} keepMounted={false}>
      <Tabs.List><Tabs.Tab value="summary">Summary</Tabs.Tab><Tabs.Tab value="evidence">Evidence</Tabs.Tab><Tabs.Tab value="trace">Trace</Tabs.Tab><Tabs.Tab value="verification">Verification</Tabs.Tab></Tabs.List>
      <Tabs.Panel value="summary"><div className="document-panel"><Title order={3}>Authenticated inference</Title><Text>This portable package binds canonical OpenTelemetry output to the disclosed provider exchange and TLSNotary evidence.</Text><dl className="metadata-grid"><Fact label="Capture" value={captureId} /><Fact label="Format" value={String(manifest.format ?? 'verified trace')} /><Fact label="Normalizer" value={String(manifest.normalizer_version ?? 'v1')} /><Fact label="Files" value="5 authenticated artifacts" /></dl></div></Tabs.Panel>
      <Tabs.Panel value="evidence"><Receipt title="Evidence receipt" fields={[
        ['Trace SHA-256', String(manifest.trace_sha256 ?? '9a32d7c6…')], ['Provider', 'openrouter · openrouter.ai'], ['Disclosure', 'Credential values redacted'], ['TLS evidence', 'Included · independently verifiable']
      ]} /></Tabs.Panel>
      <Tabs.Panel value="trace"><pre className="json-view">{JSON.stringify(trace.data.trace, null, 2)}</pre></Tabs.Panel>
      <Tabs.Panel value="verification">{verification ? <Receipt title="Verification passed" verified fields={[
        ['Capture', verification.capture_id], ['Verified at', formatDate(verification.verified_at_unix_ms)], ['Notary key', verification.notary_key_id], ['Trust source', verification.trust_source]
      ]} /> : <EmptyState icon={ShieldCheck} title="Run an independent check" copy="Verification replays the provider adapter and checks every authenticated artifact." />}</Tabs.Panel>
    </Tabs>
  </article>;
}

function Receipt({ title, fields, verified = false }: { title: string; fields: Array<[string, string]>; verified?: boolean }) {
  return <div className="receipt"><Group justify="space-between"><Text className="eyebrow">{title}</Text>{verified && <StatusLabel state="verified" />}</Group><dl>{fields.map(([label, value]) => <Fact key={label} label={label} value={value} />)}</dl></div>;
}

function PublishingView({ api }: { api: LocalApi }) {
  const queryClient = useQueryClient();
  const auth = useQuery({ queryKey: ['publication-auth'], queryFn: api.publicationAuth, retry: false });
  const traces = useQuery({ queryKey: ['captures', 'publishing'], queryFn: () => api.captures({ finalization_state: 'finalized' }) });
  const [selected, setSelected] = useState<string | null>(null);
  const [confirm, setConfirm] = useState(false);
  const [started, setStarted] = useState<{ request_id: string; verification_uri_complete: string; user_code: string } | null>(null);
  const beginAuth = useMutation({ mutationFn: api.startPublicationAuth, onSuccess: setStarted });
  const pollAuth = useMutation({ mutationFn: () => api.pollPublicationAuth(started!.request_id), onSuccess: () => {
    queryClient.invalidateQueries({ queryKey: ['publication-auth'] }); setStarted(null);
  }});
  const publish = useMutation({ mutationFn: () => api.publish(selected!), onSuccess: (result) => {
    setConfirm(false); notifications.show({ title: 'Publication submitted', message: `Job ${result.job_id} is ${result.state}.` });
  }});
  const eligible = traces.data?.items ?? [];
  const selectedId = selected ?? eligible[0]?.capture_id ?? null;
  return <div className="view-page"><PageHeader eyebrow="Explicit consent" title="Publishing" copy="Local finalization and public publication are separate decisions. Nothing is uploaded until you confirm a selected verified trace." />
    <div className="publishing-grid"><Paper className="publishing-auth"><Group justify="space-between"><Text className="eyebrow">Publication account</Text><KeyRound size={17} /></Group>
      {auth.isLoading ? <Loader size="sm" /> : auth.data?.signed_in ? <><Title order={2}>{auth.data.github_login}</Title><Text>{auth.data.device_name}</Text><StatusLabel state="ready" /></> : <><Title order={2}>Not authorized</Title><Text>Begin the device flow, then approve the recognizable local dashboard session in your browser.</Text><Button variant="outline" loading={beginAuth.isPending} onClick={() => beginAuth.mutate()}>Begin authorization</Button></>}
      {started && <div className="authorization-code"><Text className="eyebrow">Approval code</Text><code>{started.user_code}</code><a href={started.verification_uri_complete} target="_blank" rel="noreferrer">Open approval page</a><Button size="xs" variant="subtle" loading={pollAuth.isPending} onClick={() => pollAuth.mutate()}>I approved it</Button></div>}
    </Paper><Paper className="publication-choice"><Text className="eyebrow">Eligible finalized trace</Text><Title order={2}>Choose what to publish</Title>{eligible.length ? <><Select label="Finalized trace" data={eligible.map((capture) => ({ value: capture.capture_id, label: `${capture.provider} · ${capture.requested_model}` }))} value={selectedId} onChange={setSelected} /><div className="consent-copy"><ShieldCheck size={18} /><Text>The finalized disclosure is verified locally before upload. The encrypted source bundle is never a publication input.</Text></div><Button disabled={!auth.data?.signed_in || !selectedId} onClick={() => setConfirm(true)}>Review publication</Button></> : <EmptyState title="Nothing eligible" copy="Finalize a capture first." />}</Paper></div>
    <Modal opened={confirm} onClose={() => setConfirm(false)} title="Publish this finalized trace?" centered><Stack><Text>This creates a public admission job for <code>{selectedId}</code>. Public trace content may be visible to anyone.</Text><Group justify="flex-end"><Button variant="subtle" onClick={() => setConfirm(false)}>Keep private</Button><Button loading={publish.isPending} onClick={() => publish.mutate()}>Publish trace</Button></Group></Stack></Modal>
  </div>;
}

function ActivityView({ api }: { api: LocalApi }) {
  const events = useQuery({ queryKey: ['events'], queryFn: api.events, refetchInterval: 5_000 });
  const [filter, setFilter] = useState<string | null>(null);
  const visible = events.data?.items.filter((event) => !filter || event.severity === filter) ?? [];
  return <div className="view-page"><PageHeader eyebrow="Redacted history" title="Activity" copy="Bounded service events use safe identifiers and failure codes—never credentials, raw headers, bundle plaintext, or arbitrary paths." action={<Button variant="outline" leftSection={<RefreshCw size={14} />} onClick={() => events.refetch()}>Refresh</Button>} />
    <div className="filter-bar filter-bar--short"><Select aria-label="Activity severity" placeholder="All severities" clearable data={['info', 'success', 'warning', 'error']} value={filter} onChange={setFilter} /></div>
    {events.isLoading ? <LoadingState /> : visible.length ? <EventList events={visible} /> : <EmptyState icon={Activity} title="No activity" copy="New capture and finalization events will appear here." />}</div>;
}

function EventList({ events }: { events: Event[] }) {
  if (!events.length) return <EmptyState icon={Activity} title="No recent activity" copy="The local event history is empty." />;
  return <div className="event-list">{events.map((event) => <div key={event.event_id} className="event-row"><ThemeIcon variant="transparent" className={`event-icon event-icon--${stateTone(event.severity)}`}>{event.severity === 'error' ? <XCircle size={17} /> : event.severity === 'success' ? <Check size={17} /> : <CircleDot size={17} />}</ThemeIcon><div><Group gap="xs"><b>{event.message}</b><StatusLabel state={event.severity} /></Group><Text>{event.capture_id ?? event.operation_id ?? event.event_type}</Text></div><time>{formatDate(event.created_at_unix_ms)}</time></div>)}</div>;
}

function SettingsView({ status }: { status: Status }) {
  const copyOpenApi = async () => { await navigator.clipboard.writeText(`${window.location.origin}/openapi.json`); notifications.show({ title: 'OpenAPI URL copied', message: 'Point a coding agent at this local contract.' }); };
  return <div className="view-page"><PageHeader eyebrow="Safe service information" title="Settings & API" copy="Inspect listener roles, preview policy, and endpoint discovery without exposing secrets or local artifact paths." />
    <SimpleGrid cols={{ base: 1, md: 2 }} spacing="lg"><Paper className="settings-panel"><Text className="eyebrow">Listeners</Text><Title order={2}>Two ports, two roles.</Title><dl className="receipt-list"><Fact label="Provider proxy" value={status.proxy_listener} /><Fact label="Admin & dashboard" value={status.admin_listener} /><Fact label="API version" value="v1" /><Fact label="Service version" value={status.version} /></dl><Text className="safe-note"><ShieldCheck size={15} /> Both listeners are restricted to loopback.</Text></Paper>
      <Paper className="settings-panel"><Text className="eyebrow">Agent discovery</Text><Title order={2}>OpenAPI is the contract.</Title><Text>Fetch the code-generated specification before selecting routes or request bodies.</Text><div className="api-link"><code>{window.location.origin}/openapi.json</code><ActionIcon variant="subtle" onClick={copyOpenApi} aria-label="Copy OpenAPI URL"><Copy size={15} /></ActionIcon></div><Button component="a" href="/openapi.json" target="_blank" variant="outline" leftSection={<CodeXml size={15} />}>Open specification</Button></Paper>
      <Paper className="settings-panel"><Text className="eyebrow">Privacy policy</Text><Title order={2}>Preview storage</Title><Text>Up to {status.preview_chars.toLocaleString()} characters of known text fields are indexed locally. Raw headers are never cataloged.</Text><dl className="receipt-list"><Fact label="Vault" value={status.vault} /><Fact label="Notary discovery" value={status.notary} /></dl></Paper>
      <Paper className="settings-panel inverse"><TerminalSquare size={20} /><Text className="eyebrow">Provider routes</Text><Title order={2}>Keep credentials in the SDK.</Title><code>http://{status.proxy_listener}/openai/v1</code><code>http://{status.proxy_listener}/anthropic</code><code>http://{status.proxy_listener}/deepseek</code><code>http://{status.proxy_listener}/openrouter/api/v1</code></Paper>
    </SimpleGrid>
  </div>;
}
