import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from 'react';
import {
  ActionIcon, AppShell, Badge, Box, Burger, Button, Center, Drawer, Group,
  Loader, Modal, NavLink, Paper, PasswordInput, ScrollArea, Select, SimpleGrid,
  Stack, Table, Tabs, Text, TextInput, ThemeIcon, Title, Tooltip, UnstyledButton,
  useMantineColorScheme
} from '@mantine/core';
import { useDisclosure, useMediaQuery } from '@mantine/hooks';
import { notifications } from '@mantine/notifications';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Activity, Archive, ArrowLeft, Check, CheckCircle2, CodeXml,
  ChevronRight, CircleDot, Clock3, Copy, Database, FileCheck2, FileJson2, Gauge,
  KeyRound, ListChecks, Moon, PanelLeft, Play, RefreshCw, Search,
  Send, Settings, ShieldCheck, Sun, TerminalSquare, Unplug, XCircle
} from 'lucide-react';
import { LocalApiError } from './api';
import type { Capture, CaptureDetail, Event, LocalApi, Operation, Publication, PublicationAuthStarted, Status, Verification } from './api';

const logoDarkUrl = new URL('../../public/logo-dark.png', import.meta.url).href;
const logoLightUrl = new URL('../../public/logo-light.png', import.meta.url).href;

export type DashboardView = 'overview' | 'captures' | 'finalizations' | 'traces' | 'publishing' | 'activity' | 'settings';

type Route = { view: DashboardView; id?: string };

const navigation: Array<{ view: DashboardView; label: string; icon: typeof Gauge }> = [
  { view: 'overview', label: 'Overview', icon: Gauge },
  { view: 'captures', label: 'Captures', icon: Archive },
  { view: 'finalizations', label: 'Finalizations', icon: ListChecks },
  { view: 'traces', label: 'Finalized traces', icon: FileCheck2 },
  { view: 'publishing', label: 'Publishing', icon: Send },
  { view: 'activity', label: 'Activity', icon: Activity },
  { view: 'settings', label: 'Settings', icon: Settings }
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
  if (['finalized', 'verified', 'ready', 'success', 'admitted'].includes(state)) return 'ready';
  if (['failed', 'interrupted', 'error', 'unavailable', 'rejected', 'expired'].includes(state)) return 'danger';
  if (['running', 'capturing', 'queued', 'uploading', 'verifying'].includes(state)) return 'active';
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

function QueryError({ error, title }: { error: unknown; title?: string }) {
  const unauthorized = error instanceof LocalApiError && error.status === 401;
  return <ErrorState title={unauthorized ? 'The dashboard session expired' : title} />;
}

function mutationError(title: string, error: unknown) {
  const code = error instanceof LocalApiError ? error.code : 'request_failed';
  notifications.show({ color: 'red', title, message: `The service returned ${code}. Review Activity for safe details.` });
}

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

type TraceMessagePart = { kind: string; text: string };
type TraceMessage = { role: string; parts: TraceMessagePart[]; finishReason?: string };
type TraceTranscript = { model: string; input: TraceMessage[]; output: TraceMessage[] };

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function readableTraceValue(value: unknown) {
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value, null, 2) ?? String(value);
  } catch {
    return String(value);
  }
}

function traceMessagePart(value: unknown): TraceMessagePart {
  const part = asRecord(value);
  const kind = typeof part.type === 'string' ? part.type : 'structured content';
  if (kind === 'text') {
    return { kind, text: typeof part.content === 'string' ? part.content : readableTraceValue(part.content) };
  }
  if (kind === 'tool_call') {
    const name = typeof part.name === 'string' && part.name ? part.name : 'unnamed tool';
    return { kind: 'tool call', text: `${name}(${readableTraceValue(part.arguments)})` };
  }
  if (kind === 'tool_call_response') {
    return { kind: 'tool result', text: readableTraceValue(part.result) };
  }
  return { kind: kind.replaceAll('_', ' '), text: readableTraceValue(value) };
}

function traceMessages(value?: string): TraceMessage[] {
  if (!value) return [];
  try {
    return asArray(JSON.parse(value)).map((item) => {
      const message = asRecord(item);
      return {
        role: typeof message.role === 'string' ? message.role : 'message',
        parts: asArray(message.parts).map(traceMessagePart),
        ...(typeof message.finish_reason === 'string' ? { finishReason: message.finish_reason } : {})
      };
    });
  } catch {
    return [];
  }
}

function traceTranscripts(value: unknown): TraceTranscript[] {
  const trace = asRecord(value);
  const transcripts: TraceTranscript[] = [];
  for (const resourceValue of asArray(trace.resourceSpans)) {
    const resource = asRecord(resourceValue);
    for (const scopeValue of asArray(resource.scopeSpans)) {
      const scope = asRecord(scopeValue);
      for (const spanValue of asArray(scope.spans)) {
        const span = asRecord(spanValue);
        const attributes = new Map<string, string>();
        for (const attributeValue of asArray(span.attributes)) {
          const attribute = asRecord(attributeValue);
          const key = typeof attribute.key === 'string' ? attribute.key : null;
          const stringValue = asRecord(attribute.value).stringValue;
          if (key && typeof stringValue === 'string') attributes.set(key, stringValue);
        }
        const input = traceMessages(attributes.get('gen_ai.input.messages'));
        const output = traceMessages(attributes.get('gen_ai.output.messages'));
        if (input.length || output.length) {
          transcripts.push({ model: attributes.get('gen_ai.response.model') ?? attributes.get('gen_ai.request.model') ?? 'Model not reported', input, output });
        }
      }
    }
  }
  return transcripts;
}

function withinTime(timestamp: number, range: string | null) {
  if (!range) return true;
  const milliseconds = range === 'hour' ? 60 * 60 * 1000 : range === 'day' ? 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000;
  return timestamp >= Date.now() - milliseconds;
}

function timeRangeStart(range: string | null) {
  if (!range) return undefined;
  const milliseconds = range === 'hour' ? 60 * 60 * 1000 : range === 'day' ? 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000;
  return Date.now() - milliseconds;
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
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const mutation = useMutation({
    mutationFn: () => api.session(username, password),
    onSuccess: () => { setUsername(''); setPassword(''); onAuthenticated(); },
    onError: () => notifications.show({ color: 'red', title: 'Authentication failed', message: 'Check the username and password configured under admin.auth.' })
  });
  const submit = (event: FormEvent) => { event.preventDefault(); if (username && password) mutation.mutate(); };
  return <main className="auth-shell">
    <section className="auth-document">
      <Brand />
      <Text className="eyebrow">Local administration</Text>
      <Title order={1}>Sign in</Title>
      <Text className="auth-copy">This service requires the credentials configured under admin.auth.</Text>
      <form onSubmit={submit}>
        <TextInput label="Username" value={username} onChange={(event) => setUsername(event.currentTarget.value)}
          autoComplete="username" autoFocus />
        <PasswordInput label="Password" value={password} onChange={(event) => setPassword(event.currentTarget.value)}
          autoComplete="current-password" />
        <Button type="submit" loading={mutation.isPending} disabled={!username || !password} rightSection={<ChevronRight size={15} />}>Open dashboard</Button>
      </form>
      <div className="trust-note"><ShieldCheck aria-hidden="true" /><div><b>Loopback only</b><span>This control surface is available only on the local admin listener.</span></div></div>
    </section>
  </main>;
}

function Brand() {
  return <div className="local-brand"><span className="local-mark" aria-hidden="true">
    <img className="local-mark-light" src={logoDarkUrl} alt="" width={30} height={30} />
    <img className="local-mark-dark" src={logoLightUrl} alt="" width={30} height={30} />
  </span><span>LLM Notary</span></div>;
}

function Sidebar({ route, status, onNavigate, fixture, showBrand = true }: {
  route: Route; status: Status; onNavigate: (route: Route) => void; fixture: boolean; showBrand?: boolean;
}) {
  const count = (view: DashboardView) => view === 'captures' ? status.counts.pending
    : view === 'finalizations' ? status.counts.active_operations : undefined;
  return <div className="sidebar-inner">
    <div className="sidebar-primary">
      {showBrand && <Brand />}
      <nav aria-label="Local dashboard">
        {navigation.map(({ view, label, icon: Icon }) => <NavLink key={view} component="button" type="button" aria-label={label} active={route.view === view}
          label={label} leftSection={<Icon size={17} strokeWidth={1.7} />} rightSection={count(view) ? <Badge size="xs">{count(view)}</Badge> : null}
          onClick={() => onNavigate({ view })} />)}
      </nav>
    </div>
    {fixture && <div className="sidebar-foot"><div className="fixture-flag"><Database size={14} aria-hidden="true" />Documentation fixture</div></div>}
  </div>;
}

export function Dashboard({ api, fixture = false }: { api: LocalApi; fixture?: boolean }) {
  const route = useRoute();
  const queryClient = useQueryClient();
  const [navOpened, { open: openNav, close: closeNav }] = useDisclosure(false);
  const statusQuery = useQuery({ queryKey: ['status'], queryFn: api.status, retry: false, refetchInterval: 10_000 });
  const navigate = (next: Route) => { closeNav(); goTo(next); };

  if (statusQuery.isLoading) return <LoadingState label="Connecting to the local service" />;
  if (statusQuery.error && (statusQuery.error as LocalApiError).status === 401) {
    return <AuthGate api={api} onAuthenticated={() => queryClient.invalidateQueries({ queryKey: ['status'] })} />;
  }
  if (statusQuery.error) return <ErrorState onRetry={() => statusQuery.refetch()} />;
  if (!statusQuery.data) return <ErrorState onRetry={() => statusQuery.refetch()} />;
  const status = statusQuery.data;
  return <AppShell
    navbar={{ width: 248, breakpoint: 820, collapsed: { mobile: true } }}
    padding={0} className="dashboard-shell">
    <AppShell.Navbar className="dashboard-navbar"><Sidebar route={route} status={status} onNavigate={navigate} fixture={fixture} /></AppShell.Navbar>
    <Drawer opened={navOpened} onClose={closeNav} title={<Brand />} size="min(88vw, 340px)" classNames={{ body: 'mobile-nav-body' }}>
      <Sidebar route={route} status={status} onNavigate={navigate} fixture={fixture} showBrand={false} />
    </Drawer>
    <AppShell.Main className="dashboard-main">
      <Burger opened={navOpened} onClick={openNav} className="mobile-nav-trigger" size="sm" aria-label="Open navigation" />
      <View route={route} status={status} api={api} navigate={navigate} fixture={fixture} />
    </AppShell.Main>
  </AppShell>;
}

function View({ route, status, api, navigate, fixture }: { route: Route; status: Status; api: LocalApi; navigate: (route: Route) => void; fixture: boolean }) {
  switch (route.view) {
    case 'captures': return <CapturesView api={api} selectedId={route.id} navigate={navigate} />;
    case 'finalizations': return <FinalizationsView api={api} selectedId={route.id} navigate={navigate} fixture={fixture} />;
    case 'traces': return <TracesView api={api} selectedId={route.id} navigate={navigate} />;
    case 'publishing': return <PublishingView api={api} fixture={fixture} navigate={navigate} />;
    case 'activity': return <ActivityView api={api} />;
    case 'settings': return <SettingsView status={status} />;
    default: return <OverviewView api={api} status={status} navigate={navigate} />;
  }
}

function OverviewView({ api, status, navigate }: { api: LocalApi; status: Status; navigate: (route: Route) => void }) {
  const events = useQuery({ queryKey: ['events'], queryFn: () => api.events() });
  const stats = [
    ['Capturing', status.counts.capturing, 'active'], ['Pending', status.counts.pending, 'muted'],
    ['Finalizing', status.counts.active_operations, 'active'], ['Finalized', status.counts.finalized, 'ready'],
    ['Failed', status.counts.failed, 'danger']
  ] as const;
  return <div className="view-page overview-page"><PageHeader eyebrow="Local service" title="Service overview"
    copy="Review captures as they move from private recording to a verified trace." />
    <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }} spacing={0} className="service-grid">
      <ServiceFact icon={CheckCircle2} label="Service" value="Online" detail={`v${status.version}`} tone="ready" />
      <ServiceFact icon={KeyRound} label="Vault" value={status.vault} detail="Key material stays local" />
      <ServiceFact icon={ShieldCheck} label="Notary" value={status.notary === 'directory' ? 'Directory pinned' : 'Configured'} detail="Provider connection delegated" />
      <ServiceFact icon={Activity} label="Work queue" value={status.counts.active_operations ? 'Active' : 'Idle'} detail={`${status.counts.active_operations} operation${status.counts.active_operations === 1 ? '' : 's'}`} />
    </SimpleGrid>
    <section className="overview-work"><div><Text className="eyebrow">Capture states</Text><div className="count-strip">{stats.map(([label, value, tone]) => <UnstyledButton key={label} onClick={() => navigate({ view: label === 'Finalizing' ? 'finalizations' : 'captures' })}>
      <span className={`count-marker count-marker--${tone}`} /><b>{value}</b><span>{label}</span></UnstyledButton>)}</div></div>
      <Paper className="next-action"><Text className="eyebrow">Next action</Text><Title order={2}>{status.counts.pending ? 'Finalize pending evidence' : 'Send a provider request'}</Title>
        <Text>{status.counts.pending ? `${status.counts.pending} capture${status.counts.pending === 1 ? ' is' : 's are'} ready to finalize.` : 'Point an SDK at the local provider proxy to create a private capture.'}</Text>
        <Button onClick={() => navigate({ view: status.counts.pending ? 'captures' : 'settings' })}>{status.counts.pending ? 'Review captures' : 'View proxy routes'}</Button></Paper>
    </section>
    <section className="recent-section"><Group justify="space-between"><div><Text className="eyebrow">Recent activity</Text><Title order={2}>What changed</Title></div><Button variant="subtle" onClick={() => navigate({ view: 'activity' })}>All activity</Button></Group>
      {events.isLoading ? <LoadingState /> : events.error ? <QueryError error={events.error} title="Recent activity is unavailable" /> : <EventList events={events.data?.items.slice(0, 4) ?? []} />}</section>
  </div>;
}

function ServiceFact({ icon: Icon, label, value, detail, tone }: { icon: typeof Gauge; label: string; value: string; detail: string; tone?: string }) {
  return <div className="service-fact"><Group justify="space-between"><Text className="eyebrow">{label}</Text><Icon size={17} aria-hidden="true" /></Group><Title order={3}>{value}</Title><Text>{detail}</Text>{tone && <StatusLabel state={tone} />}</div>;
}

function CapturesView({ api, selectedId, navigate }: { api: LocalApi; selectedId?: string; navigate: (route: Route) => void }) {
  const [query, setQuery] = useState('');
  const [model, setModel] = useState('');
  const [provider, setProvider] = useState<string | null>(null);
  const [captureState, setCaptureState] = useState<string | null>(null);
  const [finalization, setFinalization] = useState<string | null>(null);
  const [streaming, setStreaming] = useState<string | null>(null);
  const [time, setTime] = useState<string | null>(null);
  const mobile = useMediaQuery('(max-width: 820px)');
  const captures = useQuery({
    queryKey: ['captures', query, model, provider, captureState, finalization],
    queryFn: () => api.allCaptures({ query, model, provider: provider ?? undefined, capture_state: captureState ?? undefined, finalization_state: finalization ?? undefined })
  });
  const selectedDetail = useQuery({
    queryKey: ['capture', selectedId], queryFn: () => api.capture(selectedId!), enabled: Boolean(selectedId)
  });
  const visible = useMemo(() => (captures.data?.items ?? []).filter((capture) =>
    (!streaming || capture.streaming === (streaming === 'streaming')) && withinTime(capture.created_at_unix_ms, time)
  ), [captures.data, streaming, time]);
  const activeId = selectedId ?? visible[0]?.capture_id;
  const active = visible.find((capture) => capture.capture_id === activeId) ?? selectedDetail.data?.capture;
  const showDetail = Boolean(mobile && selectedId);
  return <div className="view-page capture-page"><PageHeader eyebrow="Local catalog" title="Captures"
    copy="Search the prompt and output previews stored in the local catalog. Select a pending capture to finalize it." />
    {!showDetail && <div className="filter-bar filter-bar--captures"><TextInput aria-label="Search captures" placeholder="Search prompt and output previews" leftSection={<Search size={15} />} value={query} onChange={(event) => setQuery(event.currentTarget.value)} />
      <TextInput aria-label="Model filter" placeholder="All models" value={model} onChange={(event) => setModel(event.currentTarget.value)} />
      <Select aria-label="Provider filter" placeholder="All providers" clearable data={['openai', 'anthropic', 'deepseek', 'openrouter']} value={provider} onChange={setProvider} />
      <Select aria-label="Capture state filter" placeholder="All capture states" clearable data={['capturing', 'pending', 'failed']} value={captureState} onChange={setCaptureState} />
      <Select aria-label="Finalization filter" placeholder="All finalization states" clearable data={['not_requested', 'queued', 'running', 'finalized', 'failed', 'interrupted']} value={finalization} onChange={setFinalization} />
      <Select aria-label="Streaming filter" placeholder="Streaming or buffered" clearable data={[{ value: 'streaming', label: 'Streaming' }, { value: 'buffered', label: 'Buffered' }]} value={streaming} onChange={setStreaming} />
      <Select aria-label="Capture time filter" placeholder="Any time" clearable data={[{ value: 'hour', label: 'Last hour' }, { value: 'day', label: 'Last 24 hours' }, { value: 'week', label: 'Last 7 days' }]} value={time} onChange={setTime} /></div>}
    {captures.isLoading || (selectedId && selectedDetail.isLoading) ? <LoadingState /> : captures.error ? <QueryError error={captures.error} title="Captures are unavailable" /> : selectedDetail.error ? <QueryError error={selectedDetail.error} title="Capture detail is unavailable" /> : !visible.length && !active ? <EmptyState title="No captures match" copy="Clear a filter or send a new request through the provider proxy." />
      : <div className={`master-detail ${showDetail ? 'show-detail' : ''}`}>
        <ScrollArea className="master-list" type="auto"><ul className="capture-list" aria-label="Captures">{visible.map((capture) => <li key={capture.capture_id}><CaptureRow capture={capture} active={capture.capture_id === activeId} onClick={() => navigate({ view: 'captures', id: capture.capture_id })} /></li>)}</ul></ScrollArea>
        <div className="detail-panel">{active ? <CaptureInspector api={api} capture={active} mobile={Boolean(mobile)} onBack={() => navigate({ view: 'captures' })} navigate={navigate} /> : null}</div>
      </div>}
  </div>;
}

function CaptureRow({ capture, active, onClick }: { capture: Capture; active: boolean; onClick: () => void }) {
  return <UnstyledButton className={`capture-row ${active ? 'is-active' : ''}`} onClick={onClick}>
    <Group justify="space-between" wrap="nowrap"><Text className="row-provider">{capture.provider}</Text><Text className="mono-time">{formatDate(capture.created_at_unix_ms)}</Text></Group>
    <Title order={3}>{capture.requested_model ?? 'Model not reported'}</Title><Text lineClamp={2}>{capture.prompt_preview || 'Preview disabled for this capture.'}</Text>
    <Group justify="space-between"><StatusLabel state={capture.finalization_state === 'not_requested' ? capture.capture_state : capture.finalization_state} /><Text className="row-size">{formatBytes(capture.response_bytes)}</Text></Group>
  </UnstyledButton>;
}

function CaptureInspector({ api, capture, mobile, onBack, navigate }: { api: LocalApi; capture: Capture; mobile: boolean; onBack: () => void; navigate: (route: Route) => void }) {
  const queryClient = useQueryClient();
  const detail = useQuery({ queryKey: ['capture', capture.capture_id], queryFn: () => api.capture(capture.capture_id) });
  const failedOperation = detail.data?.finalizations.find((operation) => operation.capture_id === capture.capture_id
    && ['failed', 'interrupted'].includes(operation.state));
  const finalize = useMutation({
    mutationFn: () => api.startFinalization(capture.capture_id),
    onSuccess: (result) => {
      notifications.show({ title: result.deduplicated ? 'Already in the queue' : 'Finalization queued', message: result.deduplicated ? 'The existing operation remains active.' : 'Proof generation will run in the background.' });
      queryClient.invalidateQueries({ queryKey: ['captures'] });
      queryClient.invalidateQueries({ queryKey: ['operations'] });
      queryClient.invalidateQueries({ queryKey: ['status'] });
      queryClient.invalidateQueries({ queryKey: ['events'] });
      navigate({ view: 'finalizations', id: result.operation.operation_id });
    },
    onError: (error) => mutationError('Could not finalize', error)
  });
  const retry = useMutation({
    mutationFn: () => api.retry(failedOperation!.operation_id),
    onSuccess: (operation) => {
      notifications.show({ title: 'Retry queued', message: 'The existing durable operation will make another attempt.' });
      queryClient.invalidateQueries({ queryKey: ['captures'] });
      queryClient.invalidateQueries({ queryKey: ['operations'] });
      queryClient.invalidateQueries({ queryKey: ['status'] });
      queryClient.invalidateQueries({ queryKey: ['events'] });
      navigate({ view: 'finalizations', id: operation.operation_id });
    },
    onError: (error) => mutationError('Could not retry finalization', error)
  });
  if (detail.isLoading) return <LoadingState />;
  if (detail.error) return <QueryError error={detail.error} title="Capture detail is unavailable" />;
  const value = detail.data;
  if (!value) return <ErrorState title="Capture detail is unavailable" onRetry={() => detail.refetch()} />;
  const canFinalize = capture.capture_state === 'pending' && capture.finalization_state === 'not_requested';
  const canRetry = capture.capture_state === 'pending' && Boolean(failedOperation);
  return <article className="inspector capture-inspector">
    {mobile && <Button variant="subtle" leftSection={<ArrowLeft size={15} />} onClick={onBack}>All captures</Button>}
    <div className="inspector-head"><div><Text className="eyebrow">Capture detail</Text><Title order={2}>{capture.requested_model ?? 'Unreported model'}</Title><Text className="mono-id">{capture.capture_id}</Text></div>
      <Group>{canFinalize && <Button loading={finalize.isPending} leftSection={<Play size={15} />} onClick={() => finalize.mutate()}>Finalize</Button>}
        {canRetry && <Button loading={retry.isPending} leftSection={<RefreshCw size={15} />} onClick={() => retry.mutate()}>Retry finalization</Button>}</Group></div>
    <Lifecycle capture={capture} />
    <InspectorSection title="Safe metadata"><dl className="metadata-grid"><Fact label="Provider" value={capture.provider} /><Fact label="Operation" value={capture.operation} /><Fact label="HTTP status" value={capture.http_status?.toString() ?? 'In progress'} /><Fact label="Streaming" value={capture.streaming ? 'Yes' : 'No'} /><Fact label="Request" value={formatBytes(capture.request_bytes)} /><Fact label="Response" value={formatBytes(capture.response_bytes)} /></dl></InspectorSection>
    <InspectorSection title="Privacy-aware previews"><div className="preview-block"><Text className="eyebrow">Prompt {capture.prompt_preview_truncated && '· truncated'}</Text><Text>{capture.prompt_preview || 'Preview storage is disabled.'}</Text></div><div className="preview-block"><Text className="eyebrow">Output {capture.output_preview_truncated && '· truncated'}</Text><Text>{capture.output_preview || 'No output preview is available yet.'}</Text></div></InspectorSection>
    <InspectorSection title="Retained artifacts"><ArtifactList detail={value} /></InspectorSection>
    <InspectorSection title="Finalization history"><FinalizationHistory operations={value.finalizations} navigate={navigate} /></InspectorSection>
  </article>;
}

function FinalizationHistory({ operations, navigate }: { operations: Operation[]; navigate: (route: Route) => void }) {
  if (!operations.length) return <Text className="empty-copy">No finalization has been requested for this capture.</Text>;
  return <ol className="history-list">{operations.map((operation) => <li key={operation.operation_id}>
    <div><Group gap="xs"><b>Attempted finalization</b><StatusLabel state={operation.state} /></Group>
      <Text>{operation.attempt} proof attempt{operation.attempt === 1 ? '' : 's'} · queued {formatDate(operation.created_at_unix_ms)}</Text></div>
    <Button size="xs" variant="subtle" onClick={() => navigate({ view: 'finalizations', id: operation.operation_id })}>Inspect</Button>
  </li>)}</ol>;
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

function FinalizationsView({ api, selectedId, navigate, fixture }: { api: LocalApi; selectedId?: string; navigate: (route: Route) => void; fixture: boolean }) {
  const operations = useQuery({ queryKey: ['operations'], queryFn: () => api.operations(), refetchInterval: 3_000 });
  const selectedOperation = useQuery({
    queryKey: ['operation', selectedId], queryFn: () => api.operation(selectedId!),
    enabled: Boolean(selectedId), refetchInterval: 3_000
  });
  const active = operations.data?.items.find((item) => item.operation_id === selectedId)
    ?? selectedOperation.data ?? operations.data?.items[0];
  return <div className="view-page"><PageHeader eyebrow="Proof operations" title="Finalizations" copy="See queued, running, failed, and completed proof operations. Retry interrupted work here." />
    {operations.isLoading || (selectedId && selectedOperation.isLoading) ? <LoadingState /> : operations.error ? <QueryError error={operations.error} title="Finalizations are unavailable" /> : selectedOperation.error ? <QueryError error={selectedOperation.error} title="Finalization detail is unavailable" /> : !operations.data?.items.length && !active ? <EmptyState icon={ListChecks} title="No finalizations yet" copy="Queue one from a pending capture." />
      : <div className="operations-layout"><div className="operations-table"><Table.ScrollContainer minWidth={700}><Table highlightOnHover>
        <Table.Thead><Table.Tr><Table.Th>State</Table.Th><Table.Th>Capture</Table.Th><Table.Th>Attempt</Table.Th><Table.Th>Queued</Table.Th><Table.Th /></Table.Tr></Table.Thead>
        <Table.Tbody>{(operations.data?.items ?? []).map((operation) => <Table.Tr key={operation.operation_id} className={active?.operation_id === operation.operation_id ? 'is-selected' : ''}>
          <Table.Td><StatusLabel state={operation.state} /></Table.Td><Table.Td><code>{operation.capture_id}</code></Table.Td><Table.Td>{operation.attempt}</Table.Td><Table.Td>{formatDate(operation.created_at_unix_ms)}</Table.Td><Table.Td><ActionIcon variant="subtle" aria-label={`Inspect ${operation.operation_id}`} onClick={() => navigate({ view: 'finalizations', id: operation.operation_id })}><ChevronRight size={16} /></ActionIcon></Table.Td>
        </Table.Tr>)}</Table.Tbody></Table></Table.ScrollContainer></div>{active && <OperationInspector api={api} operation={active} fixture={fixture} />}</div>}
  </div>;
}

function OperationInspector({ api, operation, fixture }: { api: LocalApi; operation: Operation; fixture: boolean }) {
  const queryClient = useQueryClient();
  const retry = useMutation({ mutationFn: () => api.retry(operation.operation_id), onSuccess: (updated) => {
    notifications.show({ title: 'Retry queued', message: 'The same durable operation will make another attempt.' });
    queryClient.setQueryData(['operation', operation.operation_id], updated);
    queryClient.invalidateQueries({ queryKey: ['operations'] });
    queryClient.invalidateQueries({ queryKey: ['captures'] });
    queryClient.invalidateQueries({ queryKey: ['status'] });
    queryClient.invalidateQueries({ queryKey: ['events'] });
  }, onError: (error) => mutationError('Could not retry finalization', error) });
  const retryable = ['failed', 'interrupted'].includes(operation.state);
  return <Paper className="operation-inspector"><Text className="eyebrow">Selected operation</Text><Group justify="space-between" align="flex-start"><div><Title order={2}>{operation.state === 'running' ? fixture ? 'Simulated proof generation' : 'Generating private proof' : operation.state.replaceAll('_', ' ')}</Title><Text className="mono-id">{operation.operation_id}</Text></div><StatusLabel state={operation.state} /></Group>
    {fixture && <div className="fixture-flow-note operation-fixture-note"><Database size={16} aria-hidden="true" /><Text><b>Simulation only.</b> No proof worker is running. Times are relative to when this preview was opened.</Text></div>}
    <div className="operation-stage"><span className={['queued', 'running', 'finalized'].includes(operation.state) ? 'complete' : ''}>Queued</span><i /><span className={['running', 'finalized'].includes(operation.state) ? 'complete' : ''}>Proof generation</span><i /><span className={operation.state === 'finalized' ? 'complete' : ''}>Verified package</span></div>
    <dl className="receipt-list"><Fact label="Capture" value={operation.capture_id ?? '—'} /><Fact label="Attempt" value={String(operation.attempt)} /><Fact label="Started" value={formatDate(operation.started_at_unix_ms)} /><Fact label="Finished" value={formatDate(operation.completed_at_unix_ms)} />{operation.failure_code && <Fact label="Safe failure code" value={operation.failure_code} />}</dl>
    <div className="attempt-history"><Text className="eyebrow">Attempt history</Text>{operation.attempt_history.length ? <ol className="history-list">{operation.attempt_history.map((attempt) => <li key={attempt.attempt}><div><Group gap="xs"><b>Attempt {attempt.attempt}</b><StatusLabel state={attempt.state} /></Group><Text>{formatDate(attempt.started_at_unix_ms)} → {formatDate(attempt.completed_at_unix_ms)}</Text>{attempt.failure_code && <code>{attempt.failure_code}</code>}</div></li>)}</ol> : <Text className="empty-copy">No proof attempt has started yet.</Text>}</div>
    {operation.state === 'running' && <div className="no-progress-note"><Clock3 size={16} /><Text>Proof generation can take several minutes. The service does not report a meaningful percentage.</Text></div>}
    {retryable && <Button leftSection={<RefreshCw size={15} />} loading={retry.isPending} onClick={() => retry.mutate()}>Retry finalization</Button>}
  </Paper>;
}

function TracesView({ api, selectedId, navigate }: { api: LocalApi; selectedId?: string; navigate: (route: Route) => void }) {
  const [query, setQuery] = useState('');
  const mobile = useMediaQuery('(max-width: 820px)');
  const captures = useQuery({ queryKey: ['captures', 'finalized'], queryFn: () => api.allCaptures({ finalization_state: 'finalized' }) });
  const visible = (captures.data?.items ?? []).filter((capture) => `${capture.capture_id} ${capture.provider} ${capture.requested_model ?? ''} ${capture.prompt_preview} ${capture.output_preview}`.toLowerCase().includes(query.toLowerCase()));
  const activeId = selectedId ?? visible[0]?.capture_id;
  const showDetail = Boolean(mobile && selectedId);
  return <div className="view-page"><PageHeader eyebrow="Finalized packages" title="Finalized traces" copy="Inspect a finalized trace and run local verification against its evidence." />
    {!showDetail && <div className="filter-bar filter-bar--short"><TextInput aria-label="Search finalized traces" placeholder="Search finalized traces" leftSection={<Search size={15} />} value={query} onChange={(event) => setQuery(event.currentTarget.value)} /></div>}
    {captures.isLoading ? <LoadingState /> : captures.error ? <QueryError error={captures.error} title="Finalized traces are unavailable" /> : !visible.length && !selectedId ? <EmptyState icon={FileCheck2} title="No finalized traces" copy="Finalize a pending capture or clear the search." />
      : <div className={`trace-layout ${showDetail ? 'show-detail' : ''}`}>{!showDetail && <ul className="trace-list" aria-label="Finalized traces">{visible.map((capture) => <li key={capture.capture_id}><CaptureRow capture={capture} active={capture.capture_id === activeId} onClick={() => navigate({ view: 'traces', id: capture.capture_id })} /></li>)}</ul>}{activeId && (!mobile || selectedId) && <TraceInspector api={api} captureId={activeId} mobile={Boolean(mobile)} onBack={() => navigate({ view: 'traces' })} />}</div>}
  </div>;
}

function TraceInspector({ api, captureId, mobile, onBack }: { api: LocalApi; captureId: string; mobile: boolean; onBack: () => void }) {
  const trace = useQuery({ queryKey: ['trace', captureId], queryFn: () => api.trace(captureId) });
  const [verification, setVerification] = useState<Verification | null>(null);
  const [activeTab, setActiveTab] = useState<string | null>('summary');
  const currentCapture = useRef(captureId);
  useEffect(() => {
    currentCapture.current = captureId;
    setVerification(null);
    setActiveTab('summary');
  }, [captureId]);
  const verify = useMutation({
    mutationFn: () => api.verify(captureId),
    onSuccess: (result) => {
      if (currentCapture.current !== result.capture_id) return;
      setVerification(result);
      setActiveTab('verification');
      notifications.show({ title: 'Trace verified', message: 'The package passed every local verification check.' });
    },
    onError: (error) => mutationError('Trace verification failed', error)
  });
  if (trace.isLoading) return <LoadingState />;
  if (trace.error) return <QueryError error={trace.error} title="Trace package is unavailable" />;
  if (!trace.data) return <ErrorState title="Trace package is unavailable" onRetry={() => trace.refetch()} />;
  const manifest = asRecord(trace.data.manifest);
  const source = asRecord(manifest.source);
  const provider = asRecord(source.provider);
  const providerName = typeof provider.name === 'string' ? provider.name : null;
  const providerHost = typeof provider.host === 'string' ? provider.host : null;
  const providerLabel = [providerName, providerHost].filter(Boolean).join(' · ') || 'Not reported';
  const traceDigest = typeof manifest.trace_sha256 === 'string' ? manifest.trace_sha256 : 'Not reported';
  const transcripts = traceTranscripts(trace.data.trace);
  return <article className="trace-inspector">{mobile && <Button variant="subtle" leftSection={<ArrowLeft size={15} />} onClick={onBack}>All finalized traces</Button>}<Group justify="space-between"><div><Text className="eyebrow">Verified trace package</Text><Title order={2}>{captureId}</Title></div><Button leftSection={<ShieldCheck size={15} />} loading={verify.isPending} onClick={() => verify.mutate()}>Verify now</Button></Group>
    <Tabs value={activeTab} onChange={setActiveTab} keepMounted={false}>
      <Tabs.List><Tabs.Tab value="summary">Summary</Tabs.Tab><Tabs.Tab value="evidence">Evidence</Tabs.Tab><Tabs.Tab value="trace">Trace</Tabs.Tab><Tabs.Tab value="verification">Verification</Tabs.Tab></Tabs.List>
      <Tabs.Panel value="summary"><div className="document-panel"><Title order={3}>Authenticated inference</Title><Text>The package contains the disclosed provider exchange, its canonical OpenTelemetry trace, and the supporting TLSNotary evidence.</Text><dl className="metadata-grid"><Fact label="Capture" value={captureId} /><Fact label="Format" value={typeof manifest.format === 'string' ? manifest.format : 'Not reported'} /><Fact label="Normalizer" value={typeof manifest.normalizer_version === 'string' ? manifest.normalizer_version : 'Not reported'} /><Fact label="Provider" value={providerLabel} /></dl><TraceTranscriptView transcripts={transcripts} /></div></Tabs.Panel>
      <Tabs.Panel value="evidence"><Receipt title="Evidence receipt" fields={[
        ['Trace SHA-256', traceDigest], ['Provider', providerLabel], ['Source created', typeof source.created_at_unix_ms === 'number' ? formatDate(source.created_at_unix_ms) : 'Not reported'], ['Manifest format', typeof manifest.format === 'string' ? manifest.format : 'Not reported']
      ]} /></Tabs.Panel>
      <Tabs.Panel value="trace"><pre className="json-view">{JSON.stringify(trace.data.trace, null, 2)}</pre></Tabs.Panel>
      <Tabs.Panel value="verification">{verification ? <Receipt title="Verification passed" verified fields={[
        ['Capture', verification.capture_id], ['Verified at', formatDate(verification.verified_at_unix_ms)], ['Notary key', verification.notary_key_id], ['Trust source', verification.trust_source]
      ]} /> : <EmptyState icon={ShieldCheck} title="Run an independent check" copy="Verification replays the provider adapter and checks every authenticated artifact." />}</Tabs.Panel>
    </Tabs>
  </article>;
}

function TraceTranscriptView({ transcripts }: { transcripts: TraceTranscript[] }) {
  const messageCount = transcripts.reduce((count, transcript) => count + transcript.input.length + transcript.output.length, 0);
  return <section className="trace-transcript" aria-label="Disclosed prompt and response">
    <div className="trace-transcript-heading">
      <div>
        <Text className="eyebrow">Disclosed trace contents</Text>
        <Title order={3}>Prompt and response</Title>
      </div>
      <Text>{messageCount} messages</Text>
    </div>
    {!transcripts.length
      ? <Text className="trace-transcript-empty">This trace does not disclose message contents.</Text>
      : transcripts.map((transcript, inferenceIndex) => {
        const messages = [
          ...transcript.input.map((message) => ({ flow: 'Prompt', message })),
          ...transcript.output.map((message) => ({ flow: 'Response', message }))
        ];
        return <section className="trace-inference" key={`${transcript.model}-${inferenceIndex}`}>
          {transcripts.length > 1 && <Text className="trace-inference-label">Inference {inferenceIndex + 1} · {transcript.model}</Text>}
          <div className="trace-message-list">
            {messages.map(({ flow, message }, messageIndex) => <TraceMessageView
              key={`${flow}-${messageIndex}`}
              flow={flow}
              message={message}
            />)}
          </div>
        </section>;
      })}
  </section>;
}

function TraceMessageView({ flow, message }: { flow: string; message: TraceMessage }) {
  return <article className="trace-message">
    <header>
      <span>{flow}</span>
      <b>{message.role}</b>
      {message.finishReason && <em>{message.finishReason}</em>}
    </header>
    <div className="trace-message-body">
      {message.parts.length
        ? message.parts.map((part, index) => part.kind === 'text'
          ? <p key={index}>{part.text}</p>
          : <div className="trace-structured-part" key={index}><span>{part.kind}</span><pre>{part.text}</pre></div>)
        : <p className="trace-transcript-empty">No disclosed content.</p>}
    </div>
  </article>;
}

function Receipt({ title, fields, verified = false }: { title: string; fields: Array<[string, string]>; verified?: boolean }) {
  return <div className="receipt"><Group justify="space-between"><Text className="eyebrow">{title}</Text>{verified && <StatusLabel state="verified" />}</Group><dl>{fields.map(([label, value]) => <Fact key={label} label={label} value={value} />)}</dl></div>;
}

function PublishingView({ api, fixture, navigate }: { api: LocalApi; fixture: boolean; navigate: (route: Route) => void }) {
  const queryClient = useQueryClient();
  const auth = useQuery({ queryKey: ['publication-auth'], queryFn: api.publicationAuth, retry: false });
  const traces = useQuery({ queryKey: ['captures', 'publishing'], queryFn: () => api.allCaptures({ finalization_state: 'finalized' }) });
  const [selected, setSelected] = useState<string | null>(null);
  const [confirm, setConfirm] = useState(false);
  const [submitted, setSubmitted] = useState<Publication | null>(null);
  const [started, setStarted] = useState<{ flow: PublicationAuthStarted; nextPollAt: number } | null>(null);
  const [now, setNow] = useState(Date.now());
  const eligible = traces.data?.items ?? [];
  const selectedId = selected ?? eligible[0]?.capture_id ?? null;
  useEffect(() => {
    setSubmitted(null);
    setConfirm(false);
  }, [selectedId]);
  const publication = useQuery({
    queryKey: ['publication', submitted?.job_id],
    queryFn: () => api.publicationStatus(submitted!.job_id),
    enabled: Boolean(submitted),
    refetchInterval: (query) => {
      const state = query.state.data?.state;
      return state && ['admitted', 'rejected', 'expired', 'failed'].includes(state) ? false : 3_000;
    }
  });
  useEffect(() => {
    if (!started) return;
    const timer = window.setInterval(() => setNow(Date.now()), 250);
    return () => window.clearInterval(timer);
  }, [started]);
  const schedule = (flow: PublicationAuthStarted) => setStarted({ flow, nextPollAt: Date.now() + flow.poll_interval_seconds * 1000 });
  const beginAuth = useMutation({
    mutationFn: api.startPublicationAuth,
    onSuccess: schedule,
    onError: (error) => mutationError('Could not begin authorization', error)
  });
  const pollAuth = useMutation({
    mutationFn: () => api.pollPublicationAuth(started!.flow.request_id),
    onSuccess: (result) => {
      queryClient.setQueryData(['publication-auth'], result);
      if (result.signed_in) setStarted(null);
      else if (started) setStarted({ ...started, nextPollAt: Date.now() + started.flow.poll_interval_seconds * 1000 });
    },
    onError: (error) => mutationError('Could not check authorization', error)
  });
  const publish = useMutation({ mutationFn: () => api.publish(selectedId!), onSuccess: (result) => {
    setConfirm(false); setSubmitted(result); notifications.show({ title: 'Publication submitted', message: `Job ${result.job_id} is ${result.state}.` });
  }, onError: (error) => mutationError('Publication failed', error) });
  const pollReady = Boolean(started && (fixture || now >= started.nextPollAt));
  const publicationState = publication.data?.state ?? submitted?.state;
  let publicationCopy = `The local service reports ${publicationState ?? 'queued'}. Status refreshes while admission is in progress.`;
  if (publicationState === 'admitted') {
    publicationCopy = fixture
      ? 'The fixture completed admission in this browser. It did not upload data.'
      : 'The platform admitted this trace and published its verification record.';
  } else if (publicationState && ['rejected', 'expired', 'failed'].includes(publicationState)) {
    publicationCopy = `The publication ended in ${publicationState}. Review the safe failure code before retrying.`;
  }

  return <div className="view-page"><PageHeader eyebrow="Public upload" title="Publishing" copy="Publishing is separate from finalization. Select and confirm a verified trace before uploading it." />
    <div className="publishing-grid">
      <Paper className="publishing-auth">
        <Group justify="space-between"><Text className="eyebrow">Publication account</Text><KeyRound size={17} /></Group>
        {auth.isLoading
          ? <Loader size="sm" />
          : auth.error
            ? <QueryError error={auth.error} title="Publication authorization is unavailable" />
            : auth.data?.signed_in
              ? <><Title order={2}>{auth.data.github_login}</Title><Text>{auth.data.device_name}</Text><StatusLabel state="ready" /></>
              : <>
                <Title order={2}>Not authorized</Title>
                <Text>{fixture ? 'Use the simulated approval below to test publication.' : 'Begin the device flow, then approve this dashboard session in your browser.'}</Text>
                <Button variant="outline" loading={beginAuth.isPending} onClick={() => beginAuth.mutate()}>Begin authorization</Button>
              </>}
        {started && <div className="authorization-code">
          <Text className="eyebrow">{fixture ? 'Example approval code' : 'Approval code'}</Text>
          <code>{started.flow.user_code}</code>
          {fixture
            ? <div className="fixture-flow-note"><Database size={16} aria-hidden="true" /><Text>This fixture stays in the browser and does not contact GitHub.</Text></div>
            : <a href={started.flow.verification_uri_complete} target="_blank" rel="noreferrer">Open approval page</a>}
          <Text>{pollReady
            ? fixture ? 'You can approve the simulated session now.' : 'You can check for approval now.'
            : `Waiting ${Math.max(1, Math.ceil((started.nextPollAt - now) / 1000))}s before the next check.`}</Text>
          <Button size="xs" variant="subtle" disabled={!pollReady} loading={pollAuth.isPending} onClick={() => pollAuth.mutate()}>{fixture ? 'Approve demo session' : 'Check approval'}</Button>
        </div>}
      </Paper>
      <Paper className="publication-choice">
        <Text className="eyebrow">Eligible finalized trace</Text>
        <Title order={2}>Choose what to publish</Title>
        {traces.error
          ? <QueryError error={traces.error} title="Eligible traces are unavailable" />
          : traces.isLoading
            ? <Loader size="sm" />
            : eligible.length
              ? <>
                <Select label="Finalized trace" data={eligible.map((capture) => ({ value: capture.capture_id, label: `${capture.provider} · ${capture.requested_model}` }))} value={selectedId} onChange={setSelected} />
                <div className="consent-copy"><ShieldCheck size={18} /><Text>The service verifies the disclosure before upload. It never uploads the encrypted source bundle.</Text></div>
                <Button disabled={!auth.data?.signed_in || !selectedId} onClick={() => setConfirm(true)}>Review publication</Button>
                {submitted && <div className="publication-result">
                  <Group justify="space-between"><Text className="eyebrow">Latest submission</Text><StatusLabel state={publicationState ?? 'queued'} /></Group>
                  <Text>Capture <code>{submitted.capture_id}</code></Text>
                  <code>{submitted.job_id}</code>
                  {publication.error ? <QueryError error={publication.error} title="Publication status is unavailable" /> : <Text>{publicationCopy}</Text>}
                  {publication.data?.failure_code && <Text>Safe failure code: <code>{publication.data.failure_code}</code></Text>}
                  <Group>
                    <Button variant="outline" loading={publication.isFetching} onClick={() => publication.refetch()}>Refresh status</Button>
                    {fixture && publicationState === 'admitted'
                      ? <Button variant="outline" onClick={() => navigate({ view: 'traces', id: submitted.capture_id })}>Inspect admitted fixture</Button>
                      : publication.data?.trace_url && <Button component="a" href={publication.data.trace_url} target="_blank" rel="noreferrer" variant="outline">Open public trace</Button>}
                    {!fixture && publication.data?.stamp_url && <Button component="a" href={publication.data.stamp_url} target="_blank" rel="noreferrer" variant="outline">Open admission receipt</Button>}
                  </Group>
                </div>}
              </>
              : <EmptyState title="Nothing eligible" copy="Finalize a capture first." />}
      </Paper>
    </div>
    <Modal opened={confirm} onClose={() => setConfirm(false)} title="Publish this finalized trace?" centered>
      <Stack>
        <Text>This submits <code>{selectedId}</code> for public admission. Its disclosed trace may become visible to anyone.</Text>
        <Group justify="flex-end"><Button variant="subtle" onClick={() => setConfirm(false)}>Keep private</Button><Button loading={publish.isPending} onClick={() => publish.mutate()}>Publish trace</Button></Group>
      </Stack>
    </Modal>
  </div>;
}

function ActivityView({ api }: { api: LocalApi }) {
  const [severity, setSeverity] = useState<string | null>(null);
  const [captureId, setCaptureId] = useState('');
  const [operationId, setOperationId] = useState('');
  const [eventType, setEventType] = useState('');
  const [time, setTime] = useState<string | null>(null);
  const createdAfter = useMemo(() => timeRangeStart(time), [time]);
  const filters = {
    severity: severity ?? undefined,
    capture_id: captureId,
    operation_id: operationId,
    event_type: eventType,
    created_after_unix_ms: createdAfter
  };
  const events = useQuery({
    queryKey: ['events', filters],
    queryFn: () => api.events(filters),
    refetchInterval: 5_000
  });
  const visible = events.data?.items ?? [];
  return <div className="view-page"><PageHeader eyebrow="Service events" title="Activity" copy="Event history contains defined identifiers and failure codes. It excludes credentials, raw headers, bundle contents, and artifact paths." action={<Button variant="outline" leftSection={<RefreshCw size={14} />} onClick={() => events.refetch()}>Refresh</Button>} />
    <div className="filter-bar filter-bar--activity"><Select aria-label="Activity severity" placeholder="All severities" clearable data={['info', 'success', 'warning', 'error']} value={severity} onChange={setSeverity} />
      <TextInput aria-label="Activity capture ID" placeholder="Capture ID" value={captureId} onChange={(event) => setCaptureId(event.currentTarget.value)} />
      <TextInput aria-label="Activity operation ID" placeholder="Operation ID" value={operationId} onChange={(event) => setOperationId(event.currentTarget.value)} />
      <TextInput aria-label="Activity event type" placeholder="Event type" value={eventType} onChange={(event) => setEventType(event.currentTarget.value)} />
      <Select aria-label="Activity time filter" placeholder="Any time" clearable data={[{ value: 'hour', label: 'Last hour' }, { value: 'day', label: 'Last 24 hours' }, { value: 'week', label: 'Last 7 days' }]} value={time} onChange={setTime} /></div>
    {events.isLoading ? <LoadingState /> : events.error ? <QueryError error={events.error} title="Activity is unavailable" /> : visible.length ? <EventList events={visible} /> : <EmptyState icon={Activity} title="No activity" copy="New capture and finalization events will appear here." />}</div>;
}

function EventList({ events }: { events: Event[] }) {
  if (!events.length) return <EmptyState icon={Activity} title="No recent activity" copy="The local event history is empty." />;
  return <div className="event-list">{events.map((event) => <div key={event.event_id} className="event-row"><ThemeIcon variant="transparent" className={`event-icon event-icon--${stateTone(event.severity)}`}>{event.severity === 'error' ? <XCircle size={17} /> : event.severity === 'success' ? <Check size={17} /> : <CircleDot size={17} />}</ThemeIcon><div><Group gap="xs"><b>{event.message}</b><StatusLabel state={event.severity} /></Group><Text>{event.capture_id ?? event.operation_id ?? event.event_type}</Text></div><time>{formatDate(event.created_at_unix_ms)}</time></div>)}</div>;
}

function SettingsView({ status }: { status: Status }) {
  const openApiUrl = `${window.location.origin}/openapi.json`;
  const copyOpenApi = async () => {
    await navigator.clipboard.writeText(openApiUrl);
    notifications.show({
      title: 'OpenAPI URL copied',
      message: 'Use this URL to discover admin routes and request bodies.'
    });
  };

  return <div className="view-page">
    <PageHeader
      eyebrow="Configuration"
      title="Settings"
      copy="View how this service is configured without exposing credentials or artifact paths."
    />
    <Paper className="appearance-setting">
      <Text fw={700}>Theme</Text>
      <SchemeControl />
    </Paper>
    <SimpleGrid cols={{ base: 1, md: 2 }} spacing="lg">
      <Paper className="settings-panel">
        <Text className="eyebrow">Listeners</Text>
        <Title order={2}>Listener addresses</Title>
        <dl className="receipt-list">
          <Fact label="Provider proxy" value={status.proxy_listener} />
          <Fact label="Admin & dashboard" value={status.admin_listener} />
          <Fact label="API version" value="v1" />
          <Fact label="Service version" value={status.version} />
        </dl>
        <Text className="safe-note"><ShieldCheck size={15} /> Both listeners are restricted to loopback.</Text>
      </Paper>
      <Paper className="settings-panel">
        <Text className="eyebrow">Agent discovery</Text>
        <Title order={2}>API specification</Title>
        <Text>Use the generated OpenAPI document to discover routes and request bodies.</Text>
        <div className="api-link">
          <code>{openApiUrl}</code>
          <ActionIcon variant="subtle" onClick={copyOpenApi} aria-label="Copy OpenAPI URL"><Copy size={15} /></ActionIcon>
        </div>
        <Button component="a" href="/openapi.json" target="_blank" variant="outline" leftSection={<CodeXml size={15} />}>Open specification</Button>
      </Paper>
      <Paper className="settings-panel">
        <Text className="eyebrow">Privacy policy</Text>
        <Title order={2}>Preview storage</Title>
        <Text>Up to {status.preview_chars.toLocaleString()} characters of known text fields are indexed locally. Raw headers are never cataloged.</Text>
        <dl className="receipt-list">
          <Fact label="Vault" value={status.vault} />
          <Fact label="Notary discovery" value={status.notary} />
        </dl>
      </Paper>
      <Paper className="settings-panel inverse">
        <TerminalSquare size={20} />
        <Text className="eyebrow">Provider routes</Text>
        <Title order={2}>Proxy base URLs</Title>
        <Text>Keep provider credentials in the SDK and replace its base URL with the matching local route.</Text>
        <code>http://{status.proxy_listener}/openai/v1</code>
        <code>http://{status.proxy_listener}/anthropic</code>
        <code>http://{status.proxy_listener}/deepseek</code>
        <code>http://{status.proxy_listener}/openrouter/api/v1</code>
      </Paper>
    </SimpleGrid>
  </div>;
}
