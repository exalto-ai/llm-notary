import {
  useEffect, useMemo, useRef, useState, type CSSProperties, type FormEvent,
  type KeyboardEvent as ReactKeyboardEvent, type PointerEvent as ReactPointerEvent, type ReactNode
} from 'react';
import {
  ActionIcon, AppShell, Badge, Burger, Button, Center, Drawer, Group,
  Loader, NavLink, Paper, PasswordInput, ScrollArea, SimpleGrid,
  Stack, Tabs, Text, TextInput, ThemeIcon, Title, Tooltip, UnstyledButton,
  useMantineColorScheme
} from '@mantine/core';
import { useDisclosure, useMediaQuery } from '@mantine/hooks';
import { notifications } from '@mantine/notifications';
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Activity, Archive, ArrowLeft, Check, CheckCircle2, CodeXml,
  ChevronRight, CircleDot, Copy, Database, FileCheck2, FileJson2, Gauge,
  KeyRound, ListChecks, Moon, PanelLeft, Play, RefreshCw, Search, Download,
  Send, Settings, ShieldCheck, Sun, TerminalSquare, Unplug, XCircle
} from 'lucide-react';
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle
} from '@/components/ui/alert-dialog';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue
} from '@/components/ui/select';
import { LocalApiError } from './api';
import type { AccountConnectionStarted, Capture, CaptureDetail, Event, LocalApi, Notary, Operation, OperationSummary, Share, ShareVisibility, Status, Verification } from './api';
import { abbreviatedKeyId, formatNotaryBoundary, notaryLifecycle, orderNotaries } from '../notaryLifecycle';
import { ProviderIdentity } from '../ProviderIdentity';

const logoUrl = new URL('../../public/notary-mark.svg', import.meta.url).href;

export type DashboardView = 'overview' | 'captures' | 'finalizations' | 'traces' | 'sharing' | 'activity' | 'settings';

type Route = { view: DashboardView; id?: string };

type AxisSelectOption = string | { value: string; label: ReactNode };

function AxisSelect({
  value,
  onChange,
  data,
  placeholder,
  ariaLabel,
  label,
  clearable = true
}: {
  value: string | null;
  onChange: (value: string | null) => void;
  data: AxisSelectOption[];
  placeholder: string;
  ariaLabel?: string;
  label?: string;
  clearable?: boolean;
}) {
  const allValue = '__axis_all__';
  const options = data.map((option) => typeof option === 'string' ? { value: option, label: option } : option);
  return <div className="axis-select-field">
    {label && <span className="axis-select-label">{label}</span>}
    <Select value={value ?? (clearable ? allValue : undefined)} onValueChange={(next) => onChange(next === allValue ? null : next)}>
      <SelectTrigger className="axis-select-trigger" aria-label={ariaLabel ?? label}>
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent className="axis-select-content" position="popper" align="start">
        {clearable && <SelectItem value={allValue}>{placeholder}</SelectItem>}
        {options.map((option) => <SelectItem key={option.value} value={option.value}>{option.label}</SelectItem>)}
      </SelectContent>
    </Select>
  </div>;
}

const navigation: Array<{ view: DashboardView; label: string; icon: typeof Gauge }> = [
  { view: 'overview', label: 'Overview', icon: Gauge },
  { view: 'captures', label: 'Captures', icon: Archive },
  { view: 'finalizations', label: 'Finalizations', icon: ListChecks },
  { view: 'traces', label: 'Finalized traces', icon: FileCheck2 },
  { view: 'sharing', label: 'Share', icon: Send },
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

function finalizationPhaseLabel(phase: string) {
  switch (phase) {
    case 'queued': return 'Waiting for proof worker';
    case 'preparing': return 'Preparing proof inputs';
    case 'proving': return 'Generating private proof';
    case 'signing': return 'Requesting notary signature';
    case 'packaging': return 'Building verified package';
    case 'complete': return 'Verified package complete';
    default: return phase.replaceAll('_', ' ');
  }
}

function proofPercent(operation: Operation | OperationSummary) {
  const proof = operation.progress.proof;
  if (!proof?.bytes_total) return null;
  return Math.min(100, Math.floor((proof.bytes_completed / proof.bytes_total) * 100));
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

function timeRangeStart(range: string | null) {
  if (!range) return undefined;
  const milliseconds = range === 'hour' ? 60 * 60 * 1000 : range === 'day' ? 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000;
  return Date.now() - milliseconds;
}

function LoadingState({ label = 'Loading local evidence' }: { label?: string }) {
  return <Center className="loading-state"><Stack align="center" gap="sm"><Loader size="sm" /><Text>{label}</Text></Stack></Center>;
}

const splitStorageKey = 'llm-notary-dashboard-split-width';
const splitDefault = 320;
const splitMinimum = 272;
const splitMaximum = 460;
const splitDetailMinimum = 360;

function storedSplitWidth() {
  const stored = Number(window.localStorage.getItem(splitStorageKey));
  return Number.isFinite(stored) && stored >= splitMinimum && stored <= splitMaximum ? stored : splitDefault;
}

function ResizableSplit({ className, children }: { className: string; children: [ReactNode, ReactNode] }) {
  const container = useRef<HTMLDivElement>(null);
  const [leftWidth, setLeftWidth] = useState(storedSplitWidth);
  const clampWidth = (width: number) => {
    const available = container.current?.getBoundingClientRect().width ?? splitMaximum + splitDetailMinimum;
    return Math.round(Math.max(splitMinimum, Math.min(splitMaximum, available - splitDetailMinimum, width)));
  };
  const updateWidth = (width: number, persist = false) => {
    const next = clampWidth(width);
    setLeftWidth(next);
    if (persist) window.localStorage.setItem(splitStorageKey, String(next));
  };
  const resizeFromPointer = (event: ReactPointerEvent<HTMLDivElement>) => {
    const bounds = container.current?.getBoundingClientRect();
    if (bounds) updateWidth(event.clientX - bounds.left);
  };
  const stopResize = (event: ReactPointerEvent<HTMLDivElement>) => {
    const bounds = container.current?.getBoundingClientRect();
    if (bounds) updateWidth(event.clientX - bounds.left, true);
    if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId);
    document.documentElement.classList.remove('is-resizing-split');
  };
  const onKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    const next = event.key === 'ArrowLeft' ? leftWidth - 16
      : event.key === 'ArrowRight' ? leftWidth + 16
        : event.key === 'Home' ? splitMinimum
          : event.key === 'End' ? splitMaximum : null;
    if (next === null) return;
    event.preventDefault();
    updateWidth(next, true);
  };
  return <div ref={container} className={`resizable-split ${className}`} style={{ '--split-left': `${leftWidth}px` } as CSSProperties}>
    {children[0]}
    <div className="split-handle" role="separator" aria-label="Resize list and detail panels" aria-orientation="vertical"
      aria-valuemin={splitMinimum} aria-valuemax={splitMaximum} aria-valuenow={leftWidth} tabIndex={0}
      onKeyDown={onKeyDown}
      onPointerDown={(event) => {
        event.currentTarget.setPointerCapture(event.pointerId);
        document.documentElement.classList.add('is-resizing-split');
        resizeFromPointer(event);
      }}
      onPointerMove={(event) => {
        if (event.currentTarget.hasPointerCapture(event.pointerId)) resizeFromPointer(event);
      }}
      onPointerUp={stopResize}
      onPointerCancel={stopResize} />
    {children[1]}
  </div>;
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
    <img src={logoUrl} alt="" width={30} height={30} />
  </span><span>LLM Notary</span></div>;
}

function Sidebar({ route, status, onNavigate }: {
  route: Route; status: Status; onNavigate: (route: Route) => void;
}) {
  const count = (view: DashboardView) => view === 'captures' ? status.counts.ready_to_finalize
    : view === 'finalizations' ? status.counts.active_operations : undefined;
  return <div className="sidebar-inner">
    <div className="sidebar-primary">
      <nav aria-label="Local dashboard">
        {navigation.map(({ view, label, icon: Icon }) => <NavLink key={view} component="button" type="button" aria-label={label} active={route.view === view}
          label={label} leftSection={<Icon size={17} strokeWidth={1.7} />} rightSection={count(view) ? <Badge size="xs">{count(view)}</Badge> : null}
          onClick={() => onNavigate({ view })} />)}
      </nav>
    </div>
  </div>;
}

function TopNav({ route, status, onNavigate, opened, onOpenNavigation, fixture }: {
  route: Route; status: Status; onNavigate: (route: Route) => void; opened: boolean; onOpenNavigation: () => void; fixture: boolean;
}) {
  const count = (view: DashboardView) => view === 'captures' ? status.counts.ready_to_finalize
    : view === 'finalizations' ? status.counts.active_operations : undefined;
  return <header className="local-topbar"><nav aria-label="Local dashboard">
    {navigation.map(({ view, label, icon: Icon }) => <UnstyledButton key={view} className={route.view === view ? 'is-active' : ''}
      onClick={() => onNavigate({ view })}><Icon size={15} aria-hidden="true" /><span>{label}</span>{count(view) ? <b>{count(view)}</b> : null}</UnstyledButton>)}
  </nav><div className="local-topbar-status">{fixture && <span className="sample-data-label" title="This preview uses synthetic sample data">Sample data</span>}<Burger opened={opened} onClick={onOpenNavigation} size="sm" aria-label="Open navigation" /></div></header>;
}

export function Dashboard({ api, fixture = false, embedded = false }: { api: LocalApi; fixture?: boolean; embedded?: boolean }) {
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
  if (embedded) {
    return <main className="dashboard-shell dashboard-shell--embedded dashboard-main">
      <View route={route} status={status} api={api} navigate={navigate} fixture={fixture} />
    </main>;
  }
  return <AppShell header={{ height: 50 }} padding={0} className="dashboard-shell">
    <AppShell.Header className="dashboard-header"><TopNav route={route} status={status} onNavigate={navigate} opened={navOpened} onOpenNavigation={openNav} fixture={fixture} /></AppShell.Header>
    <Drawer opened={navOpened} onClose={closeNav} title="Navigation" size="min(88vw, 340px)" classNames={{ body: 'mobile-nav-body' }}>
      <Sidebar route={route} status={status} onNavigate={navigate} />
    </Drawer>
    <AppShell.Main className="dashboard-main">
      <View route={route} status={status} api={api} navigate={navigate} fixture={fixture} />
    </AppShell.Main>
  </AppShell>;
}

function View({ route, status, api, navigate, fixture }: { route: Route; status: Status; api: LocalApi; navigate: (route: Route) => void; fixture: boolean }) {
  switch (route.view) {
    case 'captures': return <CapturesView api={api} selectedId={route.id} navigate={navigate} />;
    case 'finalizations': return <FinalizationsView api={api} selectedId={route.id} navigate={navigate} fixture={fixture} />;
    case 'traces': return <TracesView api={api} selectedId={route.id} navigate={navigate} />;
    case 'sharing': return <SharingView api={api} fixture={fixture} navigate={navigate} />;
    case 'activity': return <ActivityView api={api} />;
    case 'settings': return <SettingsView status={status} api={api} />;
    default: return <OverviewView api={api} status={status} navigate={navigate} />;
  }
}

function OverviewView({ api, status, navigate }: { api: LocalApi; status: Status; navigate: (route: Route) => void }) {
  const events = useQuery({ queryKey: ['events'], queryFn: () => api.events() });
  const stats = [
    ['Capturing', status.counts.capturing, 'active'], ['Ready to finalize', status.counts.ready_to_finalize, 'muted'],
    ['Finalizing', status.counts.active_operations, 'active'], ['Finalized', status.counts.finalized, 'ready'],
    ['Failed', status.counts.failed, 'danger']
  ] as const;
  return <div className="view-page overview-page"><SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }} spacing={0} className="service-grid">
      <ServiceFact icon={CheckCircle2} label="Service" value="Online" detail={`v${status.version}`} tone="ready" />
      <ServiceFact icon={KeyRound} label="Vault" value={status.vault} detail="Key material stays local" />
      <ServiceFact icon={ShieldCheck} label="Notary" value={status.notary === 'directory' ? 'Directory pinned' : 'Configured'} detail="Provider connection delegated" />
      <ServiceFact icon={Activity} label="Work queue" value={status.counts.active_operations ? 'Active' : 'Idle'} detail={`${status.counts.active_operations} operation${status.counts.active_operations === 1 ? '' : 's'}`} />
    </SimpleGrid>
    <section className="overview-work"><div><Text className="eyebrow">Capture states</Text><div className="count-strip">{stats.map(([label, value, tone]) => <UnstyledButton key={label} onClick={() => navigate({ view: label === 'Finalizing' ? 'finalizations' : 'captures' })}>
      <span className={`count-marker count-marker--${tone}`} /><b>{value}</b><span>{label}</span></UnstyledButton>)}</div></div>
      <Paper className="next-action"><Text className="eyebrow">Next action</Text><Title order={2}>{status.counts.ready_to_finalize ? 'Finalize captured evidence' : 'Send a provider request'}</Title>
        <Text>{status.counts.ready_to_finalize ? `${status.counts.ready_to_finalize} capture${status.counts.ready_to_finalize === 1 ? ' is' : 's are'} ready to finalize.` : 'Point an SDK at the local provider proxy to create a private capture.'}</Text>
        <Button onClick={() => navigate({ view: status.counts.ready_to_finalize ? 'captures' : 'settings' })}>{status.counts.ready_to_finalize ? 'Review captures' : 'View proxy routes'}</Button></Paper>
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
  const createdAfter = useMemo(() => timeRangeStart(time), [time]);
  const captures = useInfiniteQuery({
    queryKey: ['captures', query, model, provider, captureState, finalization, streaming, createdAfter],
    queryFn: ({ pageParam }) => api.captures({
      query, model, provider: provider ?? undefined, capture_state: captureState ?? undefined,
      finalization_state: finalization ?? undefined,
      streaming: streaming ? streaming === 'streaming' : undefined,
      created_after_unix_ms: createdAfter, limit: 50, cursor: pageParam
    }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (page) => page.next_cursor ?? undefined
  });
  const selectedDetail = useQuery({
    queryKey: ['capture', selectedId], queryFn: () => api.capture(selectedId!), enabled: Boolean(selectedId)
  });
  const visible = useMemo(() => captures.data?.pages.flatMap((page) => page.items) ?? [], [captures.data]);
  const activeId = selectedId ?? visible[0]?.capture_id;
  const active = visible.find((capture) => capture.capture_id === activeId) ?? selectedDetail.data?.capture;
  const showDetail = Boolean(mobile && selectedId);
  return <div className="view-page capture-page">{!showDetail && <div className="filter-bar filter-bar--captures"><TextInput aria-label="Search captures" placeholder="Search prompt and output previews" leftSection={<Search size={15} />} value={query} onChange={(event) => setQuery(event.currentTarget.value)} />
      <TextInput aria-label="Model filter" placeholder="All models" value={model} onChange={(event) => setModel(event.currentTarget.value)} />
      <AxisSelect ariaLabel="Provider filter" placeholder="All providers" data={['openai', 'anthropic', 'deepseek', 'openrouter'].map((value) => ({ value, label: <ProviderIdentity provider={value} /> }))} value={provider} onChange={setProvider} />
      <AxisSelect ariaLabel="Capture state filter" placeholder="All capture states" data={['capturing', 'captured', 'failed']} value={captureState} onChange={setCaptureState} />
      <AxisSelect ariaLabel="Finalization filter" placeholder="All finalization states" data={['not_requested', 'queued', 'running', 'finalized', 'failed', 'interrupted']} value={finalization} onChange={setFinalization} />
      <AxisSelect ariaLabel="Streaming filter" placeholder="Streaming or buffered" data={[{ value: 'streaming', label: 'Streaming' }, { value: 'buffered', label: 'Buffered' }]} value={streaming} onChange={setStreaming} />
      <AxisSelect ariaLabel="Capture time filter" placeholder="Any time" data={[{ value: 'hour', label: 'Last hour' }, { value: 'day', label: 'Last 24 hours' }, { value: 'week', label: 'Last 7 days' }]} value={time} onChange={setTime} /></div>}
    {captures.isLoading || (selectedId && selectedDetail.isLoading) ? <LoadingState /> : captures.error ? <QueryError error={captures.error} title="Captures are unavailable" /> : selectedDetail.error ? <QueryError error={selectedDetail.error} title="Capture detail is unavailable" /> : !visible.length && !active ? <EmptyState title="No captures match" copy="Clear a filter or send a new request through the provider proxy." />
      : <ResizableSplit className={`master-detail ${showDetail ? 'show-detail' : ''}`}>
        <ScrollArea className="master-list" type="auto"><ul className="capture-list" aria-label="Captures">{visible.map((capture) => <li key={capture.capture_id}><CaptureRow capture={capture} active={capture.capture_id === activeId} onClick={() => navigate({ view: 'captures', id: capture.capture_id })} /></li>)}</ul>{captures.hasNextPage && <Button className="load-more" variant="subtle" loading={captures.isFetchingNextPage} onClick={() => captures.fetchNextPage()}>Load more captures</Button>}</ScrollArea>
        <div className="detail-panel">{active ? <CaptureInspector api={api} capture={active} mobile={Boolean(mobile)} onBack={() => navigate({ view: 'captures' })} navigate={navigate} /> : null}</div>
      </ResizableSplit>}
  </div>;
}

function CaptureRow({ capture, active, onClick }: { capture: Capture; active: boolean; onClick: () => void }) {
  return <UnstyledButton className={`capture-row ${active ? 'is-active' : ''}`} onClick={onClick}>
    <span className="capture-row-state"><StatusLabel state={capture.finalization_state === 'not_requested' ? capture.capture_state : capture.finalization_state} /></span>
    <span className="capture-row-copy"><b>{capture.requested_model ?? 'Model not reported'}</b><small><ProviderIdentity provider={capture.provider} detail={capture.operation} /></small></span>
    <time className="mono-time">{formatDate(capture.created_at_unix_ms)}</time>
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
  const incompatibleProviderResponse = capture.capture_state === 'captured'
    && capture.finalization_ineligibility_code === 'unsupported_provider_http_status';
  const canFinalize = capture.capture_state === 'captured' && capture.finalization_state === 'not_requested'
    && capture.finalization_eligible;
  const canRetry = capture.capture_state === 'captured' && capture.finalization_eligible
    && Boolean(failedOperation?.retryable);
  return <article className="inspector capture-inspector">
    {mobile && <Button variant="subtle" leftSection={<ArrowLeft size={15} />} onClick={onBack}>All captures</Button>}
    <div className="inspector-head"><div><Text className="eyebrow">Capture detail</Text><Title order={2}>{capture.requested_model ?? 'Unreported model'}</Title><Text className="mono-id">{capture.capture_id}</Text></div>
      <Group>{canFinalize && <Button loading={finalize.isPending} leftSection={<Play size={15} />} onClick={() => finalize.mutate()}>Finalize</Button>}
        {canRetry && <Button loading={retry.isPending} leftSection={<RefreshCw size={15} />} onClick={() => retry.mutate()}>Retry finalization</Button>}</Group></div>
    <Lifecycle capture={capture} />
    {incompatibleProviderResponse && <div className="finalization-ineligible-note" role="status"><XCircle size={18} aria-hidden="true" /><div><b>Provider response cannot be finalized</b><Text>The provider returned HTTP {capture.http_status}. Finalization currently supports successful provider responses only.</Text><code>{capture.finalization_ineligibility_code}</code></div></div>}
    <InspectorSection title="Safe metadata"><dl className="metadata-grid"><Fact label="Provider" value={<ProviderIdentity provider={capture.provider} />} /><Fact label="Operation" value={capture.operation} /><Fact label="HTTP status" value={capture.http_status?.toString() ?? 'In progress'} /><Fact label="Streaming" value={capture.streaming ? 'Yes' : 'No'} /><Fact label="Request" value={formatBytes(capture.request_bytes)} /><Fact label="Response" value={formatBytes(capture.response_bytes)} /></dl></InspectorSection>
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
    { label: 'Bundle encrypted', state: capture.capture_state === 'captured' ? 'ready' : capture.capture_state === 'failed' ? 'danger' : 'muted' },
    { label: 'Finalized', state: capture.finalization_state === 'finalized' ? 'ready' : ['running', 'queued'].includes(capture.finalization_state) ? 'active' : capture.finalization_state === 'failed' ? 'danger' : 'muted' }
  ];
  return <ol className="lifecycle" aria-label="Capture lifecycle">{steps.map((step) => <li key={step.label} className={`lifecycle--${step.state}`}><span aria-hidden="true" /><b>{step.label}</b></li>)}</ol>;
}

function InspectorSection({ title, children }: { title: string; children: ReactNode }) {
  return <section className="inspector-section"><Title order={3}>{title}</Title>{children}</section>;
}

function Fact({ label, value }: { label: string; value: ReactNode }) { return <div><dt>{label}</dt><dd>{value}</dd></div>; }

function ArtifactList({ detail }: { detail: CaptureDetail }) {
  return <div className="artifact-list">{detail.artifacts.map((artifact) => <div key={artifact.kind}><FileJson2 size={17} aria-hidden="true" /><div><b>{artifact.kind.replaceAll('_', ' ')}</b><span>{formatBytes(artifact.size_bytes)}</span></div><code>{artifact.sha256.slice(0, 12)}…</code></div>)}</div>;
}

function FinalizationsView({ api, selectedId, navigate, fixture }: { api: LocalApi; selectedId?: string; navigate: (route: Route) => void; fixture: boolean }) {
  const operations = useInfiniteQuery({
    queryKey: ['operations'],
    queryFn: ({ pageParam }) => api.operations({ limit: 50, cursor: pageParam }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (page) => page.next_cursor ?? undefined,
    refetchInterval: 3_000
  });
  const activeId = selectedId ?? operations.data?.pages[0]?.items[0]?.operation_id;
  const selectedOperation = useQuery({
    queryKey: ['operation', activeId], queryFn: () => api.operation(activeId!),
    enabled: Boolean(activeId),
    refetchInterval: (query) => ['queued', 'running'].includes(query.state.data?.state ?? '') ? 1_000 : false
  });
  const items = operations.data?.pages.flatMap((page) => page.items) ?? [];
  const active = selectedOperation.data;
  return <div className="view-page">{operations.isLoading || (activeId && selectedOperation.isLoading) ? <LoadingState /> : operations.error ? <QueryError error={operations.error} title="Finalizations are unavailable" /> : selectedOperation.error ? <QueryError error={selectedOperation.error} title="Finalization detail is unavailable" /> : !items.length && !active ? <EmptyState icon={ListChecks} title="No finalizations yet" copy="Queue one from a captured provider response." />
      : <ResizableSplit className="operations-layout">
        <ScrollArea className="operations-list-scroll" type="auto"><ul className="operations-list" aria-label="Finalizations">{items.map((operation) => <li key={operation.operation_id}><OperationRow operation={operation} active={active?.operation_id === operation.operation_id} onClick={() => navigate({ view: 'finalizations', id: operation.operation_id })} /></li>)}</ul>{operations.hasNextPage && <Button className="load-more" variant="subtle" loading={operations.isFetchingNextPage} onClick={() => operations.fetchNextPage()}>Load more finalizations</Button>}</ScrollArea>
        {active ? <OperationInspector api={api} operation={active} fixture={fixture} /> : <div />}
      </ResizableSplit>}
  </div>;
}

function OperationRow({ operation, active, onClick }: { operation: OperationSummary; active: boolean; onClick: () => void }) {
  const percent = proofPercent(operation);
  return <UnstyledButton className={`operation-row ${active ? 'is-active' : ''}`} onClick={onClick} aria-label={`Inspect ${operation.operation_id}`}>
    <span className="operation-row-top"><StatusLabel state={operation.state} /><time>{formatDate(operation.created_at_unix_ms)}</time></span>
    <code>{operation.capture_id ?? 'Capture not reported'}</code>
    <small>{percent === null ? finalizationPhaseLabel(operation.progress.phase) : `${percent}% transcript authenticated`} · Attempt {operation.attempt}</small>
  </UnstyledButton>;
}

function ProofProgress({ operation }: { operation: Operation }) {
  const proof = operation.progress.proof;
  if (!proof?.bytes_total) {
    if (!['queued', 'running'].includes(operation.state)) return null;
    return <div className="proof-phase-status" role="status"><i className="proof-phase-marker" aria-hidden="true" /><div>
      <b>{finalizationPhaseLabel(operation.progress.phase)}</b>
      <span>Proof-work totals will appear when transcript authentication starts.</span>
    </div></div>;
  }
  const percent = proofPercent(operation) ?? 0;
  return <section className="proof-work" aria-label="Private proof progress">
    <header><div><Text className="eyebrow">Authenticated transcript</Text>
      <b>{formatBytes(proof.bytes_completed)} <span>/ {formatBytes(proof.bytes_total)}</span></b></div>
      <strong>{percent}%</strong></header>
    <div className="proof-work-track" role="progressbar" aria-label="Private transcript bytes authenticated"
      aria-valuemin={0} aria-valuemax={proof.bytes_total} aria-valuenow={proof.bytes_completed}
      aria-valuetext={`${formatBytes(proof.bytes_completed)} of ${formatBytes(proof.bytes_total)}`}>
      <i style={{ width: `${percent}%` }} />
    </div>
    <footer><span>{proof.commitments_completed} / {proof.commitments_total} commitments sealed</span>
      <span>{finalizationPhaseLabel(operation.progress.phase)}</span></footer>
  </section>;
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
  const retryable = operation.retryable;
  return <Paper className="operation-inspector"><Text className="eyebrow">Selected operation</Text><Group justify="space-between" align="flex-start"><div><Title order={2}>{operation.state === 'running' ? fixture ? 'Simulated proof generation' : finalizationPhaseLabel(operation.progress.phase) : operation.state.replaceAll('_', ' ')}</Title><Text className="mono-id">{operation.operation_id}</Text></div><StatusLabel state={operation.state} /></Group>
    {fixture && <div className="fixture-flow-note operation-fixture-note"><Database size={16} aria-hidden="true" /><Text><b>Simulation only.</b> No proof worker is running. Times are relative to when this preview was opened.</Text></div>}
    <ProofProgress operation={operation} />
    <dl className="receipt-list"><Fact label="Capture" value={operation.capture_id ?? '—'} /><Fact label="Attempt" value={String(operation.attempt)} /><Fact label="Started" value={formatDate(operation.started_at_unix_ms)} /><Fact label="Finished" value={formatDate(operation.completed_at_unix_ms)} />{operation.failure_code && <Fact label="Safe failure code" value={operation.failure_code} />}</dl>
    <div className="attempt-history"><Text className="eyebrow">Attempt history</Text>{operation.attempt_history.length ? <ol className="history-list">{operation.attempt_history.map((attempt) => <li key={attempt.attempt}><div><Group gap="xs"><b>Attempt {attempt.attempt}</b><StatusLabel state={attempt.state} /></Group><Text>{formatDate(attempt.started_at_unix_ms)} → {formatDate(attempt.completed_at_unix_ms)}</Text>{attempt.failure_code && <code>{attempt.failure_code}</code>}</div></li>)}</ol> : <Text className="empty-copy">No proof attempt has started yet.</Text>}</div>
    {retryable && <Button leftSection={<RefreshCw size={15} />} loading={retry.isPending} onClick={() => retry.mutate()}>Retry finalization</Button>}
  </Paper>;
}

function TracesView({ api, selectedId, navigate }: { api: LocalApi; selectedId?: string; navigate: (route: Route) => void }) {
  const [query, setQuery] = useState('');
  const mobile = useMediaQuery('(max-width: 820px)');
  const captures = useInfiniteQuery({
    queryKey: ['captures', 'finalized', query],
    queryFn: ({ pageParam }) => api.captures({ finalization_state: 'finalized', query, limit: 50, cursor: pageParam }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (page) => page.next_cursor ?? undefined
  });
  const visible = captures.data?.pages.flatMap((page) => page.items) ?? [];
  const activeId = selectedId ?? visible[0]?.capture_id;
  const showDetail = Boolean(mobile && selectedId);
  return <div className="view-page">{!showDetail && <div className="filter-bar filter-bar--short"><TextInput aria-label="Search finalized traces" placeholder="Search finalized traces" leftSection={<Search size={15} />} value={query} onChange={(event) => setQuery(event.currentTarget.value)} /></div>}
    {captures.isLoading ? <LoadingState /> : captures.error ? <QueryError error={captures.error} title="Finalized traces are unavailable" /> : !visible.length && !selectedId ? <EmptyState icon={FileCheck2} title="No finalized traces" copy="Finalize a captured provider response or clear the search." />
      : <ResizableSplit className={`trace-layout ${showDetail ? 'show-detail' : ''}`}>
        {!showDetail ? <div><ul className="trace-list" aria-label="Finalized traces">{visible.map((capture) => <li key={capture.capture_id}><CaptureRow capture={capture} active={capture.capture_id === activeId} onClick={() => navigate({ view: 'traces', id: capture.capture_id })} /></li>)}</ul>{captures.hasNextPage && <Button className="load-more" variant="subtle" loading={captures.isFetchingNextPage} onClick={() => captures.fetchNextPage()}>Load more traces</Button>}</div> : <div />}
        {activeId && (!mobile || selectedId) ? <TraceInspector api={api} captureId={activeId} mobile={Boolean(mobile)} onBack={() => navigate({ view: 'traces' })} /> : <div />}
      </ResizableSplit>}
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
  const download = useMutation({
    mutationFn: () => api.downloadPackage(captureId),
    onSuccess: (packageBytes) => {
      const url = URL.createObjectURL(packageBytes);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${captureId}.llmtrace`;
      link.click();
      URL.revokeObjectURL(url);
      notifications.show({ title: 'Verified package downloaded', message: 'Keep the .llmtrace file to verify or share privately.' });
    },
    onError: (error) => mutationError('Could not download verified package', error)
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
  return <article className="trace-inspector">{mobile && <Button variant="subtle" leftSection={<ArrowLeft size={15} />} onClick={onBack}>All finalized traces</Button>}<Group justify="space-between" align="flex-start"><div><Text className="eyebrow">Verified trace package</Text><Title order={2}>{captureId}</Title></div><Group><Button leftSection={<Download size={15} />} loading={download.isPending} onClick={() => download.mutate()}>Download verified package</Button><Button variant="outline" leftSection={<ShieldCheck size={15} />} loading={verify.isPending} onClick={() => verify.mutate()}>Verify locally</Button></Group></Group>
    <Tabs value={activeTab} onChange={setActiveTab} keepMounted={false}>
      <Tabs.List><Tabs.Tab value="summary">Summary</Tabs.Tab><Tabs.Tab value="evidence">Evidence</Tabs.Tab><Tabs.Tab value="trace">Trace</Tabs.Tab><Tabs.Tab value="verification">Verification</Tabs.Tab></Tabs.List>
      <Tabs.Panel value="summary"><div className="document-panel"><Title order={3}>Authenticated inference</Title><Text>The package contains the disclosed provider exchange, its canonical OpenTelemetry trace, and the supporting TLSNotary evidence.</Text><dl className="metadata-grid"><Fact label="Capture" value={captureId} /><Fact label="Format" value={typeof manifest.format === 'string' ? manifest.format : 'Not reported'} /><Fact label="Normalizer" value={typeof manifest.normalizer_version === 'string' ? manifest.normalizer_version : 'Not reported'} /><Fact label="Provider" value={<ProviderIdentity provider={providerName} fallback="Not reported" detail={providerHost} />} /></dl><TraceTranscriptView transcripts={transcripts} /></div></Tabs.Panel>
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

function SharingView({ api, fixture, navigate }: { api: LocalApi; fixture: boolean; navigate: (route: Route) => void }) {
  const queryClient = useQueryClient();
  const account = useQuery({ queryKey: ['account'], queryFn: api.account, retry: false });
  const captures = useInfiniteQuery({
    queryKey: ['captures', 'sharing'],
    queryFn: ({ pageParam }) => api.captures({ finalization_state: 'finalized', limit: 50, cursor: pageParam }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (page) => page.next_cursor ?? undefined
  });
  const [selected, setSelected] = useState<string | null>(null);
  const [visibility, setVisibility] = useState<ShareVisibility>('unlisted');
  const [confirm, setConfirm] = useState(false);
  const [submitted, setSubmitted] = useState<Share | null>(null);
  const [started, setStarted] = useState<{ flow: AccountConnectionStarted; nextPollAt: number } | null>(null);
  const [now, setNow] = useState(Date.now());
  const eligible = captures.data?.pages.flatMap((page) => page.items) ?? [];
  const selectedId = selected ?? eligible[0]?.capture_id ?? null;
  const preview = useQuery({
    queryKey: ['share-preview', selectedId],
    queryFn: () => api.trace(selectedId!),
    enabled: Boolean(selectedId)
  });
  useEffect(() => {
    setSubmitted(null);
    setConfirm(false);
  }, [selectedId, visibility]);
  const share = useQuery({
    queryKey: ['share', submitted?.share_id],
    queryFn: () => api.shareStatus(submitted!.share_id),
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
  const schedule = (flow: AccountConnectionStarted) => setStarted({ flow, nextPollAt: Date.now() + flow.poll_interval_seconds * 1000 });
  const beginAccount = useMutation({
    mutationFn: api.startAccountConnection,
    onSuccess: schedule,
    onError: (error) => mutationError('Could not begin authorization', error)
  });
  const pollAccount = useMutation({
    mutationFn: () => api.pollAccountConnection(started!.flow.request_id),
    onSuccess: (result) => {
      queryClient.setQueryData(['account'], result);
      if (result.signed_in) setStarted(null);
      else if (started) setStarted({ ...started, nextPollAt: Date.now() + started.flow.poll_interval_seconds * 1000 });
    },
    onError: (error) => mutationError('Could not check authorization', error)
  });
  const createShare = useMutation({
    mutationFn: () => api.share(selectedId!, visibility),
    onSuccess: (result) => {
      setConfirm(false);
      setSubmitted(result);
      notifications.show({ title: 'Share started', message: 'The package is uploaded and awaiting verification.' });
    },
    onError: (error) => mutationError('Sharing failed', error)
  });
  const pollReady = Boolean(started && now >= started.nextPollAt);
  const shareState = share.data?.state ?? submitted?.state;
  const shareUrl = share.data?.share_url ?? submitted?.share_url;
  const packageUrl = share.data?.package_url ?? submitted?.package_url;
  const transcripts = preview.data ? traceTranscripts(preview.data.trace) : [];
  const copyShareLink = async () => {
    if (!shareUrl) return;
    await navigator.clipboard.writeText(shareUrl);
    notifications.show({ title: 'URL copied', message: 'The share URL is on the clipboard.' });
  };
  const resultTitle = shareState === 'admitted'
    ? 'Share ready'
    : shareState === 'rejected'
      ? 'Share rejected'
      : shareState === 'expired'
        ? 'Upload expired'
        : shareState === 'failed'
          ? 'Verification failed'
          : 'Checking share';
  const resultCopy = shareState === 'admitted'
    ? `${submitted?.visibility === 'listed' ? 'Listed' : 'Unlisted'} · Anyone with the URL can open it.`
    : shareState === 'rejected'
      ? 'The package was rejected before a public URL was created.'
      : shareState === 'expired'
        ? 'The upload expired before verification finished.'
        : shareState === 'failed'
          ? 'Verification could not finish. Refresh the status or try again.'
          : 'Uploaded. Checking the package and evidence.';
  const confirmationTitle = visibility === 'listed' ? 'List this share?' : 'Create this share?';
  const confirmationCopy = visibility === 'listed'
    ? 'This share will appear in Library. Anyone can read the disclosed messages and tool data. Header values remain hidden.'
    : 'Anyone with the URL can read the disclosed messages and tool data. Header values remain hidden.';

  return <div className="view-page share-flow">
    <section className="sharing-toolbar" aria-label="Share settings">
      {captures.error ? <QueryError error={captures.error} title="Finalized traces are unavailable" /> : captures.isLoading ? <Loader size="sm" /> : eligible.length ? <>
        <div className="sharing-trace-picker"><AxisSelect label="Trace" placeholder="Choose a finalized trace" clearable={false} data={eligible.map((capture) => ({ value: capture.capture_id, label: <ProviderIdentity provider={capture.provider} detail={capture.requested_model} /> }))} value={selectedId} onChange={setSelected} />
          {captures.hasNextPage && <Button variant="subtle" loading={captures.isFetchingNextPage} onClick={() => captures.fetchNextPage()}>Load more traces</Button>}</div>
        <div className="share-visibility" role="radiogroup" aria-label="Visibility">
          <span className="share-control-label">Visibility</span>
          <div>
            <button type="button" role="radio" aria-checked={visibility === 'unlisted'} className={visibility === 'unlisted' ? 'active' : ''} onClick={() => setVisibility('unlisted')}><b>Unlisted</b><small>URL access</small></button>
            <button type="button" role="radio" aria-checked={visibility === 'listed'} className={visibility === 'listed' ? 'active' : ''} onClick={() => setVisibility('listed')}><b>Listed</b><small>Shown in Library</small></button>
          </div>
        </div>
        <Button className="share-primary" disabled={!account.data?.signed_in || !selectedId || preview.isLoading || Boolean(preview.error)} onClick={() => setConfirm(true)}>Share trace</Button>
      </> : <EmptyState title="Nothing ready to share" copy="Finalize a capture first." />}
    </section>
    {submitted && <section className={`share-result share-result--${shareState ?? 'queued'}`}>
      <Group justify="space-between"><div><Text className="eyebrow">Share status</Text><Title order={2}>{resultTitle}</Title></div><StatusLabel state={shareState ?? 'queued'} /></Group>
      <Text>{resultCopy}</Text>
      <code>{submitted.share_id}</code>
      {share.data?.failure_code && <Text>Failure code: <code>{share.data.failure_code}</code></Text>}
      {share.error && <QueryError error={share.error} title="Share status is unavailable" />}
      <Group>
        {shareUrl && <Button onClick={copyShareLink} leftSection={<Copy size={15} />}>Copy URL</Button>}
        {shareUrl && <Button component="a" href={shareUrl} target="_blank" rel="noreferrer" variant="outline">Open share</Button>}
        {packageUrl && <Button component="a" href={packageUrl} variant="outline">Download .llmtrace</Button>}
        {!shareUrl && <Button variant="outline" loading={share.isFetching} onClick={() => share.refetch()}>Refresh status</Button>}
        {fixture && shareState === 'admitted' && <Button variant="subtle" onClick={() => navigate({ view: 'traces', id: submitted.capture_id })}>Open local trace</Button>}
      </Group>
    </section>}
    <div className="sharing-grid">
      <Paper className="sharing-preview">
        {preview.isLoading ? <LoadingState label="Loading preview" /> : preview.error ? <QueryError error={preview.error} title="Preview is unavailable" /> : preview.data ? <TraceTranscriptView transcripts={transcripts} /> : <EmptyState title="Choose a trace" copy="Select a finalized trace to preview its disclosed content." />}
      </Paper>
      <Paper className="sharing-controls">
        <section className="sharing-disclosure">
          <Group justify="space-between"><Text className="eyebrow">Disclosure</Text><ShieldCheck size={16} /></Group>
          <dl className="sharing-facts">
            <Fact label="Visible" value="Prompts, responses, tools" />
            <Fact label="Hidden" value="HTTP header values" />
            <Fact label="Access" value={visibility === 'listed' ? 'Library and URL' : 'URL only'} />
            <Fact label="Checks" value="Safety and cryptographic verification" />
          </dl>
        </section>
        <div className="share-package-preview"><FileCheck2 size={18} /><div><b>.llmtrace included</b><Text>Size and SHA-256 appear on the share.</Text></div></div>
        <div className="sharing-account">
          <Group justify="space-between"><Text className="eyebrow">Account</Text><KeyRound size={16} /></Group>
          {account.isLoading ? <Loader size="xs" /> : account.error ? <QueryError error={account.error} title="Account connection is unavailable" /> : account.data?.signed_in ? <Group justify="space-between"><div><b>{account.data.github_login}</b><Text>{account.data.credential_name ?? account.data.device_name}</Text>{account.data.credential_kind === 'api_key' && <Text className="eyebrow">API key</Text>}</div><StatusLabel state="ready" /></Group> : <><Text>Connect an account to share this trace.</Text><Button variant="outline" loading={beginAccount.isPending} onClick={() => beginAccount.mutate()}>Connect account</Button></>}
          {started && <div className="authorization-code"><Text className="eyebrow">Approval code</Text><code>{started.flow.user_code}</code>{!fixture && <a href={started.flow.verification_uri_complete} target="_blank" rel="noreferrer">Open approval page</a>}<Text>{pollReady ? 'Ready to check.' : `Check available in ${Math.max(1, Math.ceil((started.nextPollAt - now) / 1000))}s.`}</Text><Button size="xs" variant="subtle" disabled={!pollReady} loading={pollAccount.isPending} onClick={() => pollAccount.mutate()}>Check approval</Button></div>}
        </div>
      </Paper>
    </div>
    <AlertDialog open={confirm} onOpenChange={setConfirm}><AlertDialogContent className="axis-local-dialog"><AlertDialogHeader><AlertDialogTitle>{confirmationTitle}</AlertDialogTitle><AlertDialogDescription>{confirmationCopy}</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>Cancel</AlertDialogCancel><AlertDialogAction disabled={createShare.isPending} onClick={() => createShare.mutate()}>{createShare.isPending ? 'Sharing…' : visibility === 'listed' ? 'List share' : 'Create share'}</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>
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
  const events = useInfiniteQuery({
    queryKey: ['events', filters],
    queryFn: ({ pageParam }) => api.events({ ...filters, limit: 50, cursor: pageParam }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (page) => page.next_cursor ?? undefined,
    refetchInterval: 5_000
  });
  const visible = events.data?.pages.flatMap((page) => page.items) ?? [];
  return <div className="view-page"><div className="filter-bar filter-bar--activity"><AxisSelect ariaLabel="Activity severity" placeholder="All severities" data={['info', 'success', 'warning', 'error']} value={severity} onChange={setSeverity} />
      <TextInput aria-label="Activity capture ID" placeholder="Capture ID" value={captureId} onChange={(event) => setCaptureId(event.currentTarget.value)} />
      <TextInput aria-label="Activity operation ID" placeholder="Operation ID" value={operationId} onChange={(event) => setOperationId(event.currentTarget.value)} />
      <TextInput aria-label="Activity event type" placeholder="Event type" value={eventType} onChange={(event) => setEventType(event.currentTarget.value)} />
      <AxisSelect ariaLabel="Activity time filter" placeholder="Any time" data={[{ value: 'hour', label: 'Last hour' }, { value: 'day', label: 'Last 24 hours' }, { value: 'week', label: 'Last 7 days' }]} value={time} onChange={setTime} />
      <Button variant="outline" leftSection={<RefreshCw size={14} />} onClick={() => events.refetch()}>Refresh</Button></div>
    {events.isLoading ? <LoadingState /> : events.error ? <QueryError error={events.error} title="Activity is unavailable" /> : visible.length ? <><EventList events={visible} />{events.hasNextPage && <Button className="load-more" variant="subtle" loading={events.isFetchingNextPage} onClick={() => events.fetchNextPage()}>Load more activity</Button>}</> : <EmptyState icon={Activity} title="No activity" copy="New capture and finalization events will appear here." />}</div>;
}

function EventList({ events }: { events: Event[] }) {
  if (!events.length) return <EmptyState icon={Activity} title="No recent activity" copy="The local event history is empty." />;
  return <div className="event-list">{events.map((event) => <div key={event.event_id} className="event-row"><ThemeIcon variant="transparent" className={`event-icon event-icon--${stateTone(event.severity)}`}>{event.severity === 'error' ? <XCircle size={17} /> : event.severity === 'success' ? <Check size={17} /> : <CircleDot size={17} />}</ThemeIcon><div><Group gap="xs"><b>{event.message}</b><StatusLabel state={event.severity} /></Group><Text>{event.capture_id ?? event.operation_id ?? event.event_type}</Text></div><time>{formatDate(event.created_at_unix_ms)}</time></div>)}</div>;
}

function LocalNotaryRecord({ record, activeKeyId }: { record: Notary; activeKeyId?: string | null }) {
  const lifecycle = notaryLifecycle(record.status);
  const copyKey = async () => {
    await navigator.clipboard.writeText(record.key_id);
    notifications.show({ title: 'Notary key ID copied', message: 'The complete key ID is on the clipboard.' });
  };
  return <article className={`local-notary-record local-notary-record--${record.status}`}>
    <header><span className={`local-notary-state local-notary-state--${record.status}`}><i aria-hidden="true" />{record.status}</span>
      {record.key_id === activeKeyId && <span className="local-notary-selected">Selected active key</span>}</header>
    <Title order={3}>{lifecycle.label}</Title>
    <Text>{lifecycle.description}</Text>
    <dl className="local-notary-facts">
      <Fact label="Endpoint" value={record.endpoint} />
      <Fact label="Transport" value={record.transport.toUpperCase()} />
      <Fact label="Valid from" value={formatNotaryBoundary(record.valid_from_unix_ms, { kind: 'lower', missingLabel: 'Not defined by explicit configuration' })} />
      <Fact label="Capture cutoff" value={formatNotaryBoundary(record.valid_until_unix_ms)} />
      <Fact label="Finalization cutoff" value={formatNotaryBoundary(record.finalize_until_unix_ms)} />
    </dl>
    <div className="local-notary-key"><span>Key ID / fingerprint</span><code title={record.key_id}>{abbreviatedKeyId(record.key_id)}</code><ActionIcon variant="subtle" onClick={copyKey} aria-label={`Copy full key ID ${record.key_id}`}><Copy size={15} /></ActionIcon></div>
  </article>;
}

function SettingsNotaries({ api }: { api: LocalApi }) {
  const notaries = useQuery({ queryKey: ['notaries'], queryFn: api.notaries, retry: false });
  const errorCode = notaries.error instanceof LocalApiError ? notaries.error.code : null;
  const records = orderNotaries(notaries.data?.notaries ?? [], notaries.data?.active_key_id);
  return <Paper className="settings-panel settings-notaries">
    <div className="settings-notaries-heading"><div><Text className="eyebrow">Notaries</Text><Title order={2}>Configured trust</Title></div>{notaries.data?.generation != null && <Text>Directory generation {notaries.data.generation}</Text>}</div>
    <Text className="settings-notaries-note">This is the trust state used by the local service. It describes key lifecycle and permitted work, not endpoint health or availability.</Text>
    {notaries.isLoading ? <div className="local-notary-loading" role="status" aria-label="Loading local notary trust"><i /><i /><i /></div>
      : notaries.error ? <div className="local-notary-state-panel" role="alert"><b>{errorCode === 'notary_trust_state_invalid' ? 'Pinned trust state is malformed' : 'Local notary trust is unavailable'}</b><span>{errorCode === 'notary_trust_state_invalid' ? 'The cached directory could not be validated. No notary is presented as usable.' : 'The local service could not return its configured trust metadata. No endpoint status can be inferred.'}</span><Button variant="outline" onClick={() => notaries.refetch()}>Try again</Button></div>
        : !records.length ? <div className="local-notary-state-panel"><b>No pinned notary records</b><span>The local service has not retained a directory generation. No notary is presented as available.</span></div>
          : <><dl className="settings-notary-source"><Fact label="Trust source" value={notaries.data?.source === 'explicit_configuration' ? 'Explicit self-hosted configuration' : 'Pinned directory'} />
            {notaries.data?.directory_source && <Fact label="Directory source" value={notaries.data.directory_source} />}</dl>
            {notaries.data?.source === 'explicit_configuration' && <Text className="explicit-notary-note">This endpoint and key come from local configuration and are not members of the hosted directory.</Text>}
            <div className="local-notary-list">{records.map((record) => <LocalNotaryRecord key={record.key_id} record={record} activeKeyId={notaries.data?.active_key_id} />)}</div></>}
  </Paper>;
}

function SettingsView({ status, api }: { status: Status; api: LocalApi }) {
  const openApiUrl = `${window.location.origin}/openapi.json`;
  const copyOpenApi = async () => {
    await navigator.clipboard.writeText(openApiUrl);
    notifications.show({
      title: 'OpenAPI URL copied',
      message: 'Use this URL to discover admin routes and request bodies.'
    });
  };
  const updateState = !status.updates.enabled ? 'Disabled for source builds'
    : status.updates.update_available ? `Available: ${status.updates.latest_build_id}`
    : status.updates.error_code ? 'Check failed'
    : status.updates.last_checked_unix_ms ? 'Up to date'
    : 'Not checked yet';

  return <div className="view-page"><Paper className="appearance-setting">
      <Text fw={700}>Theme</Text>
      <SchemeControl />
    </Paper>
    <SimpleGrid cols={{ base: 1, md: 2 }} spacing="lg">
      <SettingsNotaries api={api} />
      <Paper className="settings-panel">
        <Text className="eyebrow">Listeners</Text>
        <Title order={2}>Listener addresses</Title>
        <dl className="receipt-list">
          <Fact label="Provider proxy" value={status.proxy_listener} />
          <Fact label="Admin & dashboard" value={status.admin_listener} />
          <Fact label="Metadata" value={`${status.metadata_backend} (${status.metadata_status})`} />
          <Fact label="Artifacts" value={`${status.artifact_backend} (${status.artifact_status})`} />
          <Fact label="API version" value="v1" />
          <Fact label="Service version" value={status.version} />
          <Fact label="Build" value={status.build_id} />
          <Fact label="Updates" value={updateState} />
        </dl>
        <Text className="safe-note"><ShieldCheck size={15} /> Both listeners are restricted to loopback.</Text>
        {status.updates.update_available && <Text>Run <code>llm-notary update</code>, then restart the service after active work finishes.</Text>}
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
