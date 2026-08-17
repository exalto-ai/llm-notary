import {
  ActionIcon,
  AppShell,
  Badge,
  Burger,
  Button,
  Center,
  Drawer,
  Group,
  Loader,
  NavLink,
  Paper,
  PasswordInput,
  ScrollArea,
  SimpleGrid,
  Stack,
  Switch,
  Tabs,
  Text,
  TextInput,
  ThemeIcon,
  Title,
  Tooltip,
  UnstyledButton,
  useMantineColorScheme,
} from '@mantine/core';
import { useDisclosure, useMediaQuery } from '@mantine/hooks';
import { notifications } from '@mantine/notifications';
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Activity,
  Archive,
  ArrowLeft,
  Check,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  CodeXml,
  Copy,
  Database,
  Download,
  FileCheck2,
  FileJson2,
  Gauge,
  KeyRound,
  ListChecks,
  Moon,
  PanelLeft,
  Play,
  RefreshCw,
  Search,
  Send,
  Settings,
  ShieldCheck,
  Sun,
  TerminalSquare,
  Unplug,
  XCircle,
} from 'lucide-react';
import {
  type CSSProperties,
  type FormEvent,
  type KeyboardEvent as ReactKeyboardEvent,
  type ReactNode,
  type PointerEvent as ReactPointerEvent,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import type {
  AccountConnection,
  AccountConnectionStarted,
  Event,
  LocalApi,
  Notary,
  Operation,
  OperationSummary,
  Share,
  ShareVisibility,
  Status,
  TraceDetail,
  TraceSummary,
  Verification,
} from './api';
import { LocalApiError } from './api';
import {
  abbreviatedKeyId,
  formatNotaryBoundary,
  notaryLifecycle,
  orderNotaries,
} from './notaryLifecycle';
import { ProviderIdentity } from './ProviderIdentity';

function requiredValue<T>(value: T | null | undefined, label: string): T {
  if (value === null || value === undefined) throw new Error(`${label} is required`);
  return value;
}

const logoUrl = new URL('./assets/notary-mark.svg', import.meta.url).href;

export type DashboardView =
  | 'overview'
  | 'captures'
  | 'notarizations'
  | 'traces'
  | 'sharing'
  | 'activity'
  | 'settings';

type Route = { view: DashboardView; id?: string };

type AxisSelectOption = string | { value: string; label: ReactNode };

function AxisSelect({
  value,
  onChange,
  data,
  placeholder,
  ariaLabel,
  label,
  clearable = true,
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
  const options = data.map((option) =>
    typeof option === 'string' ? { value: option, label: option } : option,
  );
  return (
    <div className="axis-select-field">
      {label && <span className="axis-select-label">{label}</span>}
      <Select
        value={value ?? (clearable ? allValue : undefined)}
        onValueChange={(next) => onChange(next === allValue ? null : next)}
      >
        <SelectTrigger className="axis-select-trigger" aria-label={ariaLabel ?? label}>
          <SelectValue placeholder={placeholder} />
        </SelectTrigger>
        <SelectContent className="axis-select-content" position="popper" align="start">
          {clearable && <SelectItem value={allValue}>{placeholder}</SelectItem>}
          {options.map((option) => (
            <SelectItem key={option.value} value={option.value}>
              {option.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

const navigation: Array<{ view: DashboardView; label: string; icon: typeof Gauge }> = [
  { view: 'overview', label: 'Overview', icon: Gauge },
  { view: 'captures', label: 'Captures', icon: Archive },
  { view: 'notarizations', label: 'Notarizations', icon: ListChecks },
  { view: 'traces', label: 'Notarized traces', icon: FileCheck2 },
  { view: 'sharing', label: 'Share', icon: Send },
  { view: 'activity', label: 'Activity', icon: Activity },
  { view: 'settings', label: 'Settings', icon: Settings },
];

function routeFromHash(): Route {
  const [view = 'overview', id] = window.location.hash.replace(/^#\/?/, '').split('/');
  return navigation.some((item) => item.view === view)
    ? { view: view as DashboardView, id }
    : { view: 'overview' };
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
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(new Date(value));
}

function formatBytes(value?: number | null) {
  if (value === undefined || value === null) return '—';
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 ** 2).toFixed(1)} MB`;
}

function stateTone(state: string) {
  if (['succeeded', 'verified', 'ready', 'success', 'admitted'].includes(state)) return 'ready';
  if (['failed', 'interrupted', 'error', 'unavailable', 'rejected', 'expired'].includes(state))
    return 'danger';
  if (['running', 'capturing', 'queued', 'uploading', 'verifying'].includes(state)) return 'active';
  return 'muted';
}

function StatusLabel({ state }: { state: string }) {
  return (
    <span className={`status-label status-label--${stateTone(state)}`}>
      <span aria-hidden="true" />
      {state.replaceAll('_', ' ')}
    </span>
  );
}

function notarizationPhaseLabel(phase: string) {
  switch (phase) {
    case 'queued':
      return 'Waiting for proof worker';
    case 'preparing':
      return 'Preparing proof inputs';
    case 'proving':
      return 'Generating private proof';
    case 'signing':
      return 'Requesting notary signature';
    case 'packaging':
      return 'Building verified package';
    case 'complete':
      return 'Verified package complete';
    default:
      return phase.replaceAll('_', ' ');
  }
}

function proofPercent(operation: Operation | OperationSummary) {
  const proof = operation.progress.proof;
  if (!proof?.bytes_total) return null;
  return Math.min(100, Math.floor((proof.bytes_completed / proof.bytes_total) * 100));
}

function traceDisplayStatus(trace: TraceSummary) {
  return trace.status ?? trace.state ?? 'unknown';
}

function captureStatus(trace: TraceSummary) {
  if (trace.status === 'capturing') return 'capturing';
  if (trace.status === 'capture_failed') return 'failed';
  return 'captured';
}

function notarizationStatus(trace: TraceSummary) {
  if (trace.state === 'notarized') return 'succeeded';
  if (trace.status === 'notarizing') return 'running';
  if (trace.status === 'notarization_failed') return 'failed';
  if (trace.status === 'notarization_interrupted') return 'interrupted';
  return 'not_requested';
}

function EmptyState({
  icon: Icon = Archive,
  title,
  copy,
}: {
  icon?: typeof Archive;
  title: string;
  copy: string;
}) {
  return (
    <Center className="empty-state">
      <Stack align="center" gap="sm">
        <Icon aria-hidden="true" />
        <Title order={3}>{title}</Title>
        <Text>{copy}</Text>
      </Stack>
    </Center>
  );
}

function ErrorState({
  title = 'The local service is unavailable',
  onRetry,
}: {
  title?: string;
  onRetry?: () => void;
}) {
  return (
    <Center className="error-state">
      <Stack align="center" gap="md">
        <Unplug aria-hidden="true" />
        <Title order={2}>{title}</Title>
        <Text>Check that the foreground service is running on this loopback address.</Text>
        {onRetry && (
          <Button variant="outline" leftSection={<RefreshCw size={15} />} onClick={onRetry}>
            Try again
          </Button>
        )}
      </Stack>
    </Center>
  );
}

function QueryError({ error, title }: { error: unknown; title?: string }) {
  const unauthorized = error instanceof LocalApiError && error.status === 401;
  return <ErrorState title={unauthorized ? 'The dashboard session expired' : title} />;
}

function mutationError(title: string, error: unknown) {
  const code = error instanceof LocalApiError ? error.code : 'request_failed';
  notifications.show({
    color: 'red',
    title,
    message: `The service returned ${code}. Review Activity for safe details.`,
  });
}

type AccountConnectionController = ReturnType<typeof useAccountConnection>;

function accountPollRetryDelaySeconds(intervalSeconds: number, failures: number) {
  const base = Math.max(1, intervalSeconds);
  return Math.min(30, base * 2 ** Math.min(Math.max(0, failures - 1), 4));
}

function useAccountConnection(api: LocalApi) {
  const queryClient = useQueryClient();
  const account = useQuery({ queryKey: ['account'], queryFn: api.account, retry: false });
  const [started, setStarted] = useState<{
    flow: AccountConnectionStarted;
    nextPollAt: number;
    startedAt: number;
    failures: number;
  } | null>(null);
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    if (!started) return;
    const timer = window.setInterval(() => setNow(Date.now()), 250);
    return () => window.clearInterval(timer);
  }, [started]);

  const schedule = (flow: AccountConnectionStarted) => {
    const startedAt = Date.now();
    setStarted({
      flow,
      startedAt,
      nextPollAt: startedAt + flow.poll_interval_seconds * 1000,
      failures: 0,
    });
  };
  const begin = useMutation({
    mutationFn: api.startAccountConnection,
    onSuccess: schedule,
    onError: (error) => mutationError('Could not begin authorization', error),
  });
  const poll = useMutation({
    mutationFn: () =>
      api.pollAccountConnection(
        requiredValue(started, 'started account connection').flow.request_id,
      ),
    onSuccess: (result) => {
      queryClient.setQueryData(['account'], result);
      if (result.signed_in || result.connection_state === 'connected') setStarted(null);
      else if (started)
        setStarted({
          ...started,
          nextPollAt: Date.now() + started.flow.poll_interval_seconds * 1000,
          failures: 0,
        });
    },
    onError: (error) => {
      mutationError('Could not check authorization', error);
      setStarted((current) => {
        if (!current) return current;
        const failures = current.failures + 1;
        const delay = accountPollRetryDelaySeconds(current.flow.poll_interval_seconds, failures);
        return { ...current, failures, nextPollAt: Date.now() + delay * 1000 };
      });
    },
  });
  const disconnect = useMutation({
    mutationFn: api.disconnectAccount,
    onSuccess: () => {
      setStarted(null);
      void queryClient.invalidateQueries({ queryKey: ['account'] });
    },
    onError: (error) => mutationError('Could not disconnect this device', error),
  });
  const expired = Boolean(
    started && now >= started.startedAt + started.flow.expires_in_seconds * 1000,
  );
  const pollReady = Boolean(started && !expired && now >= started.nextPollAt);

  useEffect(() => {
    // A zero interval is used by deterministic dashboard fixtures to require
    // an explicit check. The daemon clamps real intervals to at least one
    // second, so only real authorization flows are automatically polled.
    if (
      !started ||
      expired ||
      started.flow.poll_interval_seconds === 0 ||
      !pollReady ||
      poll.isPending
    )
      return;
    poll.mutate();
  }, [expired, poll, pollReady, started]);

  return {
    account,
    started,
    now,
    expired,
    pollReady,
    begin,
    poll,
    disconnect,
    cancel: () => setStarted(null),
    refresh: () => account.refetch(),
  };
}

function accountDisplayName(account: AccountConnection) {
  return account.display_name || account.provider_display_name || 'LLM Notary account';
}

function authProviderLabel(provider?: string | null) {
  if (!provider) return 'Hosted account';
  return provider === 'google' ? 'Google' : provider === 'github' ? 'GitHub' : provider;
}

function accountConnectionLabel(account: AccountConnection | undefined, error: unknown) {
  if (error) return 'Temporarily unavailable';
  if (!account) return 'Loading account';
  if (account.connection_state === 'reauthorization_required') return 'Reconnect required';
  if (account.connection_state === 'unavailable') return 'Temporarily unavailable';
  if (account.signed_in || account.connection_state === 'connected') return 'Connected';
  return 'Not connected';
}

function AccountConnectionCard({
  controller,
  compact = false,
  fixture = false,
}: {
  controller: AccountConnectionController;
  compact?: boolean;
  fixture?: boolean;
}) {
  const { account, started, expired, pollReady, begin, poll, cancel, refresh } = controller;
  const [disconnectOpen, setDisconnectOpen] = useState(false);
  const { disconnect } = controller;
  const api = controller.account.data;
  const canDisconnect = Boolean(api?.signed_in && api.credential_kind !== 'api_key');
  const disconnectAccount = async () => {
    if (!canDisconnect) return;
    setDisconnectOpen(false);
    disconnect.mutate();
  };
  const state = accountConnectionLabel(api, account.error);
  const connected = Boolean(api?.signed_in || api?.connection_state === 'connected');
  const unavailable = state === 'Temporarily unavailable';
  const links = api?.links;

  return (
    <section
      className={`account-connection-card${compact ? ' account-connection-card--compact' : ''}`}
      aria-labelledby={compact ? undefined : 'local-account-title'}
    >
      <Group justify="space-between" align="flex-start">
        <div>
          <Text className="eyebrow">Account</Text>
          {!compact && (
            <Title id="local-account-title" order={2}>
              Hosted account connection
            </Title>
          )}
        </div>
        <StatusLabel
          state={
            connected
              ? 'ready'
              : unavailable
                ? 'unavailable'
                : api?.connection_state === 'reauthorization_required'
                  ? 'expired'
                  : 'muted'
          }
        />
      </Group>
      {account.isLoading ? (
        <Loader size="sm" />
      ) : connected && api ? (
        <>
          <div className="account-connection-identity">
            <div>
              <b>{accountDisplayName(api)}</b>
              {api.provider_display_name && api.display_name && (
                <Text>{api.provider_display_name}</Text>
              )}
              <Text>
                {authProviderLabel(api.auth_provider)} ·{' '}
                {api.credential_name || api.device_name || 'Connected service'}
              </Text>
            </div>
            {api.credential_kind === 'api_key' && <Badge variant="light">API key</Badge>}
          </div>
          {api.billing && (
            <dl className="account-connection-facts">
              <Fact
                label="Plan"
                value={`${api.billing.service_plan} · ${api.billing.billing_status}`}
              />
              {api.billing.purchase_mode && (
                <Fact label="Billing" value={api.billing.purchase_mode} />
              )}
              {api.credits && (
                <Fact
                  label="Notarization"
                  value={`${formatBytes(api.credits.notarization.total_used_bytes)} used · ${formatBytes(api.credits.notarization.total_remaining_bytes)} remaining`}
                />
              )}
              {api.credits && (
                <Fact
                  label="Capture"
                  value={`${formatBytes(api.credits.capture.total_used_bytes)} used · ${formatBytes(api.credits.capture.total_remaining_bytes)} remaining`}
                />
              )}
              {api.credits && (
                <Fact
                  label="Monthly included"
                  value={formatBytes(api.credits.notarization.included_monthly_remaining_bytes)}
                />
              )}
              {api.credits && (
                <Fact
                  label="Supplemental"
                  value={formatBytes(api.credits.notarization.supplemental_remaining_bytes)}
                />
              )}
              {api.credits && (
                <Fact label="Reset" value={formatDate((api.credits.reset_at ?? 0) * 1000)} />
              )}
              {api.credits?.notarization.next_grant_expiration && (
                <Fact
                  label="Next expiration"
                  value={formatDate(api.credits.notarization.next_grant_expiration * 1000)}
                />
              )}
            </dl>
          )}
          {links && (
            <Group className="account-connection-links" gap="xs">
              <Button
                component="a"
                href={links.account}
                target="_blank"
                rel="noreferrer"
                variant="subtle"
              >
                Open account
              </Button>
              <Button
                component="a"
                href={links.usage}
                target="_blank"
                rel="noreferrer"
                variant="subtle"
              >
                Usage and credits
              </Button>
              <Button
                component="a"
                href={links.plans}
                target="_blank"
                rel="noreferrer"
                variant="subtle"
              >
                Plans and pricing
              </Button>
              <Button
                component="a"
                href={links.settings}
                target="_blank"
                rel="noreferrer"
                variant="subtle"
              >
                {api.credential_kind === 'api_key' ? 'Manage API keys' : 'Account settings'}
              </Button>
            </Group>
          )}
          {canDisconnect && (
            <Button variant="outline" onClick={() => setDisconnectOpen(true)}>
              Disconnect this device
            </Button>
          )}
        </>
      ) : (
        <>
          <Text>
            {api?.connection_state === 'reauthorization_required'
              ? 'The local authorization expired or was revoked. Reconnect to restore hosted credits and account-owned sharing.'
              : unavailable
                ? 'The account service could not be reached. Local captures and verification remain available.'
                : 'Connect an account to see hosted credits and use account-owned sharing.'}
          </Text>
          <Group>
            <Button variant="outline" loading={begin.isPending} onClick={() => begin.mutate()}>
              {api?.connection_state === 'reauthorization_required'
                ? 'Reconnect'
                : compact
                  ? 'Connect account'
                  : 'Sign in or create account'}
            </Button>
            {unavailable && (
              <Button variant="subtle" onClick={() => refresh()}>
                Refresh
              </Button>
            )}
          </Group>
        </>
      )}
      {started && (
        <div className="authorization-code">
          <Text className="eyebrow">Approval code</Text>
          <code>{started.flow.user_code}</code>
          {!fixture && (
            <a href={started.flow.verification_uri_complete} target="_blank" rel="noreferrer">
              Open approval page
            </a>
          )}
          {expired ? (
            <Text>Authorization expired. Start again to get a fresh request.</Text>
          ) : (
            <Text>
              {pollReady
                ? 'Ready to check.'
                : `Next check in ${Math.max(1, Math.ceil((started.nextPollAt - controller.now) / 1000))}s.`}
            </Text>
          )}
          <Group>
            <Button
              size="xs"
              variant="subtle"
              disabled={expired || !pollReady}
              loading={poll.isPending}
              onClick={() => poll.mutate()}
            >
              Check approval
            </Button>
            <Button size="xs" variant="subtle" onClick={cancel}>
              Cancel
            </Button>
            {expired && (
              <Button
                size="xs"
                variant="subtle"
                loading={begin.isPending}
                onClick={() => begin.mutate()}
              >
                Try again
              </Button>
            )}
          </Group>
        </div>
      )}
      <AlertDialog open={disconnectOpen} onOpenChange={setDisconnectOpen}>
        <AlertDialogContent className="axis-local-dialog">
          <AlertDialogHeader>
            <AlertDialogTitle>Disconnect this device?</AlertDialogTitle>
            <AlertDialogDescription>
              This revokes only the local browser-approved session. It does not sign out the website
              or delete your hosted account.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Keep connected</AlertDialogCancel>
            <AlertDialogAction
              disabled={disconnect.isPending}
              onClick={() => void disconnectAccount()}
            >
              {disconnect.isPending ? 'Disconnecting…' : 'Disconnect device'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </section>
  );
}

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
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
    return {
      kind,
      text: typeof part.content === 'string' ? part.content : readableTraceValue(part.content),
    };
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
        ...(typeof message.finish_reason === 'string'
          ? { finishReason: message.finish_reason }
          : {}),
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
          transcripts.push({
            model:
              attributes.get('gen_ai.response.model') ??
              attributes.get('gen_ai.request.model') ??
              'Model not reported',
            input,
            output,
          });
        }
      }
    }
  }
  return transcripts;
}

function timeRangeStart(range: string | null) {
  if (!range) return undefined;
  const milliseconds =
    range === 'hour'
      ? 60 * 60 * 1000
      : range === 'day'
        ? 24 * 60 * 60 * 1000
        : 7 * 24 * 60 * 60 * 1000;
  return Date.now() - milliseconds;
}

function LoadingState({ label = 'Loading local evidence' }: { label?: string }) {
  return (
    <Center className="loading-state">
      <Stack align="center" gap="sm">
        <Loader size="sm" />
        <Text>{label}</Text>
      </Stack>
    </Center>
  );
}

const splitStorageKey = 'llm-notary-dashboard-split-width';
const splitDefault = 320;
const splitMinimum = 272;
const splitMaximum = 460;
const splitDetailMinimum = 360;

function storedSplitWidth() {
  const stored = Number(window.localStorage.getItem(splitStorageKey));
  return Number.isFinite(stored) && stored >= splitMinimum && stored <= splitMaximum
    ? stored
    : splitDefault;
}

function ResizableSplit({
  className,
  children,
}: {
  className: string;
  children: [ReactNode, ReactNode];
}) {
  const container = useRef<HTMLDivElement>(null);
  const [leftWidth, setLeftWidth] = useState(storedSplitWidth);
  const clampWidth = (width: number) => {
    const available =
      container.current?.getBoundingClientRect().width ?? splitMaximum + splitDetailMinimum;
    return Math.round(
      Math.max(splitMinimum, Math.min(splitMaximum, available - splitDetailMinimum, width)),
    );
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
    if (event.currentTarget.hasPointerCapture(event.pointerId))
      event.currentTarget.releasePointerCapture(event.pointerId);
    document.documentElement.classList.remove('is-resizing-split');
  };
  const onKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    const next =
      event.key === 'ArrowLeft'
        ? leftWidth - 16
        : event.key === 'ArrowRight'
          ? leftWidth + 16
          : event.key === 'Home'
            ? splitMinimum
            : event.key === 'End'
              ? splitMaximum
              : null;
    if (next === null) return;
    event.preventDefault();
    updateWidth(next, true);
  };
  return (
    <div
      ref={container}
      className={`resizable-split ${className}`}
      style={{ '--split-left': `${leftWidth}px` } as CSSProperties}
    >
      {children[0]}
      <div
        className="split-handle"
        role="separator"
        aria-label="Resize list and detail panels"
        aria-orientation="vertical"
        aria-valuemin={splitMinimum}
        aria-valuemax={splitMaximum}
        aria-valuenow={leftWidth}
        tabIndex={0}
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
        onPointerCancel={stopResize}
      />
      {children[1]}
    </div>
  );
}

function SchemeControl() {
  const { colorScheme, setColorScheme } = useMantineColorScheme();
  const options = [
    { value: 'auto' as const, label: 'System', icon: PanelLeft },
    { value: 'light' as const, label: 'Light', icon: Sun },
    { value: 'dark' as const, label: 'Dark', icon: Moon },
  ];
  return (
    <div className="scheme-control" role="group" aria-label="Color scheme">
      {options.map(({ value, label, icon: Icon }) => (
        <Tooltip key={value} label={label}>
          <button
            type="button"
            className={colorScheme === value ? 'is-active' : ''}
            aria-pressed={colorScheme === value}
            aria-label={`${label} color scheme`}
            onClick={() => setColorScheme(value)}
          >
            <Icon size={14} aria-hidden="true" />
            <span>{label}</span>
          </button>
        </Tooltip>
      ))}
    </div>
  );
}

function AuthGate({ api, onAuthenticated }: { api: LocalApi; onAuthenticated: () => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const mutation = useMutation({
    mutationFn: () => api.session(username, password),
    onSuccess: () => {
      setUsername('');
      setPassword('');
      onAuthenticated();
    },
    onError: () =>
      notifications.show({
        color: 'red',
        title: 'Authentication failed',
        message: 'Check the username and password configured under admin.auth.',
      }),
  });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (username && password) mutation.mutate();
  };
  return (
    <main className="auth-shell">
      <section className="auth-document">
        <Brand />
        <Text className="eyebrow">Local administration</Text>
        <Title order={1}>Sign in</Title>
        <Text className="auth-copy">
          This service requires the credentials configured under admin.auth.
        </Text>
        <form onSubmit={submit}>
          <TextInput
            label="Username"
            value={username}
            onChange={(event) => setUsername(event.currentTarget.value)}
            autoComplete="username"
            autoFocus
          />
          <PasswordInput
            label="Password"
            value={password}
            onChange={(event) => setPassword(event.currentTarget.value)}
            autoComplete="current-password"
          />
          <Button
            type="submit"
            loading={mutation.isPending}
            disabled={!username || !password}
            rightSection={<ChevronRight size={15} />}
          >
            Open dashboard
          </Button>
        </form>
        <div className="trust-note">
          <ShieldCheck aria-hidden="true" />
          <div>
            <b>Loopback only</b>
            <span>This control surface is available only on the local admin listener.</span>
          </div>
        </div>
      </section>
    </main>
  );
}

function Brand() {
  return (
    <div className="local-brand">
      <span className="local-mark" aria-hidden="true">
        <img src={logoUrl} alt="" width={30} height={30} />
      </span>
      <span>LLM Notary</span>
    </div>
  );
}

function Sidebar({
  route,
  status,
  onNavigate,
}: {
  route: Route;
  status: Status;
  onNavigate: (route: Route) => void;
}) {
  const count = (view: DashboardView) =>
    view === 'captures'
      ? status.counts.captured
      : view === 'notarizations'
        ? status.counts.notarizing
        : undefined;
  return (
    <div className="sidebar-inner">
      <div className="sidebar-primary">
        <nav aria-label="Local dashboard">
          {navigation.map(({ view, label, icon: Icon }) => (
            <NavLink
              key={view}
              component="button"
              type="button"
              aria-label={label}
              active={route.view === view}
              label={label}
              leftSection={<Icon size={17} strokeWidth={1.7} />}
              rightSection={count(view) ? <Badge size="xs">{count(view)}</Badge> : null}
              onClick={() => onNavigate({ view })}
            />
          ))}
        </nav>
      </div>
    </div>
  );
}

function TopNav({
  route,
  status,
  onNavigate,
  opened,
  onOpenNavigation,
  fixture,
}: {
  route: Route;
  status: Status;
  onNavigate: (route: Route) => void;
  opened: boolean;
  onOpenNavigation: () => void;
  fixture: boolean;
}) {
  const count = (view: DashboardView) =>
    view === 'captures'
      ? status.counts.captured
      : view === 'notarizations'
        ? status.counts.notarizing
        : undefined;
  return (
    <header className="local-topbar">
      <nav aria-label="Local dashboard">
        {navigation.map(({ view, label, icon: Icon }) => (
          <UnstyledButton
            key={view}
            className={route.view === view ? 'is-active' : ''}
            onClick={() => onNavigate({ view })}
          >
            <Icon size={15} aria-hidden="true" />
            <span>{label}</span>
            {count(view) ? <b>{count(view)}</b> : null}
          </UnstyledButton>
        ))}
      </nav>
      <div className="local-topbar-status">
        {fixture && (
          <span className="sample-data-label" title="This preview uses synthetic sample data">
            Sample data
          </span>
        )}
        <Burger opened={opened} onClick={onOpenNavigation} size="sm" aria-label="Open navigation" />
      </div>
    </header>
  );
}

export function Dashboard({
  api,
  fixture = false,
  embedded = false,
}: {
  api: LocalApi;
  fixture?: boolean;
  embedded?: boolean;
}) {
  const route = useRoute();
  const queryClient = useQueryClient();
  const [navOpened, { open: openNav, close: closeNav }] = useDisclosure(false);
  const statusQuery = useQuery({
    queryKey: ['status'],
    queryFn: api.status,
    retry: false,
    refetchInterval: 10_000,
  });
  const navigate = (next: Route) => {
    closeNav();
    goTo(next);
  };

  if (statusQuery.isLoading) return <LoadingState label="Connecting to the local service" />;
  if (statusQuery.error && (statusQuery.error as LocalApiError).status === 401) {
    return (
      <AuthGate
        api={api}
        onAuthenticated={() => queryClient.invalidateQueries({ queryKey: ['status'] })}
      />
    );
  }
  if (statusQuery.error) return <ErrorState onRetry={() => statusQuery.refetch()} />;
  if (!statusQuery.data) return <ErrorState onRetry={() => statusQuery.refetch()} />;
  const status = statusQuery.data;
  if (embedded) {
    return (
      <main className="dashboard-shell dashboard-shell--embedded dashboard-main">
        <View route={route} status={status} api={api} navigate={navigate} fixture={fixture} />
      </main>
    );
  }
  return (
    <AppShell header={{ height: 50 }} padding={0} className="dashboard-shell">
      <AppShell.Header className="dashboard-header">
        <TopNav
          route={route}
          status={status}
          onNavigate={navigate}
          opened={navOpened}
          onOpenNavigation={openNav}
          fixture={fixture}
        />
      </AppShell.Header>
      <Drawer
        opened={navOpened}
        onClose={closeNav}
        title="Navigation"
        size="min(88vw, 340px)"
        classNames={{ body: 'mobile-nav-body' }}
      >
        <Sidebar route={route} status={status} onNavigate={navigate} />
      </Drawer>
      <AppShell.Main className="dashboard-main">
        <View route={route} status={status} api={api} navigate={navigate} fixture={fixture} />
      </AppShell.Main>
    </AppShell>
  );
}

function View({
  route,
  status,
  api,
  navigate,
  fixture,
}: {
  route: Route;
  status: Status;
  api: LocalApi;
  navigate: (route: Route) => void;
  fixture: boolean;
}) {
  switch (route.view) {
    case 'captures':
      return <CapturesView api={api} selectedId={route.id} navigate={navigate} />;
    case 'notarizations':
      return (
        <NotarizationsView api={api} selectedId={route.id} navigate={navigate} fixture={fixture} />
      );
    case 'traces':
      return <TracesView api={api} selectedId={route.id} navigate={navigate} />;
    case 'sharing':
      return <SharingView api={api} fixture={fixture} navigate={navigate} />;
    case 'activity':
      return <ActivityView api={api} />;
    case 'settings':
      return <SettingsView status={status} api={api} />;
    default:
      return <OverviewView api={api} status={status} navigate={navigate} />;
  }
}

function OverviewView({
  api,
  status,
  navigate,
}: {
  api: LocalApi;
  status: Status;
  navigate: (route: Route) => void;
}) {
  const isCluster = status.runtime_profile === 'cluster';
  const events = useQuery({ queryKey: ['events'], queryFn: () => api.events() });
  const stats = [
    ['Capturing', status.counts.capturing, 'active'],
    ['Captured', status.counts.captured, 'muted'],
    ['Notarizing', status.counts.notarizing, 'active'],
    ['Notarized', status.counts.notarized, 'ready'],
    ['Needs attention', status.counts.needs_attention + status.counts.capture_failed, 'danger'],
  ] as const;
  return (
    <div className="view-page overview-page">
      <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }} spacing={0} className="service-grid">
        <ServiceFact
          icon={CheckCircle2}
          label={isCluster ? 'Cluster' : 'Service'}
          value={status.capture_enabled ? 'Online' : 'Online · Capture off'}
          detail={
            isCluster
              ? `${status.instance_id ?? 'replica'} · v${status.version}`
              : `v${status.version}`
          }
          tone="ready"
        />
        <ServiceFact
          icon={KeyRound}
          label="Vault"
          value={status.vault}
          detail={isCluster ? 'Shared by cluster replicas' : 'Key material stays local'}
        />
        <ServiceFact
          icon={ShieldCheck}
          label="New requests"
          value={status.capture_enabled ? 'Notarized capture' : 'Direct passthrough'}
          detail={
            status.capture_enabled
              ? 'Provider connection delegated'
              : 'No notary or evidence artifact'
          }
        />
        <ServiceFact
          icon={Activity}
          label="Work queue"
          value={status.counts.notarizing ? 'Active' : 'Idle'}
          detail={`${status.counts.notarizing} operation${status.counts.notarizing === 1 ? '' : 's'}`}
        />
      </SimpleGrid>
      <section className="overview-work">
        <div>
          <Text className="eyebrow">Trace states</Text>
          <div className="count-strip">
            {stats.map(([label, value, tone]) => (
              <UnstyledButton
                key={label}
                onClick={() =>
                  navigate({ view: label === 'Notarizing' ? 'notarizations' : 'captures' })
                }
              >
                <span className={`count-marker count-marker--${tone}`} />
                <b>{value}</b>
                <span>{label}</span>
              </UnstyledButton>
            ))}
          </div>
        </div>
        <Paper className="next-action">
          <Text className="eyebrow">Next action</Text>
          <Title order={2}>
            {status.counts.captured
              ? 'Notarize captured evidence'
              : status.capture_enabled
                ? 'Send a provider request'
                : 'Capture requests are off'}
          </Title>
          <Text>
            {status.counts.captured
              ? `${status.counts.captured} trace${status.counts.captured === 1 ? ' is' : 's are'} captured.`
              : status.capture_enabled
                ? `Point an SDK at the ${isCluster ? 'cluster' : 'local'} provider proxy to create a private capture.`
                : 'Requests still use the provider proxy, but go directly to the provider and create no evidence.'}
          </Text>
          <Button
            onClick={() => navigate({ view: status.counts.captured ? 'captures' : 'settings' })}
          >
            {status.counts.captured
              ? 'Review captures'
              : status.capture_enabled
                ? 'View proxy routes'
                : 'Turn capture on'}
          </Button>
        </Paper>
      </section>
      <section className="recent-section">
        <Group justify="space-between">
          <div>
            <Text className="eyebrow">Recent activity</Text>
            <Title order={2}>What changed</Title>
          </div>
          <Button variant="subtle" onClick={() => navigate({ view: 'activity' })}>
            All activity
          </Button>
        </Group>
        {events.isLoading ? (
          <LoadingState />
        ) : events.error ? (
          <QueryError error={events.error} title="Recent activity is unavailable" />
        ) : (
          <EventList events={events.data?.items.slice(0, 4) ?? []} />
        )}
      </section>
    </div>
  );
}

function ServiceFact({
  icon: Icon,
  label,
  value,
  detail,
  tone,
}: {
  icon: typeof Gauge;
  label: string;
  value: string;
  detail: string;
  tone?: string;
}) {
  return (
    <div className="service-fact">
      <Group justify="space-between">
        <Text className="eyebrow">{label}</Text>
        <Icon size={17} aria-hidden="true" />
      </Group>
      <Title order={3}>{value}</Title>
      <Text>{detail}</Text>
      {tone && <StatusLabel state={tone} />}
    </div>
  );
}

function CapturesView({
  api,
  selectedId,
  navigate,
}: {
  api: LocalApi;
  selectedId?: string;
  navigate: (route: Route) => void;
}) {
  const [query, setQuery] = useState('');
  const [model, setModel] = useState('');
  const [provider, setProvider] = useState<string | null>(null);
  const [traceState, setTraceState] = useState<string | null>(null);
  const [operationalStatus, setOperationalStatus] = useState<string | null>(null);
  const [streaming, setStreaming] = useState<string | null>(null);
  const [time, setTime] = useState<string | null>(null);
  const mobile = useMediaQuery('(max-width: 820px)');
  const createdAfter = useMemo(() => timeRangeStart(time), [time]);
  const captures = useInfiniteQuery({
    queryKey: [
      'captures',
      query,
      model,
      provider,
      traceState,
      operationalStatus,
      streaming,
      createdAfter,
    ],
    queryFn: ({ pageParam }) =>
      api.traces({
        query,
        model,
        provider: provider ?? undefined,
        state: traceState ?? undefined,
        status: operationalStatus ?? undefined,
        streaming: streaming ? streaming === 'streaming' : undefined,
        created_after_unix_ms: createdAfter,
        limit: 50,
        cursor: pageParam,
      }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  });
  const selectedDetail = useQuery({
    queryKey: ['capture', selectedId],
    queryFn: () => api.trace(requiredValue(selectedId, 'selected capture')),
    enabled: Boolean(selectedId),
  });
  const visible = useMemo(
    () => captures.data?.pages.flatMap((page) => page.items) ?? [],
    [captures.data],
  );
  const activeId = selectedId ?? visible[0]?.trace_id;
  const active = visible.find((capture) => capture.trace_id === activeId) ?? selectedDetail.data;
  const showDetail = Boolean(mobile && selectedId);
  return (
    <div className="view-page capture-page">
      {!showDetail && (
        <div className="filter-bar filter-bar--captures">
          <TextInput
            aria-label="Search captures"
            placeholder="Search prompt and output previews"
            leftSection={<Search size={15} />}
            value={query}
            onChange={(event) => setQuery(event.currentTarget.value)}
          />
          <TextInput
            aria-label="Model filter"
            placeholder="All models"
            value={model}
            onChange={(event) => setModel(event.currentTarget.value)}
          />
          <AxisSelect
            ariaLabel="Provider filter"
            placeholder="All providers"
            data={['openai', 'anthropic', 'deepseek', 'openrouter'].map((value) => ({
              value,
              label: <ProviderIdentity provider={value} />,
            }))}
            value={provider}
            onChange={setProvider}
          />
          <AxisSelect
            ariaLabel="Trace state filter"
            placeholder="All trace states"
            data={['captured', 'notarized']}
            value={traceState}
            onChange={setTraceState}
          />
          <AxisSelect
            ariaLabel="Operational status filter"
            placeholder="All operational statuses"
            data={[
              'capturing',
              'capture_failed',
              'notarizing',
              'notarization_failed',
              'notarization_interrupted',
            ]}
            value={operationalStatus}
            onChange={setOperationalStatus}
          />
          <AxisSelect
            ariaLabel="Streaming filter"
            placeholder="Streaming or buffered"
            data={[
              { value: 'streaming', label: 'Streaming' },
              { value: 'buffered', label: 'Buffered' },
            ]}
            value={streaming}
            onChange={setStreaming}
          />
          <AxisSelect
            ariaLabel="Trace time filter"
            placeholder="Any time"
            data={[
              { value: 'hour', label: 'Last hour' },
              { value: 'day', label: 'Last 24 hours' },
              { value: 'week', label: 'Last 7 days' },
            ]}
            value={time}
            onChange={setTime}
          />
        </div>
      )}
      {captures.isLoading || (selectedId && selectedDetail.isLoading) ? (
        <LoadingState />
      ) : captures.error ? (
        <QueryError error={captures.error} title="Captures are unavailable" />
      ) : selectedDetail.error ? (
        <QueryError error={selectedDetail.error} title="Trace detail is unavailable" />
      ) : !visible.length && !active ? (
        <EmptyState
          title="No captures match"
          copy="Clear a filter or send a new request through the provider proxy."
        />
      ) : (
        <ResizableSplit className={`master-detail ${showDetail ? 'show-detail' : ''}`}>
          <ScrollArea className="master-list" type="auto">
            <ul className="capture-list" aria-label="Captures">
              {visible.map((capture) => (
                <li key={capture.trace_id}>
                  <CaptureRow
                    capture={capture}
                    active={capture.trace_id === activeId}
                    onClick={() => navigate({ view: 'captures', id: capture.trace_id })}
                  />
                </li>
              ))}
            </ul>
            {captures.hasNextPage && (
              <Button
                className="load-more"
                variant="subtle"
                loading={captures.isFetchingNextPage}
                onClick={() => captures.fetchNextPage()}
              >
                Load more captures
              </Button>
            )}
          </ScrollArea>
          <div className="detail-panel">
            {active ? (
              <CaptureInspector
                api={api}
                capture={active}
                mobile={Boolean(mobile)}
                onBack={() => navigate({ view: 'captures' })}
                navigate={navigate}
              />
            ) : null}
          </div>
        </ResizableSplit>
      )}
    </div>
  );
}

function CaptureRow({
  capture,
  active,
  onClick,
}: {
  capture: TraceSummary;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <UnstyledButton className={`capture-row ${active ? 'is-active' : ''}`} onClick={onClick}>
      <span className="capture-row-state">
        <StatusLabel state={traceDisplayStatus(capture)} />
      </span>
      <span className="capture-row-copy">
        <b>{capture.requested_model ?? 'Model not reported'}</b>
        <small>
          <ProviderIdentity provider={capture.provider} detail={capture.operation} />
        </small>
      </span>
      <time className="mono-time">{formatDate(capture.created_at_unix_ms)}</time>
    </UnstyledButton>
  );
}

function CaptureInspector({
  api,
  capture,
  mobile,
  onBack,
  navigate,
}: {
  api: LocalApi;
  capture: TraceSummary;
  mobile: boolean;
  onBack: () => void;
  navigate: (route: Route) => void;
}) {
  const queryClient = useQueryClient();
  const detail = useQuery({
    queryKey: ['capture', capture.trace_id],
    queryFn: () => api.trace(capture.trace_id),
  });
  const notarize = useMutation({
    mutationFn: () => api.startNotarization(capture.trace_id),
    onSuccess: (result) => {
      notifications.show({
        title: result.deduplicated ? 'Already in the queue' : 'Notarization queued',
        message: result.deduplicated
          ? 'The existing operation remains active.'
          : 'Proof generation will run in the background.',
      });
      queryClient.invalidateQueries({ queryKey: ['captures'] });
      queryClient.invalidateQueries({ queryKey: ['capture', capture.trace_id] });
      queryClient.invalidateQueries({ queryKey: ['operations'] });
      queryClient.invalidateQueries({ queryKey: ['status'] });
      queryClient.invalidateQueries({ queryKey: ['events'] });
      navigate({ view: 'captures', id: capture.trace_id });
    },
    onError: (error) => mutationError('Could not notarize', error),
  });
  if (detail.isLoading) return <LoadingState />;
  if (detail.error) return <QueryError error={detail.error} title="Trace detail is unavailable" />;
  const value = detail.data;
  if (!value)
    return <ErrorState title="Trace detail is unavailable" onRetry={() => detail.refetch()} />;
  const incompatibleProviderResponse =
    captureStatus(capture) === 'captured' &&
    capture.notarization_ineligibility_code === 'unsupported_provider_http_status';
  const canNotarize =
    captureStatus(capture) === 'captured' &&
    notarizationStatus(capture) === 'not_requested' &&
    capture.notarization_eligible;
  return (
    <article className="inspector capture-inspector">
      {mobile && (
        <Button variant="subtle" leftSection={<ArrowLeft size={15} />} onClick={onBack}>
          All captures
        </Button>
      )}
      <div className="inspector-head">
        <div>
          <Text className="eyebrow">Trace detail</Text>
          <Title order={2}>{capture.requested_model ?? 'Unreported model'}</Title>
          <Text className="mono-id">{capture.trace_id}</Text>
        </div>
        <Group>
          {canNotarize && (
            <Button
              loading={notarize.isPending}
              leftSection={<Play size={15} />}
              onClick={() => notarize.mutate()}
            >
              Notarize
            </Button>
          )}
        </Group>
      </div>
      <Lifecycle capture={capture} />
      {incompatibleProviderResponse && (
        <div className="notarization-ineligible-note" role="status">
          <XCircle size={18} aria-hidden="true" />
          <div>
            <b>Provider response cannot be notarized</b>
            <Text>
              The provider returned HTTP {capture.http_status}. Notarization currently supports
              successful provider responses only.
            </Text>
            <code>{capture.notarization_ineligibility_code}</code>
          </div>
        </div>
      )}
      <InspectorSection title="Safe metadata">
        <dl className="metadata-grid">
          <Fact label="Provider" value={<ProviderIdentity provider={capture.provider} />} />
          <Fact label="Operation" value={capture.operation} />
          <Fact label="HTTP status" value={capture.http_status?.toString() ?? 'In progress'} />
          <Fact label="Streaming" value={capture.streaming ? 'Yes' : 'No'} />
          <Fact label="Request" value={formatBytes(capture.request_bytes)} />
          <Fact label="Response" value={formatBytes(capture.response_bytes)} />
        </dl>
      </InspectorSection>
      <InspectorSection title="Privacy-aware previews">
        <div className="preview-block">
          <Text className="eyebrow">
            Prompt {capture.prompt_preview_truncated && '· truncated'}
          </Text>
          <Text>{capture.prompt_preview || 'Preview storage is disabled.'}</Text>
        </div>
        <div className="preview-block">
          <Text className="eyebrow">
            Output {capture.output_preview_truncated && '· truncated'}
          </Text>
          <Text>{capture.output_preview || 'No output preview is available yet.'}</Text>
        </div>
      </InspectorSection>
      <InspectorSection title="Retained artifacts">
        <ArtifactList detail={value} />
      </InspectorSection>
      <InspectorSection title="Notarization history">
        {value.notarization ? (
          <OperationInspector api={api} operation={value.notarization} fixture={false} />
        ) : (
          <Text className="empty-copy">No notarization has been requested for this capture.</Text>
        )}
      </InspectorSection>
    </article>
  );
}

function Lifecycle({ capture }: { capture: TraceSummary }) {
  const steps = [
    { label: 'Captured', state: captureStatus(capture) === 'capturing' ? 'active' : 'ready' },
    {
      label: 'Capture checkpoint encrypted',
      state:
        captureStatus(capture) === 'captured'
          ? 'ready'
          : captureStatus(capture) === 'failed'
            ? 'danger'
            : 'muted',
    },
    {
      label: 'Notarized',
      state:
        notarizationStatus(capture) === 'succeeded'
          ? 'ready'
          : ['running', 'queued'].includes(notarizationStatus(capture))
            ? 'active'
            : notarizationStatus(capture) === 'failed'
              ? 'danger'
              : 'muted',
    },
  ];
  return (
    <ol className="lifecycle" aria-label="Trace lifecycle">
      {steps.map((step) => (
        <li key={step.label} className={`lifecycle--${step.state}`}>
          <span aria-hidden="true" />
          <b>{step.label}</b>
        </li>
      ))}
    </ol>
  );
}

function InspectorSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="inspector-section">
      <Title order={3}>{title}</Title>
      {children}
    </section>
  );
}

function Fact({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function ArtifactList({ detail }: { detail: TraceDetail }) {
  return (
    <div className="artifact-list">
      {detail.artifacts.map((artifact) => (
        <div key={artifact.kind}>
          <FileJson2 size={17} aria-hidden="true" />
          <div>
            <b>{artifact.kind.replaceAll('_', ' ')}</b>
            <span>{formatBytes(artifact.size_bytes)}</span>
          </div>
          <code>{artifact.sha256.slice(0, 12)}…</code>
        </div>
      ))}
    </div>
  );
}

function NotarizationsView({
  api,
  selectedId,
  navigate,
  fixture,
}: {
  api: LocalApi;
  selectedId?: string;
  navigate: (route: Route) => void;
  fixture: boolean;
}) {
  const operations = useInfiniteQuery({
    queryKey: ['operations'],
    queryFn: ({ pageParam }) => api.operations({ limit: 50, cursor: pageParam }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (page) => page.next_cursor ?? undefined,
    refetchInterval: 3_000,
  });
  const activeId = selectedId ?? operations.data?.pages[0]?.items[0]?.operation_id;
  const selectedOperation = useQuery({
    queryKey: ['operation', activeId],
    queryFn: () => api.operation(requiredValue(activeId, 'active operation')),
    enabled: Boolean(activeId),
    refetchInterval: (query) =>
      ['queued', 'running'].includes(query.state.data?.state ?? '') ? 1_000 : false,
  });
  const items = operations.data?.pages.flatMap((page) => page.items) ?? [];
  const active = selectedOperation.data;
  return (
    <div className="view-page">
      {operations.isLoading || (activeId && selectedOperation.isLoading) ? (
        <LoadingState />
      ) : operations.error ? (
        <QueryError error={operations.error} title="Notarizations are unavailable" />
      ) : selectedOperation.error ? (
        <QueryError error={selectedOperation.error} title="Notarization detail is unavailable" />
      ) : !items.length && !active ? (
        <EmptyState
          icon={ListChecks}
          title="No notarizations yet"
          copy="Queue one from a captured provider response."
        />
      ) : (
        <ResizableSplit className="operations-layout">
          <ScrollArea className="operations-list-scroll" type="auto">
            <ul className="operations-list" aria-label="Notarizations">
              {items.map((operation) => (
                <li key={operation.operation_id}>
                  <OperationRow
                    operation={operation}
                    active={active?.operation_id === operation.operation_id}
                    onClick={() => navigate({ view: 'notarizations', id: operation.operation_id })}
                  />
                </li>
              ))}
            </ul>
            {operations.hasNextPage && (
              <Button
                className="load-more"
                variant="subtle"
                loading={operations.isFetchingNextPage}
                onClick={() => operations.fetchNextPage()}
              >
                Load more notarizations
              </Button>
            )}
          </ScrollArea>
          {active ? <OperationInspector api={api} operation={active} fixture={fixture} /> : <div />}
        </ResizableSplit>
      )}
    </div>
  );
}

function OperationRow({
  operation,
  active,
  onClick,
}: {
  operation: OperationSummary;
  active: boolean;
  onClick: () => void;
}) {
  const percent = proofPercent(operation);
  return (
    <UnstyledButton
      className={`operation-row ${active ? 'is-active' : ''}`}
      onClick={onClick}
      aria-label={`Inspect ${operation.operation_id}`}
    >
      <span className="operation-row-top">
        <StatusLabel state={operation.state} />
        <time>{formatDate(operation.created_at_unix_ms)}</time>
      </span>
      <code>{operation.trace_id ?? 'Trace not reported'}</code>
      <small>
        {percent === null
          ? notarizationPhaseLabel(operation.progress.phase)
          : `${percent}% transcript authenticated`}{' '}
        · Attempt {operation.attempt}
      </small>
    </UnstyledButton>
  );
}

function ProofProgress({ operation }: { operation: Operation }) {
  const proof = operation.progress.proof;
  if (!proof?.bytes_total) {
    if (!['queued', 'running'].includes(operation.state)) return null;
    return (
      <div className="proof-phase-status" role="status">
        <i className="proof-phase-marker" aria-hidden="true" />
        <div>
          <b>{notarizationPhaseLabel(operation.progress.phase)}</b>
          <span>Proof-work totals will appear when transcript authentication starts.</span>
        </div>
      </div>
    );
  }
  const percent = proofPercent(operation) ?? 0;
  return (
    <section className="proof-work" aria-label="Private proof progress">
      <header>
        <div>
          <Text className="eyebrow">Authenticated transcript</Text>
          <b>
            {formatBytes(proof.bytes_completed)} <span>/ {formatBytes(proof.bytes_total)}</span>
          </b>
        </div>
        <strong>{percent}%</strong>
      </header>
      <div
        className="proof-work-track"
        role="progressbar"
        aria-label="Private transcript bytes authenticated"
        aria-valuemin={0}
        aria-valuemax={proof.bytes_total}
        aria-valuenow={proof.bytes_completed}
        aria-valuetext={`${formatBytes(proof.bytes_completed)} of ${formatBytes(proof.bytes_total)}`}
      >
        <i style={{ width: `${percent}%` }} />
      </div>
      <footer>
        <span>
          {proof.commitments_completed} / {proof.commitments_total} commitments sealed
        </span>
        <span>{notarizationPhaseLabel(operation.progress.phase)}</span>
      </footer>
    </section>
  );
}

function OperationInspector({
  api,
  operation,
  fixture,
}: {
  api: LocalApi;
  operation: Operation;
  fixture: boolean;
}) {
  const queryClient = useQueryClient();
  const retry = useMutation({
    mutationFn: () => api.startNotarization(operation.trace_id),
    onSuccess: (updated) => {
      notifications.show({
        title: 'Retry queued',
        message: 'The same durable operation will make another attempt.',
      });
      queryClient.setQueryData(['operation', operation.operation_id], updated.operation);
      queryClient.invalidateQueries({ queryKey: ['operations'] });
      queryClient.invalidateQueries({ queryKey: ['captures'] });
      queryClient.invalidateQueries({ queryKey: ['capture', operation.trace_id] });
      queryClient.invalidateQueries({ queryKey: ['status'] });
      queryClient.invalidateQueries({ queryKey: ['events'] });
    },
    onError: (error) => mutationError('Could not retry notarization', error),
  });
  const retryable = operation.retryable;
  return (
    <Paper className="operation-inspector">
      <Text className="eyebrow">Selected operation</Text>
      <Group justify="space-between" align="flex-start">
        <div>
          <Title order={2}>
            {operation.state === 'running'
              ? fixture
                ? 'Simulated proof generation'
                : notarizationPhaseLabel(operation.progress.phase)
              : operation.state.replaceAll('_', ' ')}
          </Title>
          <Text className="mono-id">{operation.operation_id}</Text>
        </div>
        <StatusLabel state={operation.state} />
      </Group>
      {fixture && (
        <div className="fixture-flow-note operation-fixture-note">
          <Database size={16} aria-hidden="true" />
          <Text>
            <b>Simulation only.</b> No proof worker is running. Times are relative to when this
            preview was opened.
          </Text>
        </div>
      )}
      <ProofProgress operation={operation} />
      <dl className="receipt-list">
        <Fact label="Trace" value={operation.trace_id ?? '—'} />
        <Fact label="Attempt" value={String(operation.attempt)} />
        <Fact label="Started" value={formatDate(operation.started_at_unix_ms)} />
        <Fact label="Finished" value={formatDate(operation.completed_at_unix_ms)} />
        {operation.failure_code && (
          <Fact label="Safe failure code" value={operation.failure_code} />
        )}
      </dl>
      <div className="attempt-history">
        <Text className="eyebrow">Attempt history</Text>
        {operation.attempt_history.length ? (
          <ol className="history-list">
            {operation.attempt_history.map((attempt) => (
              <li key={attempt.attempt}>
                <div>
                  <Group gap="xs">
                    <b>Attempt {attempt.attempt}</b>
                    <StatusLabel state={attempt.state} />
                  </Group>
                  <Text>
                    {formatDate(attempt.started_at_unix_ms)} →{' '}
                    {formatDate(attempt.completed_at_unix_ms)}
                  </Text>
                  {attempt.failure_code && <code>{attempt.failure_code}</code>}
                </div>
              </li>
            ))}
          </ol>
        ) : (
          <Text className="empty-copy">No proof attempt has started yet.</Text>
        )}
      </div>
      {retryable && (
        <Button
          leftSection={<RefreshCw size={15} />}
          loading={retry.isPending}
          onClick={() => retry.mutate()}
        >
          Retry notarization
        </Button>
      )}
    </Paper>
  );
}

function TracesView({
  api,
  selectedId,
  navigate,
}: {
  api: LocalApi;
  selectedId?: string;
  navigate: (route: Route) => void;
}) {
  const [query, setQuery] = useState('');
  const mobile = useMediaQuery('(max-width: 820px)');
  const captures = useInfiniteQuery({
    queryKey: ['captures', 'succeeded', query],
    queryFn: ({ pageParam }) =>
      api.traces({ state: 'notarized', query, limit: 50, cursor: pageParam }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  });
  const visible = captures.data?.pages.flatMap((page) => page.items) ?? [];
  const activeId = selectedId ?? visible[0]?.trace_id;
  const showDetail = Boolean(mobile && selectedId);
  return (
    <div className="view-page">
      {!showDetail && (
        <div className="filter-bar filter-bar--short">
          <TextInput
            aria-label="Search notarized traces"
            placeholder="Search notarized traces"
            leftSection={<Search size={15} />}
            value={query}
            onChange={(event) => setQuery(event.currentTarget.value)}
          />
        </div>
      )}
      {captures.isLoading ? (
        <LoadingState />
      ) : captures.error ? (
        <QueryError error={captures.error} title="Notarized traces are unavailable" />
      ) : !visible.length && !selectedId ? (
        <EmptyState
          icon={FileCheck2}
          title="No notarized traces"
          copy="Notarize a captured provider response or clear the search."
        />
      ) : (
        <ResizableSplit className={`trace-layout ${showDetail ? 'show-detail' : ''}`}>
          {!showDetail ? (
            <div>
              <ul className="trace-list" aria-label="Notarized traces">
                {visible.map((capture) => (
                  <li key={capture.trace_id}>
                    <CaptureRow
                      capture={capture}
                      active={capture.trace_id === activeId}
                      onClick={() => navigate({ view: 'traces', id: capture.trace_id })}
                    />
                  </li>
                ))}
              </ul>
              {captures.hasNextPage && (
                <Button
                  className="load-more"
                  variant="subtle"
                  loading={captures.isFetchingNextPage}
                  onClick={() => captures.fetchNextPage()}
                >
                  Load more traces
                </Button>
              )}
            </div>
          ) : (
            <div />
          )}
          {activeId && (!mobile || selectedId) ? (
            <TraceInspector
              api={api}
              captureId={activeId}
              mobile={Boolean(mobile)}
              onBack={() => navigate({ view: 'traces' })}
            />
          ) : (
            <div />
          )}
        </ResizableSplit>
      )}
    </div>
  );
}

function TraceInspector({
  api,
  captureId,
  mobile,
  onBack,
}: {
  api: LocalApi;
  captureId: string;
  mobile: boolean;
  onBack: () => void;
}) {
  const trace = useQuery({
    queryKey: ['trace', captureId],
    queryFn: () => api.traceContent(captureId),
  });
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
      if (currentCapture.current !== result.trace_id) return;
      setVerification(result);
      setActiveTab('verification');
      notifications.show({
        title: 'Trace verified',
        message: 'The package passed every local verification check.',
      });
    },
    onError: (error) => mutationError('Trace verification failed', error),
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
      notifications.show({
        title: 'Verified package downloaded',
        message: 'Keep the .llmtrace file to verify or share privately.',
      });
    },
    onError: (error) => mutationError('Could not download verified package', error),
  });
  if (trace.isLoading) return <LoadingState />;
  if (trace.error) return <QueryError error={trace.error} title="Trace package is unavailable" />;
  if (!trace.data)
    return <ErrorState title="Trace package is unavailable" onRetry={() => trace.refetch()} />;
  const manifest = asRecord(trace.data.manifest);
  const source = asRecord(manifest.source);
  const provider = asRecord(source.provider);
  const providerName = typeof provider.name === 'string' ? provider.name : null;
  const providerHost = typeof provider.host === 'string' ? provider.host : null;
  const providerLabel = [providerName, providerHost].filter(Boolean).join(' · ') || 'Not reported';
  const traceDigest =
    typeof manifest.trace_sha256 === 'string' ? manifest.trace_sha256 : 'Not reported';
  const transcripts = traceTranscripts(trace.data.trace);
  return (
    <article className="trace-inspector">
      {mobile && (
        <Button variant="subtle" leftSection={<ArrowLeft size={15} />} onClick={onBack}>
          All notarized traces
        </Button>
      )}
      <Group justify="space-between" align="flex-start">
        <div>
          <Text className="eyebrow">Verified trace package</Text>
          <Title order={2}>{captureId}</Title>
        </div>
        <Group>
          <Button
            leftSection={<Download size={15} />}
            loading={download.isPending}
            onClick={() => download.mutate()}
          >
            Download verified package
          </Button>
          <Button
            variant="outline"
            leftSection={<ShieldCheck size={15} />}
            loading={verify.isPending}
            onClick={() => verify.mutate()}
          >
            Verify locally
          </Button>
        </Group>
      </Group>
      <Tabs value={activeTab} onChange={setActiveTab} keepMounted={false}>
        <Tabs.List>
          <Tabs.Tab value="summary">Summary</Tabs.Tab>
          <Tabs.Tab value="evidence">Evidence</Tabs.Tab>
          <Tabs.Tab value="trace">Trace</Tabs.Tab>
          <Tabs.Tab value="verification">Verification</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="summary">
          <div className="document-panel">
            <Title order={3}>Authenticated inference</Title>
            <Text>
              The package contains the disclosed provider exchange, its canonical OpenTelemetry
              trace, and the supporting TLSNotary evidence.
            </Text>
            <dl className="metadata-grid">
              <Fact label="Trace" value={captureId} />
              <Fact
                label="Format"
                value={typeof manifest.format === 'string' ? manifest.format : 'Not reported'}
              />
              <Fact
                label="Normalizer"
                value={
                  typeof manifest.normalizer_version === 'string'
                    ? manifest.normalizer_version
                    : 'Not reported'
                }
              />
              <Fact
                label="Provider"
                value={
                  <ProviderIdentity
                    provider={providerName}
                    fallback="Not reported"
                    detail={providerHost}
                  />
                }
              />
            </dl>
            <TraceTranscriptView transcripts={transcripts} />
          </div>
        </Tabs.Panel>
        <Tabs.Panel value="evidence">
          <Receipt
            title="Evidence receipt"
            fields={[
              ['Trace SHA-256', traceDigest],
              ['Provider', providerLabel],
              [
                'Source created',
                typeof source.created_at_unix_ms === 'number'
                  ? formatDate(source.created_at_unix_ms)
                  : 'Not reported',
              ],
              [
                'Manifest format',
                typeof manifest.format === 'string' ? manifest.format : 'Not reported',
              ],
            ]}
          />
        </Tabs.Panel>
        <Tabs.Panel value="trace">
          <pre className="json-view">{JSON.stringify(trace.data.trace, null, 2)}</pre>
        </Tabs.Panel>
        <Tabs.Panel value="verification">
          {verification ? (
            <Receipt
              title="Verification passed"
              verified
              fields={[
                ['Trace', verification.trace_id ?? 'Not reported'],
                ['Verified at', formatDate(verification.verified_at_unix_ms)],
                ['Notary key', verification.notary_key_id ?? 'Not reported'],
                ['Trust source', verification.trust_source ?? 'Not reported'],
              ]}
            />
          ) : (
            <EmptyState
              icon={ShieldCheck}
              title="Run an independent check"
              copy="Verification replays the provider adapter and checks every authenticated artifact."
            />
          )}
        </Tabs.Panel>
      </Tabs>
    </article>
  );
}

function TraceTranscriptView({ transcripts }: { transcripts: TraceTranscript[] }) {
  const messageCount = transcripts.reduce(
    (count, transcript) => count + transcript.input.length + transcript.output.length,
    0,
  );
  return (
    <section className="trace-transcript" aria-label="Disclosed prompt and response">
      <div className="trace-transcript-heading">
        <div>
          <Text className="eyebrow">Disclosed trace contents</Text>
          <Title order={3}>Prompt and response</Title>
        </div>
        <Text>{messageCount} messages</Text>
      </div>
      {!transcripts.length ? (
        <Text className="trace-transcript-empty">
          This trace does not disclose message contents.
        </Text>
      ) : (
        transcripts.map((transcript, inferenceIndex) => {
          const messages = [
            ...transcript.input.map((message) => ({ flow: 'Prompt', message })),
            ...transcript.output.map((message) => ({ flow: 'Response', message })),
          ];
          return (
            <section className="trace-inference" key={`${transcript.model}-${inferenceIndex}`}>
              {transcripts.length > 1 && (
                <Text className="trace-inference-label">
                  Inference {inferenceIndex + 1} · {transcript.model}
                </Text>
              )}
              <div className="trace-message-list">
                {messages.map(({ flow, message }, messageIndex) => (
                  <TraceMessageView key={`${flow}-${messageIndex}`} flow={flow} message={message} />
                ))}
              </div>
            </section>
          );
        })
      )}
    </section>
  );
}

function TraceMessageView({ flow, message }: { flow: string; message: TraceMessage }) {
  return (
    <article className="trace-message">
      <header>
        <span>{flow}</span>
        <b>{message.role}</b>
        {message.finishReason && <em>{message.finishReason}</em>}
      </header>
      <div className="trace-message-body">
        {message.parts.length ? (
          message.parts.map((part, index) =>
            part.kind === 'text' ? (
              <p key={index}>{part.text}</p>
            ) : (
              <div className="trace-structured-part" key={index}>
                <span>{part.kind}</span>
                <pre>{part.text}</pre>
              </div>
            ),
          )
        ) : (
          <p className="trace-transcript-empty">No disclosed content.</p>
        )}
      </div>
    </article>
  );
}

function Receipt({
  title,
  fields,
  verified = false,
}: {
  title: string;
  fields: Array<[string, string]>;
  verified?: boolean;
}) {
  return (
    <div className="receipt">
      <Group justify="space-between">
        <Text className="eyebrow">{title}</Text>
        {verified && <StatusLabel state="verified" />}
      </Group>
      <dl>
        {fields.map(([label, value]) => (
          <Fact key={label} label={label} value={value} />
        ))}
      </dl>
    </div>
  );
}

function SharingView({
  api,
  fixture,
  navigate,
}: {
  api: LocalApi;
  fixture: boolean;
  navigate: (route: Route) => void;
}) {
  const accountConnection = useAccountConnection(api);
  const { account } = accountConnection;
  const captures = useInfiniteQuery({
    queryKey: ['captures', 'sharing'],
    queryFn: ({ pageParam }) => api.traces({ state: 'notarized', limit: 50, cursor: pageParam }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  });
  const [selected, setSelected] = useState<string | null>(null);
  const [visibility, setVisibility] = useState<ShareVisibility>('unlisted');
  const [confirm, setConfirm] = useState(false);
  const [submitted, setSubmitted] = useState<Share | null>(null);
  const eligible = captures.data?.pages.flatMap((page) => page.items) ?? [];
  const selectedId = selected ?? eligible[0]?.trace_id ?? null;
  const preview = useQuery({
    queryKey: ['share-preview', selectedId],
    queryFn: () => api.traceContent(requiredValue(selectedId, 'selected capture')),
    enabled: Boolean(selectedId),
  });
  useEffect(() => {
    setSubmitted(null);
    setConfirm(false);
  }, [selectedId, visibility]);
  const share = useQuery({
    queryKey: ['share', submitted?.trace_id],
    queryFn: () => api.shareStatus(requiredValue(submitted, 'submitted share').trace_id),
    enabled: Boolean(submitted),
    refetchInterval: (query) => {
      const progress = query.state.data?.progress;
      return progress && ['shared', 'rejected', 'failed'].includes(progress) ? false : 3_000;
    },
  });
  const createShare = useMutation({
    mutationFn: () => api.share(requiredValue(selectedId, 'selected capture'), visibility),
    onSuccess: (result) => {
      setConfirm(false);
      setSubmitted(result);
      notifications.show({
        title: 'Share started',
        message: 'The package is uploaded and awaiting verification.',
      });
    },
    onError: (error) => mutationError('Sharing failed', error),
  });
  const shareState = share.data?.progress ?? submitted?.progress;
  const shareUrl = share.data?.share_url ?? submitted?.share_url;
  const packageUrl = share.data?.package_url ?? submitted?.package_url;
  const transcripts = preview.data ? traceTranscripts(preview.data.trace) : [];
  const copyShareLink = async () => {
    if (!shareUrl) return;
    await navigator.clipboard.writeText(shareUrl);
    notifications.show({ title: 'URL copied', message: 'The share URL is on the clipboard.' });
  };
  const resultTitle =
    shareState === 'shared'
      ? 'Share ready'
      : shareState === 'rejected'
        ? 'Share rejected'
        : shareState === 'failed'
          ? 'Verification failed'
          : 'Checking share';
  const resultCopy =
    shareState === 'shared'
      ? `${submitted?.visibility === 'listed' ? 'Listed' : 'Unlisted'} · Anyone with the URL can open it.`
      : shareState === 'rejected'
        ? 'The package was rejected before a public URL was created.'
        : shareState === 'failed'
          ? 'Verification could not finish. Refresh the status or try again.'
          : 'Uploaded. Checking the package and evidence.';
  const confirmationTitle = visibility === 'listed' ? 'List this share?' : 'Create this share?';
  const confirmationCopy =
    visibility === 'listed'
      ? 'This share will appear in Library. Anyone can read the disclosed messages and tool data. Header values remain hidden.'
      : 'Anyone with the URL can read the disclosed messages and tool data. Header values remain hidden.';

  return (
    <div className="view-page share-flow">
      <section className="sharing-toolbar" aria-label="Share settings">
        {captures.error ? (
          <QueryError error={captures.error} title="Notarized traces are unavailable" />
        ) : captures.isLoading ? (
          <Loader size="sm" />
        ) : eligible.length ? (
          <>
            <div className="sharing-trace-picker">
              <AxisSelect
                label="Trace"
                placeholder="Choose a notarized trace"
                clearable={false}
                data={eligible.map((capture) => ({
                  value: capture.trace_id,
                  label: (
                    <ProviderIdentity
                      provider={capture.provider}
                      detail={capture.requested_model}
                    />
                  ),
                }))}
                value={selectedId}
                onChange={setSelected}
              />
              {captures.hasNextPage && (
                <Button
                  variant="subtle"
                  loading={captures.isFetchingNextPage}
                  onClick={() => captures.fetchNextPage()}
                >
                  Load more traces
                </Button>
              )}
            </div>
            <div className="share-visibility" role="radiogroup" aria-label="Visibility">
              <span className="share-control-label">Visibility</span>
              <div>
                <button
                  type="button"
                  role="radio"
                  aria-checked={visibility === 'unlisted'}
                  className={visibility === 'unlisted' ? 'active' : ''}
                  onClick={() => setVisibility('unlisted')}
                >
                  <b>Unlisted</b>
                  <small>URL access</small>
                </button>
                <button
                  type="button"
                  role="radio"
                  aria-checked={visibility === 'listed'}
                  className={visibility === 'listed' ? 'active' : ''}
                  onClick={() => setVisibility('listed')}
                >
                  <b>Listed</b>
                  <small>Shown in Library</small>
                </button>
              </div>
            </div>
            <Button
              className="share-primary"
              disabled={
                !account.data?.signed_in ||
                !selectedId ||
                preview.isLoading ||
                Boolean(preview.error)
              }
              onClick={() => setConfirm(true)}
            >
              Share trace
            </Button>
          </>
        ) : (
          <EmptyState title="Nothing ready to share" copy="Notarize a capture first." />
        )}
      </section>
      {submitted && (
        <section className={`share-result share-result--${shareState ?? 'queued'}`}>
          <Group justify="space-between">
            <div>
              <Text className="eyebrow">Share status</Text>
              <Title order={2}>{resultTitle}</Title>
            </div>
            <StatusLabel state={shareState ?? 'queued'} />
          </Group>
          <Text>{resultCopy}</Text>
          <code>{submitted.share_id}</code>
          {share.data?.failure_code && (
            <Text>
              Failure code: <code>{share.data.failure_code}</code>
            </Text>
          )}
          {share.error && <QueryError error={share.error} title="Share status is unavailable" />}
          <Group>
            {shareUrl && (
              <Button onClick={copyShareLink} leftSection={<Copy size={15} />}>
                Copy URL
              </Button>
            )}
            {shareUrl && (
              <Button
                component="a"
                href={shareUrl}
                target="_blank"
                rel="noreferrer"
                variant="outline"
              >
                Open share
              </Button>
            )}
            {packageUrl && (
              <Button component="a" href={packageUrl} variant="outline">
                Download .llmtrace
              </Button>
            )}
            {!shareUrl && (
              <Button variant="outline" loading={share.isFetching} onClick={() => share.refetch()}>
                Refresh status
              </Button>
            )}
            {fixture && shareState === 'shared' && (
              <Button
                variant="subtle"
                onClick={() => navigate({ view: 'traces', id: submitted.trace_id })}
              >
                Open local trace
              </Button>
            )}
          </Group>
        </section>
      )}
      <div className="sharing-grid">
        <Paper className="sharing-preview">
          {preview.isLoading ? (
            <LoadingState label="Loading preview" />
          ) : preview.error ? (
            <QueryError error={preview.error} title="Preview is unavailable" />
          ) : preview.data ? (
            <TraceTranscriptView transcripts={transcripts} />
          ) : (
            <EmptyState
              title="Choose a trace"
              copy="Select a notarized trace to preview its disclosed content."
            />
          )}
        </Paper>
        <Paper className="sharing-controls">
          <section className="sharing-disclosure">
            <Group justify="space-between">
              <Text className="eyebrow">Disclosure</Text>
              <ShieldCheck size={16} />
            </Group>
            <dl className="sharing-facts">
              <Fact label="Visible" value="Prompts, responses, tools" />
              <Fact label="Hidden" value="HTTP header values" />
              <Fact
                label="Access"
                value={visibility === 'listed' ? 'Library and URL' : 'URL only'}
              />
              <Fact label="Checks" value="Safety and cryptographic verification" />
            </dl>
          </section>
          <div className="share-package-preview">
            <FileCheck2 size={18} />
            <div>
              <b>.llmtrace included</b>
              <Text>Size and SHA-256 appear on the share.</Text>
            </div>
          </div>
          <div className="sharing-account">
            <Group justify="space-between">
              <Text className="eyebrow">Account</Text>
              <KeyRound size={16} />
            </Group>
            <AccountConnectionCard
              controller={accountConnection}
              compact={true}
              fixture={fixture}
            />
          </div>
        </Paper>
      </div>
      <AlertDialog open={confirm} onOpenChange={setConfirm}>
        <AlertDialogContent className="axis-local-dialog">
          <AlertDialogHeader>
            <AlertDialogTitle>{confirmationTitle}</AlertDialogTitle>
            <AlertDialogDescription>{confirmationCopy}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              disabled={createShare.isPending}
              onClick={() => createShare.mutate()}
            >
              {createShare.isPending
                ? 'Sharing…'
                : visibility === 'listed'
                  ? 'List share'
                  : 'Create share'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
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
    trace_id: captureId,
    operation_id: operationId,
    event_type: eventType,
    created_after_unix_ms: createdAfter,
  };
  const events = useInfiniteQuery({
    queryKey: ['events', filters],
    queryFn: ({ pageParam }) => api.events({ ...filters, limit: 50, cursor: pageParam }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (page) => page.next_cursor ?? undefined,
    refetchInterval: 5_000,
  });
  const visible = events.data?.pages.flatMap((page) => page.items) ?? [];
  return (
    <div className="view-page">
      <div className="filter-bar filter-bar--activity">
        <AxisSelect
          ariaLabel="Activity severity"
          placeholder="All severities"
          data={['info', 'success', 'warning', 'error']}
          value={severity}
          onChange={setSeverity}
        />
        <TextInput
          aria-label="Activity trace ID"
          placeholder="Trace ID"
          value={captureId}
          onChange={(event) => setCaptureId(event.currentTarget.value)}
        />
        <TextInput
          aria-label="Activity operation ID"
          placeholder="Operation ID"
          value={operationId}
          onChange={(event) => setOperationId(event.currentTarget.value)}
        />
        <TextInput
          aria-label="Activity event type"
          placeholder="Event type"
          value={eventType}
          onChange={(event) => setEventType(event.currentTarget.value)}
        />
        <AxisSelect
          ariaLabel="Activity time filter"
          placeholder="Any time"
          data={[
            { value: 'hour', label: 'Last hour' },
            { value: 'day', label: 'Last 24 hours' },
            { value: 'week', label: 'Last 7 days' },
          ]}
          value={time}
          onChange={setTime}
        />
        <Button
          variant="outline"
          leftSection={<RefreshCw size={14} />}
          onClick={() => events.refetch()}
        >
          Refresh
        </Button>
      </div>
      {events.isLoading ? (
        <LoadingState />
      ) : events.error ? (
        <QueryError error={events.error} title="Activity is unavailable" />
      ) : visible.length ? (
        <>
          <EventList events={visible} />
          {events.hasNextPage && (
            <Button
              className="load-more"
              variant="subtle"
              loading={events.isFetchingNextPage}
              onClick={() => events.fetchNextPage()}
            >
              Load more activity
            </Button>
          )}
        </>
      ) : (
        <EmptyState
          icon={Activity}
          title="No activity"
          copy="New capture and notarization events will appear here."
        />
      )}
    </div>
  );
}

function EventList({ events }: { events: Event[] }) {
  if (!events.length)
    return (
      <EmptyState
        icon={Activity}
        title="No recent activity"
        copy="The local event history is empty."
      />
    );
  return (
    <div className="event-list">
      {events.map((event) => (
        <div key={event.event_id} className="event-row">
          <ThemeIcon
            variant="transparent"
            className={`event-icon event-icon--${stateTone(event.severity)}`}
          >
            {event.severity === 'error' ? (
              <XCircle size={17} />
            ) : event.severity === 'success' ? (
              <Check size={17} />
            ) : (
              <CircleDot size={17} />
            )}
          </ThemeIcon>
          <div>
            <Group gap="xs">
              <b>{event.message}</b>
              <StatusLabel state={event.severity} />
            </Group>
            <Text>{event.trace_id ?? event.operation_id ?? event.event_type}</Text>
          </div>
          <time>{formatDate(event.created_at_unix_ms)}</time>
        </div>
      ))}
    </div>
  );
}

function LocalNotaryRecord({
  record,
  activeKeyId,
}: {
  record: Notary;
  activeKeyId?: string | null;
}) {
  const lifecycle = notaryLifecycle(record.lifecycle);
  const copyKey = async () => {
    await navigator.clipboard.writeText(record.key_id);
    notifications.show({
      title: 'Notary key ID copied',
      message: 'The complete key ID is on the clipboard.',
    });
  };
  return (
    <article className={`local-notary-record local-notary-record--${record.lifecycle}`}>
      <header>
        <span className={`local-notary-state local-notary-state--${record.lifecycle}`}>
          <i aria-hidden="true" />
          {record.lifecycle}
        </span>
        {record.key_id === activeKeyId && (
          <span className="local-notary-selected">Selected active key</span>
        )}
      </header>
      <Title order={3}>{lifecycle.label}</Title>
      <Text>{lifecycle.description}</Text>
      <dl className="local-notary-facts">
        <Fact label="Endpoint" value={record.endpoint} />
        <Fact label="Transport" value={record.transport.toUpperCase()} />
        <Fact
          label="Valid from"
          value={formatNotaryBoundary(record.valid_from_unix_ms, {
            kind: 'lower',
            missingLabel: 'Not defined by explicit configuration',
          })}
        />
        <Fact label="Capture cutoff" value={formatNotaryBoundary(record.valid_until_unix_ms)} />
        <Fact
          label="Notarization cutoff"
          value={formatNotaryBoundary(record.notarize_until_unix_ms)}
        />
      </dl>
      <div className="local-notary-key">
        <span>Key ID / fingerprint</span>
        <code title={record.key_id}>{abbreviatedKeyId(record.key_id)}</code>
        <ActionIcon
          variant="subtle"
          onClick={copyKey}
          aria-label={`Copy full key ID ${record.key_id}`}
        >
          <Copy size={15} />
        </ActionIcon>
      </div>
    </article>
  );
}

function SettingsNotaries({ api }: { api: LocalApi }) {
  const notaries = useQuery({ queryKey: ['notaries'], queryFn: api.notaries, retry: false });
  const errorCode = notaries.error instanceof LocalApiError ? notaries.error.code : null;
  const records = orderNotaries(notaries.data?.notaries ?? [], notaries.data?.active_key_id);
  return (
    <Paper className="settings-panel settings-notaries">
      <div className="settings-notaries-heading">
        <div>
          <Text className="eyebrow">Notaries</Text>
          <Title order={2}>Configured trust</Title>
        </div>
        {notaries.data?.generation != null && (
          <Text>Directory generation {notaries.data.generation}</Text>
        )}
      </div>
      <Text className="settings-notaries-note">
        This is the trust state used by the local service. It describes key lifecycle and permitted
        work, not endpoint health or availability.
      </Text>
      {notaries.isLoading ? (
        <div className="local-notary-loading" role="status" aria-label="Loading local notary trust">
          <i />
          <i />
          <i />
        </div>
      ) : notaries.error ? (
        <div className="local-notary-state-panel" role="alert">
          <b>
            {errorCode === 'notary_trust_state_invalid'
              ? 'Pinned trust state is malformed'
              : 'Local notary trust is unavailable'}
          </b>
          <span>
            {errorCode === 'notary_trust_state_invalid'
              ? 'The cached directory could not be validated. No notary is presented as usable.'
              : 'The local service could not return its configured trust metadata. No endpoint status can be inferred.'}
          </span>
          <Button variant="outline" onClick={() => notaries.refetch()}>
            Try again
          </Button>
        </div>
      ) : !records.length ? (
        <div className="local-notary-state-panel">
          <b>No pinned notary records</b>
          <span>
            The local service has not retained a directory generation. No notary is presented as
            available.
          </span>
        </div>
      ) : (
        <>
          <dl className="settings-notary-source">
            <Fact
              label="Trust source"
              value={
                notaries.data?.source === 'explicit_configuration'
                  ? 'Explicit self-hosted configuration'
                  : 'Pinned directory'
              }
            />
            {notaries.data?.registry_source && (
              <Fact label="Registry source" value={notaries.data.registry_source} />
            )}
          </dl>
          {notaries.data?.source === 'explicit_configuration' && (
            <Text className="explicit-notary-note">
              This endpoint and key come from local configuration and are not members of the hosted
              directory.
            </Text>
          )}
          <div className="local-notary-list">
            {records.map((record) => (
              <LocalNotaryRecord
                key={record.key_id}
                record={record}
                activeKeyId={notaries.data?.active_key_id}
              />
            ))}
          </div>
        </>
      )}
    </Paper>
  );
}

function SettingsView({ status, api }: { status: Status; api: LocalApi }) {
  const queryClient = useQueryClient();
  const [captureEnabled, setCaptureEnabled] = useState(status.capture_enabled);
  const captureMode = useMutation({
    mutationFn: (enabled: boolean) => api.updateCaptureSetting(enabled),
    onSuccess: (setting) => {
      setCaptureEnabled(setting.enabled);
      queryClient.invalidateQueries({ queryKey: ['status'] });
      queryClient.invalidateQueries({ queryKey: ['events'] });
      notifications.show({
        title: setting.enabled ? 'Capture requests on' : 'Capture requests off',
        message: setting.enabled
          ? 'Later provider requests will use the remote notary and create private captures.'
          : 'Later provider requests will go directly to the provider and create no evidence.',
      });
    },
    onError: (error) => mutationError('Capture mode did not change', error),
  });
  useEffect(() => setCaptureEnabled(status.capture_enabled), [status.capture_enabled]);
  const isCluster = status.runtime_profile === 'cluster';
  const accountConnection = useAccountConnection(api);
  const proxyOrigin = status.proxy_origin.replace(/\/$/, '');
  const openApiUrl = `${window.location.origin}/openapi.json`;
  const copyOpenApi = async () => {
    await navigator.clipboard.writeText(openApiUrl);
    notifications.show({
      title: 'OpenAPI URL copied',
      message: 'Use this URL to discover admin routes and request bodies.',
    });
  };
  const updateState = !status.updates.enabled
    ? isCluster
      ? 'Managed by deployment'
      : 'Disabled for source builds'
    : status.updates.update_available
      ? `Available: ${status.updates.latest_build_id}`
      : status.updates.error_code
        ? 'Check failed'
        : status.updates.last_checked_unix_ms
          ? 'Up to date'
          : 'Not checked yet';

  return (
    <div className="view-page">
      <AccountConnectionCard controller={accountConnection} />
      <Paper className="capture-mode-setting">
        <div>
          <Text fw={700}>Capture requests</Text>
          <Text>
            {captureEnabled
              ? 'On — requests use the remote notary and create private captures.'
              : 'Off — requests still pass through the local daemon, go directly to the provider, and create no evidence.'}
          </Text>
        </div>
        <Switch
          aria-label="Capture requests"
          checked={captureEnabled}
          disabled={captureMode.isPending}
          onChange={(event) => captureMode.mutate(event.currentTarget.checked)}
        />
      </Paper>
      <Paper className="appearance-setting">
        <Text fw={700}>Theme</Text>
        <SchemeControl />
      </Paper>
      <SimpleGrid cols={{ base: 1, md: 2 }} spacing="lg">
        <SettingsNotaries api={api} />
        <Paper className="settings-panel">
          <Text className="eyebrow">{isCluster ? 'Deployment' : 'Listeners'}</Text>
          <Title order={2}>{isCluster ? 'Cluster endpoints' : 'Listener addresses'}</Title>
          <dl className="receipt-list">
            <Fact
              label="Provider proxy"
              value={isCluster ? status.proxy_origin : status.proxy_listener}
            />
            <Fact
              label="Admin & dashboard"
              value={isCluster ? status.admin_origin : status.admin_listener}
            />
            {isCluster && (
              <Fact label="Replica" value={status.instance_id ?? 'Assigned automatically'} />
            )}
            {isCluster && <Fact label="Lifecycle" value={status.lifecycle} />}
            <Fact
              label="Metadata"
              value={`${status.metadata_backend} (${status.metadata_status})`}
            />
            <Fact
              label="Artifacts"
              value={`${status.artifact_backend} (${status.artifact_status})`}
            />
            <Fact label="API version" value="v1" />
            <Fact label="Service version" value={status.version} />
            <Fact label="Build" value={status.build_id} />
            <Fact label="Updates" value={updateState} />
          </dl>
          <Text className="safe-note">
            <ShieldCheck size={15} />{' '}
            {isCluster
              ? 'Public traffic uses the configured TLS ingress; provider requests must never be replayed.'
              : 'Both listeners are restricted to loopback.'}
          </Text>
          {status.updates.update_available && (
            <Text>
              Run <code>llm-notary update</code>, then restart the service after active work
              finishes.
            </Text>
          )}
        </Paper>
        <Paper className="settings-panel">
          <Text className="eyebrow">Agent discovery</Text>
          <Title order={2}>API specification</Title>
          <Text>Use the generated OpenAPI document to discover routes and request bodies.</Text>
          <div className="api-link">
            <code>{openApiUrl}</code>
            <ActionIcon variant="subtle" onClick={copyOpenApi} aria-label="Copy OpenAPI URL">
              <Copy size={15} />
            </ActionIcon>
          </div>
          <Button
            component="a"
            href="/openapi.json"
            target="_blank"
            variant="outline"
            leftSection={<CodeXml size={15} />}
          >
            Open specification
          </Button>
        </Paper>
        <Paper className="settings-panel">
          <Text className="eyebrow">Privacy policy</Text>
          <Title order={2}>Preview storage</Title>
          <Text>
            Up to {status.preview_chars.toLocaleString()} characters of known text fields are
            indexed {isCluster ? 'in shared metadata' : 'locally'}. Raw headers are never indexed.
          </Text>
          <dl className="receipt-list">
            <Fact label="Vault" value={status.vault} />
            <Fact label="Notary discovery" value={status.notary} />
          </dl>
        </Paper>
        <Paper className="settings-panel inverse">
          <TerminalSquare size={20} />
          <Text className="eyebrow">Provider routes</Text>
          <Title order={2}>Proxy base URLs</Title>
          <Text>
            Keep provider credentials in the SDK and replace its base URL with the matching{' '}
            {isCluster ? 'cluster' : 'local'} route.
          </Text>
          <code>{proxyOrigin}/openai/v1</code>
          <code>{proxyOrigin}/anthropic</code>
          <code>{proxyOrigin}/deepseek</code>
          <code>{proxyOrigin}/openrouter/api/v1</code>
        </Paper>
      </SimpleGrid>
    </div>
  );
}
