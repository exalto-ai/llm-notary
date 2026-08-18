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
  Moon,
  PanelLeft,
  Play,
  RefreshCw,
  Search,
  Send,
  Settings,
  ShieldCheck,
  Sun,
  Trash2,
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
import {
  type DashboardRoute,
  type DashboardView,
  dashboardRouteFromHash,
  dashboardRouteHash,
} from './routes';

function requiredValue<T>(value: T | null | undefined, label: string): T {
  if (value === null || value === undefined) throw new Error(`${label} is required`);
  return value;
}

const logoUrl = new URL('./assets/notary-mark.svg', import.meta.url).href;

type Route = DashboardRoute;
type TraceFilters = NonNullable<Parameters<LocalApi['traces']>[0]>;
type TraceStateFilter = NonNullable<TraceFilters['state']>;
type TraceStatusFilter = NonNullable<TraceFilters['status']>;

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
  { view: 'traces', label: 'Traces', icon: FileCheck2 },
  { view: 'activity', label: 'Activity', icon: Activity },
  { view: 'providers', label: 'Providers', icon: Unplug },
  { view: 'settings', label: 'Settings', icon: Settings },
];

function goTo(route: Route) {
  window.location.hash = dashboardRouteHash(route);
}

function useRoute() {
  const [route, setRoute] = useState<Route>(() => dashboardRouteFromHash(window.location.hash));
  useEffect(() => {
    const change = () => setRoute(dashboardRouteFromHash(window.location.hash));
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
      return 'Building portable package';
    case 'complete':
      return 'Portable package complete';
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

function traceTitle(trace: TraceSummary) {
  const preview = trace.prompt_preview?.replace(/\s+/g, ' ').trim();
  if (preview) return preview;
  const providerNames: Record<string, string> = {
    anthropic: 'Anthropic',
    deepseek: 'DeepSeek',
    openai: 'OpenAI',
    openrouter: 'OpenRouter',
  };
  const provider = trace.provider
    ? (providerNames[trace.provider.toLowerCase()] ?? trace.provider)
    : 'Model provider';
  return `${provider} request`;
}

function traceLifecycleLabel(trace: TraceSummary) {
  if (trace.status === 'capturing') return 'Capturing';
  if (trace.status === 'capture_failed') return 'Capture failed';
  if (trace.state === 'notarized') return 'Notarized';
  if (trace.status === 'notarizing') return 'Captured · Notarizing';
  if (trace.status === 'notarization_failed') return 'Captured · Notarization failed';
  if (trace.status === 'notarization_interrupted') return 'Captured · Notarization interrupted';
  if (trace.state === 'captured') return 'Captured';
  return 'Trace pending';
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
  return account.display_name || account.provider_display_name || 'Notary Account';
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
              <Fact label="Plan" value={`${api.billing.plan} · ${api.billing.billing_status}`} />
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
                ? 'The account service could not be reached. Local Traces and verification remain available.'
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

const splitStorageKey = 'notary-admin-dashboard-split-width';
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
        <Text className="eyebrow">Notary administration</Text>
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
            <b>Authenticated administration</b>
            <span>
              Use the credentials configured for this service. Access may be loopback or an
              explicitly configured cluster ingress.
            </span>
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
      <span>Notary</span>
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
  const count = (view: DashboardView) => (view === 'traces' ? status.counts.captured : undefined);
  return (
    <div className="sidebar-inner">
      <div className="sidebar-primary">
        <nav aria-label="Admin dashboard">
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
  const count = (view: DashboardView) => (view === 'traces' ? status.counts.captured : undefined);
  return (
    <header className="local-topbar">
      <Brand />
      <nav aria-label="Admin dashboard">
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
        <span className="admin-context-label">
          {status.runtime_profile === 'cluster' ? 'Cluster admin' : 'Local admin'}
        </span>
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
}: {
  route: Route;
  status: Status;
  api: LocalApi;
  navigate: (route: Route) => void;
  fixture: boolean;
}) {
  switch (route.view) {
    case 'traces':
      return (
        <TracesView
          api={api}
          selectedId={route.id}
          initialFilters={route.filters}
          navigate={navigate}
        />
      );
    case 'activity':
      return <ActivityView api={api} initialTraceId={route.filters?.traceId} />;
    case 'providers':
      return <ProvidersView api={api} status={status} />;
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
  const queryClient = useQueryClient();
  const events = useQuery({ queryKey: ['events'], queryFn: () => api.events() });
  const enableCapture = useMutation({
    mutationFn: () => api.updateCaptureSetting(true),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['status'] });
      queryClient.invalidateQueries({ queryKey: ['events'] });
      notifications.show({
        title: 'Capture is on',
        message: 'New provider requests can create private Traces.',
      });
    },
    onError: (error) => mutationError('Could not turn capture on', error),
  });
  const stats = [
    ['Captured', status.counts.captured, 'muted', { state: 'captured' }],
    ['Notarizing', status.counts.notarizing, 'active', { status: 'notarizing' }],
    ['Notarized', status.counts.notarized, 'ready', { state: 'notarized' }],
    ['Needs attention', status.counts.needs_attention, 'danger', { status: 'needs_attention' }],
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
            {stats.map(([label, value, tone, filters]) => (
              <UnstyledButton key={label} onClick={() => navigate({ view: 'traces', filters })}>
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
            loading={enableCapture.isPending}
            onClick={() => {
              if (status.counts.captured) navigate({ view: 'traces' });
              else if (status.capture_enabled) navigate({ view: 'providers' });
              else enableCapture.mutate();
            }}
          >
            {status.counts.captured
              ? 'Review traces'
              : status.capture_enabled
                ? 'View providers'
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

function TracesView({
  api,
  selectedId,
  initialFilters,
  navigate,
}: {
  api: LocalApi;
  selectedId?: string;
  initialFilters?: Route['filters'];
  navigate: (route: Route) => void;
}) {
  const [query, setQuery] = useState('');
  const [model, setModel] = useState('');
  const [provider, setProvider] = useState<string | null>(null);
  const [traceState, setTraceState] = useState<TraceStateFilter | null>(
    (initialFilters?.state as TraceStateFilter | undefined) ?? null,
  );
  const [operationalStatus, setOperationalStatus] = useState<TraceStatusFilter | null>(
    (initialFilters?.status as TraceStatusFilter | undefined) ?? null,
  );
  const [streaming, setStreaming] = useState<string | null>(null);
  const [time, setTime] = useState<string | null>(null);
  const [moreOpen, setMoreOpen] = useState(Boolean(initialFilters?.status));
  const mobile = useMediaQuery('(max-width: 820px)');
  const createdAfter = useMemo(() => timeRangeStart(time), [time]);
  const traces = useInfiniteQuery({
    queryKey: [
      'traces',
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
        created_from_unix_ms: createdAfter,
        limit: 50,
        cursor: pageParam,
      }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (page) => page.next_cursor ?? undefined,
    refetchInterval: 3_000,
  });
  const selectedDetail = useQuery({
    queryKey: ['capture', selectedId],
    queryFn: () => api.trace(requiredValue(selectedId, 'selected capture')),
    enabled: Boolean(selectedId),
  });
  const visible = useMemo(
    () => traces.data?.pages.flatMap((page) => page.items) ?? [],
    [traces.data],
  );
  const activeId = selectedId ?? visible[0]?.trace_id;
  const active = visible.find((capture) => capture.trace_id === activeId) ?? selectedDetail.data;
  const showDetail = Boolean(mobile && selectedId);
  const hasAdditionalFilters = Boolean(
    query || model || provider || operationalStatus || streaming || time,
  );
  const emptyCopy = hasAdditionalFilters
    ? 'No traces match these filters.'
    : traceState === 'captured'
      ? 'No traces are currently in the Captured state.'
      : traceState === 'notarized'
        ? 'No traces have been notarized yet.'
        : 'No traces have been captured yet.';
  return (
    <div className="view-page capture-page">
      {!showDetail && (
        <div className="trace-filters">
          <div className="trace-filter-primary">
            <TextInput
              aria-label="Search traces"
              placeholder="Search traces"
              leftSection={<Search size={15} />}
              value={query}
              onChange={(event) => setQuery(event.currentTarget.value)}
            />
            <div className="trace-state-filter" role="group" aria-label="Trace state filter">
              {[
                [null, 'All'],
                ['captured', 'Captured'],
                ['notarized', 'Notarized'],
              ].map(([value, label]) => (
                <button
                  key={label}
                  type="button"
                  className={traceState === value ? 'is-active' : ''}
                  aria-pressed={traceState === value}
                  onClick={() => setTraceState(value as TraceStateFilter | null)}
                >
                  {label}
                </button>
              ))}
            </div>
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
              ariaLabel="Trace time filter"
              placeholder="Any date"
              data={[
                { value: 'hour', label: 'Last hour' },
                { value: 'day', label: 'Last 24 hours' },
                { value: 'week', label: 'Last 7 days' },
              ]}
              value={time}
              onChange={setTime}
            />
            <Button
              variant={moreOpen || operationalStatus || model || streaming ? 'light' : 'default'}
              onClick={() => setMoreOpen((open) => !open)}
              aria-expanded={moreOpen}
            >
              More filters
            </Button>
          </div>
          {moreOpen && (
            <div className="trace-filter-more">
              <TextInput
                aria-label="Model filter"
                placeholder="All models"
                value={model}
                onChange={(event) => setModel(event.currentTarget.value)}
              />
              <AxisSelect
                ariaLabel="Operational status filter"
                placeholder="All operational statuses"
                data={[
                  { value: 'needs_attention', label: 'Needs attention' },
                  'capturing',
                  'capture_failed',
                  'notarizing',
                  'notarization_failed',
                  'notarization_interrupted',
                ]}
                value={operationalStatus}
                onChange={(value) => setOperationalStatus(value as TraceStatusFilter | null)}
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
            </div>
          )}
        </div>
      )}
      {traces.isLoading || (selectedId && selectedDetail.isLoading) ? (
        <LoadingState />
      ) : traces.error ? (
        <QueryError error={traces.error} title="Traces are unavailable" />
      ) : selectedDetail.error ? (
        <QueryError error={selectedDetail.error} title="Trace detail is unavailable" />
      ) : !visible.length && !active ? (
        <EmptyState title={emptyCopy} copy="Send a request through a configured provider route." />
      ) : (
        <ResizableSplit className={`master-detail ${showDetail ? 'show-detail' : ''}`}>
          {!showDetail ? (
            <ScrollArea className="master-list" type="auto">
              <ul className="capture-list" aria-label="Traces">
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
              {traces.hasNextPage && (
                <Button
                  className="load-more"
                  variant="subtle"
                  loading={traces.isFetchingNextPage}
                  onClick={() => traces.fetchNextPage()}
                >
                  Load more traces
                </Button>
              )}
            </ScrollArea>
          ) : (
            <div />
          )}
          <div className="detail-panel">
            {active ? (
              <TraceInspector
                api={api}
                capture={active}
                mobile={Boolean(mobile)}
                onBack={() => navigate({ view: 'traces' })}
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
        <span
          className={`trace-lifecycle-label trace-lifecycle-label--${stateTone(traceDisplayStatus(capture))}`}
        >
          {traceLifecycleLabel(capture)}
        </span>
      </span>
      <span className="capture-row-copy">
        <b>{traceTitle(capture)}</b>
        <small>
          <ProviderIdentity
            provider={capture.provider}
            detail={capture.requested_model ?? 'Model not reported'}
          />
        </small>
      </span>
      <time className="mono-time">{formatDate(capture.created_at_unix_ms)}</time>
    </UnstyledButton>
  );
}

function TraceInspector(props: {
  api: LocalApi;
  capture: TraceSummary;
  mobile: boolean;
  onBack: () => void;
  navigate: (route: Route) => void;
}) {
  return props.capture.state === 'notarized' ? (
    <NotarizedTraceInspector
      api={props.api}
      capture={props.capture}
      mobile={props.mobile}
      onBack={props.onBack}
      navigate={props.navigate}
    />
  ) : (
    <CapturedTraceInspector {...props} />
  );
}

function CapturedTraceInspector({
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
    refetchInterval: 2_000,
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
      queryClient.invalidateQueries({ queryKey: ['traces'] });
      queryClient.invalidateQueries({ queryKey: ['capture', capture.trace_id] });
      queryClient.invalidateQueries({ queryKey: ['operations'] });
      queryClient.invalidateQueries({ queryKey: ['status'] });
      queryClient.invalidateQueries({ queryKey: ['events'] });
      navigate({ view: 'traces', id: capture.trace_id });
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
  const canRetry = Boolean(value.notarization?.retryable);
  return (
    <article className="inspector capture-inspector">
      {mobile && (
        <Button variant="subtle" leftSection={<ArrowLeft size={15} />} onClick={onBack}>
          All traces
        </Button>
      )}
      <div className="inspector-head trace-inspector-head">
        <div>
          <Text className="eyebrow">Trace</Text>
          <Title order={2}>{traceTitle(capture)}</Title>
          <Group gap="xs" className="trace-head-facts">
            <span className="trace-lifecycle-label">{traceLifecycleLabel(capture)}</span>
            <ProviderIdentity
              provider={capture.provider}
              detail={capture.requested_model ?? 'Model not reported'}
            />
            <time>{formatDate(capture.created_at_unix_ms)}</time>
          </Group>
          <Group gap={4} className="trace-id-row">
            <Text className="mono-id">Trace ID · {capture.trace_id}</Text>
            <ActionIcon
              variant="subtle"
              aria-label="Copy Trace ID"
              onClick={() => void navigator.clipboard.writeText(capture.trace_id)}
            >
              <Copy size={13} />
            </ActionIcon>
          </Group>
        </div>
        <Group>
          {(canNotarize || canRetry) && (
            <Button
              loading={notarize.isPending}
              leftSection={canRetry ? <RefreshCw size={15} /> : <Play size={15} />}
              onClick={() => notarize.mutate()}
            >
              {canRetry ? 'Retry notarization' : 'Notarize'}
            </Button>
          )}
        </Group>
      </div>
      {capture.status === 'capture_failed' && (
        <div className="notarization-ineligible-note" role="status">
          <XCircle size={18} aria-hidden="true" />
          <div>
            <b>The original request cannot be replayed</b>
            <Text>
              Capture did not complete, so this Trace has no private evidence to notarize.
            </Text>
          </div>
        </div>
      )}
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
      <Tabs defaultValue="summary" keepMounted={false}>
        <Tabs.List>
          <Tabs.Tab value="summary">Summary</Tabs.Tab>
          <Tabs.Tab value="notarization">Notarization</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="summary">
          <InspectorSection title="Private on this device">
            <div className="preview-block private-preview-label">
              <Text>
                These previews come from private local retention, not from a portable package.
              </Text>
            </div>
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
          <InspectorSection title="Trace facts">
            <dl className="metadata-grid">
              <Fact label="Provider" value={<ProviderIdentity provider={capture.provider} />} />
              <Fact label="Operation" value={capture.operation} />
              <Fact label="HTTP status" value={capture.http_status?.toString() ?? 'In progress'} />
              <Fact label="Streaming" value={capture.streaming ? 'Yes' : 'No'} />
              <Fact label="Request" value={formatBytes(capture.request_bytes)} />
              <Fact label="Response" value={formatBytes(capture.response_bytes)} />
            </dl>
          </InspectorSection>
          <InspectorSection title="Retained artifacts">
            <ArtifactList detail={value} />
          </InspectorSection>
        </Tabs.Panel>
        <Tabs.Panel value="notarization">
          <InspectorSection title="Notarization">
            {!capture.notarization_eligible && capture.notarization_ineligibility_code && (
              <Text className="empty-copy">
                Cannot be notarized · {capture.notarization_ineligibility_code}
              </Text>
            )}
            {value.notarization ? (
              <OperationInspector
                operation={value.notarization}
                fixture={false}
                onViewActivity={() =>
                  navigate({ view: 'activity', filters: { traceId: capture.trace_id } })
                }
              />
            ) : (
              <Text className="empty-copy">No notarization has been requested for this Trace.</Text>
            )}
          </InspectorSection>
        </Tabs.Panel>
      </Tabs>
    </article>
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
  operation,
  fixture,
  onViewActivity,
}: {
  operation: Operation;
  fixture: boolean;
  onViewActivity?: () => void;
}) {
  return (
    <Paper className="operation-inspector">
      <Text className="eyebrow">Notarization attempt</Text>
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
        <Fact label="Trace ID" value={operation.trace_id ?? '—'} />
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
      {onViewActivity && (
        <Button variant="subtle" onClick={onViewActivity}>
          View Trace activity
        </Button>
      )}
    </Paper>
  );
}

function NotarizedTraceInspector({
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
  const captureId = capture.trace_id;
  const trace = useQuery({
    queryKey: ['trace', captureId],
    queryFn: () => api.traceContent(captureId),
  });
  const detail = useQuery({
    queryKey: ['capture', captureId],
    queryFn: () => api.trace(captureId),
  });
  const [verification, setVerification] = useState<Verification | null>(null);
  const [activeTab, setActiveTab] = useState<string | null>('summary');
  const [shareConfirmation, setShareConfirmation] = useState(false);
  const [shareRequested, setShareRequested] = useState(false);
  const currentCapture = useRef(captureId);
  useEffect(() => {
    currentCapture.current = captureId;
    setVerification(null);
    setActiveTab('summary');
    setShareConfirmation(false);
    setShareRequested(false);
  }, [captureId]);
  const verify = useMutation({
    mutationFn: () => api.verify(captureId),
    onSuccess: (result) => {
      if (currentCapture.current !== result.trace_id) return;
      setVerification(result);
      setActiveTab('evidence');
      notifications.show({
        title: 'Trace verified',
        message: 'The package passed every local verification check.',
      });
    },
    onError: (error) => mutationError('Trace verification failed', error),
  });
  const exportTrace = useMutation({
    mutationFn: () => api.downloadPackage(captureId),
    onSuccess: (packageBytes) => {
      const url = URL.createObjectURL(packageBytes);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${captureId}.llmtrace`;
      link.click();
      URL.revokeObjectURL(url);
      notifications.show({
        title: 'Trace exported',
        message: 'The portable notarized package was exported without modification.',
      });
    },
    onError: (error) => mutationError('Could not export Trace', error),
  });
  const shareStatus = useQuery({
    queryKey: ['share', captureId],
    queryFn: async () => {
      try {
        return await api.shareStatus(captureId);
      } catch (error) {
        if (error instanceof LocalApiError && error.status === 404) return null;
        throw error;
      }
    },
    enabled: Boolean(detail.data?.share) || shareRequested,
    retry: false,
    refetchInterval: (query) => {
      const progress = query.state.data?.progress;
      return !progress || ['shared', 'rejected', 'failed'].includes(progress) ? false : 3_000;
    },
  });
  const createShare = useMutation({
    mutationFn: () => api.share(captureId, 'unlisted'),
    onSuccess: (share) => {
      setShareConfirmation(false);
      setShareRequested(true);
      queryClient.setQueryData(['share', captureId], share);
      queryClient.invalidateQueries({ queryKey: ['capture', captureId] });
      notifications.show({
        title: 'Unlisted share started',
        message: 'The disclosed package is being verified before a public URL is created.',
      });
    },
    onError: (error) => mutationError('Could not share this Trace', error),
  });
  const stopShare = useMutation({
    mutationFn: () => api.stopSharing(captureId),
    onSuccess: () => {
      setShareRequested(false);
      queryClient.setQueryData(['share', captureId], null);
      queryClient.invalidateQueries({ queryKey: ['capture', captureId] });
      notifications.show({
        title: 'Sharing stopped',
        message: 'The public share is no longer accessible.',
      });
    },
    onError: (error) => mutationError('Could not stop sharing', error),
  });
  if (trace.isLoading || detail.isLoading) return <LoadingState />;
  if (trace.error) return <QueryError error={trace.error} title="Trace package is unavailable" />;
  if (!trace.data || !detail.data)
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
  const activeShare = shareStatus.isSuccess
    ? shareStatus.data
    : (shareStatus.data ?? detail.data.share);
  return (
    <article className="trace-inspector">
      {mobile && (
        <Button variant="subtle" leftSection={<ArrowLeft size={15} />} onClick={onBack}>
          All traces
        </Button>
      )}
      <Group justify="space-between" align="flex-start" className="trace-inspector-head">
        <div>
          <Text className="eyebrow">Trace</Text>
          <Title order={2}>{traceTitle(capture)}</Title>
          <Group gap="xs" className="trace-head-facts">
            <span className="trace-lifecycle-label">Notarized</span>
            <ProviderIdentity
              provider={capture.provider}
              detail={capture.requested_model ?? 'Model not reported'}
            />
            <time>{formatDate(capture.created_at_unix_ms)}</time>
          </Group>
          <Group gap={4} className="trace-id-row">
            <Text className="mono-id">Trace ID · {captureId}</Text>
            <ActionIcon
              variant="subtle"
              aria-label="Copy Trace ID"
              onClick={() => void navigator.clipboard.writeText(captureId)}
            >
              <Copy size={13} />
            </ActionIcon>
          </Group>
        </div>
        <Group>
          <Button
            leftSection={<Download size={15} />}
            loading={exportTrace.isPending}
            onClick={() => exportTrace.mutate()}
          >
            {exportTrace.isPending ? 'Exporting…' : 'Export .llmtrace'}
          </Button>
          <Button
            variant="outline"
            leftSection={<ShieldCheck size={15} />}
            loading={verify.isPending}
            onClick={() => verify.mutate()}
          >
            Verify locally
          </Button>
          {!activeShare && (
            <Button
              variant="outline"
              leftSection={<Send size={15} />}
              onClick={() => setShareConfirmation(true)}
            >
              Share
            </Button>
          )}
        </Group>
      </Group>
      {activeShare && (
        <Paper className="trace-share-status">
          <div>
            <Text className="eyebrow">
              {activeShare.visibility === 'listed' ? 'Listed share' : 'Unlisted share'}
            </Text>
            <Text>
              {!activeShare.access_enabled
                ? 'Public access is disabled for this share.'
                : activeShare.progress === 'shared'
                  ? activeShare.visibility === 'listed'
                    ? 'This disclosed Trace is publicly listed and readable.'
                    : 'Anyone with this URL can read the disclosed Trace.'
                  : `Status · ${activeShare.progress}`}
            </Text>
            {shareStatus.error && (
              <Text role="status">
                Could not refresh share status. Showing the last known state.
              </Text>
            )}
          </div>
          <Group>
            {activeShare.access_enabled && activeShare.share_url && (
              <Button
                variant="outline"
                leftSection={<Copy size={15} />}
                onClick={() => void navigator.clipboard.writeText(activeShare.share_url ?? '')}
              >
                Copy URL
              </Button>
            )}
            {shareStatus.error && (
              <Button variant="outline" onClick={() => shareStatus.refetch()}>
                Retry status
              </Button>
            )}
            <Button
              variant="subtle"
              color="red"
              leftSection={<Trash2 size={15} />}
              loading={stopShare.isPending}
              onClick={() => stopShare.mutate()}
            >
              Stop sharing
            </Button>
          </Group>
        </Paper>
      )}
      <Tabs value={activeTab} onChange={setActiveTab} keepMounted={false}>
        <Tabs.List>
          <Tabs.Tab value="summary">Summary</Tabs.Tab>
          <Tabs.Tab value="notarization">Notarization</Tabs.Tab>
          <Tabs.Tab value="evidence">Evidence</Tabs.Tab>
          <Tabs.Tab value="technical">Technical</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="summary">
          <div className="document-panel">
            <Text className="eyebrow">Private on this device</Text>
            <Title order={3}>Prompt and response preview</Title>
            <Text>
              These previews come from private local retention and are separate from the package's
              disclosed conversation.
            </Text>
            <div className="preview-block">
              <Text className="eyebrow">Prompt</Text>
              <Text>{capture.prompt_preview || 'Preview storage is disabled.'}</Text>
            </div>
            <div className="preview-block">
              <Text className="eyebrow">Output</Text>
              <Text>{capture.output_preview || 'Preview storage is disabled.'}</Text>
            </div>
            <dl className="metadata-grid">
              <Fact label="Provider" value={<ProviderIdentity provider={capture.provider} />} />
              <Fact label="Operation" value={capture.operation} />
              <Fact label="HTTP status" value={capture.http_status?.toString() ?? 'Not reported'} />
              <Fact label="Streaming" value={capture.streaming ? 'Yes' : 'No'} />
              <Fact label="Request" value={formatBytes(capture.request_bytes)} />
              <Fact label="Response" value={formatBytes(capture.response_bytes)} />
            </dl>
          </div>
        </Tabs.Panel>
        <Tabs.Panel value="notarization">
          <div className="document-panel">
            <Title order={3}>Notarization</Title>
            {detail.data.notarization ? (
              <OperationInspector
                operation={detail.data.notarization}
                fixture={false}
                onViewActivity={() =>
                  navigate({ view: 'activity', filters: { traceId: captureId } })
                }
              />
            ) : (
              <Text className="empty-copy">No notarization history is available.</Text>
            )}
          </div>
        </Tabs.Panel>
        <Tabs.Panel value="evidence">
          <div className="document-panel">
            <Text className="eyebrow">Portable package disclosure</Text>
            <Title order={3}>Disclosed conversation</Title>
            <TraceTranscriptView transcripts={transcripts} />
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
          </div>
        </Tabs.Panel>
        <Tabs.Panel value="technical">
          <div className="document-panel">
            <Title order={3}>Package and OpenTelemetry details</Title>
            <dl className="metadata-grid">
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
              <Fact label="Trace SHA-256" value={traceDigest} />
            </dl>
            <pre className="json-view">{JSON.stringify(trace.data.trace, null, 2)}</pre>
          </div>
        </Tabs.Panel>
      </Tabs>
      <AlertDialog open={shareConfirmation} onOpenChange={setShareConfirmation}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Create an unlisted share?</AlertDialogTitle>
            <AlertDialogDescription>
              Anyone with the URL can read the disclosed prompt, response, and tool data. Header
              values remain hidden. Review the Trace before continuing.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              disabled={createShare.isPending}
              onClick={() => createShare.mutate()}
            >
              {createShare.isPending ? 'Starting…' : 'Create unlisted share'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
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

function ActivityView({ api, initialTraceId = '' }: { api: LocalApi; initialTraceId?: string }) {
  const [severity, setSeverity] = useState<string | null>(null);
  const [captureId, setCaptureId] = useState(initialTraceId);
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

function ProvidersView({ api, status }: { api: LocalApi; status: Status }) {
  const providers = useQuery({ queryKey: ['providers'], queryFn: api.providers, retry: false });
  const isCluster = status.runtime_profile === 'cluster';
  const copyBaseUrl = async (providerName: string, baseUrl: string) => {
    await navigator.clipboard.writeText(baseUrl);
    notifications.show({
      title: `${providerName} base URL copied`,
      message: 'Keep the provider credential in your SDK and replace only its base URL.',
    });
  };
  return (
    <div className="view-page providers-page">
      <header className="view-heading">
        <div>
          <Text className="eyebrow">{isCluster ? 'Cluster admin' : 'Local admin'}</Text>
          <Title order={1}>Providers</Title>
        </div>
        <Text>
          Route supported SDK traffic through Notary. Credentials stay in the client and are never
          sent to the remote notary.
        </Text>
      </header>
      {providers.isLoading ? (
        <LoadingState label="Loading providers" />
      ) : providers.error ? (
        <QueryError error={providers.error} title="Providers are unavailable" />
      ) : !providers.data?.providers.length ? (
        <EmptyState
          icon={Unplug}
          title="No provider routes"
          copy="This service has no configured provider allowlist entries."
        />
      ) : (
        <section className="provider-route-list" aria-label="Provider routes">
          {providers.data.providers.map((provider) => (
            <Paper className="settings-panel provider-route" key={provider.id}>
              <Group justify="space-between" align="flex-start">
                <div>
                  <ProviderIdentity provider={provider.id} detail={provider.host} />
                  <Title order={2}>{provider.name}</Title>
                </div>
                <StatusLabel state={provider.ready ? 'ready' : 'unavailable'} />
              </Group>
              <dl className="receipt-list">
                <Fact label="Client API" value={provider.client_api} />
                <Fact label="Allowed host" value={provider.host} />
                <Fact label="Route" value={provider.route_prefix} />
                <Fact label="Readiness" value={provider.ready ? 'Ready' : 'Unavailable'} />
              </dl>
              <div className="api-link">
                <code>{provider.proxy_base_url}</code>
                <ActionIcon
                  variant="subtle"
                  onClick={() => copyBaseUrl(provider.name, provider.proxy_base_url)}
                  aria-label={`Copy ${provider.name} base URL`}
                >
                  <Copy size={15} />
                </ActionIcon>
              </div>
              <Text className="safe-note">
                <ShieldCheck size={15} /> Configure this as the SDK base URL. Keep the original API
                key environment variable unchanged.
              </Text>
            </Paper>
          ))}
        </section>
      )}
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
          <Text>Registry generation {notaries.data.generation}</Text>
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
            {errorCode === 'registry_state_invalid'
              ? 'Pinned trust state is malformed'
              : 'Local notary trust is unavailable'}
          </b>
          <span>
            {errorCode === 'registry_state_invalid'
              ? 'The cached Registry could not be validated. No notary is presented as usable.'
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
            The local service has not retained a Registry generation. No notary is presented as
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
                  : 'Pinned Registry'
              }
            />
            {notaries.data?.registry_source && (
              <Fact label="Registry source" value={notaries.data.registry_source} />
            )}
          </dl>
          {notaries.data?.source === 'explicit_configuration' && (
            <Text className="explicit-notary-note">
              This endpoint and key come from local configuration and are not members of the hosted
              Registry.
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

function SettingsGroup({
  id,
  title,
  children,
}: {
  id: string;
  title: string;
  children: ReactNode;
}) {
  return (
    <section className="settings-group" aria-labelledby={id}>
      <Title id={id} order={1} className="settings-group-title">
        {title}
      </Title>
      {children}
    </section>
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
    <div className="view-page settings-page">
      <SettingsGroup id="settings-general" title="General">
        <SimpleGrid cols={{ base: 1, md: 2 }} spacing="lg">
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
        </SimpleGrid>
      </SettingsGroup>
      <SettingsGroup id="settings-account" title="Account">
        <AccountConnectionCard controller={accountConnection} />
      </SettingsGroup>
      <SettingsGroup id="settings-notarization" title="Notarization">
        <SettingsNotaries api={api} />
      </SettingsGroup>
      <SettingsGroup id="settings-security" title="Security & storage">
        <Paper className="settings-panel">
          <Text className="eyebrow">Privacy policy</Text>
          <Title order={2}>Preview storage</Title>
          <Text>
            Up to {status.preview_chars.toLocaleString()} characters of known text fields are
            indexed {isCluster ? 'in shared metadata' : 'locally'}. Raw headers are never indexed.
          </Text>
          <dl className="receipt-list">
            <Fact label="Vault" value={status.vault} />
            <Fact
              label="Metadata"
              value={`${status.metadata_backend} (${status.metadata_status})`}
            />
            <Fact
              label="Artifacts"
              value={`${status.artifact_backend} (${status.artifact_status})`}
            />
          </dl>
        </Paper>
      </SettingsGroup>
      <SettingsGroup id="settings-service" title="Service">
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
              Run <code>notaryctl update</code>, then restart the service after active work
              finishes.
            </Text>
          )}
        </Paper>
      </SettingsGroup>
      <SettingsGroup id="settings-developer" title="Developer">
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
      </SettingsGroup>
    </div>
  );
}
