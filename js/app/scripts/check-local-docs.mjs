import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, extname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = resolve(appRoot, '../..');
const openapi = JSON.parse(readFileSync(resolve(appRoot, 'src/local-dashboard/generated/openapi.json'), 'utf8'));
const workflowDocuments = ['README.md', 'docs/local-service.md', 'docs/local-dashboard.md', 'docs/agent-playbook.md'];
const workflowContent = workflowDocuments.map((file) => readFileSync(resolve(repoRoot, file), 'utf8')).join('\n');

const basicAuth = openapi.components?.securitySchemes?.basicAuth;
if (basicAuth?.type !== 'http' || basicAuth?.scheme !== 'basic') {
  throw new Error('OpenAPI must expose the optional HTTP Basic security scheme');
}

const expectedOperations = {
  '/healthz': { get: ['200'] },
  '/openapi.json': { get: ['200'] },
  '/v1/session': { post: ['204', '401'], delete: ['204', '401'] },
  '/v1/status': { get: ['200', '401'] },
  '/v1/notaries': { get: ['200', '401', '500'] },
  '/v1/captures': { get: ['200', '400', '401'] },
  '/v1/captures/{capture_id}': { get: ['200', '401', '404'] },
  '/v1/captures/{capture_id}/finalizations': { post: ['202', '401', '404', '409'] },
  '/v1/operations': { get: ['200', '400', '401'] },
  '/v1/operations/{operation_id}': { get: ['200', '401', '404'] },
  '/v1/operations/{operation_id}/retry': { post: ['202', '401', '409'] },
  '/v1/captures/{capture_id}/package': { get: ['200', '401', '404'] },
  '/v1/captures/{capture_id}/trace': { get: ['200', '401', '404'] },
  '/v1/captures/{capture_id}/trace:verify': { post: ['200', '401', '422'] },
  '/v1/events': { get: ['200', '400', '401'] },
  '/v1/account': { get: ['200', '401'], post: ['202', '401', '409'], delete: ['204', '401', '409'] },
  '/v1/account/{request_id}': { get: ['200', '401', '404'] },
  '/v1/captures/{capture_id}/shares': { post: ['202', '401', '404'] },
  '/v1/shares/{share_id}': { get: ['200', '401', '404', '409', '503'] }
};

const actualPaths = Object.keys(openapi.paths).sort();
const expectedPaths = Object.keys(expectedOperations).sort();
if (JSON.stringify(actualPaths) !== JSON.stringify(expectedPaths)) {
  throw new Error(`OpenAPI path set changed. Expected ${expectedPaths.join(', ')}; received ${actualPaths.join(', ')}`);
}
for (const [path, methods] of Object.entries(expectedOperations)) {
  for (const [method, statuses] of Object.entries(methods)) {
    const operation = openapi.paths[path]?.[method];
    if (!operation) throw new Error(`OpenAPI is missing ${method.toUpperCase()} ${path}`);
    if (!operation.summary?.trim() || !operation.description?.trim()) {
      throw new Error(`${method.toUpperCase()} ${path} needs a summary and description`);
    }
    if (path.startsWith('/v1/') && JSON.stringify(operation.security) !== JSON.stringify([{}, { basicAuth: [] }])) {
      throw new Error(`${method.toUpperCase()} ${path} must describe anonymous or configured Basic authentication`);
    }
    const actualStatuses = Object.keys(operation.responses).sort();
    const expectedStatuses = [...statuses].sort();
    if (JSON.stringify(actualStatuses) !== JSON.stringify(expectedStatuses)) {
      throw new Error(`${method.toUpperCase()} ${path} response statuses changed: ${actualStatuses.join(', ')}`);
    }
    if (!workflowContent.includes(`${method.toUpperCase()} ${path}`)) {
      throw new Error(`Workflow documentation does not name ${method.toUpperCase()} ${path}`);
    }
  }
}

function parameterNames(path, method) {
  return (openapi.paths[path][method].parameters ?? []).map((parameter) => parameter.name).sort();
}
const expectedParameters = {
  'GET /v1/captures': ['capture_state', 'created_after_unix_ms', 'cursor', 'finalization_state', 'limit', 'model', 'offset', 'provider', 'query', 'streaming'],
  'GET /v1/operations': ['capture_id', 'cursor', 'kind', 'limit', 'state'],
  'GET /v1/events': ['after', 'capture_id', 'created_after_unix_ms', 'cursor', 'event_type', 'limit', 'operation_id', 'severity'],
  'GET /v1/shares/{share_id}': ['share_id']
};
for (const [operation, expected] of Object.entries(expectedParameters)) {
  const [method, path] = operation.split(' ');
  const actual = parameterNames(path, method.toLowerCase());
  if (JSON.stringify(actual) !== JSON.stringify([...expected].sort())) {
    throw new Error(`${operation} parameters changed: ${actual.join(', ')}`);
  }
}

const expectedRequiredFields = {
  Page_CaptureResponse: ['items'],
  Page_OperationSummaryResponse: ['items'],
  CaptureDetailResponse: ['artifacts', 'capture', 'finalizations'],
  CaptureResponse: ['capture_id', 'created_at_unix_ms', 'provider', 'operation', 'streaming', 'request_bytes', 'capture_state', 'finalization_state', 'finalization_eligible', 'prompt_preview', 'prompt_preview_truncated', 'output_preview', 'output_preview_truncated'],
  ErrorBody: ['code', 'message'],
  ErrorEnvelope: ['error'],
  EventResponse: ['event_id', 'created_at_unix_ms', 'event_type', 'severity', 'message'],
  EventListResponse: ['items'],
  FinalizationResponse: ['operation', 'deduplicated'],
  NotariesResponse: ['source', 'notaries'],
  NotaryResponse: ['endpoint', 'transport', 'key_id', 'status'],
  OperationAttemptResponse: ['attempt', 'state', 'started_at_unix_ms'],
  OperationResponse: ['operation_id', 'kind', 'state', 'attempt', 'attempt_history', 'created_at_unix_ms', 'retryable'],
  AccountConnectionStartedResponse: ['request_id', 'user_code', 'verification_uri_complete', 'expires_in_seconds', 'poll_interval_seconds', 'state'],
  ShareResponse: ['capture_id', 'share_id', 'state', 'visibility', 'status_url'],
  ShareStatusResponse: ['share_id', 'state', 'visibility'],
  TraceResponse: ['capture_id', 'manifest', 'trace'],
  VerificationResponse: ['capture_id', 'verified', 'verified_at_unix_ms', 'notary_key_id', 'trust_source']
};
for (const [schema, expected] of Object.entries(expectedRequiredFields)) {
  const actual = [...(openapi.components.schemas[schema]?.required ?? [])].sort();
  if (JSON.stringify(actual) !== JSON.stringify([...expected].sort())) {
    throw new Error(`${schema} required fields changed: ${actual.join(', ')}`);
  }
}

for (const term of ['202 Accepted', 'deduplicated', 'attempt_history', 'finalization_eligible', 'retryable', 'next_cursor', 'high_water_cursor', 'poll_interval_seconds', 'notary_key_id', 'trust_source']) {
  if (!workflowContent.includes(term)) throw new Error(`Workflow documentation is missing contract term: ${term}`);
}

const screenshots = [
  'overview-light.png', 'captures-dark.png', 'finalization-retry.png',
  'trace-verification.png', 'share-preview.png', 'share-confirmation.png',
  'share-admitted.png', 'mobile-navigation.png', 'mobile-capture-detail.png',
  'mobile-share-choice.png', 'mobile-share-preview.png'
];
const dashboardGuide = readFileSync(resolve(repoRoot, 'docs/local-dashboard.md'), 'utf8');
for (const file of screenshots) {
  const path = resolve(repoRoot, 'docs/images/local-dashboard', file);
  if (!existsSync(path)) throw new Error(`Missing documentation screenshot: ${file}`);
  const image = new RegExp(`!\\[([^\\]]{24,})\\]\\(images/local-dashboard/${file.replace('.', '\\.')}\\)`);
  if (!image.test(dashboardGuide)) throw new Error(`Missing useful alt text for ${file}`);
}

function markdownFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = resolve(directory, entry.name);
    return entry.isDirectory() ? markdownFiles(path) : extname(entry.name) === '.md' ? [path] : [];
  });
}
const markdown = [
  resolve(repoRoot, 'README.md'),
  resolve(repoRoot, 'CONTRIBUTING.md'),
  resolve(repoRoot, 'AGENTS.md'),
  resolve(repoRoot, 'DESIGN.md'),
  resolve(repoRoot, 'deploy/fly/README.md'),
  ...markdownFiles(resolve(repoRoot, 'docs'))
];
const consistencySources = [
  ...markdown,
  resolve(appRoot, 'public/llms.txt'),
  resolve(appRoot, 'src/main.jsx'),
  resolve(appRoot, 'src/platform-api/generated/openapi.json'),
  resolve(appRoot, 'src/platform-api/generated/api.generated.d.ts'),
  resolve(repoRoot, 'crates/llm-notary-platform/src/lib.rs')
];
const obsoleteCommand = /llm-notary\s+(proxy|verify-trace|download|config|vault|list|show|verify|decode)\b/;
const obsoleteDaemonInvocation = /^llm-notary(?:\s+--config\s+\S+)?\s*$/m;
for (const file of consistencySources) {
  const source = readFileSync(file, 'utf8');
  if (obsoleteCommand.test(source) || obsoleteDaemonInvocation.test(source)) {
    throw new Error(`Documentation retains an obsolete local operational command: ${file.replace(`${repoRoot}/`, '')}`);
  }
}

const inaccurateClaims = [
  /signed (?:production )?notary directory/i,
  /clients cache the signed notary directory/i,
  /releases include `llm-notaryd`/i,
  /deploy the notary and check the v2 admission prelude/i,
  /download the public evidence attached/i,
  /durable human-readable result/i,
  /processes the package in memory/i
];
for (const file of consistencySources) {
  const source = readFileSync(file, 'utf8');
  for (const claim of inaccurateClaims) {
    if (claim.test(source)) {
      throw new Error(`Documentation retains an inaccurate release, trust, or rollout claim: ${file.replace(`${repoRoot}/`, '')}`);
    }
  }
}

const publicDocs = readFileSync(resolve(appRoot, 'src/main.jsx'), 'utf8');
if (!publicDocs.includes('cargo install --locked --path crates/llm-notary-client')
  || !publicDocs.includes('The JSON directory is not separately signed')
  || !publicDocs.includes('"status_url":"/v1/shares/…"')) {
  throw new Error('Public-site documentation is missing the source-install, trust-directory, or local share-status boundary');
}

for (const required of ['llm-notaryd', 'llm-notary status', 'llm-notary captures list', '--json']) {
  if (!workflowContent.includes(required)) throw new Error(`Workflow documentation is missing daemon/CLI guidance: ${required}`);
}

for (const file of markdown) {
  const source = readFileSync(file, 'utf8');
  for (const match of source.matchAll(/\[[^\]]+\]\(([^)]+)\)/g)) {
    const target = match[1].split('#', 1)[0];
    if (!target || target.startsWith('http://') || target.startsWith('https://')) continue;
    const linked = resolve(dirname(file), target);
    if (!existsSync(linked)) throw new Error(`Broken link in ${file.replace(`${repoRoot}/`, '')}: ${match[1]}`);
  }
}

for (const file of markdown) {
  const source = readFileSync(resolve(repoRoot, file), 'utf8');
  if (!source.endsWith('\n') || source.endsWith('\n\n')) {
    throw new Error(`${file.replace(`${repoRoot}/`, '')} must end with exactly one newline`);
  }
}
process.stdout.write('Local REST documentation, screenshots, methods, statuses, filters, and schemas match the generated contract.\n');
