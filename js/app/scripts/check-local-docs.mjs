import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = resolve(appRoot, '../..');
const openapi = JSON.parse(readFileSync(resolve(appRoot, 'src/local-dashboard/generated/openapi.json'), 'utf8'));
const documents = ['README.md', 'docs/local-service.md', 'docs/local-dashboard.md', 'docs/agent-playbook.md'];
const content = documents.map((file) => readFileSync(resolve(repoRoot, file), 'utf8')).join('\n');

const requiredPaths = [
  '/healthz', '/openapi.json', '/v1/status', '/v1/captures',
  '/v1/captures/{capture_id}', '/v1/captures/{capture_id}/finalizations',
  '/v1/operations/{operation_id}', '/v1/operations/{operation_id}/retry',
  '/v1/captures/{capture_id}/trace:verify'
];
for (const path of requiredPaths) {
  if (!openapi.paths[path]) throw new Error(`Documented API path is absent from OpenAPI: ${path}`);
  if (!content.includes(path)) throw new Error(`Local workflow documentation does not name API path: ${path}`);
}

const screenshots = [
  'overview-light.png', 'captures-dark.png', 'finalization-retry.png',
  'trace-verification.png', 'mobile-navigation.png'
];
const dashboardGuide = readFileSync(resolve(repoRoot, 'docs/local-dashboard.md'), 'utf8');
for (const file of screenshots) {
  const path = resolve(repoRoot, 'docs/images/local-dashboard', file);
  if (!existsSync(path)) throw new Error(`Missing documentation screenshot: ${file}`);
  const image = new RegExp(`!\\[([^\\]]{24,})\\]\\(images/local-dashboard/${file.replace('.', '\\.')}\\)`);
  if (!image.test(dashboardGuide)) throw new Error(`Missing useful alt text for ${file}`);
}

const obsoleteCommands = /^\s*llm-notary\s+(proxy|list|show|status|finalize|verify|verify-trace|decode|publish)\b/m;
if (obsoleteCommands.test(content)) throw new Error('Documentation retains an obsolete operational CLI command');

for (const file of documents) {
  if (!existsSync(resolve(repoRoot, file))) throw new Error(`Missing local workflow document: ${file}`);
  const markdown = readFileSync(resolve(repoRoot, file), 'utf8');
  for (const match of markdown.matchAll(/\[[^\]]+\]\(([^)]+)\)/g)) {
    const target = match[1].split('#', 1)[0];
    if (!target || target.startsWith('http://') || target.startsWith('https://')) continue;
    const linked = resolve(dirname(resolve(repoRoot, file)), target);
    if (!existsSync(linked)) throw new Error(`Broken link in ${file}: ${match[1]}`);
  }
}
process.stdout.write('Local REST documentation and screenshots match the generated contract.\n');
