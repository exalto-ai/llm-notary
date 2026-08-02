import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = resolve(appRoot, '../..');
const generatedDir = resolve(appRoot, 'src/local-dashboard/generated');
const specification = resolve(generatedDir, 'openapi.json');
const types = resolve(generatedDir, 'api.generated.d.ts');

mkdirSync(generatedDir, { recursive: true });
const exported = spawnSync(
  'cargo',
  ['run', '--quiet', '-p', 'llm-notary-client', '--example', 'export-local-openapi'],
  { cwd: repoRoot, encoding: 'utf8' }
);
if (exported.status !== 0) {
  process.stderr.write(exported.stderr);
  process.exit(exported.status ?? 1);
}
writeFileSync(specification, exported.stdout);

const generated = spawnSync(
  resolve(appRoot, 'node_modules/.bin/openapi-typescript'),
  [specification, '--output', types],
  { cwd: appRoot, encoding: 'utf8' }
);
if (generated.status !== 0) {
  process.stderr.write(generated.stderr);
  process.exit(generated.status ?? 1);
}
process.stdout.write(`Generated ${types.replace(`${repoRoot}/`, '')}\n`);
