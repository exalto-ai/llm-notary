import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = resolve(appRoot, '../..');
const generatedDir = resolve(appRoot, 'src/local-dashboard/generated');
const specification = resolve(generatedDir, 'openapi.json');
const types = resolve(generatedDir, 'api.generated.d.ts');
const check = process.argv.includes('--check');
const temporaryDir = check ? mkdtempSync(join(tmpdir(), 'llm-notary-openapi-')) : null;
const outputSpecification = temporaryDir ? join(temporaryDir, 'openapi.json') : specification;
const outputTypes = temporaryDir ? join(temporaryDir, 'api.generated.d.ts') : types;

mkdirSync(generatedDir, { recursive: true });
const exported = spawnSync(
  'cargo',
  ['run', '--quiet', '-p', 'llm-notary-client', '--example', 'export-local-openapi'],
  { cwd: repoRoot, encoding: 'utf8' }
);
if (exported.status !== 0) {
  process.stderr.write(exported.stderr);
  if (temporaryDir) rmSync(temporaryDir, { recursive: true, force: true });
  process.exit(exported.status ?? 1);
}
writeFileSync(outputSpecification, exported.stdout);

const generated = spawnSync(
  resolve(appRoot, 'node_modules/.bin/openapi-typescript'),
  [outputSpecification, '--output', outputTypes],
  { cwd: appRoot, encoding: 'utf8' }
);
if (generated.status !== 0) {
  process.stderr.write(generated.stderr);
  if (temporaryDir) rmSync(temporaryDir, { recursive: true, force: true });
  process.exit(generated.status ?? 1);
}
if (check) {
  const currentSpecification = readFileSync(specification, 'utf8');
  const currentTypes = readFileSync(types, 'utf8');
  const nextSpecification = readFileSync(outputSpecification, 'utf8');
  const nextTypes = readFileSync(outputTypes, 'utf8');
  rmSync(temporaryDir, { recursive: true, force: true });
  if (currentSpecification !== nextSpecification || currentTypes !== nextTypes) {
    process.stderr.write('The committed local API contract is stale. Run `npm run generate:local-api` and commit the result.\n');
    process.exit(1);
  }
  process.stdout.write('The committed local API contract is current.\n');
} else {
  process.stdout.write(`Generated ${types.replace(`${repoRoot}/`, '')}\n`);
}
