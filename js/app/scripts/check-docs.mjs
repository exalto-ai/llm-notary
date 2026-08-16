import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, extname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repositoryRoot = resolve(appRoot, '../..');
const hostedFlowPath = resolve(repositoryRoot, 'docs/hosted-platform.md');
const hostedFlow = readFileSync(hostedFlowPath, 'utf8');
const openapi = JSON.parse(
  readFileSync(resolve(appRoot, 'src/platform-api/generated/openapi.json'), 'utf8'),
);

const httpMethods = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace']);
const documentedOperations = [];
for (const [path, pathItem] of Object.entries(openapi.paths)) {
  for (const method of Object.keys(pathItem)) {
    if (!httpMethods.has(method)) continue;
    const operation = `${method.toUpperCase()} ${path}`;
    documentedOperations.push(operation);
    if (!hostedFlow.includes(`\`${operation}\``)) {
      throw new Error(`Hosted flow documentation does not assign ${operation}`);
    }
  }
}

if (documentedOperations.length === 0) {
  throw new Error('Hosted OpenAPI contract contains no operations');
}

function markdownFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = resolve(directory, entry.name);
    return entry.isDirectory() ? markdownFiles(path) : extname(entry.name) === '.md' ? [path] : [];
  });
}

const markdown = [
  resolve(repositoryRoot, 'README.md'),
  resolve(repositoryRoot, 'CONTRIBUTING.md'),
  resolve(repositoryRoot, 'AGENTS.md'),
  resolve(repositoryRoot, 'DESIGN.md'),
  resolve(repositoryRoot, 'deploy/fly/README.md'),
  ...markdownFiles(resolve(repositoryRoot, 'docs')),
];

for (const file of markdown) {
  const source = readFileSync(file, 'utf8');
  for (const match of source.matchAll(/\[[^\]]+\]\(([^)]+)\)/g)) {
    const target = match[1].split('#', 1)[0];
    if (
      !target ||
      target.startsWith('http://') ||
      target.startsWith('https://') ||
      target.startsWith('mailto:')
    ) {
      continue;
    }
    const linked = resolve(dirname(file), target);
    if (!existsSync(linked)) {
      throw new Error(`Broken link in ${file.replace(`${repositoryRoot}/`, '')}: ${match[1]}`);
    }
  }
  if (!source.endsWith('\n') || source.endsWith('\n\n')) {
    throw new Error(`${file.replace(`${repositoryRoot}/`, '')} must end with exactly one newline`);
  }
}

const publicDocs = readFileSync(resolve(appRoot, 'src/site/PublicDocs.tsx'), 'utf8');
const llms = readFileSync(resolve(appRoot, 'public/llms.txt'), 'utf8');
for (const [name, source] of [
  ['public site documentation', publicDocs],
  ['llms.txt', llms],
]) {
  if (!source.includes('github.com/exalto-ai/notary-runtime')) {
    throw new Error(`${name} must direct source users to the public runtime repository`);
  }
  if (source.includes('github.com/exalto-ai/notary.git')) {
    throw new Error(`${name} must not direct source users to the private monorepo`);
  }
}

const consistencySources = markdown.map((file) => [
  file.replace(`${repositoryRoot}/`, ''),
  readFileSync(file, 'utf8'),
]);
consistencySources.push(['public site documentation', publicDocs], ['llms.txt', llms]);

const obsoleteClaims = [
  /crates\/llm-notary-client\b/,
  /js\/app\/src\/local-dashboard\b/,
  /js\/app\/scripts\/(?:check-local-docs|generate-local-api|capture-dashboard-docs)\.mjs\b/,
  /one of four fixed provider adapters/i,
  /server mode with PostgreSQL and S3/i,
  /lime accent remains reserved/i,
  /complete all four onboarding stages/i,
];
for (const [name, source] of consistencySources) {
  for (const claim of obsoleteClaims) {
    if (claim.test(source)) {
      throw new Error(`Documentation retains an obsolete path or claim in ${name}: ${claim}`);
    }
  }
}

process.stdout.write(
  `Hosted documentation assigns all ${documentedOperations.length} OpenAPI operations and has current links, paths, and repository boundaries.\n`,
);
