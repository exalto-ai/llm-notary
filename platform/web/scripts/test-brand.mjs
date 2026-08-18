import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const html = readFileSync(resolve(root, 'index.html'), 'utf8');
const packageJson = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));
const llms = readFileSync(resolve(root, 'public/llms.txt'), 'utf8');
const mark = readFileSync(resolve(root, 'public/notary-mark.svg'), 'utf8');
const favicon = readFileSync(resolve(root, 'public/favicon.svg'), 'utf8');
const preview = readFileSync(resolve(root, 'public/social-preview.png'));

function requireText(source, expected, label) {
  if (!source.includes(expected))
    throw new Error(`${label} is missing ${JSON.stringify(expected)}`);
}

requireText(html, '<title>Notary by Exalto</title>', 'default browser title');
requireText(html, 'property="og:site_name" content="Notary by Exalto"', 'Open Graph identity');
requireText(
  html,
  'content="Notary by Exalto · Verifiable intelligence · Notarized traces for independent verification"',
  'social-preview alt text',
);
requireText(html, '"name": "Notary by Exalto"', 'structured metadata');
if (!llms.startsWith('# Notary by Exalto\n')) {
  throw new Error('llms.txt must begin with the formal endorsed identity');
}
requireText(mark, '<title id="title">Notary</title>', 'public mark title');
requireText(favicon, '<title id="title">Notary</title>', 'favicon title');
if (packageJson.name !== '@exalto/notary-web') {
  throw new Error('hosted frontend package identity is stale');
}
if (preview.readUInt32BE(16) !== 1200 || preview.readUInt32BE(20) !== 630) {
  throw new Error('social preview must be 1200x630');
}

process.stdout.write('Hosted identity metadata and assets are consistent.\n');
