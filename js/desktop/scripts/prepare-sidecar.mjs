import { execFileSync } from 'node:child_process';
import { chmodSync, copyFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const profile = process.argv[2] === 'release' ? 'release' : 'debug';
const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repository = resolve(scriptDirectory, '../../..');
const targetTriple = execFileSync('rustc', ['--print', 'host-tuple'], { encoding: 'utf8' }).trim();
const extension = process.platform === 'win32' ? '.exe' : '';
const cargoArguments = ['build', '-p', 'llm-notary-client', '--bin', 'llm-notaryd'];
if (profile === 'release') cargoArguments.push('--release');

execFileSync('cargo', cargoArguments, { cwd: repository, stdio: 'inherit' });

const source = resolve(repository, 'target', profile, `llm-notaryd${extension}`);
const destinationDirectory = resolve(scriptDirectory, '../src-tauri/binaries');
const destination = resolve(destinationDirectory, `llm-notaryd-${targetTriple}${extension}`);
mkdirSync(destinationDirectory, { recursive: true });
copyFileSync(source, destination);
if (process.platform !== 'win32') chmodSync(destination, 0o755);
console.log(`Prepared ${destination}`);
