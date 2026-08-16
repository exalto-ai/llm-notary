import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createChannelEnvelope, createChannelPointer, createReleaseManifest } from './release-manifest.mjs';

const version = '0.1.0';
const names = [
  `llm-notary-${version}-linux-x86_64.tar.gz`, 'llm-notary-linux-x86_64', 'llm-notaryd-linux-x86_64',
  `llm-notary-${version}-linux-aarch64.tar.gz`, 'llm-notary-linux-aarch64', 'llm-notaryd-linux-aarch64',
  `llm-notary-${version}-darwin-aarch64.tar.gz`, 'llm-notary-darwin-aarch64', 'llm-notaryd-darwin-aarch64',
  `llm-notary-${version}-windows-x86_64.zip`, 'llm-notary-windows-x86_64.exe', 'llm-notaryd-windows-x86_64.exe',
  'LLM-Notary-macos-arm64.dmg', 'LLM-Notary-macos-arm64.app.tar.gz',
];
const signatureText = 'untrusted comment: signature from minisign secret key\nRUTESTSIGNATURE\ntrusted comment: timestamp:1\nRUTESTTRUSTED';
const signature = Buffer.from(signatureText).toString('base64');

async function fixture() {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'llm-notary-release-'));
  await Promise.all(names.map((name) => writeFile(path.join(directory, name), `fixture:${name}`)));
  await writeFile(path.join(directory, 'LLM-Notary-macos-arm64.app.tar.gz.sig'), `${signature}\n`);
  return directory;
}

test('release manifest is deterministic and binds every installable payload', async () => {
  const releaseDir = await fixture();
  const input = {
    releaseDir,
    buildId: 'a'.repeat(40) + '-123-1',
    commitSha: 'a'.repeat(40),
    version,
    publishedAt: '2026-08-13T12:34:56Z',
    publicOrigin: 'https://notary.exalto.ai',
  };
  const first = await createReleaseManifest(input);
  const second = await createReleaseManifest(input);
  assert.deepEqual(first, second);
  assert.equal(first.platforms['darwin-aarch64'].signature, signature);
  assert.equal(first.artifacts['linux-x86_64'].llm_notary.name, 'llm-notary-linux-x86_64');
  assert.match(first.desktop['darwin-aarch64'].updater.url, /\/builds\/[a-f0-9-]+\//);
});

test('release manifest rejects incomplete releases and unsafe identities', async () => {
  const releaseDir = await fixture();
  await assert.rejects(() => createReleaseManifest({
    releaseDir,
    buildId: '../latest',
    commitSha: 'a'.repeat(40),
    version,
    publishedAt: '2026-08-13T12:34:56Z',
    publicOrigin: 'https://notary.exalto.ai',
  }), /safe release identifier/);
  await writeFile(path.join(releaseDir, 'LLM-Notary-macos-arm64.app.tar.gz.sig'), 'bad');
  await assert.rejects(() => createReleaseManifest({
    releaseDir,
    buildId: 'a'.repeat(40) + '-123-1',
    commitSha: 'a'.repeat(40),
    version,
    publishedAt: '2026-08-13T12:34:56Z',
    publicOrigin: 'https://notary.exalto.ai',
  }), /signature is malformed/);
});

test('channel pointer binds the exact immutable manifest', async () => {
  const directory = await fixture();
  const manifestFile = path.join(directory, 'release.json');
  const signatureFile = path.join(directory, 'release.json.sig');
  await writeFile(manifestFile, JSON.stringify({
    schema_version: 'llm-notary/release/v1',
    build_id: 'a'.repeat(40) + '-123-1',
  }));
  await writeFile(signatureFile, signature);
  const pointer = await createChannelPointer({
    channel: 'latest',
    channelRevision: 123001,
    manifestFile,
    manifestUrl: 'https://notary.exalto.ai/downloads/cli/builds/build/release.json',
    manifestSignatureFile: signatureFile,
  });
  assert.equal(pointer.channel, 'latest');
  assert.equal(pointer.channel_revision, 123001);
  assert.equal(pointer.manifest_sha256.length, 64);
  assert.equal(pointer.manifest_signature, signature);
  assert.equal(await readFile(signatureFile, 'utf8'), signature);
});

test('channel envelope preserves the exact signed payload bytes', async () => {
  const directory = await fixture();
  const payloadFile = path.join(directory, 'channel.payload.json');
  const signatureFile = path.join(directory, 'channel.payload.json.sig');
  const payload = '{"schema_version":"llm-notary/release-channel/v1","channel":"latest","channel_revision":123001}\n';
  await writeFile(payloadFile, payload);
  await writeFile(signatureFile, signature);
  const envelope = await createChannelEnvelope({
    payloadFile,
    payloadSignatureFile: signatureFile,
  });
  assert.equal(Buffer.from(envelope.signed, 'base64').toString(), payload);
  assert.equal(envelope.signature, signature);
  await writeFile(payloadFile, '{"schema_version":"bad"}\n');
  await assert.rejects(
    () => createChannelEnvelope({ payloadFile, payloadSignatureFile: signatureFile }),
    /unsupported schema/,
  );
});

test('release packaging uses the committed updater trust root', async () => {
  const repository = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
  const publicKey = (await readFile(path.join(repository, 'runtime/config/updater-public-key.txt'), 'utf8')).trim();
  const releaseConfig = JSON.parse(await readFile(
    path.join(repository, 'js/desktop/src-tauri/tauri.release.conf.json'),
    'utf8',
  ));
  assert.equal(releaseConfig.plugins.updater.pubkey, publicKey);
});
