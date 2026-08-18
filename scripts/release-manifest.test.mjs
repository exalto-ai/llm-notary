import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createChannelEnvelope, createChannelPointer, createReleaseManifest } from './release-manifest.mjs';

const version = '0.1.0';
const names = [
  `notary-runtime-${version}-linux-x86_64.tar.gz`, 'notaryctl-linux-x86_64', 'notaryd-linux-x86_64',
  `notary-runtime-${version}-linux-aarch64.tar.gz`, 'notaryctl-linux-aarch64', 'notaryd-linux-aarch64',
  `notary-runtime-${version}-darwin-aarch64.tar.gz`, 'notaryctl-darwin-aarch64', 'notaryd-darwin-aarch64',
  `notary-runtime-${version}-windows-x86_64.zip`, 'notaryctl-windows-x86_64.exe', 'notaryd-windows-x86_64.exe',
  'LLM-Notary-macos-arm64.dmg', 'LLM-Notary-macos-arm64.app.tar.gz',
];
const signatureText = 'untrusted comment: signature from minisign secret key\nRUTESTSIGNATURE\ntrusted comment: timestamp:1\nRUTESTTRUSTED';
const signature = Buffer.from(signatureText).toString('base64');

async function fixture() {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'notary-release-'));
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
  assert.equal(first.artifacts['linux-x86_64'].notaryctl.name, 'notaryctl-linux-x86_64');
  assert.equal(first.artifacts['linux-x86_64'].notaryd.name, 'notaryd-linux-x86_64');
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
    schema_version: 'notary/release/v1',
    build_id: 'a'.repeat(40) + '-123-1',
  }));
  await writeFile(signatureFile, signature);
  const pointer = await createChannelPointer({
    channel: 'latest',
    channelRevision: 123001,
    manifestFile,
    manifestUrl: 'https://notary.exalto.ai/downloads/releases/builds/build/release.json',
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
  const payload = '{"schema_version":"notary/release-channel/v1","channel":"latest","channel_revision":123001}\n';
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
    path.join(repository, 'apps/notary-app/src-tauri/tauri.release.conf.json'),
    'utf8',
  ));
  assert.equal(releaseConfig.plugins.updater.pubkey, publicKey);
});
