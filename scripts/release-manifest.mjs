import { createHash } from 'node:crypto';
import { readFile, stat, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import path from 'node:path';

export const RELEASE_SCHEMA = 'llm-notary/release/v1';
export const CHANNEL_SCHEMA = 'llm-notary/release-channel/v1';
export const CHANNEL_ENVELOPE_SCHEMA = 'llm-notary/release-channel-envelope/v1';

const safeIdentifier = (value) => typeof value === 'string'
  && value.length > 0
  && !value.startsWith('.')
  && !value.includes('..')
  && /^[A-Za-z0-9._-]+$/.test(value);

function requireSafeIdentifier(name, value) {
  if (!safeIdentifier(value)) throw new Error(`${name} is not a safe release identifier`);
  return value;
}

function canonicalJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function requireTauriSignature(value, name) {
  let decoded;
  try {
    decoded = Buffer.from(value, 'base64').toString('utf8');
  } catch {
    throw new Error(`${name} is malformed`);
  }
  if (!/^[A-Za-z0-9+/=]+$/.test(value) || !decoded.includes('untrusted comment:') || !decoded.includes('\n')) {
    throw new Error(`${name} is malformed`);
  }
  return value;
}

async function sha256(file) {
  return createHash('sha256').update(await readFile(file)).digest('hex');
}

async function artifact(releaseDir, buildUrl, name) {
  const file = path.join(releaseDir, name);
  const metadata = await stat(file);
  if (!metadata.isFile() || metadata.size === 0) throw new Error(`${name} is missing or empty`);
  return {
    name,
    url: `${buildUrl}/${name}`,
    size_bytes: metadata.size,
    sha256: await sha256(file),
  };
}

export async function createReleaseManifest({
  releaseDir,
  buildId,
  commitSha,
  version,
  publishedAt,
  publicOrigin,
}) {
  requireSafeIdentifier('build ID', buildId);
  if (!/^[0-9a-f]{40}$/.test(commitSha)) throw new Error('commit SHA must contain 40 lowercase hexadecimal characters');
  requireSafeIdentifier('version', version);
  if (!Number.isFinite(Date.parse(publishedAt))) throw new Error('publishedAt must be an RFC 3339 timestamp');
  const origin = new URL(publicOrigin);
  if (origin.protocol !== 'https:' || origin.pathname !== '/' || origin.search || origin.hash) {
    throw new Error('publicOrigin must be an HTTPS origin');
  }
  const buildUrl = `${origin.origin}/downloads/cli/builds/${buildId}`;
  const updaterName = 'LLM-Notary-macos-arm64.app.tar.gz';
  const updaterSignature = requireTauriSignature(
    (await readFile(path.join(releaseDir, `${updaterName}.sig`), 'utf8')).trim(),
    'the Tauri updater signature',
  );

  const platforms = {
    'linux-x86_64': {
      archive: await artifact(releaseDir, buildUrl, `llm-notary-${version}-linux-x86_64.tar.gz`),
      llm_notary: await artifact(releaseDir, buildUrl, 'llm-notary-linux-x86_64'),
      notaryd: await artifact(releaseDir, buildUrl, 'notaryd-linux-x86_64'),
    },
    'linux-aarch64': {
      archive: await artifact(releaseDir, buildUrl, `llm-notary-${version}-linux-aarch64.tar.gz`),
      llm_notary: await artifact(releaseDir, buildUrl, 'llm-notary-linux-aarch64'),
      notaryd: await artifact(releaseDir, buildUrl, 'notaryd-linux-aarch64'),
    },
    'darwin-aarch64': {
      archive: await artifact(releaseDir, buildUrl, `llm-notary-${version}-darwin-aarch64.tar.gz`),
      llm_notary: await artifact(releaseDir, buildUrl, 'llm-notary-darwin-aarch64'),
      notaryd: await artifact(releaseDir, buildUrl, 'notaryd-darwin-aarch64'),
    },
    'windows-x86_64': {
      archive: await artifact(releaseDir, buildUrl, `llm-notary-${version}-windows-x86_64.zip`),
      llm_notary: await artifact(releaseDir, buildUrl, 'llm-notary-windows-x86_64.exe'),
      notaryd: await artifact(releaseDir, buildUrl, 'notaryd-windows-x86_64.exe'),
    },
  };
  const dmg = await artifact(releaseDir, buildUrl, 'LLM-Notary-macos-arm64.dmg');
  const updater = await artifact(releaseDir, buildUrl, updaterName);

  return {
    schema_version: RELEASE_SCHEMA,
    build_id: buildId,
    commit_sha: commitSha,
    version,
    published_at: new Date(publishedAt).toISOString(),
    artifacts: platforms,
    desktop: {
      'darwin-aarch64': {
        dmg,
        updater: { ...updater, signature: updaterSignature },
      },
    },
    platforms: {
      'darwin-aarch64': {
        url: updater.url,
        signature: updaterSignature,
      },
    },
  };
}

export async function createChannelPointer({ channel, channelRevision, manifestFile, manifestUrl, manifestSignatureFile }) {
  requireSafeIdentifier('channel', channel);
  if (!Number.isSafeInteger(channelRevision) || channelRevision <= 0) {
    throw new Error('channel revision must be a positive safe integer');
  }
  const bytes = await readFile(manifestFile);
  const manifest = JSON.parse(bytes);
  if (manifest.schema_version !== RELEASE_SCHEMA || !safeIdentifier(manifest.build_id)) {
    throw new Error('release manifest has an unsupported schema or build ID');
  }
  const url = new URL(manifestUrl);
  if (url.protocol !== 'https:') throw new Error('manifest URL must use HTTPS');
  const signature = requireTauriSignature(
    (await readFile(manifestSignatureFile, 'utf8')).trim(),
    'release manifest signature',
  );
  return {
    schema_version: CHANNEL_SCHEMA,
    channel,
    channel_revision: channelRevision,
    build_id: manifest.build_id,
    manifest_url: url.toString(),
    manifest_sha256: createHash('sha256').update(bytes).digest('hex'),
    manifest_signature: signature,
  };
}

export async function createChannelEnvelope({ payloadFile, payloadSignatureFile }) {
  const payload = await readFile(payloadFile);
  const parsed = JSON.parse(payload);
  if (parsed.schema_version !== CHANNEL_SCHEMA || !safeIdentifier(parsed.channel)
      || !Number.isSafeInteger(parsed.channel_revision) || parsed.channel_revision <= 0) {
    throw new Error('channel payload has an unsupported schema, channel, or revision');
  }
  const signature = requireTauriSignature(
    (await readFile(payloadSignatureFile, 'utf8')).trim(),
    'channel payload signature',
  );
  return {
    schema_version: CHANNEL_ENVELOPE_SCHEMA,
    signed: payload.toString('base64'),
    signature,
  };
}

function parseArgs(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith('--') || value === undefined) throw new Error('arguments must be --name value pairs');
    values[key.slice(2)] = value;
  }
  return values;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  let value;
  if (args.envelope) {
    value = await createChannelEnvelope({
      payloadFile: args.payload,
      payloadSignatureFile: args.signature,
    });
  } else if (args.channel) {
    value = await createChannelPointer({
      channel: args.channel,
      channelRevision: Number(args.revision),
      manifestFile: args.manifest,
      manifestUrl: args['manifest-url'],
      manifestSignatureFile: args.signature,
    });
  } else {
    value = await createReleaseManifest({
      releaseDir: args['release-dir'],
      buildId: args['build-id'],
      commitSha: args['commit-sha'],
      version: args.version,
      publishedAt: args['published-at'],
      publicOrigin: args['public-origin'],
    });
  }
  await writeFile(args.output, canonicalJson(value), { flag: 'wx' });
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
