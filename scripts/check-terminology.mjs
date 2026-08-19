// Repository-wide brand and terminology audit for the Notary product model.
//
// The check is semantic, not a blind ban. "Capture" stays valid wherever it
// names a real capture operation, checkpoint, capture-specific storage, or
// usage meter, so it is not scanned at all. What is scanned is the vocabulary
// the product deliberately retired: the old brand, the old public origin, the
// old release namespace, retired executable names, and Finalize/Finalization
// as product terminology.
//
// Text that must keep naming a retired identifier — negative tests that assert
// old formats fail, anti-regression rules, and historical material — is
// classified explicitly below with the reason it is allowed.

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const repositoryRoot = resolve(import.meta.dirname, '..');

// Trees excluded wholesale, each for a structural reason rather than a naming one.
const excludedPrefixes = [
  'docs/adr/', // accepted ADRs are history and keep the names used at the time
  'platform/migrations/', // forward-only migrations are history
  'runtime/vendor/', // pinned third-party sources
];

const excludedPatterns = [
  /(^|\/)Cargo\.lock$/,
  /(^|\/)package-lock\.json$/,
  /(^|\/)dashboard\/assets\//, // compiled dashboard bundle
  /(^|\/)check-terminology\.mjs$/, // this audit defines the terms it rejects
  /\.(png|jpg|jpeg|gif|webp|ico|pdf|zip|gz|woff2?|ttf|otf)$/,
];

const rules = [
  {
    label: 'retired brand or first-party identifier',
    // Separator-optional and case-insensitive: LLMNotary, LLM NOTARY, and
    // llm-notary are all the retired brand.
    pattern: /llm[\s_-]*notary/gi,
  },
  { label: 'retired public origin', pattern: /llm-notary\.exalto\.ai/gi },
  {
    label: 'retired release namespace',
    // Matches the release prefix with or without the /downloads/ mount point,
    // so documentation of a bare cli/ object is caught too.
    pattern: /\bcli\/(?:builds|channels|latest)\b/g,
  },
  {
    label: 'retired executable name',
    pattern: /\b(?:llm-notaryd|llm-notary-cli|notary-cli)\b/g,
  },
  {
    label: 'retired product terminology',
    // Finalize as product vocabulary. A receiver-qualified `.finalize()` is a
    // third-party digest or writer API and is matched out before this runs.
    pattern: /\bfinaliz(?:e|es|ed|ing|ation|ations|er|ers)\b/gi,
  },
];

// A match is allowed only when the file is listed here and the matched line
// contains the given text. Every entry states why the retired name must stay.
const classified = [
  {
    file: 'platform/crates/notary-api/src/config.rs',
    contains: 'LLM_NOTARY_',
    reason: 'asserts retired environment variables are ignored',
  },
  {
    file: 'runtime/crates/notary-core/src/registry.rs',
    contains: 'llm-notary/notary-registry/',
    reason: 'asserts retired Registry formats are rejected',
  },
  {
    file: 'runtime/crates/notaryd/src/service/registry.rs',
    contains: 'llm-notary/notary-directory/',
    reason: 'asserts retired Registry cache formats are rejected',
  },
  {
    file: 'runtime/crates/notaryd/src/config.rs',
    contains: 'llm-notary/agent-config/v1',
    reason: 'asserts the retired agent-config format is rejected',
  },
  {
    file: 'runtime/crates/notary-updater/src/install.rs',
    contains: 'llm-notary/update-journal/v1',
    reason: 'asserts a retired update journal is rejected',
  },
  {
    file: 'runtime/crates/notary-updater/src/release.rs',
    contains: 'llm-notary/release/v1',
    reason: 'asserts a retired release manifest is rejected',
  },
  {
    file: 'runtime/crates/notaryd/src/admin.rs',
    contains: '/finalizations',
    reason: 'asserts the removed finalizations route returns 404',
  },
  {
    file: 'apps/notary-app/src/App.browser.test.tsx',
    contains: 'Finalizations',
    reason: 'asserts the retired navigation label is absent',
  },
  {
    file: 'runtime/benchmarks/opencode-e2e/test_runner.py',
    contains: 'llm_notaryd',
    reason: 'asserts the retired canary option never reappears',
  },
  {
    file: 'platform/web/scripts/check-docs.mjs',
    contains: 'llm-notary-client',
    reason: 'asserts the retired crate path never reappears in documentation',
  },
  {
    file: 'platform/web/scripts/test-brand.mjs',
    contains: 'LLM NOTARY',
    reason: 'asserts the retired relay label never reappears',
  },
  {
    file: 'platform/web/src/theme.ts',
    contains: 'llm-notary-theme',
    reason: 'reads the retired storage key so a visitor keeps their theme',
  },
  {
    file: 'runtime/docs/cluster-operations.md',
    contains: 'llm-notary-cluster_',
    reason: 'names the retired Compose volumes operators must keep',
  },
  // The three Fly applications keep their provisioned names for now. Renaming a
  // Fly app means creating a new one and migrating every secret and hostname,
  // which is tracked separately rather than bundled into a rename.
  {
    file: 'deploy/fly/README.md',
    contains: 'llm-notary-prod',
    reason: 'names the existing Fly organization and applications',
  },
  {
    file: 'deploy/fly/notary-api.fly.toml',
    contains: 'llm-notary-prod-api',
    reason: 'the provisioned Fly application name',
  },
  {
    file: 'deploy/fly/notary-server.fly.toml',
    contains: 'llm-notary-prod',
    reason: 'the provisioned Fly application names',
  },
  {
    file: 'deploy/fly/web.fly.toml',
    contains: 'llm-notary-prod-web',
    reason: 'the provisioned Fly application name',
  },
  {
    file: 'deploy/fly/preflight-notary-api.sh',
    contains: 'llm-notary-prod-api',
    reason: 'defaults to the provisioned Fly application name',
  },
  {
    file: 'deploy/fly/preflight-notary-server.sh',
    contains: 'llm-notary-prod-server',
    reason: 'defaults to the provisioned Fly application name',
  },
  {
    file: 'deploy/fly/test-preflight-notary-api.sh',
    contains: 'llm-notary-prod-api',
    reason: 'fixture for the provisioned Fly application name',
  },
  {
    file: 'deploy/fly/test-preflight-notary-server.sh',
    contains: 'llm-notary-prod-server',
    reason: 'fixture for the provisioned Fly application name',
  },
  {
    file: 'platform/web/Caddyfile.fly',
    contains: 'llm-notary-prod-api.flycast',
    reason: 'the provisioned Fly application name',
  },
  {
    file: '.github/workflows/deploy.yml',
    contains: 'llm-notary-prod',
    reason: 'the provisioned Fly application names',
  },
];

const usedEntries = new Set();

function isAllowed(file, line) {
  const entry = classified.find(
    (candidate) => candidate.file === file && line.includes(candidate.contains),
  );
  if (!entry) return false;
  usedEntries.add(entry);
  return true;
}

const tracked = execFileSync('git', ['ls-files', '-z'], {
  cwd: repositoryRoot,
  encoding: 'utf8',
  maxBuffer: 64 * 1024 * 1024,
})
  .split('\0')
  .filter(Boolean)
  .filter((file) => !excludedPrefixes.some((prefix) => file.startsWith(prefix)))
  .filter((file) => !excludedPatterns.some((pattern) => pattern.test(file)));

const findings = [];
for (const file of tracked) {
  let contents;
  try {
    contents = readFileSync(resolve(repositoryRoot, file), 'utf8');
  } catch {
    continue;
  }
  if (contents.includes('\0')) continue;
  contents.split('\n').forEach((rawLine, index) => {
    // Third-party digest and writer APIs legitimately expose finalize(). Only
    // a receiver-qualified, zero-argument call is exempt, so a reintroduced
    // product API such as `finalize(trace)` is still reported.
    const line = rawLine
      .replaceAll(/[A-Za-z0-9_\])]\.finalize\(\)/g, '')
      // A chain continued onto its own line keeps its receiver above it.
      .replace(/^\s*\.finalize\(\)/, '');
    for (const rule of rules) {
      rule.pattern.lastIndex = 0;
      const match = rule.pattern.exec(line);
      if (!match) continue;
      if (isAllowed(file, rawLine)) continue;
      findings.push(`${file}:${index + 1}: ${rule.label}: ${match[0]}`);
    }
  });
}

// An entry that no longer suppresses anything is stale: either the file went
// away or the retired name was cleaned up. Either way the exemption should go
// rather than sit there widening the allowlist.
const unusedEntries = classified.filter((entry) => !usedEntries.has(entry));
if (unusedEntries.length) {
  process.stderr.write(
    `Terminology allowlist entries no longer suppress anything; remove them:\n${unusedEntries
      .map((entry) => `  ${entry.file} (${entry.contains || 'whole file'})`)
      .join('\n')}\n`,
  );
  process.exit(1);
}

if (findings.length) {
  process.stderr.write(
    `Retired Notary terminology found. Rename it, or classify it in scripts/check-terminology.mjs with a reason:\n${findings
      .map((finding) => `  ${finding}`)
      .join('\n')}\n`,
  );
  process.exit(1);
}

process.stdout.write(
  `Brand and terminology audit passed across ${tracked.length} tracked files.\n`,
);
