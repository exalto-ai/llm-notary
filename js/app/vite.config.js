import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { defineConfig } from 'vite';

const brandAssetVersion = createHash('sha256')
  .update(readFileSync(new URL('./public/logo-dark.png', import.meta.url)))
  .update(readFileSync(new URL('./public/logo-light.png', import.meta.url)))
  .update(readFileSync(new URL('./public/social-preview.png', import.meta.url)))
  .digest('hex')
  .slice(0, 12);
const publicOriginUrl = new URL(process.env.VITE_PUBLIC_ORIGIN ?? 'https://llmnotary.exalto.ai');
if (!['http:', 'https:'].includes(publicOriginUrl.protocol)
  || publicOriginUrl.pathname !== '/'
  || publicOriginUrl.search
  || publicOriginUrl.hash) {
  throw new Error('VITE_PUBLIC_ORIGIN must be an HTTP(S) origin without a path, query, or fragment');
}
const publicOrigin = publicOriginUrl.origin;

export default defineConfig({
  define: {
    __BRAND_ASSET_VERSION__: JSON.stringify(brandAssetVersion),
    __PUBLIC_ORIGIN__: JSON.stringify(publicOrigin)
  },
  plugins: [{
    name: 'brand-asset-version',
    transformIndexHtml(html) {
      return html
        .replaceAll('%BRAND_ASSET_VERSION%', brandAssetVersion)
        .replaceAll('%PUBLIC_ORIGIN%', publicOrigin);
    },
    closeBundle() {
      const llmsPath = new URL('./dist/llms.txt', import.meta.url);
      writeFileSync(llmsPath, readFileSync(llmsPath, 'utf8').replaceAll('%PUBLIC_ORIGIN%', publicOrigin));
    }
  }],
  server: {
    allowedHosts: true,
    port: 4173,
    proxy: {
      '/api': 'http://127.0.0.1:8080'
    }
  }
});
