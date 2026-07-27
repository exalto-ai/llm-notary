import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { defineConfig } from 'vite';

const brandAssetVersion = createHash('sha256')
  .update(readFileSync(new URL('./public/logo-dark.png', import.meta.url)))
  .update(readFileSync(new URL('./public/logo-light.png', import.meta.url)))
  .update(readFileSync(new URL('./public/social-preview.png', import.meta.url)))
  .digest('hex')
  .slice(0, 12);

export default defineConfig({
  define: {
    __BRAND_ASSET_VERSION__: JSON.stringify(brandAssetVersion)
  },
  plugins: [{
    name: 'brand-asset-version',
    transformIndexHtml(html) {
      return html.replaceAll('%BRAND_ASSET_VERSION%', brandAssetVersion);
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
