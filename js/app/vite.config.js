import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

const brandAssetVersion = createHash('sha256')
  .update(readFileSync(new URL('./public/notary-mark.svg', import.meta.url)))
  .update(readFileSync(new URL('./public/favicon.svg', import.meta.url)))
  .update(readFileSync(new URL('./public/social-preview.png', import.meta.url)))
  .digest('hex')
  .slice(0, 12);
const publicOriginUrl = new URL(process.env.VITE_PUBLIC_ORIGIN ?? 'https://llm-notary.exalto.ai');
if (!['http:', 'https:'].includes(publicOriginUrl.protocol)
  || publicOriginUrl.pathname !== '/'
  || publicOriginUrl.search
  || publicOriginUrl.hash) {
  throw new Error('VITE_PUBLIC_ORIGIN must be an HTTP(S) origin without a path, query, or fragment');
}
const publicOrigin = publicOriginUrl.origin;
const apiProxyOrigin = process.env.VITE_API_ORIGIN ?? 'http://127.0.0.1:8080';

export default defineConfig(({ mode }) => {
  const localDashboard = mode === 'local-dashboard';
  return {
    resolve: {
      alias: {
        '@': resolve(process.cwd(), 'src')
      }
    },
    publicDir: localDashboard ? false : 'public',
    define: {
      __BRAND_ASSET_VERSION__: JSON.stringify(brandAssetVersion),
      __PUBLIC_ORIGIN__: JSON.stringify(publicOrigin)
    },
    plugins: [react(), tailwindcss(), ...(localDashboard ? [{
      name: 'local-dashboard-openapi',
      configureServer(server) {
        server.middlewares.use('/openapi.json', (request, response, next) => {
          if (!['GET', 'HEAD'].includes(request.method ?? '')) return next();
          const body = readFileSync(new URL('./src/local-dashboard/generated/openapi.json', import.meta.url));
          response.statusCode = 200;
          response.setHeader('Content-Type', 'application/json; charset=utf-8');
          response.setHeader('Cache-Control', 'no-store');
          response.setHeader('Content-Length', body.byteLength);
          response.end(request.method === 'HEAD' ? undefined : body);
        });
      }
    }] : [{
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
    }])],
    build: localDashboard ? {
      outDir: '../../crates/llm-notary-client/dashboard',
      emptyOutDir: true,
      rollupOptions: {
        input: resolve(process.cwd(), 'local.html'),
        output: {
          entryFileNames: 'assets/dashboard.js',
          chunkFileNames: 'assets/[name].js',
          assetFileNames: (asset) => asset.names?.some((name) => name.endsWith('.css'))
            ? 'assets/dashboard.css'
            : 'assets/[name][extname]'
        }
      }
    } : undefined,
    server: {
      allowedHosts: true,
      port: 4173,
      proxy: {
        '/api': { target: apiProxyOrigin, changeOrigin: true }
      }
    }
  };
});
