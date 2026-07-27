import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    allowedHosts: true,
    port: 4173,
    proxy: {
      '/api': 'http://127.0.0.1:8080'
    }
  }
});
