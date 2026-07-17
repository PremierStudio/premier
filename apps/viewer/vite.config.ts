import { defineConfig } from 'vitest/config';
import { svelte } from '@sveltejs/vite-plugin-svelte';

export default defineConfig({
  plugins: [svelte()],
  resolve: { conditions: ['browser'] },
  server: {
    port: 5173,
    proxy: { '/api': 'http://127.0.0.1:4317' }
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test-setup.ts'],
    include: ['src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'text-summary', 'html'],
      // Phase-1 trust/load modules are held to full coverage.
      include: [
        'src/lib/types.ts',
        'src/lib/traceLoad.ts',
        'src/lib/api.ts',
        'src/lib/deepLink.ts',
        'src/lib/causal.ts'
      ],
      thresholds: {
        lines: 100,
        functions: 100,
        branches: 100,
        statements: 100
      }
    }
  }
});
