/**
 * dsh-syslog-alert build.
 *
 * Two bundles (mirrors dsh-hillstone-cli-ops / dsh-knowledge-base layout):
 *   - dist/index.mjs  host plugin (ESM, Node)   — syslog receiver + loopback /syslog-api
 *   - dist/client.js  client plugin (CJS, browser) — 智能告警中心 right-sidebar tab
 *
 * `react`, `react-dom`, and `react/jsx-runtime` are externalized: the harness
 * provides them at runtime as baseline module-table entries.
 *
 * Everything else is INLINED. This plugin has zero runtime dependencies — the
 * syslog receiver uses Node's built-in `dgram`/`net`, and the host half reaches
 * the device layer through the hillstone ops service rather than bundling ssh2.
 * That keeps dist/index.mjs self-contained and load-time failure-free.
 *
 * Usage:  pnpm install && pnpm run build
 */
import { build } from 'esbuild'
import { mkdirSync } from 'node:fs'

mkdirSync('dist', { recursive: true })

const dshExternal = ['@deepseek-ai/cordis', '@deepseek-ai/dsh-*']

await build({
  entryPoints: ['src/index.ts'],
  outfile: 'dist/index.mjs',
  bundle: true,
  format: 'esm',
  platform: 'node',
  target: ['node22'],
  sourcemap: true,
  external: dshExternal,
  logLevel: 'info',
})

await build({
  entryPoints: ['src/client.tsx'],
  outfile: 'dist/client.js',
  bundle: true,
  format: 'cjs',
  platform: 'browser',
  target: ['es2022'],
  sourcemap: true,
  jsx: 'automatic',
  external: [
    ...dshExternal,
    'react',
    'react-dom',
    'react-dom/client',
    'react/jsx-runtime',
    'react/jsx-dev-runtime',
    'scheduler',
  ],
  banner: {
    js: "window.__ModuleLoader__.load({ id: 'dsh-syslog-alert', factory: (require) => { var module = { exports: {} }; var exports = module.exports;",
  },
  footer: { js: 'return module.exports; } });' },
  logLevel: 'info',
})