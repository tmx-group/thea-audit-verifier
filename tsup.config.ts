import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: ['src/verify.ts'],
    format: ['esm', 'cjs'],
    dts: true,
    clean: true,
  },
  {
    entry: { cli: 'src/cli.ts' },
    format: ['esm'],
    banner: { js: '#!/usr/bin/env node' },
    clean: false,
  },
]);
