import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/verify.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
});
