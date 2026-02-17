import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    'cli': 'src/cli.ts',
    'bin/cli': 'bin/mcp-fortify.ts',
    'index': 'src/index.ts',
  },
  format: ['esm'],
  target: 'node18',
  platform: 'node',
  dts: { entry: 'src/index.ts' },
  sourcemap: true,
  clean: true,
  splitting: false,
  banner: {
    js: '',
  },
});
