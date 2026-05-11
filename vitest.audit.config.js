// Separate config for the self-audit test, which requires dist/ to exist
// and is therefore run only after `npm run build` (in CI: as its own step).
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'node',  // node-fs, no jsdom needed
    globals: false,
    include: ['src/test/self-audit.test.js'],
    setupFiles: ['./src/test/setup.js'],
  },
})
