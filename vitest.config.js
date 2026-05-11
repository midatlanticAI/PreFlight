import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'jsdom',
    globals: false,
    include: ['src/**/*.test.{js,jsx}'],
    // self-audit.test.js needs dist/ — run it via vitest.audit.config.js after `npm run build`.
    exclude: ['**/self-audit.test.js', '**/node_modules/**'],
    setupFiles: ['./src/test/setup.js'],
  },
})
