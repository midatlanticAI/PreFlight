import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  // Apply the same JSX/automatic-runtime transform tests as the production
  // build uses. Without this, JSX in component files compiles to classic
  // React.createElement calls that fail with "React is not defined" when a
  // test renders a component via react-dom/server.
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: false,
    include: ['src/**/*.test.{js,jsx}'],
    // self-audit.test.js needs dist/ — run it via vitest.audit.config.js after `npm run build`.
    exclude: ['**/self-audit.test.js', '**/node_modules/**'],
    setupFiles: ['./src/test/setup.js'],
  },
});
