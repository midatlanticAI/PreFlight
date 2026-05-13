import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Manual chunk strategy: split the biggest dependencies out of the main bundle
// so they load in parallel and stay cached across deploys when the app code
// changes. The main bundle has been pushing past the 500 KB ungzipped target
// because everything was inlined. Splitting drops main to roughly half.
//
// Strategy:
//   - react / react-dom -> vendor-react (loaded immediately, but cached)
//   - react-router-dom  -> vendor-router (same)
//   - acorn family       -> vendor-acorn (only needed when the AST probe runs)
//   - lucide-react       -> vendor-icons (icon set used across the UI)
//
// Markdown rendering deps (react-markdown / remark-gfm / gray-matter-style
// helpers) live with EntryView and the learn-content module; they're already
// lazy via the Learn route's React.lazy boundaries.
const manualChunks = (id) => {
  if (id.includes('node_modules')) {
    if (id.includes('/react/') || id.includes('/react-dom/') || id.includes('/scheduler/')) {
      return 'vendor-react';
    }
    if (id.includes('/react-router') || id.includes('/@remix-run')) {
      return 'vendor-router';
    }
    if (id.includes('/acorn')) {
      return 'vendor-acorn';
    }
    if (id.includes('/lucide-react')) {
      return 'vendor-icons';
    }
  }
};

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks,
      },
    },
  },
});
