// Flat config (ESLint 9+). Intentionally minimal — favors signal over volume.
// Goal: catch dead code, unused imports, missing dependency arrays, and the
// JS-spec footguns. Not a style enforcer; Prettier handles formatting.
import js from '@eslint/js';
import globals from 'globals';
import react from 'eslint-plugin-react';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';

export default [
  { ignores: ['dist/', 'node_modules/', 'public/icons.svg'] },
  {
    files: ['**/*.{js,jsx}'],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: 'module',
      globals: { ...globals.browser, ...globals.node },
      parserOptions: {
        ecmaFeatures: { jsx: true },
      },
    },
    settings: { react: { version: '18' } },
    plugins: {
      react,
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...js.configs.recommended.rules,
      ...react.configs.recommended.rules,
      ...reactHooks.configs.recommended.rules,
      // JSX-usage detection — without this, every <Icon /> in JSX reads as an "unused" import.
      'react/jsx-uses-react': 'error',
      'react/jsx-uses-vars': 'error',
      // We use the new JSX transform — React doesn't need to be in scope.
      'react/react-in-jsx-scope': 'off',
      'react/prop-types': 'off', // we don't use PropTypes; TS isn't on yet
      'react/display-name': 'off',
      'react/no-unescaped-entities': 'off', // we use copy with apostrophes / quotes freely
      'no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      'no-empty': ['error', { allowEmptyCatch: true }],
      'no-prototype-builtins': 'off',
      'no-cond-assign': ['error', 'except-parens'],
      // Probe regexes intentionally use literal escapes for visual consistency with named
      // patterns (e.g. `[A-Za-z0-9_\-]` — the `\-` reads better than positioning `-` last).
      'no-useless-escape': 'off',
      'react-hooks/exhaustive-deps': 'error',
      'react-refresh/only-export-components': 'off',
    },
  },
];
