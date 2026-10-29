// src/components/RouterLink.jsx
//
// The only place react-router's Link and NavLink are imported (ESLint
// no-restricted-imports enforces it). Both run `to` through withTrailingSlash
// so every internal href is the URL the host answers with a 200, not the one
// it 308-redirects. See src/lib/trailing-slash.js for the why.

import { Link as RouterLink, NavLink as RouterNavLink } from 'react-router-dom';
import { withTrailingSlash } from '../lib/trailing-slash.js';

export function Link({ to, ...rest }) {
  return <RouterLink to={withTrailingSlash(to)} {...rest} />;
}

export function NavLink({ to, ...rest }) {
  return <RouterNavLink to={withTrailingSlash(to)} {...rest} />;
}
