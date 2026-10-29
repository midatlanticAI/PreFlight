// src/components/TrailingSlashRedirect.jsx
//
// Keeps the live location in the same shape as every internal href and the
// canonical: a route path ends in "/". The host already 308s the no-slash form
// of every prerendered page, so this only matters for client-side arrivals
// (navigate('/settings/ai'), old bookmarks of non-prerendered routes). It
// replaces the history entry instead of pushing one, so Back still works.
// Renders nothing; effects do not run under renderToString, so the prerender
// is unaffected.

import { useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { slashPath } from '../lib/trailing-slash.js';

export function TrailingSlashRedirect() {
  const { pathname, search, hash } = useLocation();
  const navigate = useNavigate();
  useEffect(() => {
    const next = slashPath(pathname);
    if (next !== pathname) navigate(next + search + hash, { replace: true });
  }, [pathname, search, hash, navigate]);
  return null;
}
