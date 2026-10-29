// src/lib/trailing-slash.js
//
// One rule for the shape of every internal URL: a route path ends in "/".
//
// Why: the host serves each prerendered page as `path/index.html` at the
// trailing-slash URL and answers the no-slash form with a 308 to it. The
// canonical and the sitemap already name the slash form (see seo.js). Until
// 2026-10-28 every internal link still pointed at the no-slash form, so each
// link a crawler followed was a redirect hop, and Search Console reported the
// site as "Page with redirect" across the whole Learn tree. The Link and
// NavLink wrappers in components/RouterLink.jsx run every `to` through
// withTrailingSlash, and TrailingSlashRedirect normalises the live location
// once on load, so the address bar, the hrefs, the canonical and the sitemap
// all agree.
//
// Pure, no browser globals: the prerender and the client share it.

const FILE_TAIL = /\.[A-Za-z0-9]{1,8}$/;

/**
 * "/learn/patterns" -> "/learn/patterns/". Leaves alone: "/", paths that
 * already end in "/", file-like paths ("/llms.txt", "/sitemap.xml"),
 * protocol-relative URLs ("//host"), and anything that is not an absolute
 * site path.
 * @param {string} pathname
 * @returns {string}
 */
export function slashPath(pathname) {
  if (typeof pathname !== 'string') return pathname;
  if (!pathname.startsWith('/') || pathname.startsWith('//')) return pathname;
  if (pathname.endsWith('/')) return pathname;
  const last = pathname.slice(pathname.lastIndexOf('/') + 1);
  if (FILE_TAIL.test(last)) return pathname;
  return pathname + '/';
}

/**
 * Normalise a react-router `to` value (string or {pathname, search, hash}).
 * Query and hash survive untouched: "/sandbox?shape=x" -> "/sandbox/?shape=x".
 * @param {string|{pathname?:string,search?:string,hash?:string}} to
 */
export function withTrailingSlash(to) {
  if (typeof to === 'string') {
    const m = to.match(/^(\/[^?#]*)([?#].*)?$/);
    if (!m) return to;
    return slashPath(m[1]) + (m[2] || '');
  }
  if (to && typeof to === 'object' && typeof to.pathname === 'string') {
    return { ...to, pathname: slashPath(to.pathname) };
  }
  return to;
}
