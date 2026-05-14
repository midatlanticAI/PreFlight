// src/components/ScrollableTabs.jsx
// Horizontal scrollable tab strip with edge-fade affordances. The fades hint that
// content extends past the visible area; they appear/disappear based on actual scroll
// position so they never lie. On route change, the currently-active tab auto-scrolls
// into the centre of the viewport so the user can see where they are without swiping.

import { useEffect, useRef, useState, useCallback } from 'react';
import { useLocation } from 'react-router-dom';
import { T } from '../lib/theme.js';

// Track horizontal-scroll state on a ref'd element so callers can show edge fades
// and auto-scroll the active tab into view. Returns the ref + booleans for whether
// content extends past each edge.
export function useScrollFades() {
  const ref = useRef(null);
  const [showLeft, setShowLeft] = useState(false);
  const [showRight, setShowRight] = useState(false);
  const location = useLocation();

  const update = useCallback(() => {
    const el = ref.current;
    if (!el) return;
    const max = el.scrollWidth - el.clientWidth;
    setShowLeft(el.scrollLeft > 4);
    setShowRight(max > 4 && el.scrollLeft < max - 4);
  }, []);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    update();
    el.addEventListener('scroll', update, { passive: true });
    const ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(update) : null;
    ro?.observe(el);
    window.addEventListener('resize', update);
    return () => {
      el.removeEventListener('scroll', update);
      ro?.disconnect();
      window.removeEventListener('resize', update);
    };
  }, [update]);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const active = el.querySelector('[aria-current="page"]');
    if (active && typeof active.scrollIntoView === 'function') {
      active.scrollIntoView({ inline: 'center', block: 'nearest', behavior: 'smooth' });
    }
  }, [location.pathname]);

  return { ref, showLeft, showRight };
}

export function ScrollFadeStyles() {
  return (
    <style>{`
      .ap-scrolltabs {
        scrollbar-width: none;
        -ms-overflow-style: none;
        scroll-behavior: smooth;
      }
      .ap-scrolltabs::-webkit-scrollbar { display: none; }
      .ap-scrolltabs-fade {
        position: absolute;
        top: 1px;
        bottom: 1px;
        width: 36px;
        pointer-events: none;
        transition: opacity 0.15s ease;
      }
      .ap-scrolltabs-fade-left { left: 1px; }
      .ap-scrolltabs-fade-right { right: 1px; }
    `}</style>
  );
}

export function ScrollableTabs({ children, ariaLabel, style = {} }) {
  const { ref, showLeft, showRight } = useScrollFades();
  return (
    <div className="ap-scrolltabs-wrap" style={{ position: 'relative', ...style }}>
      <nav
        aria-label={ariaLabel}
        ref={ref}
        className="ap-scrolltabs"
        style={{
          display: 'flex',
          gap: 4,
          background: T.panel,
          border: `1px solid ${T.border}`,
          padding: 4,
          overflowX: 'auto',
        }}
      >
        {children}
      </nav>
      <span
        aria-hidden="true"
        className="ap-scrolltabs-fade ap-scrolltabs-fade-left"
        style={{
          opacity: showLeft ? 1 : 0,
          background: `linear-gradient(to right, ${T.panel}, transparent)`,
        }}
      />
      <span
        aria-hidden="true"
        className="ap-scrolltabs-fade ap-scrolltabs-fade-right"
        style={{
          opacity: showRight ? 1 : 0,
          background: `linear-gradient(to left, ${T.panel}, transparent)`,
        }}
      />
      <ScrollFadeStyles />
      <style>{`
        @media (max-width: 640px) {
          .ap-scrolltabs a {
            padding: 10px 12px !important;
            font-size: 14px !important;
          }
        }
      `}</style>
    </div>
  );
}
