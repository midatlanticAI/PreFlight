// src/lib/probes/v2/a11y-semantics.js
//
// F8: Accessibility semantics (docs/preflight-v2-spec.md §F8, 14-probe
// roster). The element-level checks the existing A11y Landmarks probe does
// not carry. WebAIM's Million survey keeps finding the same handful of
// mechanical failures on most homepages; these are the ones a static scan
// can call with confidence.
//
// Severity ceiling: MEDIUM (accessibility axis).
//
// Roster entries deliberately not built, with reasons:
//   img_no_alt / html_no_lang / form_input_no_label / skip_link /
//   button_no_accessible_name — owned by the existing A11y Landmarks probe.
//   color_as_sole_signal — needs rendered pixels.
//   focus_after_route_change / modal_focus_trap / modal_esc /
//   modal_focus_restoration / live_region_for_async — behavioral: they need
//   the running page, and belong to the DAST side of the house when it
//   exists.

import { isTestFile, isScannerSelfSource } from '../../file-filter.js';
import { maskCommentsForPath } from '../_internal/masking.js';

export const A11Y_FILE_RE = /\.(?:[jt]sx|html?)$/i;

const finding = (o) => ({
  probe: 'A11y Semantics',
  category: 'Accessibility',
  severity: 'medium',
  cwe: 'CWE-1078',
  ...o,
});

export function probeA11ySemantics(files) {
  const findings = [];
  // Gate-1: :focus-visible styles routinely live in a different stylesheet
  // (reset.css hides, focus.css replaces) — the project-level fact decides.
  const projectHasFocusVisible = files.some(
    (f) => /\.(?:css|scss)$/i.test(f.path) && /:focus-visible/.test(f.content || '')
  );
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    const isCss = /\.(?:css|scss)$/i.test(file.path);
    if (!A11Y_FILE_RE.test(file.path) && !isCss) return;
    const content = file.content || '';
    if (!content.trim()) return;
    const code = maskCommentsForPath(file.path, content);
    const codeLines = code.split('\n');
    const rawLines = content.split('\n');
    const push = (i, o) =>
      findings.push(
        finding({
          file: file.path,
          line: i + 1,
          evidence: (rawLines[i] ?? '').trim().slice(0, 160),
          ...o,
        })
      );

    // outline removed with no replacement: keyboard users lose the cursor.
    // Gate-2 (C30): CSS-in-JS counts — styled-components templates, MUI sx
    // and inline style objects delete the focus ring exactly the way a
    // stylesheet does, so the check runs wherever the declaration appears.
    const hasCssInJs =
      !isCss && /styled[.(]|\bcss`|createGlobalStyle|\bkeyframes`|sx=\{|style=\{\{/.test(code);
    if (isCss || hasCssInJs) {
      codeLines.forEach((line, i) => {
        if (/outline\s*:\s*['"]?(?:none|0)\b/.test(line)) {
          const windowText = codeLines
            .slice(Math.max(0, i - 6), Math.min(codeLines.length, i + 7))
            .join(' ');
          if (projectHasFocusVisible || /:focus-visible/.test(code)) return;
          // (?!none|0)\S, not [^n0]: with a bare character class, \s*
          // backtracks to zero and the SPACE after the colon satisfies it.
          if (
            !/box-shadow|border(?!-radius)|outline\s*:\s*['"]?(?!none\b|0\b)\S|focus-visible/.test(
              windowText
            )
          ) {
            push(i, {
              id: `a11y-outline-${file.path}-${i}`,
              title: 'Focus outline removed with no replacement',
              severity: 'medium',
              remediation:
                'outline: none deletes the only visible sign of where keyboard focus is; for anyone tabbing, the page goes dark. Style :focus-visible instead of removing it: a box-shadow or a custom outline keeps the cursor visible without the default ring on mouse clicks.',
            });
          }
        }
      });
      if (isCss) return;
    }

    codeLines.forEach((line, i) => {
      // Click handler on a non-interactive element with no role/keyboard.
      // Gate-2 (C13): the tag OPEN and its onClick are often on different
      // lines in formatted JSX — match the tag, then look for onClick
      // inside the tag's own text, not just this line.
      const dm = line.match(/<(div|span|li|td|img|section|article)\b/);
      if (dm) {
        // Scope the attribute search to THIS tag (up to its closing '>'),
        // not a line window — a sibling element's tabIndex two lines down
        // must not vouch for this one.
        const joined = codeLines.slice(i, Math.min(codeLines.length, i + 8)).join(' ');
        const tagStart = joined.indexOf(dm[0]);
        const tagEnd = joined.indexOf('>', tagStart);
        const tagText = joined.slice(tagStart, tagEnd === -1 ? undefined : tagEnd);
        if (
          /\bon[Cc]lick\s*=/.test(tagText) &&
          !/\brole\s*=|\btabIndex\s*=|\btabindex\s*=|onKey(?:Down|Up|Press)/i.test(tagText)
        ) {
          push(i, {
            id: `a11y-div-click-${file.path}-${i}`,
            title: `Click handler on a <${dm[1]}> with no role or keyboard path`,
            severity: 'medium',
            remediation: `A <${dm[1]}> is invisible to the keyboard and to screen readers as a control: no tab stop, no Enter, no announcement. Use a <button> (it brings all three for free), or if the element must stay, add role="button", tabIndex={0}, and an onKeyDown for Enter and Space.`,
          });
        }
      }
      // tabIndex greater than zero hijacks the tab order.
      const tm = line.match(/tab[Ii]ndex\s*=\s*[{"']?\s*([1-9]\d*)/);
      if (tm) {
        push(i, {
          id: `a11y-tabindex-${file.path}-${i}`,
          title: `tabIndex ${tm[1]} overrides the natural tab order`,
          severity: 'low',
          remediation:
            'Positive tabIndex values jump ahead of everything else on the page in a global order nobody can see or maintain. Use tabIndex={0} to join the natural order (or -1 for programmatic focus) and arrange the DOM in reading order instead.',
        });
      }
    });

    // Heading hierarchy skip within one file: h1 -> h3 with no h2.
    // Gate-1: heading order only means something within ONE component's
    // render tree — file adjacency across exported components proves
    // nothing. Reset the sequence at each component boundary.
    const levels = [];
    codeLines.forEach((line, i) => {
      if (/^(?:export\s+)?(?:default\s+)?(?:function|const|class)\s+[A-Z]/.test(line)) {
        levels.push({ level: 0, line: i + 1, boundary: true });
      }
      const hm = line.match(/<h([1-6])\b/);
      if (hm) levels.push({ level: Number(hm[1]), line: i + 1 });
    });
    for (let k = 1; k < levels.length; k++) {
      if (levels[k].boundary || levels[k - 1].boundary) continue;
      if (levels[k].level > levels[k - 1].level + 1) {
        push(levels[k].line - 1, {
          id: `a11y-heading-skip-${file.path}-${levels[k].line}`,
          title: `Heading level skips from h${levels[k - 1].level} to h${levels[k].level}`,
          severity: 'low',
          remediation:
            'Screen reader users navigate by heading level the way sighted users skim size; a skipped level reads as a missing section. Use the next level down and style it with CSS if it should look smaller.',
        });
        break; // one report per file is a lesson; ten is a lecture
      }
    }
  });
  return findings;
}
