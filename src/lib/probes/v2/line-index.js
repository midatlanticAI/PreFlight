// src/lib/probes/v2/line-index.js
//
// Line number for an offset, one pass per file. Every v2 family computed it
// as content.slice(0, idx).split('\n').length per match, which re-reads the
// whole prefix for every effect, catch, loop and route and made dense files
// quadratic: 0.8s to 7.3s at 400KB against a budget well under one second
// (Gate-3 G22 to G27, G29, G31). The masks are length-preserving, so one
// index built from the raw content answers for every view of the file.

export function lineIndex(content) {
  const text = typeof content === 'string' ? content : '';
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  return (offset) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
}
