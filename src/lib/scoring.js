// src/lib/scoring.js
// Severity ordering, per-severity weight, and the score calculation. The score model is
// intentionally simple: every finding subtracts its severity weight from 100, clamped to
// 0. Crit = -25, high = -10, medium = -5, low = -2, info = -1. The probe set is small
// enough that this stays bounded; the goal is one number that maps cleanly to risk tiers.

export const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
export const SEV_WEIGHT = { critical: 25, high: 10, medium: 5, low: 2, info: 1 };

export function computeScore(findings) {
  let score = 100;
  findings.forEach((f) => {
    score -= SEV_WEIGHT[f.severity] || 0;
  });
  return Math.max(0, score);
}
