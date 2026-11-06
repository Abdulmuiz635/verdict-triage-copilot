// The deterministic risk model. The language model never picks this.

import {
  AUTO_MIN_PRIORITY,
  PRIORITY_RANK,
  SERVICE_CRITICALITY,
  DEFAULT_TIER,
} from './config.js';

// Multipliers. A critical service raises the score, a low-tier internal tool
// lowers it; exposure to the internet raises it, an internal-only system lowers it.
const TIER_MULT = { tier0: 1.25, tier1: 1.0, tier2: 0.75 };
const EXPOSURE_MULT = { exposed: 1.0, internal: 0.6, unknown: 0.85 };

// Turn severity/CVSS into a 0-10 base. Prefer the CVSS number when present.
function severityBase(severity, cvss) {
  if (typeof cvss === 'number' && !Number.isNaN(cvss)) return cvss;
  switch ((severity || '').toLowerCase()) {
    case 'critical':
      return 9.5;
    case 'high':
      return 7.5;
    case 'medium':
      return 5.0;
    case 'low':
      return 2.0;
    default:
      return null;
  }
}

// Infer exposure from the finding text (grounded in what the reporter wrote).
function detectExposure(text) {
  const t = (text || '').toLowerCase();
  if (/internet-facing|public-facing|publicly|exposed to the internet|cardholder|public internet/.test(t)) {
    return 'exposed';
  }
  if (/internal|behind sso|not public|intranet|private network|not internet-facing/.test(t)) {
    return 'internal';
  }
  return 'unknown';
}

function bucket(score) {
  if (score >= 9.0) return 'Highest';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  if (score > 0) return 'Low';
  return null;
}

// Full risk assessment. Returns the priority plus the inputs that produced it,
// so the comment can show a transparent, inspectable breakdown.
export function scoreRisk({ severity, cvss, service, description, summary }) {
  const base = severityBase(severity, cvss);
  if (base === null) {
    return { priority: null, base: null };
  }
  const tier = SERVICE_CRITICALITY[service] || DEFAULT_TIER;
  const tierMult = TIER_MULT[tier] ?? 1.0;
  const exposure = detectExposure(`${summary || ''} ${description || ''}`);
  const expMult = EXPOSURE_MULT[exposure] ?? 0.85;
  const score = Math.round(base * tierMult * expMult * 10) / 10;
  return { priority: bucket(score), base, tier, tierMult, exposure, expMult, score };
}

// Whether a finding crosses the auto-analysis threshold (full verdict vs short
// note). On-demand analysis via the agent ignores this.
export function meetsThreshold(priority) {
  return (PRIORITY_RANK[priority] ?? 0) >= (PRIORITY_RANK[AUTO_MIN_PRIORITY] ?? 0);
}
