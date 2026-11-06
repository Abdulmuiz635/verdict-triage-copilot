// Central configuration for Verdict. Everything tunable lives here.

// Only findings in this project are auto-triaged by the trigger.
export const FINDINGS_PROJECT_KEY = 'KAN';

// Custom fields are matched by NAME so the app stays portable across sites.
export const FIELD_NAMES = {
  severity: 'Severity',
  cvss: 'CVSS',
  cve: 'CVE ID',
  service: 'Affected service',
};

// Labels Verdict applies.
export const NEEDS_REVIEW_LABEL = 'verdict-needs-review'; // missing data, escalated
export const ON_DEMAND_LABEL = 'verdict-on-demand'; // below threshold, analyse on request
export const DUPLICATE_LABEL = 'verdict-duplicate'; // same CVE already tracked/fixed elsewhere

// Auto-triage threshold. The trigger always SETS the priority, but it only
// posts a full, intel-enriched verdict for findings at or above this priority.
// Anything lower gets a short note instead, and can be fully analysed on demand
// via the Verdict agent. Lower this to 'Medium' or raise it to 'Highest' to tune
// how noisy the automatic comments are.
export const AUTO_MIN_PRIORITY = 'High';

export const PRIORITY_RANK = {
  Lowest: 0,
  Low: 1,
  Medium: 2,
  High: 3,
  Highest: 4,
};

// Service -> business-criticality tier. Drives the risk multiplier so the same
// CVSS matters more on a critical service than on a low-impact internal tool.
export const SERVICE_CRITICALITY = {
  'payments-api': 'tier0',
  'auth-service': 'tier0',
  'reporting-ui': 'tier2',
};
export const DEFAULT_TIER = 'tier1';

// Status Verdict moves a finding to once it has triaged it. Tries these in
// order and uses the first one the project's workflow actually offers.
export const TRIAGED_STATUS = ['In Review', 'In Progress'];

// Issue property key used as an idempotency marker (so a finding is triaged once).
export const TRIAGED_PROPERTY = 'verdict-triaged';
