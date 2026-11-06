// The triage orchestration - one brain shared by the auto trigger and the
// issue-panel "Re-run triage" button. Given an issue key it runs the full
// sequence: escalate -> duplicate -> normal, with Atlassian AI narratives and a
// deterministic fallback.

import {
  FINDINGS_PROJECT_KEY,
  NEEDS_REVIEW_LABEL,
  ON_DEMAND_LABEL,
  DUPLICATE_LABEL,
  TRIAGED_STATUS,
  TRIAGED_PROPERTY,
} from './config.js';
import {
  getFieldIdMap,
  readIssue,
  setPriority,
  addLabel,
  postComment,
  linkDuplicate,
  assignIssue,
  transitionIssue,
  hasProperty,
  setProperty,
} from './jira.js';
import { gatherContext } from './context.js';
import { meetsThreshold } from './riskModel.js';
import {
  buildVerdictComment,
  buildBelowThresholdComment,
  buildEscalationComment,
  buildFixedElsewhereComment,
  buildOpenDuplicateComment,
} from './adf.js';
import { writeNarrative } from './llm.js';
import { isNarrativeGrounded } from './grounding.js';
import { recordAudit } from './audit.js';

async function routeToOwner(issueKey, ctx) {
  if (ctx.owner?.accountId) await assignIssue(issueKey, ctx.owner.accountId);
}

function buildFacts(ctx) {
  return {
    priority: ctx.priority,
    cve: ctx.cve,
    severity: ctx.severity,
    cvss: ctx.cvss,
    affectedService: ctx.service,
    serviceCriticalityTier: ctx.risk?.tier ?? null,
    exposure: ctx.risk?.exposure ?? null,
    knownExploited: ctx.intel?.kev ?? null,
    epssPercent:
      typeof ctx.intel?.epss === 'number' ? Math.round(ctx.intel.epss * 1000) / 10 : null,
    nvdSummary: ctx.intel?.description ? ctx.intel.description.slice(0, 300) : null,
    owner: ctx.owner?.displayName || ctx.owner?.email || null,
    ownerAssigned: !!ctx.owner?.accountId,
  };
}

async function finalize(issueKey) {
  await transitionIssue(issueKey, TRIAGED_STATUS);
  await setProperty(issueKey, TRIAGED_PROPERTY, { triaged: true, at: new Date().toISOString() });
}

// Run the whole triage for one issue. force=true re-runs even if already triaged
// (used by the panel's Re-run button).
export async function triageIssue(issueKey, { force = false } = {}) {
  if (!issueKey) return 'no issue key';

  const issue = await readIssue(issueKey);
  if (!issue) return `could not read ${issueKey}`;

  if (issue.fields?.project?.key !== FINDINGS_PROJECT_KEY) {
    return `skipped: ${issueKey} is not in the findings project`;
  }
  if (!force && (await hasProperty(issueKey, TRIAGED_PROPERTY))) {
    return `skipped: ${issueKey} already triaged`;
  }

  const fieldMap = await getFieldIdMap();
  const ctx = await gatherContext(issue, fieldMap);
  const trigger = force ? 'manual' : 'auto';

  // Grounding guard: only use an AI narrative that matches the facts; otherwise
  // fall back to the deterministic text.
  const guard = (n) => {
    if (isNarrativeGrounded(n, { cve: ctx.cve, cvss: ctx.cvss })) return n;
    if (n) console.log(`${issueKey}: AI narrative failed grounding guard, using fallback.`);
    return null;
  };

  // 1. Missing data -> escalate.
  if (ctx.escalate) {
    const n = await writeNarrative(
      { missing: ctx.missing, cve: ctx.cve, service: ctx.service },
      'escalation'
    );
    await postComment(issueKey, buildEscalationComment(ctx, guard(n)));
    await addLabel(issueKey, NEEDS_REVIEW_LABEL);
    await setProperty(issueKey, TRIAGED_PROPERTY, {
      triaged: 'escalated',
      at: new Date().toISOString(),
    });
    await recordAudit(issueKey, { action: 'escalated', missing: ctx.missing.join(', '), trigger });
    return `escalated: missing ${ctx.missing.join(', ')}`;
  }

  // 2. Already fixed elsewhere.
  if (ctx.duplicate?.fixedElsewhere) {
    const fx = ctx.duplicate.fixedElsewhere;
    await linkDuplicate(issueKey, fx.key);
    await setPriority(issueKey, ctx.priority);
    await addLabel(issueKey, DUPLICATE_LABEL);
    const n = await writeNarrative(
      {
        cve: ctx.cve,
        fixedIssue: fx.key,
        fixedService: fx.service,
        priority: ctx.priority,
        downgradedFrom: ctx.originalPriority,
      },
      'duplicate-fixed'
    );
    await postComment(issueKey, buildFixedElsewhereComment(ctx, guard(n)));
    await finalize(issueKey);
    await recordAudit(issueKey, {
      action: 'duplicate-of-fixed',
      priority: ctx.priority,
      duplicateOf: fx.key,
      downgradedFrom: ctx.originalPriority,
      cve: ctx.cve,
      trigger,
    });
    return `duplicate of fixed ${fx.key}`;
  }

  // 3. Duplicate of an open finding.
  if (ctx.duplicate?.openDuplicate) {
    const op = ctx.duplicate.openDuplicate;
    await linkDuplicate(issueKey, op.key);
    await setPriority(issueKey, ctx.priority);
    await addLabel(issueKey, DUPLICATE_LABEL);
    await routeToOwner(issueKey, ctx);
    const n = await writeNarrative(
      { cve: ctx.cve, openIssue: op.key, priority: ctx.priority, service: ctx.service },
      'duplicate-open'
    );
    await postComment(issueKey, buildOpenDuplicateComment(ctx, guard(n)));
    await finalize(issueKey);
    await recordAudit(issueKey, {
      action: 'duplicate-of-open',
      priority: ctx.priority,
      duplicateOf: op.key,
      owner: ctx.owner?.displayName || null,
      cve: ctx.cve,
      trigger,
    });
    return `duplicate of open ${op.key}`;
  }

  // 4. Normal path.
  await setPriority(issueKey, ctx.priority);
  await routeToOwner(issueKey, ctx);
  const narrative = guard(await writeNarrative(buildFacts(ctx)));
  const above = meetsThreshold(ctx.priority);
  if (above) {
    await postComment(issueKey, buildVerdictComment(ctx, narrative));
  } else {
    await postComment(issueKey, buildBelowThresholdComment(ctx, narrative));
    await addLabel(issueKey, ON_DEMAND_LABEL);
  }
  await finalize(issueKey);
  await recordAudit(issueKey, {
    action: above ? 'verdict' : 'below-threshold',
    priority: ctx.priority,
    cve: ctx.cve,
    severity: ctx.severity,
    cvss: ctx.cvss,
    service: ctx.service,
    owner: ctx.owner?.displayName || null,
    kev: ctx.intel?.kev ?? null,
    decidedBy: 'code',
    ai: !!narrative,
    trigger,
  });
  return `triaged: ${ctx.priority}`;
}
