import Resolver from '@forge/resolver';
import { getFieldIdMap, readIssue } from '../lib/jira.js';
import { gatherContext } from '../lib/context.js';
import { triageIssue } from '../lib/orchestrator.js';
import { getAudit } from '../lib/audit.js';
import { writeNarrative } from '../lib/llm.js';
import { isNarrativeGrounded } from '../lib/grounding.js';

const resolver = new Resolver();

function issueKeyFrom(req) {
  return req?.context?.extension?.issue?.key || req?.payload?.issueKey || null;
}

// Flatten the grounded context into a shape the panel UI can render.
function panelShape(ctx) {
  return {
    issueKey: ctx.issueKey,
    escalate: ctx.escalate,
    missing: ctx.missing || [],
    priority: ctx.escalate ? null : ctx.priority,
    severity: ctx.severity,
    cvss: ctx.cvss,
    cve: ctx.cve,
    service: ctx.service,
    tier: ctx.risk?.tier ?? null,
    exposure: ctx.risk?.exposure ?? null,
    kev: ctx.intel?.kev ?? null,
    epssPercent:
      typeof ctx.intel?.epss === 'number' ? Math.round(ctx.intel.epss * 1000) / 10 : null,
    summary: null, // AI one-liner, filled in by getPanelData
    nvd: ctx.intel?.description
      ? ctx.intel.description.length > 160
        ? `${ctx.intel.description.slice(0, 160).trim()}…`
        : ctx.intel.description
      : null,
    owner: ctx.owner?.displayName || ctx.owner?.email || null,
    ownerResolved: !!ctx.owner?.accountId,
    duplicateFixed: ctx.duplicate?.fixedElsewhere?.key ?? null,
    duplicateOpen: ctx.duplicate?.openDuplicate?.key ?? null,
    sources: ctx.intel?.sources ?? {},
  };
}

// Live, read-only triage view for the panel.
resolver.define('getPanelData', async (req) => {
  const issueKey = issueKeyFrom(req);
  if (!issueKey) return { error: 'No issue in context.' };
  const issue = await readIssue(issueKey);
  if (!issue) return { error: `Could not read ${issueKey}.` };
  const fieldMap = await getFieldIdMap();
  const ctx = await gatherContext(issue, fieldMap);
  const shape = panelShape(ctx);

  // One-line AI summary that combines the NVD description with the exploitation
  // outlook (EPSS + KEV). Grounded-guarded; falls back to the separate lines.
  if (ctx.cve && (ctx.intel?.description || typeof ctx.intel?.epss === 'number')) {
    const s = await writeNarrative(
      {
        cve: ctx.cve,
        nvdDescription: ctx.intel?.description || null,
        epssPercent:
          typeof ctx.intel?.epss === 'number' ? Math.round(ctx.intel.epss * 1000) / 10 : null,
        knownExploited: ctx.intel?.kev ?? null,
      },
      'panel-summary'
    );
    shape.summary = isNarrativeGrounded(s, { cve: ctx.cve }) ? s : null;
  }

  return shape;
});

// The append-only audit trail for this finding.
resolver.define('getAudit', async (req) => {
  const issueKey = issueKeyFrom(req);
  if (!issueKey) return [];
  return getAudit(issueKey);
});

// Force a full re-triage (acts: priority, comment, assign, status).
resolver.define('runTriage', async (req) => {
  const issueKey = issueKeyFrom(req);
  if (!issueKey) return { error: 'No issue in context.' };
  const result = await triageIssue(issueKey, { force: true });
  return { result };
});

export const handler = resolver.getDefinitions();
