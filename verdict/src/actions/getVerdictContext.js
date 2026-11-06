// Conversational path: the Rovo agent's read-only action. Returns the grounded
// triage context for any finding so the agent can explain it (never decide it).

import { getFieldIdMap, readIssue } from '../lib/jira.js';
import { gatherContext } from '../lib/context.js';

export async function getVerdictContext(payload) {
  const issueKey = payload?.issueKey;
  console.log('getVerdictContext called for:', issueKey);

  if (!issueKey) {
    return { error: 'No issue key was provided. Ask the user which finding to triage.' };
  }

  const issue = await readIssue(issueKey);
  if (!issue) {
    return { error: `Could not read issue ${issueKey}. Check the key and that the app has access.` };
  }

  const fieldMap = await getFieldIdMap();
  const ctx = await gatherContext(issue, fieldMap);

  return {
    issueKey: ctx.issueKey,
    summary: ctx.summary,
    description: ctx.description,
    computedPriority: ctx.priority,
    severity: ctx.severity,
    severitySource: ctx.severitySource,
    cvss: ctx.cvss,
    cvssSource: ctx.cvssSource,
    cve: ctx.cve,
    affectedService: ctx.service,
    serviceCriticalityTier: ctx.risk?.tier ?? null,
    exposure: ctx.risk?.exposure ?? null,
    riskScore: ctx.risk?.score ?? null,
    knownExploitedCISAKEV: ctx.intel?.kev ?? null,
    epssProbability: typeof ctx.intel?.epss === 'number' ? ctx.intel.epss : null,
    nvdDescription: ctx.intel?.description ?? null,
    sources: ctx.intel?.sources ?? {},
    sourcesUnavailable: ctx.intel?.errors ?? [],
    alreadyFixedIn: ctx.duplicate?.fixedElsewhere?.key ?? null,
    alreadyFixedService: ctx.duplicate?.fixedElsewhere?.service ?? null,
    openDuplicateOf: ctx.duplicate?.openDuplicate?.key ?? null,
    priorityDowngradedFrom: ctx.duplicate?.fixedElsewhere ? ctx.originalPriority : null,
    owner: ctx.owner?.displayName ?? ctx.owner?.email ?? null,
    ownerRepo: ctx.owner?.repo ?? null,
    ownerResolved: !!ctx.owner?.accountId,
    enoughDataToTriage: !ctx.escalate,
    missing: ctx.missing,
  };
}
