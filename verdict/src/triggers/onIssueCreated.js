// Auto path: fires when a finding is created. Thin handler that delegates to the
// shared orchestrator.

import { triageIssue } from '../lib/orchestrator.js';

export async function onIssueCreated(event) {
  const issueKey = event?.issue?.key ?? event?.key;
  const result = await triageIssue(issueKey);
  console.log(`onIssueCreated ${issueKey}: ${result}`);
}
