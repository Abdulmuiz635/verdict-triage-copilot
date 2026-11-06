// The shared "one brain" context builder. Takes an already-read issue + the
// field map, returns the grounded triage context used by BOTH the auto trigger
// and the Rovo agent action. Includes the associative-memory duplicate check.

import { FIELD_NAMES } from './config.js';
import { adfToText, findDuplicates, resolveUserByEmail } from './jira.js';
import { fetchCveIntel } from './intel.js';
import { scoreRisk } from './riskModel.js';
import { getOwnerForService } from './bitbucket.js';

export async function gatherContext(issue, fieldMap) {
  const fields = issue.fields || {};
  const sevId = fieldMap[FIELD_NAMES.severity];
  const cvssId = fieldMap[FIELD_NAMES.cvss];
  const cveId = fieldMap[FIELD_NAMES.cve];
  const svcId = fieldMap[FIELD_NAMES.service];

  const severityRaw = sevId ? fields[sevId] : null;
  const reportedSeverity =
    severityRaw && typeof severityRaw === 'object' ? severityRaw.value : severityRaw;
  const cvssRaw = cvssId ? fields[cvssId] : null;
  const reportedCvss =
    typeof cvssRaw === 'number' ? cvssRaw : cvssRaw ? Number(cvssRaw) : null;
  const cve = cveId ? fields[cveId] : null;
  const service = svcId ? fields[svcId] : null;
  const description = adfToText(fields.description);
  const reporterId = fields.reporter?.accountId;
  const projectKey = fields.project?.key;

  let intel = null;
  if (cve) intel = await fetchCveIntel(cve);

  const severity = reportedSeverity ?? intel?.nvdSeverity ?? null;
  const severitySource = reportedSeverity ? 'reported' : intel?.nvdSeverity ? 'NVD' : null;
  const cvss =
    typeof reportedCvss === 'number' && !Number.isNaN(reportedCvss)
      ? reportedCvss
      : typeof intel?.nvdScore === 'number'
      ? intel.nvdScore
      : null;
  const cvssSource =
    typeof reportedCvss === 'number' && !Number.isNaN(reportedCvss)
      ? 'reported'
      : typeof intel?.nvdScore === 'number'
      ? 'NVD'
      : null;

  const risk = scoreRisk({ severity, cvss, service, description, summary: fields.summary });
  let priority = risk.priority;
  if (intel?.kev === true) priority = 'Highest';

  const missing = [];
  if (!severity) missing.push('severity');
  if (cvss === null) missing.push('CVSS');
  if (!cve) missing.push('CVE');

  // Associative memory: has this CVE been seen before in this project?
  let duplicate = { fixedElsewhere: null, openDuplicate: null, matchKeys: [] };
  let originalPriority = priority;
  if (cve && priority) {
    duplicate = await findDuplicates({
      projectKey,
      cve,
      cveFieldId: cveId,
      serviceFieldId: svcId,
      excludeKey: issue.key,
    });
    // Already fixed elsewhere -> apply the "already handled" downgrade.
    if (duplicate.fixedElsewhere) {
      originalPriority = priority;
      priority = 'Low';
    }
  }

  // Owner routing: resolve the affected service -> Bitbucket CODEOWNERS -> Jira user.
  let owner = null;
  if (service) {
    const co = await getOwnerForService(service);
    if (co.ownerEmail) {
      const u = await resolveUserByEmail(co.ownerEmail);
      owner = {
        repo: co.repo,
        email: co.ownerEmail,
        accountId: u?.accountId ?? null,
        displayName: u?.displayName ?? null,
        error: u ? null : 'owner email is not a Jira user',
      };
    } else {
      owner = { repo: co.repo, email: null, accountId: null, displayName: null, error: co.error };
    }
  }

  return {
    issueKey: issue.key,
    projectKey,
    owner,
    summary: fields.summary ?? null,
    description,
    severity,
    severitySource,
    cvss,
    cvssSource,
    cve,
    service,
    reporterId,
    priority,
    originalPriority,
    risk,
    escalate: !risk.priority && !(intel?.kev === true),
    missing,
    intel,
    duplicate,
  };
}
