#!/usr/bin/env node
/*
 * Verdict demo seeder.
 *
 * Creates a realistic set of security findings as Jira issues so a judge or a
 * teammate can see the full Verdict story (auto-triage, KEV override, gap-fill,
 * duplicate memory, owner routing, escalation) without hand-building issues.
 *
 * This is a plain Node script (no Forge runtime). It talks to the Jira Cloud
 * REST API with Basic auth, using an Atlassian account email + API token.
 *
 * Requires Node 18+ (uses the built-in global fetch). No dependencies.
 *
 * Usage:
 *   JIRA_BASE_URL=https://your-site.atlassian.net \
 *   JIRA_EMAIL=you@example.com \
 *   JIRA_API_TOKEN=xxxxx \
 *   PROJECT_KEY=KAN \
 *   node seed.js
 *
 * Create an API token at: https://id.atlassian.com/manage-profile/security/api-tokens
 *
 * Fields: Verdict matches custom fields BY NAME. Before seeding, create these
 * custom fields on the project (see seed/README.md):
 *   Severity (select or short text), CVSS (number), CVE ID (short text),
 *   Affected service (short text).
 * The seeder discovers their ids automatically and skips any that do not exist.
 */

'use strict';

const fs = require('fs');
const path = require('path');

const BASE = (process.env.JIRA_BASE_URL || '').replace(/\/+$/, '');
const EMAIL = process.env.JIRA_EMAIL || '';
const TOKEN = process.env.JIRA_API_TOKEN || '';
const PROJECT_KEY = process.env.PROJECT_KEY || 'KAN';
const ISSUE_TYPE = process.env.ISSUE_TYPE || ''; // optional override, else first create-able type
const DRY_RUN = process.argv.includes('--dry-run');

// The custom-field names Verdict reads. Must match verdict/src/lib/config.js.
const FIELD_NAMES = {
  severity: 'Severity',
  cvss: 'CVSS',
  cve: 'CVE ID',
  service: 'Affected service',
};

function die(msg) {
  console.error(`\n  ✗ ${msg}\n`);
  process.exit(1);
}

if (!BASE || !EMAIL || !TOKEN) {
  die(
    'Set JIRA_BASE_URL, JIRA_EMAIL and JIRA_API_TOKEN in your environment.\n' +
      '    See the header of this file for an example.'
  );
}

const AUTH = 'Basic ' + Buffer.from(`${EMAIL}:${TOKEN}`).toString('base64');

async function api(method, pathname, body) {
  const res = await fetch(`${BASE}${pathname}`, {
    method,
    headers: {
      Authorization: AUTH,
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = text;
  }
  if (!res.ok) {
    const detail = typeof json === 'string' ? json : JSON.stringify(json);
    throw new Error(`${method} ${pathname} -> ${res.status} ${detail}`);
  }
  return json;
}

// Turn a plain string into a minimal ADF document (for the description field and
// any rich-text custom field).
function adf(textValue) {
  return {
    type: 'doc',
    version: 1,
    content: [
      {
        type: 'paragraph',
        content: textValue ? [{ type: 'text', text: textValue }] : [],
      },
    ],
  };
}

// Map a field NAME to its { id, schemaType } using the global field list.
async function buildFieldMap() {
  const fields = await api('GET', '/rest/api/3/field');
  const byName = new Map();
  for (const f of fields) {
    byName.set((f.name || '').toLowerCase(), {
      id: f.id,
      schemaType: f.schema?.type || 'string',
    });
  }
  const resolved = {};
  for (const [key, name] of Object.entries(FIELD_NAMES)) {
    const hit = byName.get(name.toLowerCase());
    if (hit) resolved[key] = { name, ...hit };
    else console.warn(`  !  Field "${name}" not found on this site. Skipping it.`);
  }
  return resolved;
}

// Format one value for Jira according to the field's schema type.
function formatValue(schemaType, value) {
  if (value === undefined || value === null || value === '') return undefined;
  switch (schemaType) {
    case 'number':
      return Number(value);
    case 'option': // single-select
      return { value: String(value) };
    case 'doc': // rich text
      return adf(String(value));
    default: // string and everything else
      return String(value);
  }
}

// Find a create-able issue type id for the project.
async function resolveIssueTypeId() {
  const meta = await api(
    'GET',
    `/rest/api/3/issue/createmeta?projectKeys=${encodeURIComponent(PROJECT_KEY)}&expand=projects.issuetypes`
  );
  const project = meta.projects?.[0];
  if (!project) die(`Project "${PROJECT_KEY}" not found, or you cannot create issues in it.`);
  const types = project.issuetypes || [];
  if (!types.length) die(`No create-able issue types in "${PROJECT_KEY}".`);
  if (ISSUE_TYPE) {
    const match = types.find((t) => t.name.toLowerCase() === ISSUE_TYPE.toLowerCase());
    if (match) return match.id;
    console.warn(`  !  Issue type "${ISSUE_TYPE}" not found. Falling back to "${types[0].name}".`);
  }
  // Prefer a Task/Bug-like type over Epic/Subtask.
  const preferred =
    types.find((t) => /^(task|bug|story)$/i.test(t.name)) ||
    types.find((t) => !t.subtask && !/epic/i.test(t.name)) ||
    types[0];
  return preferred.id;
}

async function main() {
  console.log(`\n  Verdict seeder → ${BASE}  (project ${PROJECT_KEY})`);
  if (DRY_RUN) console.log('  (dry run: nothing will be created)\n');

  const findings = JSON.parse(
    fs.readFileSync(path.join(__dirname, 'findings.json'), 'utf8')
  );

  const fieldMap = await buildFieldMap();
  console.log(
    '  Fields:',
    Object.values(fieldMap)
      .map((f) => `${f.name}=${f.id}(${f.schemaType})`)
      .join(', ') || '(none matched)'
  );

  const issueTypeId = await resolveIssueTypeId();
  console.log(`  Issue type id: ${issueTypeId}\n`);

  const created = [];
  for (const f of findings) {
    const fields = {
      project: { key: PROJECT_KEY },
      issuetype: { id: issueTypeId },
      summary: f.summary,
      description: adf(f.description || ''),
    };

    // Attach each custom field that both exists on the site and is set on the finding.
    for (const key of ['severity', 'cvss', 'cve', 'service']) {
      const def = fieldMap[key];
      if (!def) continue;
      const formatted = formatValue(def.schemaType, f[key]);
      if (formatted !== undefined) fields[def.id] = formatted;
    }

    if (DRY_RUN) {
      console.log(`  • would create: ${f.summary}`);
      continue;
    }

    try {
      const res = await api('POST', '/rest/api/3/issue', { fields });
      console.log(`  ✓ ${res.key}  ${f.summary}`);
      created.push({ key: res.key, id: f.id });
    } catch (e) {
      console.error(`  ✗ failed: ${f.summary}\n      ${e.message}`);
    }
  }

  if (!DRY_RUN) {
    fs.writeFileSync(
      path.join(__dirname, '.seed-state.json'),
      JSON.stringify({ at: new Date().toISOString(), created }, null, 2)
    );
    console.log(`\n  Done. Created ${created.length}/${findings.length} findings.`);
    console.log('  Tip: mark the auth-service xz finding Done to demo the duplicate downgrade.\n');
  }
}

main().catch((e) => die(e.message));
