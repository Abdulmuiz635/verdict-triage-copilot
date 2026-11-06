// Thin wrappers around the Jira REST API, all called as the app.

import api, { route } from '@forge/api';

// Build a { fieldName: fieldId } map so we can read custom fields by name.
export async function getFieldIdMap() {
  const res = await api.asApp().requestJira(route`/rest/api/3/field`);
  if (!res.ok) throw new Error(`Could not list Jira fields (HTTP ${res.status}).`);
  const fields = await res.json();
  const map = {};
  for (const field of fields) map[field.name] = field.id;
  return map;
}

export async function readIssue(issueKey) {
  const res = await api.asApp().requestJira(route`/rest/api/3/issue/${issueKey}`);
  if (!res.ok) return null;
  return res.json();
}

export async function setPriority(issueKey, priorityName) {
  const res = await api.asApp().requestJira(route`/rest/api/3/issue/${issueKey}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields: { priority: { name: priorityName } } }),
  });
  console.log(`setPriority ${issueKey} -> ${priorityName}: HTTP ${res.status}`);
}

export async function addLabel(issueKey, label) {
  const res = await api.asApp().requestJira(route`/rest/api/3/issue/${issueKey}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ update: { labels: [{ add: label }] } }),
  });
  console.log(`addLabel ${issueKey} -> ${label}: HTTP ${res.status}`);
}

export async function postComment(issueKey, adfBody) {
  const res = await api.asApp().requestJira(route`/rest/api/3/issue/${issueKey}/comment`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ body: adfBody }),
  });
  console.log(`postComment ${issueKey}: HTTP ${res.status}`);
}

// Best-effort plain-text extraction from an ADF description (for context only).
export function adfToText(adf) {
  if (!adf) return null;
  if (typeof adf === 'string') return adf;
  const out = [];
  const walk = (node) => {
    if (!node) return;
    if (node.type === 'text' && node.text) out.push(node.text);
    if (Array.isArray(node.content)) node.content.forEach(walk);
  };
  walk(adf);
  const text = out.join(' ').replace(/\s+/g, ' ').trim();
  return text || null;
}

// Associative memory: find other findings in the project with the SAME CVE.
// Classifies them into one already fixed (status category "done") and one still
// open, so the caller can link + downgrade duplicates of resolved work.
export async function findDuplicates({ projectKey, cve, cveFieldId, serviceFieldId, excludeKey }) {
  const empty = { fixedElsewhere: null, openDuplicate: null, matchKeys: [] };
  if (!cve || !cveFieldId) return empty;

  const num = String(cveFieldId).replace(/\D/g, ''); // customfield_10049 -> 10049
  const safeCve = cve.replace(/["\\]/g, '');
  const jql =
    `project = "${projectKey}" AND cf[${num}] ~ "${safeCve}"` +
    (excludeKey ? ` AND key != ${excludeKey}` : '') +
    ` ORDER BY created ASC`;

  const fields = ['status', 'summary'];
  if (serviceFieldId) fields.push(serviceFieldId);

  let data;
  try {
    const res = await api.asApp().requestJira(route`/rest/api/3/search/jql`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ jql, maxResults: 20, fields }),
    });
    if (!res.ok) {
      console.log(`findDuplicates: search failed HTTP ${res.status}`);
      return empty;
    }
    data = await res.json();
  } catch (e) {
    console.log('findDuplicates error:', e.message);
    return empty;
  }

  const issues = data.issues || [];
  let fixedElsewhere = null;
  let openDuplicate = null;
  for (const it of issues) {
    const cat = it.fields?.status?.statusCategory?.key; // 'new' | 'indeterminate' | 'done'
    const info = {
      key: it.key,
      service: serviceFieldId ? it.fields?.[serviceFieldId] ?? null : null,
      summary: it.fields?.summary ?? null,
    };
    if (cat === 'done') {
      if (!fixedElsewhere) fixedElsewhere = info;
    } else if (!openDuplicate) {
      openDuplicate = info;
    }
  }
  return { fixedElsewhere, openDuplicate, matchKeys: issues.map((i) => i.key) };
}

// Create a "Duplicate" issue link: newKey duplicates existingKey.
export async function linkDuplicate(newKey, existingKey) {
  const res = await api.asApp().requestJira(route`/rest/api/3/issueLink`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      type: { name: 'Duplicate' },
      outwardIssue: { key: newKey },
      inwardIssue: { key: existingKey },
    }),
  });
  console.log(`linkDuplicate ${newKey} duplicates ${existingKey}: HTTP ${res.status}`);
  return res.ok;
}

// Resolve an email to a Jira user (accountId + display name), or null.
export async function resolveUserByEmail(email) {
  if (!email) return null;
  const res = await api.asApp().requestJira(route`/rest/api/3/user/search?query=${email}`);
  if (!res.ok) {
    console.log(`resolveUserByEmail: search failed HTTP ${res.status}`);
    return null;
  }
  const users = await res.json();
  const u = Array.isArray(users) ? users[0] : null;
  if (!u) return null;
  let displayName = u.displayName || null;
  // Search can return an empty display name for freshly-invited users; fetch the
  // canonical profile by accountId to get the real name.
  if (!displayName && u.accountId) {
    const r2 = await api.asApp().requestJira(route`/rest/api/3/user?accountId=${u.accountId}`);
    if (r2.ok) {
      const full = await r2.json();
      displayName = full?.displayName || null;
    }
  }
  return { accountId: u.accountId, displayName };
}

// Assign an issue to an accountId.
export async function assignIssue(issueKey, accountId) {
  const res = await api.asApp().requestJira(route`/rest/api/3/issue/${issueKey}/assignee`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ accountId }),
  });
  console.log(`assignIssue ${issueKey} -> ${accountId}: HTTP ${res.status}`);
  return res.ok;
}

// Move an issue to the first available status whose name matches targetNames.
export async function transitionIssue(issueKey, targetNames) {
  const res = await api.asApp().requestJira(route`/rest/api/3/issue/${issueKey}/transitions`);
  if (!res.ok) {
    console.log(`transitionIssue: could not list transitions for ${issueKey} (HTTP ${res.status}).`);
    return false;
  }
  const data = await res.json();
  const wanted = targetNames.map((n) => n.toLowerCase());
  const t = (data.transitions || []).find(
    (tr) =>
      wanted.includes((tr.to?.name || '').toLowerCase()) ||
      wanted.includes((tr.name || '').toLowerCase())
  );
  if (!t) {
    console.log(`transitionIssue ${issueKey}: no transition to ${targetNames.join(' / ')}.`);
    return false;
  }
  const r2 = await api.asApp().requestJira(route`/rest/api/3/issue/${issueKey}/transitions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ transition: { id: t.id } }),
  });
  console.log(`transitionIssue ${issueKey} -> ${t.to?.name || t.name}: HTTP ${r2.status}`);
  return r2.ok;
}

// Idempotency marker via an issue property.
export async function hasProperty(issueKey, key) {
  const res = await api.asApp().requestJira(route`/rest/api/3/issue/${issueKey}/properties/${key}`);
  return res.ok; // 200 exists, 404 not
}

export async function setProperty(issueKey, key, value) {
  const res = await api.asApp().requestJira(route`/rest/api/3/issue/${issueKey}/properties/${key}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(value),
  });
  console.log(`setProperty ${issueKey}/${key}: HTTP ${res.status}`);
  return res.ok;
}
