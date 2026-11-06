// Append-only audit log in Forge storage. Every verdict/write Verdict makes is
// recorded against the issue, so any action can be traced to what it did and when.
// Needs the storage:app scope.

import { kvs } from '@forge/kvs';

const KEY = (issueKey) => `audit-${issueKey}`;
const MAX_ENTRIES = 25;

export async function recordAudit(issueKey, entry) {
  if (!issueKey) return;
  try {
    const existing = (await kvs.get(KEY(issueKey))) || [];
    existing.push({ at: new Date().toISOString(), ...entry });
    await kvs.set(KEY(issueKey), existing.slice(-MAX_ENTRIES));
  } catch (e) {
    console.log('recordAudit error:', e.message);
  }
}

// Returns the audit entries for an issue, newest first.
export async function getAudit(issueKey) {
  if (!issueKey) return [];
  try {
    const list = (await kvs.get(KEY(issueKey))) || [];
    return [...list].reverse();
  } catch (e) {
    console.log('getAudit error:', e.message);
    return [];
  }
}
