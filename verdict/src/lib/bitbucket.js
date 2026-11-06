// Bitbucket Cloud access (egress). Reads a service's CODEOWNERS to find who owns
// the affected service. Auth: API token (app passwords are removed) via Basic
// auth with the Atlassian account email + token, both stored as Forge secrets.

import { fetch } from '@forge/api';

function authHeader() {
  const email = process.env.BITBUCKET_EMAIL;
  const token = process.env.BITBUCKET_TOKEN;
  if (!email || !token) return null;
  return 'Basic ' + Buffer.from(`${email}:${token}`).toString('base64');
}

// Pull the owner from a CODEOWNERS body: the "*" rule, else the first rule.
function parseCodeowners(txt) {
  const lines = txt
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
  const starRule = lines.find((l) => l.startsWith('* ') || l.startsWith('*\t'));
  const line = starRule || lines[0];
  if (!line) return null;
  const parts = line.split(/\s+/).slice(1); // drop the path pattern
  const owner = parts[0]?.replace(/^@/, '');
  return owner || null;
}

// Given a service name (= Bitbucket repo name), return the owner identifier from
// CODEOWNERS (an email in our setup). Never throws; returns { ownerEmail, error }.
export async function getOwnerForService(service) {
  const result = { repo: service, ownerEmail: null, error: null };
  if (!service) {
    result.error = 'no service on the finding';
    return result;
  }
  const ws = process.env.BITBUCKET_WORKSPACE;
  if (!ws) {
    result.error = 'Bitbucket workspace not configured';
    return result;
  }
  // Auth is optional: public repos read anonymously; a token (if set) also lets
  // us read private repos. This avoids Bitbucket's Premium-only workspace tokens.
  const auth = authHeader();
  const headers = auth
    ? { Authorization: auth, Accept: 'application/json' }
    : { Accept: 'application/json' };

  // Find the default branch.
  let branch = 'main';
  try {
    const r = await fetch(`https://api.bitbucket.org/2.0/repositories/${ws}/${service}`, { headers });
    if (r.status === 404) {
      result.error = `repo "${service}" not found in workspace ${ws}`;
      return result;
    }
    if (r.ok) {
      const j = await r.json();
      branch = j.mainbranch?.name || 'main';
    }
  } catch (e) {
    result.error = 'Bitbucket unreachable';
    return result;
  }

  // Read CODEOWNERS from the repo root.
  try {
    const r = await fetch(
      `https://api.bitbucket.org/2.0/repositories/${ws}/${service}/src/${encodeURIComponent(branch)}/CODEOWNERS`,
      { headers }
    );
    if (!r.ok) {
      result.error = `CODEOWNERS not found for ${service} (HTTP ${r.status})`;
      return result;
    }
    const txt = await r.text();
    result.ownerEmail = parseCodeowners(txt);
    if (!result.ownerEmail) result.error = `no owner rule in ${service} CODEOWNERS`;
  } catch (e) {
    result.error = 'CODEOWNERS read failed';
  }
  return result;
}
