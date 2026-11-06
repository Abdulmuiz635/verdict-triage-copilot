# Verdict demo seed

One command to populate a realistic set of security findings so the full Verdict
story is visible end to end: auto-triage, KEV override, NVD gap-fill, duplicate
memory, owner routing, and escalation.

## 1. Prerequisites

- Node 18 or newer (the seeder uses the built-in `fetch`, no dependencies).
- A Jira Cloud site with the Verdict app installed.
- An Atlassian API token: https://id.atlassian.com/manage-profile/security/api-tokens

## 2. Create the custom fields

Verdict matches fields by name. On the findings project, add these custom fields
and put them on the create screen:

| Field name | Type |
|---|---|
| `Severity` | Short text, or single-select with Critical / High / Medium / Low |
| `CVSS` | Number |
| `CVE ID` | Short text |
| `Affected service` | Short text |

The seeder discovers each field's id automatically and adapts to whether
`Severity` is text or a select list. Any field it cannot find is skipped with a
warning, and the issue is still created.

## 3. Seed the findings

```bash
cd seed

# PowerShell
$env:JIRA_BASE_URL="https://your-site.atlassian.net"
$env:JIRA_EMAIL="you@example.com"
$env:JIRA_API_TOKEN="your-token"
$env:PROJECT_KEY="KAN"
node seed.js

# bash / zsh
JIRA_BASE_URL=https://your-site.atlassian.net \
JIRA_EMAIL=you@example.com \
JIRA_API_TOKEN=your-token \
PROJECT_KEY=KAN \
node seed.js
```

Add `--dry-run` to preview without creating anything.

## 4. Set up the Bitbucket side (owner routing)

Owner routing reads each service's `CODEOWNERS` from a Bitbucket repo named after
the service. For the demo:

1. In your Bitbucket workspace, create public repos named `payments-api`,
   `auth-service`, and `reporting-ui`.
2. Put a `CODEOWNERS` file at each repo root. Samples are in `seed/repos/`.
   Change the emails to real Atlassian account emails on your site so Verdict can
   resolve and assign them.
3. Point the app at the workspace: `forge variables set BITBUCKET_WORKSPACE your-workspace`.

Public repos are read anonymously, so no Bitbucket token is needed. A token is
only required for private repos.

## 5. What each finding demonstrates

| Finding | Demo beat |
|---|---|
| Log4Shell on payments-api | Full auto verdict, KEV override to Highest, EPSS, owner routing |
| xz backdoor on auth-service | The original. Mark it Done to set up the duplicate beat |
| xz backdoor on reporting-ui | Associative memory: linked to the auth-service one and downgraded |
| HTTP/2 Rapid Reset on auth-service | Known-exploited High on a tier-0 service |
| Spring4Shell on payments-api (no score) | NVD gap-fill: Verdict pulls the CVSS from NVD |
| zlib over-read on reporting-ui | Below threshold: short note, not noise |
| Insecure deserialization (no data) | Escalation: Verdict asks a human instead of guessing |

## Files

- `seed.js` — the seeder.
- `findings.json` — the finding data. Edit freely.
- `repos/` — sample `CODEOWNERS` files for the Bitbucket repos.
- `.seed-state.json` — written after a run, listing the created issue keys (gitignored).
