# Verdict — Grounded Vulnerability Triage Copilot

> Verdict turns a noisy pile of security findings into ranked, routed, and explained work. It reads each finding in real Atlassian context, applies a deterministic security risk model, enriches it with live threat intelligence, and lets Atlassian AI write the explanation. The decision is code. The prose is AI. Nothing is invented.

Built on **Atlassian Forge**, integrating **Jira**, **Rovo**, **Atlassian Intelligence** (Forge LLMs API), and **Bitbucket**.

A solo entry for **Codegeist 2026**.

---

## The problem

Security scanners bury teams in findings. For every one, a human answers the same questions by hand:

- Is this real, or noise?
- How bad is it here, in this environment, on this service?
- Who owns the code it touches?
- Was it already fixed somewhere else?

That triage is slow and inconsistent, so real risk sits unattended while people drown in low-value findings. The knowledge needed to decide already lives across Jira and Bitbucket. It is just scattered, and nobody has time to assemble it per finding.

## The thesis

The challenge frames it well: AI can think, but knowing what to do takes context. Verdict's whole design is about supplying that context and refusing to go beyond it.

A general AI assistant pointed at a finding will happily hallucinate a CVSS score or invent an owner. Verdict cannot, by construction. The risk decision is made by deterministic code over retrieved facts. Atlassian AI is only ever asked to phrase facts it was handed, and a grounding guard drops any sentence that names a CVE or score it was not given. When context is missing, Verdict escalates to a human instead of guessing.

## What it does

When a finding lands as a Jira issue, Verdict runs a fixed pipeline:

1. **Ground.** Read the finding's fields (severity, CVSS, CVE, affected service) and gather context.
2. **Enrich.** Pull live threat intelligence for the CVE: the NVD description and CVSS, the EPSS exploitation probability, and whether CISA lists it as Known Exploited (KEV). Every fact keeps its source link.
3. **Decide.** Score risk deterministically (severity or CVSS, times a service-criticality tier, times an exposure factor) and bucket it into a priority. A KEV hit forces the priority to Highest.
4. **Remember.** Search Jira for the same CVE elsewhere. If it was already fixed, link the two and downgrade the new one. If an open duplicate exists, link it.
5. **Route.** Resolve the service's owner from the Bitbucket repo's CODEOWNERS file and assign the issue to that person.
6. **Explain.** Atlassian AI writes the comment: two short paragraphs with the key terms in bold, a natural reading of the EPSS likelihood, and a Recommendations section with two specific actions. If the AI is unavailable or its text fails the grounding check, a deterministic fallback comment posts instead, so a verdict always lands.
7. **Record.** Every action is appended to a per-issue audit trail, visible in the panel.

Below a configurable priority threshold, a finding gets a short note instead of a full verdict, so the automatic comments stay signal, not noise. Any finding can still be analysed on demand by asking the Rovo agent.

## Two surfaces, one brain

Verdict works the same whether a trigger fires it or a human asks:

- **Automatic.** A product trigger triages every new finding in the project.
- **Issue panel.** A clean glance in the issue view shows the priority, the chips (severity, exposure, KEV), the key facts, an AI one-line summary, the sources, and the history. A Re-run triage button re-triages on demand.
- **Rovo agent.** Ask Verdict to triage a finding in natural language. It calls a read-only action for the same grounded context and explains the decision, grounded and cited.

## The grounding harness

A deterministic pipeline with AI reasoning in the middle. Code does the fetching and the acting. The model only phrases.

- **Retrieve (code).** The finding, the threat intel, the Jira duplicate search, the Bitbucket owner.
- **Decide (code).** `scoreRisk` plus the KEV override. The language model never picks the priority.
- **Phrase (AI).** Atlassian AI writes the narrative from a JSON block of grounded facts, under a system prompt that forbids inventing anything.
- **Verify (code).** `isNarrativeGrounded` rejects any narrative that names a different CVE or a mismatched CVSS. On rejection, the deterministic fallback is used.
- **Escalate, not guess.** Missing the data needed to prioritise is a first-class outcome. Verdict says exactly what is missing and tags a human.

## Built with

| Piece | Role |
|---|---|
| **Atlassian Forge** | The serverless platform the whole app runs on. Triggers, functions, resolvers, UI Kit, storage, egress. |
| **Jira** | Findings live here as issues. Verdict reads, prioritises, comments, links, assigns, and transitions them. Primary surface via a `jira:issueContext` panel. |
| **Rovo** | The conversational agent (`rovo:agent` plus `rovo:skill`) and a read-only `action` for on-demand triage. |
| **Atlassian Intelligence** | The Forge LLMs API (`@forge/llm`), Atlassian-hosted Claude, writes every human-facing narrative. No external model or key. |
| **Bitbucket** | Source of ownership. Verdict reads each service's CODEOWNERS to route the finding to its owner. |

External, non-Atlassian data sources (read-only, each cited in the output):

| Source | Used for |
|---|---|
| **NVD** (services.nvd.nist.gov) | CVE description and CVSS, including gap-fill when the finding omits a score. |
| **CISA KEV** (www.cisa.gov) | Whether the CVE is known to be actively exploited. |
| **EPSS** (api.first.org) | The probability of exploitation in the next 30 days. |

## Repository layout

```
.
├── README.md                 ← this file
├── ARCHITECTURE.md           ← the harness, modules, and manifest in depth
├── docs/
│   └── screenshots/          ← captured on the live site, with an INDEX
├── seed/                     ← one-command demo data (see seed/README.md)
│   ├── seed.js
│   ├── findings.json
│   └── repos/                ← sample CODEOWNERS for the Bitbucket side
└── verdict/                  ← the Forge app
    ├── manifest.yml
    ├── package.json
    ├── skills/verdict-triage-skill/SKILL.md
    └── src/
        ├── index.js          ← exports the function handlers
        ├── triggers/         ← onIssueCreated
        ├── actions/          ← getVerdictContext (Rovo action)
        ├── resolvers/        ← the issue-panel resolver
        ├── frontend/         ← UI Kit panel
        └── lib/              ← config, jira, intel, riskModel, context,
                                 bitbucket, adf, llm, grounding, orchestrator, audit
```

## Running it locally

Prerequisites: Node 22 (via `fnm` or `nvm`), the Forge CLI (`npm i -g @forge/cli`), an Atlassian developer site, and a logged-in CLI (`forge login`). Rovo requires a site where Rovo is available (a standard or paid Jira site, not a free gmail org).

```bash
cd verdict
npm install
forge register          # first time only, creates your own app id
forge deploy
forge install --product jira --site your-site.atlassian.net
```

Owner routing reads a Bitbucket workspace. Set these as Forge variables (the token is optional, public repos read anonymously):

```bash
forge variables set BITBUCKET_WORKSPACE your-workspace
forge variables set --encrypt BITBUCKET_EMAIL you@example.com   # optional
forge variables set --encrypt BITBUCKET_TOKEN <api-token>       # optional
```

Configuration lives in `verdict/src/lib/config.js`: the findings project key, the custom field names, the auto-triage threshold, and the service-to-criticality-tier map. Fields are matched by name so the app stays portable across sites.

## Seeding the demo

`seed/` creates a realistic set of findings in one command, so a judge or a teammate can see the full story without hand-building issues. See `seed/README.md` for the field setup and the Bitbucket repos. In short:

```bash
cd seed
# set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, PROJECT_KEY in your shell
node seed.js
```

## Screenshots

Working-reference captures of every flow live in `docs/screenshots/`, indexed in `docs/screenshots/INDEX.md`. The same file holds the shot list for the submission video.

## A note on honesty

Verdict is advisory. It sets priority, links, assigns, and explains, but it tells the user to confirm before acting when it matters. Its core promise is the one thing a security team cannot accept from an AI: it never asserts what it cannot cite.
