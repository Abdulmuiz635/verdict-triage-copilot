# Verdict — Architecture

Thorough technical design for **Verdict**, the vulnerability triage copilot on Atlassian Forge. This document covers the components, the layered design, the folder structure, the security model, the features, the output and reporting guidelines, and the setup checklist.

**Only hard date:** submission deadline **Dec 22, 2026, 12:00 PM PT**. No internal timeline is tracked here by request.

---

## 1. Design principle: the decision is code, the prose is AI

The single most important architectural choice, and the core of the anti-hallucination story:

- **The priority decision is computed by deterministic code**, not by the language model. A risk score comes from a fixed formula over retrieved facts. The model never picks the severity or the priority number.
- **The language model only explains and matches.** It writes the human-readable rationale and helps detect semantically similar past findings. Even that output is checked against sources before anything is written.
- **A deterministic gate guards every write.** Before Verdict sets a priority, assigns an owner, or links a duplicate, the gate confirms each fact has a cited source. If it does not, Verdict writes nothing except an attention-calling comment that escalates to a human.

This means the scariest failure (a fabricated severity or a wrong owner silently applied) is structurally impossible. The model cannot cause an ungrounded write, because the write path is code and it refuses ungrounded input.

## 2. How Rovo actually works here (verified constraint)

Verified against current Forge docs and developer community, Nov 2026:

- There is **no headless API** to call a Rovo agent from a Forge function and receive a structured result. ([ECO-629](https://jira.atlassian.com/browse/ECO-629), [community thread](https://community.developer.atlassian.com/t/trigger-a-rovo-agent-from-a-forge-function/87749.md))
- A **Rovo agent** is invoked by a **user** via Ask Rovo, or **asynchronously by Automation** on an event.
- Automation-invoked agents **cannot call actions whose verb is CREATE, UPDATE, DELETE, or TRIGGER**. Use `GET` verbs for actions an agent may call, and keep the writes in a separate controlled path. ([rovo-action reference](https://developer.atlassian.com/platform/forge/manifest-reference/modules/rovo-action/))
- A **Forge trigger** (`avi:jira:created:issue`) runs a **Forge function** (not an agent). Events can take up to ~3 minutes to arrive. ([automate Jira using triggers](https://developer.atlassian.com/platform/forge/automate-jira-using-triggers/))
- A `rovo:agent` declares a prompt, an optional `rovo:skill`, and a list of `actions` (Forge functions) it may call as tools. ([Jira issue analyst agent tutorial](https://developer.atlassian.com/platform/forge/build-a-jira-issue-analyst-rovo-agent/))

**Conclusion → two surfaces, one brain.** The triage logic lives once, in deterministic actions. It is reached two ways:

1. **Auto path (background):** a Forge trigger on new findings runs the deterministic pipeline and writes a guarded verdict. No agent, no user needed. This is the "it just happened" demo moment.
2. **Conversational path (foreground):** the **Verdict Rovo agent** lets a user say "triage this finding" or "re-triage all open criticals." The agent reasons and calls the same actions (read-only `GET` actions), then a controlled write action applies the result. This path earns the Rovo bonus and shows the reasoning out loud.

## 3. The harness: Retrieve, Reason, Verify, Act

The fixed sequence every finding goes through, whichever path triggered it.

### 3.1 Retrieve (deterministic)
Gather only facts, each tagged with its source:
- The finding fields from the Jira issue: title, description, CVE/CWE id, scanner-reported severity/CVSS, affected component, package, version.
- The affected repo and service from Bitbucket, and the owner from `CODEOWNERS` or repo metadata.
- The asset's business criticality from a configured mapping (service → tier).
- Candidate duplicates: a Jira search (JQL) for issues with the same CVE/CWE/component, open or recently closed.

### 3.2 Reason (constrained)
- **Risk score (deterministic code, no model):** `priority = f(scanner_severity, exposure, asset_criticality, already_handled)`. Fixed, inspectable weights. See section 7.
- **Duplicate judgement (model-assisted, then verified):** the agent/LLM may judge whether a candidate is truly the same issue, but its judgement is only accepted if it names the specific candidate issue key it matched.
- **Explanation (model-written):** a short, plain rationale. Every factual sentence must reference a retrieved fact.

### 3.3 Verify (deterministic gate)
For the drafted verdict, the gate checks, field by field:
- Does `priority` trace to the risk formula inputs, all of which were retrieved? 
- Does `owner` trace to a real `CODEOWNERS`/metadata source?
- Does each claimed `duplicate` name a real issue key returned by the search?
- Does the explanation contain only claims backed by retrieved facts?

Any field that fails is **dropped**. If the core decision (priority + owner) cannot be fully grounded, the verdict is withheld and the escalation path (section 6, case D/E) runs instead.

### 3.4 Act (deterministic, guarded writes)
Only grounded fields are written:
- Set the issue priority.
- Assign the owner (or suggest, in suggest-only mode).
- Link duplicates and, for a confirmed duplicate, downgrade/flag the newer one.
- Post the verdict comment (section 5) with citations.
- Record an audit entry in storage.

## 4. Layers and components

| Layer | Responsibility | Components |
|---|---|---|
| **Entry** | Start the harness | `trigger` (issue created), Rovo agent, issue-panel UI button |
| **Orchestration** | Run Retrieve → Reason → Verify → Act in order, handle outcomes | `lib/orchestrator` |
| **Retrieval** | Pull facts, tag each with a source | `lib/jira`, `lib/bitbucket`, `lib/criticality` |
| **Reasoning** | Deterministic risk model + model-assisted matching + explanation | `lib/riskModel`, Rovo agent prompt, `rovo:skill` |
| **Grounding** | Verify every field cites a source; decide confident vs escalate | `lib/grounding` |
| **Action** | Guarded writes back to Jira | `actions/applyVerdict`, `lib/jira` |
| **Output** | Build comments and panel views (ADF) | `lib/adf`, `lib/escalation`, `ui/` |
| **Storage/Config** | Cache, dedup index, audit log, settings, secrets | Forge Storage/KV, environment variables |

### Component list
- **Trigger: `onIssueCreated`** — fires on `avi:jira:created:issue`, filtered to the findings project/type. Runs the orchestrator in auto mode.
- **Rovo agent: `verdict-agent`** — conversational triage. Prompt + `SKILL.md` encode the rules. Declares read-only `GET` actions.
- **Actions (Forge functions):**
  - `getContext` (GET) — Retrieve step, returns facts + sources.
  - `findDuplicates` (GET) — candidate search.
  - `scoreRisk` (GET) — deterministic score from inputs.
  - `applyVerdict` — the only writer. Runs the Verify gate, then writes or escalates. Kept out of the agent's auto-callable `GET` set so an Automation-invoked agent cannot write directly (verb restriction, section 2).
- **Issue-panel UI** — shows the verdict, the citations, the risk breakdown, and buttons: Run Verdict, Accept, Override, Escalate.
- **`lib/orchestrator`** — sequences the harness, maps results to output cases.
- **`lib/riskModel`** — the formula and the weights (configurable).
- **`lib/grounding`** — citation verification and confidence.
- **`lib/jira`, `lib/bitbucket`, `lib/criticality`** — connectors.
- **`lib/adf`, `lib/escalation`** — output builders, including the attention comment.
- **`lib/audit`** — append-only record of every verdict and write.

## 5. Output and reporting guidelines

All comments are posted as Jira ADF. Every verdict comment follows one structure so it reads consistently and every claim is checkable.

**Standard verdict comment layout:**
1. **Heading:** `Verdict: <PRIORITY>` with a one-line summary.
2. **Why this priority:** the risk breakdown (severity, exposure, asset tier, handled-before), each with its source link.
3. **Owner:** who and why (source: `CODEOWNERS`/metadata link).
4. **Related:** duplicates/links, each naming the issue key.
5. **Confidence:** High / Medium, and what would raise it.
6. **Footer:** "Grounded on N sources" with the links, and a "this is advisory, confirm before acting" note.

**Tone rules (product copy):** plain, direct, calm. No hype. No em-dashes or semicolons. Never state a fact without its source. Never imply certainty the data does not support.

### Output cases

- **Case A — Confident verdict.** Full grounding. Post the standard comment, set priority, assign owner. Confidence: High.
- **Case B — Confirmed duplicate.** The finding matches an existing issue. Link both, downgrade/flag the newer, comment: "Matches <KEY>, already handled there. Downgraded as duplicate." Cite the original.
- **Case C — Partial context.** Some fields grounded, some not (for example priority is clear but no owner found). Apply what is grounded, and in the comment flag the gap and call attention: *"Priority set to High. Owner could not be determined from CODEOWNERS. @team please assign the right owner and investigate further."*
- **Case D — No usable context / nothing to analyse.** Cannot ground the core decision, or the issue has no analysable finding data. **Do not say "insufficient context" flatly.** Post an attention-calling comment that pulls a human in:
  > ⚠️ **Verdict needs a human here.** I could not confidently triage this finding because <specific reason, for example: no CVE or severity was provided and the affected component is not recognised>. **@team-security kindly investigate further** and add the missing detail so it can be triaged.
  The `@mention` targets the configured security team or a fallback user. Set a label like `verdict-needs-review` for easy filtering.
- **Case E — Conflicting signals.** Retrieved facts disagree (for example scanner says Critical but the component is not deployed/reachable). Do not pick silently. Post the conflict, show both sides with sources, and mention: *"Signals conflict. @team-security please confirm whether <component> is in production before this is prioritised."*
- **Case F — Override / human correction.** When a human overrides via the panel, record it in the audit log and learn nothing silently. The comment notes who overrode and the new value.

**The escalation voice (Cases C, D, E) is a first-class feature, not an error.** It is the honest alternative to guessing, and it is what makes a security tool trustworthy. The message always: names the specific gap, mentions the right team or user, and asks them to investigate further.

## 6. Features

**Core (MVP):**
- Auto-triage of new findings on creation (background).
- On-demand triage via the Verdict Rovo agent ("triage this finding").
- Deterministic risk scoring with an inspectable breakdown.
- Owner resolution from Bitbucket `CODEOWNERS`/metadata.
- Duplicate detection and downgrade, with the associative-memory behaviour (recognise a flaw already fixed elsewhere, link it, downgrade the new one).
- Citation on every claim, and the deterministic grounding gate.
- The escalation/attention comment for ungrounded or conflicting cases.
- Issue-panel UI: verdict, breakdown, citations, Accept/Override/Escalate.
- Audit log of every verdict and write.

**Stretch:**
- Batch triage of the whole open backlog, ranked.
- Configurable risk weights and service→criticality map (settings page).
- Teamwork Graph integration for richer ownership/relationships (EAP).
- Confluence runbook linking (attach the matching remediation runbook).
- Suggest-only mode (never writes, only recommends) for cautious teams.

## 7. The risk model (deterministic)

A transparent formula, no model involvement, so the number is always defensible.

```
base      = scanner_severity        # Critical/High/Medium/Low -> 4/3/2/1 (from CVSS or scanner field)
exposure  = reachable_in_prod ? x1.0 : x0.5   # from deployment/service data where available
assetTier = service_criticality     # Tier0/1/2 -> x1.25 / x1.0 / x0.75 (configurable map)
handled   = already_fixed_elsewhere ? x0.25 : x1.0   # duplicate/prior-fix memory

score     = base * exposure * assetTier * handled
priority  = bucket(score)           # thresholds -> Highest/High/Medium/Low
```

Every input is a retrieved, cited fact. The weights live in config and are shown in the breakdown so a reviewer sees exactly how the priority was reached. Missing inputs do not get guessed, they trigger Case C/D.

## 8. Security model

Forge runs the app on Atlassian-managed infrastructure, sandboxed, with explicit scopes. Verdict follows least privilege and treats its own non-hallucination as a security property.

- **Scopes (least privilege):** `read:jira-work` (read findings, required for the issue-created trigger), `write:jira-work` (comment, set priority, assign), and the minimum Bitbucket read scope needed. No broader scope than the features require.
- **Acting principal:** read as the user where permission-sensitive (`asUser`) so Verdict never surfaces data a viewer could not see. Writes performed as the app (`asApp`) with the narrow write scope, and always logged.
- **Bitbucket access:** Bitbucket is a separate product from the Jira-hosted app. It is reached by an external REST call to `api.bitbucket.org`, declared as an **egress** permission in the manifest, authenticated with a **repository access token / app password stored as a Forge environment variable (encrypted secret)**, never in source.
- **Egress allowlist:** only the exact external hosts the app needs (`api.bitbucket.org`, and any model endpoint if the auto-path narrative uses one) are declared. Nothing else can be reached.
- **Secrets:** all tokens/keys in Forge environment variables, never committed. `.env` is gitignored. The repo ships `.env.example` with names only.
- **Data handling:** findings and code-ownership data stay within Atlassian and the declared endpoints. No finding content is sent anywhere undeclared. Storage holds only what is needed (cache, dedup index, audit), and is scoped to the app installation.
- **Grounding as safety:** the deterministic gate prevents fabricated security assessments from ever being written. "Investigate further" is preferred to a confident guess.
- **Auditability:** every verdict, write, and human override is recorded append-only, so any action can be traced to its inputs and sources.
- **Verb hygiene:** agent-callable actions are read-only `GET`; the single writer action is not exposed to Automation-invoked agent calls, honouring the CREATE/UPDATE/DELETE/TRIGGER restriction.

## 9. Folder structure

```
verdict/
├─ manifest.yml                 # modules, scopes, egress, triggers, agent, actions
├─ package.json
├─ .env.example                 # secret NAMES only
├─ .gitignore                   # .env, node_modules, build output
├─ README.md
├─ ARCHITECTURE.md
├─ src/
│  ├─ index.js                  # handler exports
│  ├─ triggers/
│  │  └─ onIssueCreated.js      # auto path entry
│  ├─ actions/                  # Rovo/agent-callable + writer
│  │  ├─ getContext.js          # GET  (Retrieve)
│  │  ├─ findDuplicates.js      # GET  (candidate search)
│  │  ├─ scoreRisk.js           # GET  (deterministic score)
│  │  └─ applyVerdict.js        # WRITE (Verify gate + act/escalate)
│  ├─ rovo/
│  │  └─ skill/
│  │     └─ SKILL.md            # grounding rules + risk model + escalation voice
│  ├─ lib/
│  │  ├─ orchestrator.js        # sequence + case mapping
│  │  ├─ riskModel.js           # formula + weights
│  │  ├─ grounding.js           # citation verification, confidence
│  │  ├─ jira.js                # Jira REST wrappers
│  │  ├─ bitbucket.js           # Bitbucket REST (egress + secret)
│  │  ├─ criticality.js         # service -> tier map
│  │  ├─ adf.js                 # comment/panel ADF builders
│  │  ├─ escalation.js          # the "@team investigate further" builder
│  │  ├─ audit.js               # append-only log
│  │  └─ config.js              # weights, mappings, mention targets
│  └─ ui/
│     └─ issuePanel/            # UI Kit issue panel (verdict, breakdown, actions)
├─ seed/                        # scripts + data to populate the dev site demo
│  ├─ findings.json
│  ├─ repos/                    # sample repos + CODEOWNERS
│  └─ seed.js
└─ docs/
   └─ demo-script.md            # the 5-minute end-to-end walkthrough
```

UI uses **UI Kit** (React-based, renders native Atlassian components) for a complete, on-brand look with less effort. Move to Custom UI only if a view needs more than UI Kit allows.

## 10. Setup checklist

Accounts and platform:
- [x] Create free Atlassian Cloud developer site (`kingmaker1094.atlassian.net`, Jira/JSM/Confluence) using `oladipupoabdulmuiz@gmail.com`.
- [x] Sign in to `developer.atlassian.com` with the same account.
- [ ] Register for **Devpost** and the Codegeist 2026 page with the same email.
- [ ] Create a **GitHub** repo for the project with the same identity.

Forge toolchain:
- [x] Node LTS via **fnm** (Node v22.23.4, npm 10.9.9). fnm auto-loads from the PowerShell `$PROFILE`.
- [x] **Forge CLI** installed and current (`forge --version` = 15.0.0, no Node warning).
- [x] **Atlassian API token** created and `forge login` succeeded (Annafi Abdulmuiz).
- [x] **Docker Desktop** installed (29.9.1) for `forge tunnel`.

Rovo and AI:
- [ ] Enrol in the **Forge Rovo Agents EAP** (form, open to all Forge developers, do early in case of approval lag).
- [ ] **Enable Atlassian Intelligence / Rovo** on `kingmaker1094.atlassian.net` from site admin (Rovo capability can be limited on Free/Standard editions).
- [ ] Verify Ask Rovo appears in the site and an agent can be enabled.

Bitbucket:
- [ ] Sign up for **Bitbucket Cloud** at `bitbucket.org` using the same Atlassian account.
- [ ] Create 2–3 **test repositories** with a `CODEOWNERS` file each.
- [ ] Create a **repository/workspace access token** for API reads, store it as a Forge environment variable (never in source).

App scaffold and data:
- [x] `forge create` using the **rovo-agent** template (app `verdict`, App ID `24b1ea9e-fbf2-4d06-a8a0-4164e864b206`, Developer Space "Codegeist"). Seed = rovo:agent + one GET action + `messageLogger` function.
- [ ] Add the `trigger` (issue created), the issue-panel module, the actions, and scopes/egress to `manifest.yml`.
- [ ] `forge deploy` and `forge install` to the dev site.
- [ ] **Seed the demo scenario:** a findings project with issues (varied CVEs/severities), the Bitbucket repos + CODEOWNERS, and one **prior-fix case** so the memory beat fires.
- [ ] Configure the service→criticality map and the escalation `@mention` target.

Validation:
- [ ] Auto path: create a finding, confirm a grounded verdict is posted.
- [ ] Conversational path: Ask Rovo to triage a finding, confirm cited reasoning.
- [ ] Escalation: create a finding with missing data, confirm the "@team investigate further" comment.
- [ ] Duplicate: create a finding matching the prior-fix case, confirm link + downgrade.
- [ ] Record the `docs/demo-script.md` walkthrough and the under-5-minute video.

## 11. Execution model and cost

Forge is serverless and event-driven. Nothing runs continuously and nothing is "always listening" at the app's expense. Code is dormant until an event invokes it, runs for a few seconds, and stops. There is no server and no idle cost.

**How each entry point is triggered:**
- **Auto path:** the Atlassian platform watches the `avi:jira:created:issue` event (not the app). On a new finding it invokes the function. No polling, no socket. Events may take up to ~3 minutes to arrive.
- **Conversational path:** the Rovo agent runs only when a user asks it. No activity or cost when idle.
- **Panel button:** runs only on click.

**Where cost comes from:**
1. **Forge runtime** is quota-based, not hourly. Function invocations, storage, and egress have generous free quotas that hackathon and dev scale stay well within. No per-hour server cost.
2. **AI reasoning is the only real lever:**
   - Via the **Rovo agent**, AI compute runs on Atlassian's side using the site's Rovo/Atlassian Intelligence entitlement. No per-token bill to the app. Enabled on the dev site for testing. This is the primary design.
   - Via an **external LLM** (egress), billed per token per call. Optional, only if a feature needs it.

**Cost controls built into the design:**
- **Deterministic-first:** the risk score is pure code, so many findings reach a full verdict with zero AI calls.
- **Filtered trigger:** fires only on the findings project / issue type / label, not every Jira issue.
- **Idempotency marker:** a stored "triaged" flag prevents re-processing and re-spending.
- **AI on demand:** the deterministic verdict posts on creation, the richer AI explanation is produced only when a human opens the panel or asks Rovo.
- **Caching:** CODEOWNERS/repo metadata and the criticality map are cached to avoid repeated external calls.

Net effect at this scale: effectively free, with the Rovo path avoiding out-of-pocket token cost entirely.

## 12. Open items to confirm during build
- Exact minimum Bitbucket scope and token type for `CODEOWNERS`/metadata reads.
- Whether the auto-path explanation is generated deterministically or via a declared model endpoint (egress). The decision/priority stays deterministic either way.
- Teamwork Graph EAP acceptance (stretch only).
