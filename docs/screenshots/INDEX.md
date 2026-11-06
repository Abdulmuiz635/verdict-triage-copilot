# Verdict - Screenshot log

Captured on the live **verdi.atlassian.net** site (iris-soc account, where Rovo works). Working-reference shots. A final clean capture pass with a screen recording comes before the submission video.

| File | Shows | Demo beat |
|---|---|---|
| 01-full-verdict-rephrased-recommended | Full auto verdict: flowing prose + intel + Recommended line | Auto-triage verdict (final wording) |
| 02-below-threshold-note | Low finding: short note + verdict-on-demand label | Threshold keeps it quiet |
| 03-rovo-agent-analysis-uses-context | Rovo agent analysis that cites the description | **AI with context** (headline) |
| 04-xz-finding-kan3 | The xz CVE-2024-3094 finding (KAN-3), later marked Done | Set-up for the duplicate beat |
| 05-duplicate-linked-downgraded | New finding linked to KAN-3, downgraded to Low | **Associative memory** (headline) |
| 06-duplicate-verdict-comment | "already fixed in KAN-3, downgraded from Highest" | **Associative memory** (headline) |
| 07-findings-list-overview | Findings list: KAN-3 Done/Highest, KAN-4 Low, KAN-5 Low | Backlog overview |
| 08-kan3-duplicates-link-view | KAN-3 showing "duplicates KAN-5" from its side | Two-way link proof |
| 09-owner-routing-assigned | Finding assigned to Sam Ibrahim via CODEOWNERS | **Owner routing across silos** (headline) |
| 10-ai-verdict-two-paragraph-bold | AI-written verdict: 2 paragraphs, key terms bold, owner woven in | **Atlassian AI writes the verdict** (headline) |
| 11-issue-glance-panel | Right-rail Verdict glance (sectioned) + AI comment w/ Recommendations | **The product UI** (headline) |
| 12-rovo-agent-polished | Rovo agent reply: priority+reason, intel, owner, numbered Recommended Actions | **Rovo agent, grounded** (headline) |
| 13-panel-summary-and-history | Clean glance: chips, AI summary line, History (audit log) | Audit log + polished panel |

## Final video shot list (to re-capture clean)
1. A finding is created, verdict appears automatically (01).
2. Intel: NVD description + CISA KEV known-exploited + EPSS, all cited.
3. Gap-fill + override: a finding with only a CVE, Verdict pulls CVSS from NVD and forces Highest via KEV.
4. Escalation: a finding missing data, Verdict @mentions a human to investigate.
5. Threshold: a Low finding gets a short note, not noise (02).
6. Associative memory: same CVE already fixed elsewhere, linked + downgraded (05, 06, 08).
7. Rovo agent: Ask Verdict to triage, it explains with grounded context incl. the description (03).
8. Owner routing (Inc 6, upcoming): finding auto-assigned to the CODEOWNERS owner of the affected service.
