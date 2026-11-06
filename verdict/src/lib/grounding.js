// Grounding guard. Rejects an AI narrative that drifts from the grounded facts,
// so a fabricated claim never gets posted. On rejection the caller falls back to
// the deterministic text. This is the programmatic half of "the prose is AI, but
// nothing is invented": the decision is already code, and this checks the prose.

export function isNarrativeGrounded(narrative, facts = {}) {
  if (!narrative) return false;
  const text = String(narrative);

  // 1. CVE ids: the narrative must not mention a CVE other than the finding's.
  const cves = (text.match(/CVE-\d{4}-\d{4,7}/gi) || []).map((s) => s.toUpperCase());
  if (facts.cve) {
    const want = String(facts.cve).toUpperCase();
    if (cves.some((c) => c !== want)) return false;
  } else if (cves.length) {
    return false; // claims a CVE we don't actually have
  }

  // 2. CVSS: if the narrative states a CVSS score, it must match the finding's.
  if (facts.cvss !== null && facts.cvss !== undefined) {
    const m = text.match(/CVSS[^0-9]{0,15}(\d{1,2}(?:\.\d)?)/i);
    if (m && Number(m[1]) !== Number(facts.cvss)) return false;
  }

  return true;
}
