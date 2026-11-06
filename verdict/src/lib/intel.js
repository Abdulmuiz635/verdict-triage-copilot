// Threat-intelligence enrichment. Given a CVE id, collate grounded facts from
// NVD (description + CVSS), EPSS (exploitation probability) and CISA KEV
// (known-exploited). Every value is a real API fact or null. Nothing invented.

import { fetch } from '@forge/api';

export async function fetchCveIntel(cve) {
  const intel = {
    description: null,
    nvdScore: null,
    nvdSeverity: null,
    epss: null,
    epssPercentile: null,
    kev: null,
    sources: {},
    errors: [],
  };

  // NVD
  try {
    const r = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cve)}`
    );
    if (r.ok) {
      const j = await r.json();
      const v = j.vulnerabilities?.[0]?.cve;
      intel.description = v?.descriptions?.find((d) => d.lang === 'en')?.value ?? null;
      const m =
        v?.metrics?.cvssMetricV31?.[0]?.cvssData ??
        v?.metrics?.cvssMetricV30?.[0]?.cvssData ??
        null;
      intel.nvdScore = m?.baseScore ?? null;
      intel.nvdSeverity = m?.baseSeverity ?? null;
      intel.sources.nvd = `https://nvd.nist.gov/vuln/detail/${cve}`;
    } else intel.errors.push(`NVD HTTP ${r.status}`);
  } catch (e) {
    intel.errors.push('NVD unavailable');
  }

  // EPSS
  try {
    const r = await fetch(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cve)}`);
    if (r.ok) {
      const j = await r.json();
      const d = j.data?.[0];
      if (d) {
        intel.epss = Number(d.epss);
        intel.epssPercentile = Number(d.percentile);
        intel.sources.epss = 'https://www.first.org/epss/';
      }
    } else intel.errors.push(`EPSS HTTP ${r.status}`);
  } catch (e) {
    intel.errors.push('EPSS unavailable');
  }

  // CISA KEV
  try {
    const r = await fetch(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    );
    if (r.ok) {
      const j = await r.json();
      intel.kev = (j.vulnerabilities || []).some((x) => x.cveID === cve);
      intel.sources.kev = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog';
    } else intel.errors.push(`KEV HTTP ${r.status}`);
  } catch (e) {
    intel.errors.push('KEV unavailable');
  }

  return intel;
}
