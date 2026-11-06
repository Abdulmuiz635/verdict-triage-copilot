// ADF (Atlassian Document Format) builders for the comments Verdict posts.

export function para(nodes) {
  return { type: 'paragraph', content: nodes };
}
export function text(value, marks) {
  const node = { type: 'text', text: value };
  if (marks) node.marks = marks;
  return node;
}
export function link(label, href) {
  return text(label, [{ type: 'link', attrs: { href } }]);
}

// Convert a single line with **bold** markers into ADF text nodes.
function inlineToNodes(s) {
  const nodes = [];
  s.split(/\*\*/).forEach((seg, i) => {
    if (!seg) return;
    nodes.push(i % 2 === 1 ? text(seg, [{ type: 'strong' }]) : text(seg));
  });
  return nodes.length ? nodes : [text(s)];
}

function bulletList(items) {
  return {
    type: 'bulletList',
    content: items.map((it) => ({ type: 'listItem', content: [para(inlineToNodes(it))] })),
  };
}

// Convert the AI narrative (plain text with **bold**, blank-line paragraphs, and
// "- " bullet lines) into ADF: paragraphs + bullet lists, with bold runs.
export function narrativeToAdf(narrative) {
  const lines = narrative.split('\n');
  const out = [];
  let paraBuf = [];
  let listBuf = [];
  const flushPara = () => {
    if (paraBuf.length) {
      out.push(para(inlineToNodes(paraBuf.join(' ').trim())));
      paraBuf = [];
    }
  };
  const flushList = () => {
    if (listBuf.length) {
      out.push(bulletList(listBuf));
      listBuf = [];
    }
  };
  for (const raw of lines) {
    const line = raw.trim();
    if (!line) {
      flushPara();
      flushList();
      continue;
    }
    const m = line.match(/^[-*•]\s+(.*)$/);
    if (m) {
      flushPara();
      listBuf.push(m[1]);
    } else {
      flushList();
      paraBuf.push(line);
    }
  }
  flushPara();
  flushList();
  return out.length ? out : [para([text(narrative)])];
}

// Flowing, grounded prose describing the finding. Does NOT restate the priority
// (the bold header already does), it leads with the substance.
export function composeProse(ctx) {
  const { severity, cvss, cvssSource, cve, service, intel } = ctx;
  const subject = cve ? `${cve} is` : 'This finding is';
  const sevPart = severity ? `a ${severity.toLowerCase()}-severity issue` : 'an issue';
  const cvssPart = typeof cvss === 'number' ? ` (CVSS ${cvss})` : '';
  const svcPart = service ? ` affecting ${service}` : '';
  let s = `${subject} ${sevPart}${cvssPart}${svcPart}.`;

  if (intel?.kev === true) {
    s += ' It is listed in CISA KEV as actively exploited';
    s +=
      typeof intel.epss === 'number'
        ? `, with a ${(intel.epss * 100).toFixed(1)}% chance of exploitation in the next 30 days (EPSS).`
        : '.';
  } else if (typeof intel?.epss === 'number') {
    s += ` EPSS puts the chance of exploitation in the next 30 days at ${(intel.epss * 100).toFixed(1)}%.`;
  }
  if (cvssSource === 'NVD') s += ' Score retrieved from NVD.';
  return s;
}

function sourcesParagraph(intel) {
  if (!intel || !Object.keys(intel.sources || {}).length) return null;
  const nodes = [text('Sources: ')];
  const parts = [];
  if (intel.sources.nvd) parts.push(['NVD', intel.sources.nvd]);
  if (intel.sources.kev) parts.push(['CISA KEV', intel.sources.kev]);
  if (intel.sources.epss) parts.push(['EPSS', intel.sources.epss]);
  parts.forEach(([label, href], i) => {
    if (i > 0) nodes.push(text(' · '));
    nodes.push(link(label, href));
  });
  return para(nodes);
}

// Deterministic fallback narrative: combines the finding, exploitation, risk
// reasoning and owner into ONE flowing paragraph (used only when the AI is down).
function composeFallback(ctx) {
  let s = composeProse(ctx);
  const r = ctx.risk;
  if (r && r.priority) {
    const tierLabel =
      {
        tier0: 'a Tier 0 (critical) service',
        tier1: 'a Tier 1 service',
        tier2: 'a Tier 2 (lower-impact) service',
      }[r.tier] || `a ${r.tier} service`;
    s += ` It is prioritised ${ctx.priority} because ${ctx.service || 'the affected service'} is ${tierLabel} with ${r.exposure} exposure.`;
  }
  const o = ctx.owner;
  if (o?.displayName) {
    s += ` ${o.displayName} owns ${o.repo} and has been tagged and assigned this ticket.`;
  } else if (o?.email) {
    s += ` ${o.email} is listed as the owner of ${o.repo} in CODEOWNERS but is not a Jira user, so it was not auto-assigned.`;
  }
  return s;
}

// Full verdict comment (above threshold). When `narrative` (AI-written, grounded)
// is supplied it becomes the body; otherwise we fall back to deterministic text.
export function buildVerdictComment(ctx, narrative) {
  const { priority, intel } = ctx;
  const content = [];

  content.push(para([text(`Verdict: ${priority} priority.`, [{ type: 'strong' }])]));

  if (narrative) {
    narrativeToAdf(narrative).forEach((p) => content.push(p));
  } else {
    content.push(para([text(composeFallback(ctx))]));
    if (intel?.description) {
      const brief =
        intel.description.length > 300 ? `${intel.description.slice(0, 300).trim()}…` : intel.description;
      content.push(para([text('About this CVE (NVD): ', [{ type: 'strong' }]), text(brief)]));
    }
  }

  const src = sourcesParagraph(intel);
  if (src) content.push(src);
  content.push(para([text('This is advisory. Confirm before acting.', [{ type: 'em' }])]));
  return { type: 'doc', version: 1, content };
}

// Short note for findings below the auto-analysis threshold.
export function buildBelowThresholdComment(ctx, narrative) {
  const content = [para([text(`Verdict: ${ctx.priority} priority.`, [{ type: 'strong' }])])];
  if (narrative) {
    narrativeToAdf(narrative).forEach((p) => content.push(p));
  } else {
    content.push(para([text(composeFallback(ctx))]));
  }
  content.push(
    para([
      text('Below the auto-analysis threshold, so it was triaged but not fully analysed. Open the '),
      text('Agents', [{ type: 'strong' }]),
      text(' menu and ask Verdict to analyse it for a full breakdown with threat intelligence.'),
    ])
  );
  return { type: 'doc', version: 1, content };
}

// Escalation comment for findings missing the data needed to triage. The AI
// writes the explanation; the @mention call-to-action stays deterministic so the
// real person is tagged.
export function buildEscalationComment(ctx, narrative) {
  const content = [para([text('Verdict needs a human here.', [{ type: 'strong' }])])];
  if (narrative) {
    narrativeToAdf(narrative).forEach((p) => content.push(p));
  } else {
    content.push(
      para([text(`This finding is missing ${ctx.missing.join(', ')}, so it cannot be prioritised safely.`)])
    );
  }
  const mention = [];
  if (ctx.reporterId) {
    mention.push({ type: 'mention', attrs: { id: ctx.reporterId } });
    mention.push(text(' kindly investigate further and add the missing detail so it can be triaged.'));
  } else {
    mention.push(text('The security team should investigate further and add the missing detail.'));
  }
  content.push(para(mention));
  return { type: 'doc', version: 1, content };
}

// Duplicate of ALREADY-FIXED work. The associative-memory "money" comment.
export function buildFixedElsewhereComment(ctx, narrative) {
  const fx = ctx.duplicate.fixedElsewhere;
  const where = fx.service ? `${fx.key} (${fx.service})` : fx.key;
  const content = [para([text(`Verdict: ${ctx.priority} priority (downgraded).`, [{ type: 'strong' }])])];
  if (narrative) {
    narrativeToAdf(narrative).forEach((p) => content.push(p));
  } else {
    content.push(
      para([
        text(
          `${ctx.cve} was already fixed in ${where}, so this is a duplicate of resolved work. ` +
            `Linked to ${fx.key} and downgraded from ${ctx.originalPriority}.`
        ),
      ])
    );
  }
  content.push(para([text('This is advisory. Confirm before acting.', [{ type: 'em' }])]));
  return { type: 'doc', version: 1, content };
}

// Duplicate of a still-OPEN finding. Keeps the computed priority, adds a link note.
export function buildOpenDuplicateComment(ctx, narrative) {
  const op = ctx.duplicate.openDuplicate;
  const content = [para([text(`Verdict: ${ctx.priority} priority.`, [{ type: 'strong' }])])];
  if (narrative) {
    narrativeToAdf(narrative).forEach((p) => content.push(p));
  } else {
    content.push(para([text(composeProse(ctx))]));
    content.push(
      para([text(`Note: the same CVE is already open in ${op.key}. Linked as a duplicate.`, [{ type: 'em' }])])
    );
  }
  const src = sourcesParagraph(ctx.intel);
  if (src) content.push(src);
  content.push(para([text('This is advisory. Confirm before acting.', [{ type: 'em' }])]));
  return { type: 'doc', version: 1, content };
}
