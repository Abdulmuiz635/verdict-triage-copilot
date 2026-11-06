// Atlassian AI (Forge LLMs API, @forge/llm) writes the human-facing narratives.
// Atlassian-hosted Claude, no external key. The DECISION is always made by
// deterministic code; the model only phrases the grounded facts and is told
// never to invent anything. On any failure the caller falls back to deterministic
// text, so a comment always posts.

import { chat, list } from '@forge/llm';

let workingModel = null;
let orderedCandidates = null;

// Prefer sonnet, then opus, then haiku. Not every model is permitted, so we try
// them in order until one is allowed, then cache it.
function orderModels(active) {
  const rank = (m) => (/sonnet/i.test(m) ? 0 : /opus/i.test(m) ? 1 : /haiku/i.test(m) ? 2 : 3);
  return [...active].sort((a, b) => rank(a) - rank(b));
}

async function getCandidates() {
  if (orderedCandidates) return orderedCandidates;
  try {
    const res = await list();
    const active = (res.models || []).filter((m) => m.status === 'active').map((m) => m.model);
    orderedCandidates = orderModels(active);
    console.log('Forge LLM candidates (ordered):', orderedCandidates.join(', '));
  } catch (e) {
    console.log('list models error:', e.message);
    orderedCandidates = [];
  }
  return orderedCandidates;
}

const BASE =
  'You are Verdict, a security triage assistant. Use ONLY the facts provided; never invent a CVE ' +
  'detail, score, status, person, service or issue key. No headings, bullet lists or links. ' +
  'Emphasise key specifics in bold with **double asterisks** (CVE id, CVSS, affected service, the ' +
  'priority word, EPSS percentage, owner name, and issue keys). Vary your wording so it does not read ' +
  'like a template.';

function systemFor(scenario) {
  switch (scenario) {
    case 'duplicate-fixed':
      return (
        BASE +
        ' Write ONE short sentence stating that this finding is a duplicate of already-resolved work ' +
        '(reference the given fixed issue key and its service) and so has been linked and downgraded to ' +
        'the given priority.'
      );
    case 'duplicate-open':
      return (
        BASE +
        ' Write ONE short sentence stating that this finding duplicates the given still-open issue for ' +
        'the same CVE and so has been linked, keeping the stated priority.'
      );
    case 'escalation':
      return (
        BASE +
        ' Write ONE short sentence explaining that this finding cannot be prioritised because it is ' +
        'missing the listed fields. Do NOT name or tag anyone and do NOT tell anyone to investigate ' +
        '(that is added separately).'
      );
    case 'panel-summary':
      return (
        'You are Verdict, a security triage assistant. Write ONE short plain-text sentence ' +
        '(max ~35 words) summarising what this CVE is and its exploitation outlook, combining the NVD ' +
        'description with the EPSS probability and whether it is known-exploited (CISA KEV). Use ONLY ' +
        'the facts provided; never invent anything. No markdown, no bold, no bullets, no links.'
      );
    default: // 'verdict' and 'below-threshold'
      return (
        BASE +
        ' Format as TWO short paragraphs separated by a blank line, each 1 to 2 sentences. Paragraph 1: ' +
        'what the vulnerability is, the affected service, the severity and CVSS, and whether it is ' +
        'actively exploited (CISA KEV), including the EPSS likelihood. Paragraph 2: why the priority is ' +
        'what it is (service criticality tier and exposure) and that the named owner has been tagged as ' +
        'owner of the service and assigned this ticket. ' +
        'When you mention EPSS, phrase it naturally, for example "it has a 63.8% chance of being ' +
        'exploited in the next 30 days", NOT "EPSS probability of 63.8%". ' +
        'After the two paragraphs, add a blank line, then a line containing exactly **Recommendations:** ' +
        'on its own, then exactly two short, specific action bullets, each on its own line starting with ' +
        '"- ". Do not begin with the priority as a header.'
      );
  }
}

async function tryChat(model, system, facts) {
  const resp = await chat({
    model,
    temperature: 0.7,
    max_completion_tokens: 320,
    messages: [
      { role: 'system', content: system },
      { role: 'user', content: 'Facts (JSON):\n' + JSON.stringify(facts) },
    ],
  });
  const content = resp?.choices?.[0]?.message?.content;
  const out =
    typeof content === 'string'
      ? content
      : Array.isArray(content)
      ? content.map((p) => p?.text || '').join('')
      : '';
  return (out || '').trim() || null;
}

// Returns a narrative string (may contain **bold** and blank-line paragraph
// breaks) or null if the AI is unavailable.
export async function writeNarrative(facts, scenario = 'verdict') {
  const system = systemFor(scenario);
  if (workingModel) {
    try {
      const out = await tryChat(workingModel, system, facts);
      if (out) return out;
    } catch (e) {
      console.log(`cached model ${workingModel} failed: ${e.message}`);
      workingModel = null;
    }
  }
  const candidates = await getCandidates();
  for (const model of candidates) {
    try {
      const out = await tryChat(model, system, facts);
      if (out) {
        workingModel = model;
        console.log('Forge LLM using model:', model);
        return out;
      }
    } catch (e) {
      console.log(`model ${model} not usable: ${e.message}`);
    }
  }
  return null;
}
