import React, { useEffect, useState } from 'react';
import ForgeReconciler, {
  Text,
  Strong,
  Heading,
  Stack,
  Inline,
  Lozenge,
  Link,
  Button,
  SectionMessage,
  Spinner,
} from '@forge/react';
import { invoke } from '@forge/bridge';

const PRIORITY_APPEARANCE = {
  Highest: 'removed',
  High: 'removed',
  Medium: 'moved',
  Low: 'success',
  Lowest: 'success',
};
const SEVERITY_APPEARANCE = { Critical: 'removed', High: 'removed', Medium: 'moved', Low: 'success' };
const EXPOSURE_APPEARANCE = { exposed: 'removed', internal: 'success', unknown: 'default' };

// Label left, value right.
const TextRow = ({ label, value }) =>
  value === null || value === undefined || value === '' ? null : (
    <Inline spread="space-between" alignBlock="center" space="space.200">
      <Text><Strong>{label}</Strong></Text>
      <Text>{String(value)}</Text>
    </Inline>
  );

const App = () => {
  const [data, setData] = useState(null);
  const [audit, setAudit] = useState([]);
  const [busy, setBusy] = useState(false);

  const load = () =>
    Promise.all([invoke('getPanelData').then(setData), invoke('getAudit').then(setAudit)]);
  useEffect(() => {
    load();
  }, []);

  if (!data) return <Spinner label="Loading verdict" />;
  if (data.error)
    return (
      <SectionMessage appearance="warning">
        <Text>{data.error}</Text>
      </SectionMessage>
    );

  const rerun = async () => {
    setBusy(true);
    await invoke('runTriage');
    await load();
    setBusy(false);
  };

  const chips = [];
  if (data.severity)
    chips.push(
      <Lozenge key="sev" appearance={SEVERITY_APPEARANCE[data.severity] || 'default'}>
        {data.severity}
      </Lozenge>
    );
  if (data.exposure)
    chips.push(
      <Lozenge key="exp" appearance={EXPOSURE_APPEARANCE[data.exposure] || 'default'}>
        {data.exposure}
      </Lozenge>
    );
  if (data.kev === true)
    chips.push(
      <Lozenge key="kev" appearance="removed" isBold>
        KEV
      </Lozenge>
    );

  return (
    <Stack space="space.200">
      {data.escalate ? (
        <SectionMessage appearance="warning" title="Needs a human">
          <Text>Missing {data.missing.join(', ')}. Add the detail, then Re-run triage.</Text>
        </SectionMessage>
      ) : (
        <Inline spread="space-between" alignBlock="center">
          <Heading size="small">Verdict</Heading>
          <Lozenge appearance={PRIORITY_APPEARANCE[data.priority] || 'default'} isBold>
            {data.priority}
          </Lozenge>
        </Inline>
      )}

      {chips.length > 0 && <Inline space="space.100">{chips}</Inline>}

      <Stack space="space.075">
        <TextRow label="CVE" value={data.cve} />
        <TextRow label="CVSS" value={data.cvss} />
        <TextRow label="Service" value={data.service} />
        <TextRow label="Criticality" value={data.tier} />
        <TextRow
          label="Owner"
          value={data.owner ? `${data.owner}${data.ownerResolved ? '' : ' (unassigned)'}` : null}
        />
      </Stack>

      {data.summary && <Text>{data.summary}</Text>}
      {!data.summary && data.epssPercent !== null && data.epssPercent !== undefined && (
        <Text>
          <Strong>EPSS</Strong> {data.epssPercent}% chance of exploitation in the next 30 days
        </Text>
      )}
      {!data.summary && data.nvd && (
        <Text>
          <Strong>NVD </Strong>
          {data.nvd}
        </Text>
      )}
      {data.duplicateFixed && <Text>Duplicate of already-fixed {data.duplicateFixed}.</Text>}
      {data.duplicateOpen && <Text>Duplicate of open {data.duplicateOpen}.</Text>}

      {(data.sources?.nvd || data.sources?.kev || data.sources?.epss) && (
        <Inline space="space.150">
          {data.sources.nvd && (
            <Link href={data.sources.nvd} openNewTab>
              NVD
            </Link>
          )}
          {data.sources.kev && (
            <Link href={data.sources.kev} openNewTab>
              CISA KEV
            </Link>
          )}
          {data.sources.epss && (
            <Link href={data.sources.epss} openNewTab>
              EPSS
            </Link>
          )}
        </Inline>
      )}

      {audit.length > 0 && (
        <Stack space="space.050">
          <Text><Strong>History</Strong></Text>
          {audit.slice(0, 3).map((e, i) => (
            <Text key={i}>
              {(e.at || '').slice(0, 16).replace('T', ' ')} — {e.action}
              {e.priority ? ` (${e.priority})` : ''}
            </Text>
          ))}
        </Stack>
      )}

      <Button appearance="primary" shouldFitContainer onClick={rerun} isDisabled={busy}>
        {busy ? 'Running…' : 'Re-run triage'}
      </Button>
    </Stack>
  );
};

ForgeReconciler.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
