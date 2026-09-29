import { useQuery } from '@tanstack/react-query'
import { ArrowLeft } from 'lucide-react'
import { Link, useParams } from 'react-router-dom'
import { PageHeader } from '@/components/AppShell'
import { BandBadge, ConfidenceBadge, SourceBadge, StatusBadge } from '@/components/badges'
import { FindingList } from '@/components/Findings'
import { ActiveBars, ShareBar } from '@/components/ShareBar'
import { WindowTimeline } from '@/components/WindowTimeline'
import { CardSkeleton, EmptyState, ErrorState } from '@/components/states'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, Td, Th, Tr } from '@/components/ui/table'
import { api, type Fact } from '@/lib/api'
import { factValue, num, pct, seconds } from '@/lib/format'

const groups: { title: string; hint: string; keys: string[] }[] = [
  { title: 'Handshake and IKE', hint: 'read from cleartext IKE messages when the setup is in the capture',
    keys: ['handshake_status', 'ike_version', 'ikev1_mode', 'ikev1_auth', 'ike_encryption', 'ike_integ', 'ike_prf', 'ike_dh',
      'ike_lifetime_s', 'ike_exchanges', 'ike_init_payloads', 'ike_notifies', 'ike_retransmissions'] },
  { title: 'ESP (inferred from sizes)', hint: 'models trained on the dataset; confidence is calibrated',
    keys: ['esp_suite', 'mode', 'pfs'] },
  { title: 'Observed on the wire', hint: 'outer headers only',
    keys: ['outer_family', 'nat_t', 'rekeys', 'rekey_times_s', 'capture_span_s', 'ah_packets', 'esp_plaintext_share',
      'esp_duplicate_seq', 'spi_first_seen_s'] },
]
const labels: Record<string, string> = {
  handshake_status: 'Handshake status', ike_version: 'IKE version', ikev1_mode: 'IKEv1 phase 1 mode', ikev1_auth: 'IKEv1 authentication',
  ike_encryption: 'IKE encryption', ike_integ: 'IKE integrity', ike_prf: 'IKE PRF', ike_dh: 'DH group', ike_lifetime_s: 'IKE lifetime (s)',
  ike_exchanges: 'IKE exchanges', ike_init_payloads: 'IKE_SA_INIT payloads', ike_notifies: 'Notifies', ike_retransmissions: 'IKE retransmissions',
  esp_suite: 'ESP cipher / integrity', mode: 'Mode', pfs: 'Perfect forward secrecy', outer_family: 'Outer IP family', nat_t: 'NAT traversal',
  rekeys: 'Rekeys', rekey_times_s: 'Rekey times (s)', capture_span_s: 'Captured span (s)', ah_packets: 'AH packets',
  esp_plaintext_share: 'Plaintext-looking ESP', esp_duplicate_seq: 'Repeated sequence numbers', spi_first_seen_s: 'SPIs first seen (s)',
}

function FactRow({ name, f }: { name: string; f: Fact }) {
  const v = name === 'esp_plaintext_share' && typeof f.value === 'number' ? pct(f.value, 1) : factValue(f.value)
  return (
    <Tr>
      <Td className="w-[38%] text-xs text-text-2">{labels[name] ?? name}</Td>
      <Td className="num break-words text-xs">{v}</Td>
      <Td className="w-[1%] whitespace-nowrap">
        <div className="flex flex-col items-start gap-1">
          <ConfidenceBadge value={f.value === 'not determinable' ? null : f.confidence} />
          <span className="sm:hidden"><SourceBadge source={f.source} /></span>
        </div>
      </Td>
      <Td className="hidden sm:table-cell w-[1%] whitespace-nowrap"><SourceBadge source={f.source} /></Td>
    </Tr>
  )
}

export function TunnelPage() {
  const { id = '', idx = '0' } = useParams()
  const a = useQuery({ queryKey: ['analysis', id], queryFn: () => api.analysis(id) })
  // a live run's tunnel changes with every chunk
  const q = useQuery({ queryKey: ['tunnel', id, idx], queryFn: () => api.tunnel(id, Number(idx)),
    refetchInterval: a.data?.source === 'live' ? 5_000 : false })
  if (q.isLoading) return <div className="grid gap-4 lg:grid-cols-2"><CardSkeleton rows={10} /><CardSkeleton rows={10} /></div>
  if (q.error) return <Card><ErrorState error={q.error} retry={() => q.refetch()} /></Card>
  const t = q.data!
  const probs = t.esp_suite_probabilities
  return (
    <>
      <PageHeader
        eyebrow={<Link to={`/analyses/${id}`} className="inline-flex items-center gap-1 hover:text-text"><ArrowLeft className="size-3.5" /> {a.data?.name ?? 'Analysis'}</Link>}
        title={<span className="flex flex-wrap items-center gap-3">Tunnel #{t.idx} <span className="num text-sm font-normal text-text-2">{t.initiator ?? '?'} → {t.responder.join(', ') || '?'}</span></span>}
        description={`Direction from ${t.direction_from}. ${num(t.esp_packets)} ESP packets over ${seconds((t.end_s ?? 0) - (t.start_s ?? 0))}.`}
        actions={<><StatusBadge status={t.handshake_status} />{t.risk ? <BandBadge band={t.risk.band} score={t.risk.score} /> : null}</>}
      />
      <div className="grid gap-4 xl:grid-cols-5">
        <div className="space-y-4 xl:col-span-3">
          {groups.map((g) => {
            const rows = g.keys.filter((k) => t.facts[k])
            return (
              <Card key={g.title}>
                <CardHeader><div><CardTitle>{g.title}</CardTitle><CardDescription>{g.hint}</CardDescription></div></CardHeader>
                {rows.length ? (
                  <Table><thead><tr><Th>Fact</Th><Th>Value</Th><Th>Confidence</Th><Th className="hidden sm:table-cell">Source</Th></tr></thead>
                    <tbody>{rows.map((k) => <FactRow key={k} name={k} f={t.facts[k]} />)}</tbody></Table>
                ) : <p className="px-5 pb-5 text-xs text-text-2">Not in this capture{g.title.startsWith('Handshake') ? ' (it started after the tunnel was set up)' : ''}.</p>}
                {g.title.startsWith('ESP') && probs ? (
                  <CardContent className="pt-3">
                    <p className="mb-2 text-xs text-muted">Suite model distribution</p>
                    <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                      {Object.entries(probs).map(([k, v]) => (
                        <div key={k} className="rounded-lg border border-border p-2">
                          <div className="num text-[11px] text-text-2">{k}</div>
                          <div className="mt-1 h-1.5 rounded-full bg-surface-3"><div className="h-full rounded-full bg-accent" style={{ width: `${v * 100}%` }} /></div>
                          <div className="num mt-1 text-xs">{pct(v, 1)}</div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                ) : null}
              </Card>
            )
          })}
        </div>
        <div className="space-y-4 xl:col-span-2">
          <Card>
            <CardHeader><div><CardTitle>Bandwidth share</CardTitle><CardDescription>Session byte share, sums to 100% with unknown; ± out-of-fold error</CardDescription></div></CardHeader>
            <CardContent>{t.shares.length ? <ShareBar shares={t.shares} /> : <EmptyState title="No traffic to classify">This tunnel carries no ESP payload windows.</EmptyState>}</CardContent>
          </Card>
          <Card>
            <CardHeader><div><CardTitle>Active time</CardTitle><CardDescription>Per app, separate bars</CardDescription></div></CardHeader>
            <CardContent>{t.shares.length ? <ActiveBars shares={t.shares} /> : <p className="text-xs text-text-2">No windows.</p>}</CardContent>
          </Card>
        </div>
      </div>
      <Card className="mt-4">
        <CardHeader><div><CardTitle>Window timeline</CardTitle><CardDescription>2-second windows: ESP bytes split by predicted app share (top), calibrated presence probability (bottom)</CardDescription></div></CardHeader>
        <CardContent>{t.windows?.length ? <WindowTimeline windows={t.windows} /> : <EmptyState title="No windows">No ESP traffic to show.</EmptyState>}</CardContent>
      </Card>
      <Card className="mt-4">
        <CardHeader><div><CardTitle>Findings for this tunnel</CardTitle><CardDescription>Click a finding for its evidence and standard</CardDescription></div></CardHeader>
        <div className="border-t border-border"><FindingList findings={t.findings ?? []} /></div>
      </Card>
    </>
  )
}
