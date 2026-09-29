import { useQuery } from '@tanstack/react-query'
import { FileText, Grid3x3, ListChecks, Timer } from 'lucide-react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { PageHeader } from '@/components/AppShell'
import { BandBadge, ConfidenceBadge, StatusBadge } from '@/components/badges'
import { FindingList } from '@/components/Findings'
import { RiskGauge } from '@/components/RiskGauge'
import { StatTile } from '@/components/StatTile'
import { CardSkeleton, EmptyState, ErrorState } from '@/components/states'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Table, Td, Th, Tr } from '@/components/ui/table'
import { useAnalysisPoll } from '@/hooks/usePoll'
import { api } from '@/lib/api'
import { appLabel } from '@/lib/colors'
import { bytes, factValue, num, seconds, when } from '@/lib/format'
import { StatusSteps } from '@/pages/Upload'

export function AnalysisPage() {
  const { id = '' } = useParams()
  const a = useAnalysisPoll(id)
  const done = a.data?.status === 'done'
  const tunnels = useQuery({ queryKey: ['tunnels', id], queryFn: () => api.tunnels(id), enabled: done })
  const findings = useQuery({ queryKey: ['findings', id], queryFn: () => api.findings(id), enabled: done })
  const nav = useNavigate()
  if (a.isLoading) return <CardSkeleton rows={8} />
  if (a.error) return <Card><ErrorState error={a.error} retry={() => a.refetch()} /></Card>
  const x = a.data!
  if (x.status !== 'done') {
    return (
      <>
        <PageHeader title={x.name || 'Analysis'} eyebrow={<span className="num">{id}</span>} />
        <Card className="max-w-xl">
          <CardHeader><div><CardTitle>{x.status === 'failed' ? 'Analysis failed' : x.status === 'pending' ? 'Waiting to start' : 'Analysing'}</CardTitle>
            <CardDescription>Polled with backoff until it finishes</CardDescription></div><StatusBadge status={x.status} /></CardHeader>
          <CardContent className="space-y-4">
            <StatusSteps uploading={false} analysis={x} />
            <Progress value={(x.progress ?? 0) * 100} label="analysis progress" />
            {x.error ? <p role="alert" className="text-sm" style={{ color: 'var(--critical)' }}>{x.error}</p> : null}
          </CardContent>
        </Card>
      </>
    )
  }
  const fs = findings.data ?? []
  const bad = fs.filter((f) => f.verdict === 'fail' || f.verdict === 'warn')
  const nd = fs.filter((f) => f.verdict === 'not determinable')
  return (
    <>
      <PageHeader title={x.name} eyebrow={<span>{x.source === 'replay' ? 'Replay' : x.source === 'demo' ? 'Demo capture' : 'Uploaded capture'} · {when(x.created_at)}</span>}
        actions={<>
          <Button onClick={() => nav(`/analyses/${id}/threats`)}><Grid3x3 /> Threat matrix</Button>
          <Button onClick={() => nav(`/reports/${id}/executive`)}><FileText /> Executive report</Button>
          <Button onClick={() => nav(`/reports/${id}/technical`)}><FileText /> Technical report</Button>
        </>} />
      <div className="grid gap-4 lg:grid-cols-4">
        <Card className="lg:row-span-2">
          <CardHeader><div><CardTitle>Risk</CardTitle><CardDescription>worst tunnel</CardDescription></div></CardHeader>
          <CardContent className="flex justify-center"><RiskGauge score={x.risk} /></CardContent>
        </Card>
        <StatTile label="Tunnels" value={num(x.tunnel_count)} icon={ListChecks} />
        <StatTile label="Failed or warning checks" value={num(bad.length)} hint={`${nd.length} not determinable`} />
        <StatTile label="Analysis time" value={seconds(x.timings?.total_s)} hint={`for ${seconds(x.timings?.traffic_s)} of traffic`} icon={Timer} />
        <StatTile label="Capture" value={bytes(x.size_bytes)} hint={`${num(x.packets)} packets`} />
        <StatTile label="Model bundle" value={<span className="text-base">{x.bundle_version}</span>} hint={x.schema_version} />
        <StatTile label="Status" value={<StatusBadge status={x.status} />} hint={x.stage} />
      </div>
      <Card className="mt-4">
        <CardHeader><div><CardTitle>Tunnels</CardTitle><CardDescription>Grouped by address pair, NAT-T ports, IKE and ESP SPIs</CardDescription></div></CardHeader>
        {tunnels.isLoading ? <CardContent><CardSkeleton rows={3} /></CardContent> : tunnels.error ? <ErrorState error={tunnels.error} /> :
          tunnels.data?.length ? (
            <Table>
              <thead><tr><Th>#</Th><Th>Initiator → responder</Th><Th>Handshake</Th><Th>ESP suite</Th><Th>Mode</Th><Th>Top traffic</Th><Th className="text-right">ESP packets</Th><Th>Risk</Th></tr></thead>
              <tbody>
                {tunnels.data.map((t) => {
                  const top = [...t.shares].filter((s) => s.app !== 'unknown').sort((a, b) => b.byte_share - a.byte_share).slice(0, 2)
                  return (
                    <Tr key={t.idx} className="cursor-pointer" onClick={() => nav(`/analyses/${id}/tunnels/${t.idx}`)}>
                      <Td className="num">#{t.idx}</Td>
                      <Td className="num text-xs"><Link to={`/analyses/${id}/tunnels/${t.idx}`} className="hover:underline" onClick={(e) => e.stopPropagation()}>{t.initiator ?? '?'} → {t.responder.join(', ') || '?'}</Link></Td>
                      <Td><StatusBadge status={t.handshake_status} /></Td>
                      <Td>{t.facts.esp_suite ? <span className="flex items-center gap-2 text-xs">{factValue(t.facts.esp_suite.value)} <ConfidenceBadge value={t.facts.esp_suite.confidence} /></span> : <span className="text-xs text-muted">no ESP</span>}</Td>
                      <Td className="text-xs">{t.facts.mode ? factValue(t.facts.mode.value) : '-'}</Td>
                      <Td className="text-xs">{top.length && top[0].byte_rounded > 0 ? top.filter((s) => s.byte_rounded > 0).map((s) => `${appLabel[s.app]} ${s.byte_rounded}%`).join(' · ') : <span className="text-muted">-</span>}</Td>
                      <Td className="num text-right">{num(t.esp_packets)}</Td>
                      <Td>{t.risk ? <BandBadge band={t.risk.band} score={t.risk.score} /> : '-'}</Td>
                    </Tr>
                  )
                })}
              </tbody>
            </Table>
          ) : <EmptyState title="No IPsec tunnels in this capture">The capture holds no ESP, AH or IKE packets.</EmptyState>}
      </Card>
      <Card className="mt-4">
        <CardHeader><div><CardTitle>Findings</CardTitle><CardDescription>Every check of every tunnel: failed and warning first, then not determinable, then passed</CardDescription></div></CardHeader>
        <div className="border-t border-border">
          {findings.isLoading ? <CardContent className="pt-4"><CardSkeleton rows={4} /></CardContent> : <FindingList findings={fs} showTunnel />}
        </div>
      </Card>
    </>
  )
}

export function AnalysesPage() {
  const q = useQuery({ queryKey: ['analyses'], queryFn: api.analyses, refetchInterval: 10_000 })
  const nav = useNavigate()
  return (
    <>
      <PageHeader title="Analyses" description="Every analysis, newest first." actions={<Button variant="primary" onClick={() => nav('/upload')}>New analysis</Button>} />
      <Card>
        {q.isLoading ? <CardContent className="pt-5"><CardSkeleton rows={6} /></CardContent> : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} /> :
          q.data?.length ? (
            <Table>
              <thead><tr><Th>Name</Th><Th>Source</Th><Th>Status</Th><Th>Risk</Th><Th className="text-right">Tunnels</Th><Th className="text-right">Size</Th><Th className="text-right">Time</Th><Th>Bundle</Th><Th className="text-right">Created</Th></tr></thead>
              <tbody>
                {q.data.map((a) => (
                  <Tr key={a.id} className="cursor-pointer" onClick={() => nav(`/analyses/${a.id}`)}>
                    <Td className="max-w-[320px] truncate">{a.name}</Td>
                    <Td className="text-xs capitalize text-text-2">{a.source}</Td>
                    <Td><StatusBadge status={a.status} /></Td>
                    <Td>{a.risk != null ? <BandBadge band={a.risk_band} score={a.risk} /> : '-'}</Td>
                    <Td className="num text-right">{a.tunnel_count}</Td>
                    <Td className="num text-right text-xs">{bytes(a.size_bytes)}</Td>
                    <Td className="num text-right text-xs">{seconds(a.timings?.total_s)}</Td>
                    <Td className="num text-xs text-text-2">{a.bundle_version || '-'}</Td>
                    <Td className="text-right text-xs text-muted">{when(a.created_at)}</Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          ) : <EmptyState title="No analyses yet" action={<Button variant="primary" onClick={() => nav('/upload')}>Analyze a capture</Button>} />}
      </Card>
    </>
  )
}
