import { useQuery } from '@tanstack/react-query'
import { ArrowRight, Network, PlayCircle, RadioTower, ShieldAlert, UploadCloud, Waypoints } from 'lucide-react'
import { Link, useNavigate } from 'react-router-dom'
import { PageHeader } from '@/components/AppShell'
import { BandBadge, ConfidenceBadge, SeverityBadge, StatusBadge } from '@/components/badges'
import { RiskGauge } from '@/components/RiskGauge'
import { StatTile } from '@/components/StatTile'
import { BrandLogo } from '@/components/Brand'
import { CardSkeleton, ErrorState } from '@/components/states'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, Td, Th, Tr } from '@/components/ui/table'
import { api } from '@/lib/api'
import { factValue, num, when } from '@/lib/format'
import { setSelectedRun, useSelectedRun } from '@/lib/run'

export function Overview() {
  const run = useSelectedRun()
  // one run (the top bar's choice) or every run; a live run refreshes as its chunks arrive
  const q = useQuery({
    queryKey: ['overview', run], queryFn: () => api.overview(run),
    refetchInterval: (query) => (run && query.state.data?.recent.some((x) => x.source === 'live') ? 5_000 : 15_000),
  })
  const nav = useNavigate()
  if (q.isLoading) {
    return (
      <>
        <PageHeader title="Overview" description="Tunnels, risk and alerts across recent analyses." />
        <div className="grid gap-4 md:grid-cols-4">{[0, 1, 2, 3].map((i) => <CardSkeleton key={i} rows={1} />)}</div>
        <div className="mt-4 grid gap-4 lg:grid-cols-3"><CardSkeleton rows={6} /><CardSkeleton rows={6} className="lg:col-span-2" /></div>
      </>
    )
  }
  if (q.error) return <Card><ErrorState error={q.error} retry={() => q.refetch()} /></Card>
  const d = q.data!
  if (!d.recent.length) {
    return (
      <>
        <PageHeader title="Overview" description="Tunnels, risk and alerts across recent analyses." />
        <Card className="flex flex-col items-center px-6 py-12 text-center">
          <BrandLogo className="w-56" />
          <p className="mt-6 max-w-md text-sm text-text-2">
            No analyses yet. Upload an outer IPsec capture (pcap or pcapng), or load one of the three demo captures with one click.
          </p>
          <div className="mt-5 flex flex-wrap justify-center gap-2">
            <Button variant="primary" onClick={() => nav('/upload')}><UploadCloud /> Analyze a capture</Button>
            <Button onClick={() => nav('/replay')}><PlayCircle /> Watch a demo replay</Button>
          </div>
        </Card>
      </>
    )
  }
  const crit = d.alerts.filter((a) => a.severity === 'critical').length
  const one = run ? d.recent[0] : null
  return (
    <>
      <PageHeader title="Overview"
        description={one ? <>Tunnels, risk and alerts of one run: <span className="text-text">{one.name}</span></> : 'Tunnels, risk and alerts across the last 20 finished analyses.'}
        actions={<>
          {one ? <Button variant="ghost" onClick={() => setSelectedRun(null)}>Show all runs</Button> : null}
          {one?.source === 'live' ? <Button onClick={() => nav(`/live/${one.id}`)}><RadioTower /> Live view</Button> : null}
          <Button variant="primary" onClick={() => nav('/upload')}><UploadCloud /> Analyze capture</Button>
        </>} />
      {one && !d.analyses_done ? (
        <p role="note" className="mb-4 rounded-[12px] border border-border px-4 py-3 text-sm text-text-2">
          {one.source === 'live' ? 'This live session has no analysed chunk yet; the figures below fill in as its sensor sends traffic.' : 'This analysis has not finished yet.'}
        </p>
      ) : null}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile label="Analyses" value={num(d.analyses_done)} hint="finished" icon={Waypoints} />
        <StatTile label="Tunnels" value={num(d.inventory.length)} hint="in the inventory below" icon={Network} />
        <StatTile label="High and critical alerts" value={num(d.alerts.length)} hint={`${crit} critical`} icon={ShieldAlert} />
        <StatTile label="Worst tunnel score" value={d.overall.score ?? '-'} hint="0-100, critical findings dominate" />
      </div>
      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader><div><CardTitle>Overall risk</CardTitle><CardDescription>{d.overall.rule}</CardDescription></div></CardHeader>
          <CardContent className="flex justify-center pt-2"><RiskGauge score={d.overall.score} /></CardContent>
        </Card>
        <Card className="lg:col-span-2">
          <CardHeader>
            <div><CardTitle>Critical and high alerts</CardTitle><CardDescription>Failed checks, most severe first</CardDescription></div>
          </CardHeader>
          <div className="border-t border-border">
            {d.alerts.length ? d.alerts.slice(0, 7).map((a) => (
              <Link key={`${a.analysis_id}-${a.id}`} to={`/analyses/${a.analysis_id}/tunnels/${a.tunnel ?? 0}`}
                className="flex items-center gap-3 border-b border-border px-5 py-3 last:border-0 hover:bg-surface-2">
                <SeverityBadge severity={a.severity} />
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm">{a.text}</p>
                  <p className="truncate text-xs text-muted">{a.analysis} · tunnel {a.tunnel} · {a.check_id}</p>
                </div>
                <ArrowRight className="size-4 text-muted" aria-hidden />
              </Link>
            )) : <p className="px-5 py-8 text-center text-xs text-text-2">No high or critical findings in recent analyses.</p>}
          </div>
        </Card>
      </div>
      <Card className="mt-4">
        <CardHeader><div><CardTitle>Tunnel inventory</CardTitle><CardDescription>Every tunnel of the recent analyses</CardDescription></div></CardHeader>
        <Table>
          <thead><tr><Th>Analysis</Th><Th>Tunnel</Th><Th>Endpoints</Th><Th>Handshake</Th><Th>ESP suite</Th><Th>Mode</Th><Th>IKE</Th><Th className="text-right">ESP packets</Th><Th>Risk</Th></tr></thead>
          <tbody>
            {d.inventory.map((t) => (
              <Tr key={`${t.analysis_id}-${t.idx}`} className="cursor-pointer" onClick={() => nav(`/analyses/${t.analysis_id}/tunnels/${t.idx}`)}>
                <Td className="max-w-[220px] truncate"><Link className="hover:underline" to={`/analyses/${t.analysis_id}`} onClick={(e) => e.stopPropagation()}>{t.analysis}</Link><div className="text-xs text-muted">{when(t.created_at)}</div></Td>
                <Td className="num">#{t.idx}</Td>
                <Td className="num text-xs">{t.initiator ?? '?'} → {t.responder.join(', ') || '?'}</Td>
                <Td><StatusBadge status={t.handshake_status} /></Td>
                <Td>{t.esp_suite ? <span className="flex items-center gap-2 text-xs">{factValue(t.esp_suite.value)} <ConfidenceBadge value={t.esp_suite.confidence} /></span> : <span className="text-xs text-muted">no ESP</span>}</Td>
                <Td className="text-xs">{t.mode ? factValue(t.mode.value) : '-'}</Td>
                <Td className="text-xs">{t.ike_version ? `IKEv${t.ike_version.value}` : <span className="text-muted">not captured</span>}</Td>
                <Td className="num text-right">{num(t.esp_packets)}</Td>
                <Td>{t.risk ? <BandBadge band={t.risk.band} score={t.risk.score} /> : '-'}</Td>
              </Tr>
            ))}
          </tbody>
        </Table>
      </Card>
      <Card className="mt-4">
        <CardHeader><div><CardTitle>Recent analyses</CardTitle></div>
          <Button variant="ghost" size="sm" onClick={() => nav('/analyses')}>All analyses <ArrowRight /></Button></CardHeader>
        <Table>
          <tbody>
            {d.recent.map((a) => (
              <Tr key={a.id} className="cursor-pointer" onClick={() => nav(`/analyses/${a.id}`)}>
                <Td className="max-w-[320px] truncate">{a.name}</Td>
                <Td><span className="text-xs text-muted capitalize">{a.source}</span></Td>
                <Td><StatusBadge status={a.status} /></Td>
                <Td>{a.risk != null ? <BandBadge band={a.risk_band} score={a.risk} /> : '-'}</Td>
                <Td className="text-right text-xs text-muted">{when(a.created_at)}</Td>
              </Tr>
            ))}
          </tbody>
        </Table>
      </Card>
    </>
  )
}
