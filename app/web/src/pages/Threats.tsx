import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, Navigate, useParams } from 'react-router-dom'
import { PageHeader } from '@/components/AppShell'
import { FindingList } from '@/components/Findings'
import { ThreatHeatmap } from '@/components/ThreatHeatmap'
import { CardSkeleton, EmptyState, ErrorState } from '@/components/states'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, Td, Th, Tr } from '@/components/ui/table'
import { api } from '@/lib/api'
import { useSelectedRun } from '@/lib/run'
import { cn } from '@/lib/utils'

// /threats: the selected run's matrix, else the latest finished analysis'
export function LatestThreats() {
  const run = useSelectedRun()
  const q = useQuery({ queryKey: ['analyses'], queryFn: api.analyses, enabled: !run })
  if (run) return <Navigate to={`/analyses/${run}/threats`} replace />
  if (q.isLoading) return <CardSkeleton rows={8} />
  const a = q.data?.find((x) => x.status === 'done')
  if (!a) return <Card><EmptyState title="No finished analysis yet">Run an analysis to see its threat matrix.</EmptyState></Card>
  return <Navigate to={`/analyses/${a.id}/threats`} replace />
}

export function ThreatsPage() {
  const { id = '' } = useParams()
  const a = useQuery({ queryKey: ['analysis', id], queryFn: () => api.analysis(id) })
  // a live run's matrix changes with every chunk
  const every = a.data?.source === 'live' ? 5_000 : false
  const th = useQuery({ queryKey: ['threats', id], queryFn: () => api.threats(id), refetchInterval: every })
  const fs = useQuery({ queryKey: ['findings', id], queryFn: () => api.findings(id), refetchInterval: every })
  const [cell, setCell] = useState<string | null>(null)
  const [pick, setPick] = useState<string | null>(null)
  if (th.isLoading || fs.isLoading) return <CardSkeleton rows={10} />
  if (th.error) return <Card><ErrorState error={th.error} retry={() => th.refetch()} /></Card>
  const threats = th.data!.threats
  const inCell = cell ? threats.filter((t) => `${t.likelihood}-${t.impact}` === cell) : threats
  const chosen = pick ? threats.find((t) => t.threat_id === pick) : null
  const linked = chosen ? (fs.data ?? []).filter((f) => chosen.findings.includes(`${f.check_id}#${f.tunnel}`)) : []
  return (
    <>
      <PageHeader eyebrow={<Link to={`/analyses/${id}`} className="hover:text-text">{a.data?.name ?? 'Analysis'}</Link>}
        title="Threat matrix" description="Likelihood comes from the linked findings' severity and confidence; impact is fixed per threat. Select a cell, then a threat, to see the findings behind it." />
      {!threats.length ? (
        <Card><EmptyState title="No threats">No check failed or warned for this analysis.</EmptyState></Card>
      ) : (
        <div className="grid gap-4 xl:grid-cols-5">
          <Card className="xl:col-span-2">
            <CardHeader><div><CardTitle>Likelihood × impact</CardTitle><CardDescription>cell number: likelihood × impact</CardDescription></div></CardHeader>
            <CardContent>
              <div className="flex gap-2">
                <div className="flex items-center"><span className="-rotate-90 whitespace-nowrap text-xs text-text-2">Likelihood →</span></div>
                <div className="flex-1"><ThreatHeatmap threats={threats} selected={cell} onSelect={(c) => { setCell(c); setPick(null) }} /></div>
              </div>
            </CardContent>
          </Card>
          <Card className="xl:col-span-3">
            <CardHeader><div><CardTitle>{cell ? `Threats in cell ${cell.replace('-', ' × ')}` : 'All threats'}</CardTitle><CardDescription>highest likelihood × impact first</CardDescription></div></CardHeader>
            <Table>
              <thead><tr><Th>Threat</Th><Th className="text-right">Likelihood</Th><Th className="text-right">Impact</Th><Th>Tunnels</Th><Th className="text-right">Findings</Th></tr></thead>
              <tbody>
                {inCell.map((t) => (
                  <Tr key={t.threat_id} className={cn('cursor-pointer', pick === t.threat_id && 'bg-accent-soft')} onClick={() => setPick(t.threat_id)}>
                    <Td><div className="text-sm">{t.threat}</div><div className="num text-xs text-muted">{t.threat_id}</div></Td>
                    <Td className="num text-right">{t.likelihood}</Td>
                    <Td className="num text-right">{t.impact}</Td>
                    <Td className="num text-xs">{t.tunnels.map((x) => `#${x}`).join(', ')}</Td>
                    <Td className="num text-right">{t.findings.length}</Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
            {chosen ? (
              <div className="border-t border-border">
                <p className="px-4 pt-3 text-xs font-medium text-muted">Findings behind {chosen.threat_id}</p>
                <FindingList findings={linked} showTunnel />
              </div>
            ) : <p className="px-5 py-4 text-xs text-text-2">Select a threat to drill down to its findings.</p>}
          </Card>
        </div>
      )}
    </>
  )
}
