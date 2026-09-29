import { keepPreviousData, useQuery, useQueryClient } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { CheckCircle2, FileText, Gauge, Grid3x3, History, Hourglass, Play, Square, TimerOff, type LucideIcon } from 'lucide-react'
import * as React from 'react'
import { useEffect, useRef, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { PageHeader } from '@/components/AppShell'
import { BandBadge, ConfidenceBadge, LiveBadge, SeverityBadge, SourceBadge, StatusBadge } from '@/components/badges'
import { CodeBlock } from '@/components/Code'
import { ActiveBars, ShareBar } from '@/components/ShareBar'
import { CardSkeleton, EmptyState, ErrorState } from '@/components/states'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tip } from '@/components/ui/tooltip'
import { api, type Fact, type Finding, type LiveSession, type Tunnel, type Window } from '@/lib/api'
import { appLabel, shareNames } from '@/lib/colors'
import { demoLabel, demoRun, isDemoSession, startDemoSensor, stopDemoSensor } from '@/lib/demoSensor'
import { bytes, factValue, num, pct, when } from '@/lib/format'
import { setSelectedRun } from '@/lib/run'
import { agentCommands, keptSensor, stopSession, useSensors } from '@/lib/sensors'
import { toast } from '@/lib/toast'

const terminal = ['stopped', 'completed', 'expired']
const shown = ['handshake_status', 'ike_version', 'ikev1_mode', 'ike_encryption', 'ike_integ', 'ike_dh', 'esp_suite', 'mode', 'pfs', 'nat_t']
const labels: Record<string, string> = {
  handshake_status: 'Handshake status', ike_version: 'IKE version', ikev1_mode: 'IKEv1 phase 1 mode', ike_encryption: 'IKE encryption',
  ike_integ: 'IKE integrity', ike_dh: 'DH group', esp_suite: 'ESP cipher / integrity', mode: 'Mode', pfs: 'Perfect forward secrecy',
  nat_t: 'NAT traversal',
}

// /live/{id}: one live session as its chunks arrive
export function LiveSessionPage() {
  const { id = '' } = useParams()
  useSensors()
  const nav = useNavigate()
  const qc = useQueryClient()
  const q = useQuery({
    queryKey: ['live', id], queryFn: () => api.liveSession(id),
    refetchInterval: (query) => (terminal.includes(query.state.data?.status ?? '') ? false : 3_000),
  })
  const over = terminal.includes(q.data?.status ?? '')
  const a = useQuery({ queryKey: ['analysis', id], queryFn: () => api.analysis(id), refetchInterval: over ? false : 3_000 })
  // finished_at changes once per analysed chunk: the heavier data is fetched once per chunk and
  // the previous chunk's stays on screen meanwhile
  const stamp = a.data?.finished_at ?? null
  const data = useQuery({
    queryKey: ['live-data', id, stamp], enabled: !!stamp, placeholderData: keepPreviousData,
    queryFn: async () => {
      const [ts, alerts] = await Promise.all([api.tunnels(id), api.liveAlerts(id)])
      return { tunnels: await Promise.all(ts.map((t) => api.tunnel(id, t.idx))), alerts }
    },
  })

  // confidence per fact over the chunks seen while this page is open
  const [hist, setHist] = useState<Record<string, (number | null)[]>>({})
  const histStamp = useRef<string | null>(null)
  useEffect(() => {
    const ts = data.data?.tunnels
    if (!ts || data.isPlaceholderData || !stamp || histStamp.current === stamp) return
    histStamp.current = stamp
    setHist((h) => {
      const n = { ...h }
      for (const t of ts) {
        for (const [k, f] of Object.entries(t.facts)) {
          n[`${t.idx}:${k}`] = [...(n[`${t.idx}:${k}`] ?? []), f.value === 'not determinable' ? null : f.confidence].slice(-60)
        }
      }
      return n
    })
  }, [data.data, data.isPlaceholderData, stamp])

  // a toast for each new alert; opened mid-session, the ones already raised are only listed
  const openedAt = useRef<number | null>(null)
  const seen = useRef<Set<string> | null>(null)
  useEffect(() => {
    if (openedAt.current == null && q.data) openedAt.current = q.data.chunks
  }, [q.data])
  useEffect(() => {
    const al = data.data?.alerts
    if (!al || data.isPlaceholderData) return
    if (seen.current == null) {
      seen.current = new Set()
      if ((openedAt.current ?? 0) > 1) {
        al.forEach((f) => seen.current!.add(`${f.check_id}#${f.tunnel}`))
        return
      }
    }
    for (const f of al) {
      const k = `${f.check_id}#${f.tunnel}`
      if (seen.current.has(k)) continue
      seen.current.add(k)
      toast({ title: f.title, description: `Tunnel #${f.tunnel}: ${f.text}`, severity: f.severity })
    }
  }, [data.data, data.isPlaceholderData])

  if (q.isLoading) return <div className="grid gap-4"><CardSkeleton rows={3} /><CardSkeleton rows={8} /></div>
  if (q.error) return <Card><ErrorState error={q.error} retry={() => q.refetch()} /></Card>
  const s = q.data!
  const kept = keptSensor(id)
  const run = demoRun(id)
  const demo = isDemoSession(id, s.name)
  const active = !over
  const analysing = a.data?.status === 'running' && a.data.stage !== 'waiting'
  const d = data.data
  const stop = async () => {
    stopDemoSensor(id)
    try {
      await stopSession(id)
    } catch (err) {
      toast({ title: 'Could not stop the session', description: err instanceof Error ? err.message : String(err) })
    }
    await qc.invalidateQueries({ queryKey: ['live', id] })
  }
  return (
    <>
      <PageHeader eyebrow={<Link to="/live" className="hover:text-text">Live sessions</Link>}
        title={<span className="flex flex-wrap items-center gap-3">{s.name || 'Live session'}<LiveBadge status={s.status} /></span>}
        description={<span className="num">
          {num(s.chunks)} chunks · {bytes(s.bytes)} received · updated {when(s.last_chunk_at ?? s.created_at)}
          {analysing ? ' · analysing the latest chunk…' : ''}
        </span>}
        actions={<>
          {kept?.kind === 'demo' && active && !run?.running ? (
            <Button onClick={() => startDemoSensor(id, kept.demo ?? 'mixture', s.last_seq + 1)}><Play /> Resume demo sensor</Button>
          ) : null}
          {kept && active ? <Button variant="outline" onClick={stop}><Square /> Stop</Button> : null}
          {stamp ? <>
            <Button variant="ghost" onClick={() => { setSelectedRun(id); nav('/') }}><Gauge /> Overview</Button>
            <Button variant="ghost" onClick={() => nav(`/analyses/${id}/threats`)}><Grid3x3 /> Threat matrix</Button>
            <Button variant="ghost" onClick={() => nav(`/reports/${id}/technical`)}><FileText /> Report</Button>
          </> : null}
        </>} />
      {demo ? (
        <Note c="var(--medium)" I={History}>
          <strong className="font-semibold">{demoLabel}.</strong>{' '}
          <span className="text-text-2">
            A stored test capture is fed in 5-second slices through the same path as a real sensor's chunks; the timestamps are the capture's own.
            {run?.steps ? <span className="num"> Slice {Math.min(run.seq, run.steps)} of {run.steps}.</span> : null}
          </span>
        </Note>
      ) : null}
      <StateNote s={s} />
      {run?.error ? <Note c="var(--critical)" I={TimerOff}><span className="text-text-2">The demo sensor stopped: {run.error}</span></Note> : null}
      {!stamp && active ? <Waiting id={id} demo={demo} running={!!run?.running} /> : null}
      {d ? (
        <>
          <Alerts id={id} alerts={d.alerts} />
          {d.tunnels.length ? d.tunnels.map((t) => <TunnelLive key={t.idx} id={id} t={t} hist={hist} />) : (
            <Card><EmptyState title="No IPsec tunnel seen yet">The chunks so far carry no ESP, AH or IKE packets.</EmptyState></Card>
          )}
        </>
      ) : stamp ? <CardSkeleton rows={6} /> : null}
    </>
  )
}

function Note({ c, I, children }: { c: string; I: LucideIcon; children: React.ReactNode }) {
  return (
    <div role="note" className="mb-4 flex items-start gap-3 rounded-[12px] border px-4 py-3 text-sm"
      style={{ borderColor: `color-mix(in oklab, ${c} 45%, transparent)`, background: `color-mix(in oklab, ${c} 10%, transparent)` }}>
      <I className="mt-0.5 size-4 shrink-0" style={{ color: c }} aria-hidden />
      <span>{children}</span>
    </div>
  )
}

function StateNote({ s }: { s: LiveSession }) {
  if (s.status === 'stopped') {
    return <Note c="var(--info)" I={Square}><strong className="font-semibold">Stopped.</strong> <span className="text-text-2">The sensor stopped this session; everything it sent is analysed below.</span></Note>
  }
  if (s.status === 'completed') {
    return (
      <Note c="var(--pass)" I={CheckCircle2}>
        <strong className="font-semibold">Completed: {s.note ?? 'the session reached a cap'}.</strong>{' '}
        <span className="text-text-2">Everything it received is analysed below. Start a new session to go on.</span>
      </Note>
    )
  }
  if (s.status === 'expired') {
    return (
      <Note c="var(--medium)" I={TimerOff}>
        <strong className="font-semibold">Expired.</strong>{' '}
        <span className="text-text-2">No chunk arrived for 20 minutes, so the session closed. Start a new session to go on.</span>
      </Note>
    )
  }
  return null
}

// before the first analysed chunk: the demo sensor starting, or the agent command again
function Waiting({ id, demo, running }: { id: string; demo: boolean; running: boolean }) {
  const kept = keptSensor(id)
  if (demo) {
    return (
      <Card>
        <EmptyState icon={Hourglass} title={running || !kept ? "Waiting for the demo sensor's first slice" : 'The demo sensor is paused'}>
          {running || !kept ? 'The first 5 seconds of the recorded capture are on their way.' : 'It pauses when the page reloads. Resume it with the button above.'}
        </EmptyState>
      </Card>
    )
  }
  return (
    <Card>
      <CardHeader>
        <div><CardTitle>Waiting for the sensor's first chunk</CardTitle><CardDescription>run the agent on a machine that sees the IPsec traffic</CardDescription></div>
        <Hourglass className="size-4 text-text-2" aria-hidden />
      </CardHeader>
      <CardContent className="space-y-3">
        <CodeBlock label="on the sensor machine: download the agent, then run it as root"
          code={agentCommands(window.location.origin, id, kept?.key ?? '<sensor key>')} />
        {!kept ? <p className="text-xs text-text-2">The sensor key was shown once, to whoever created this session; this browser does not hold it.</p> : null}
        <p className="text-xs text-text-2">
          Interfaces, test traffic and troubleshooting: <Link to="/docs/live-sensor" className="text-accent hover:underline">the sensor docs</Link>.
        </p>
      </CardContent>
    </Card>
  )
}

function Alerts({ id, alerts }: { id: string; alerts: Finding[] }) {
  return (
    <Card className="mb-6">
      <CardHeader>
        <div><CardTitle>Alerts</CardTitle><CardDescription>critical and high failed checks, raised on the chunk that shows them</CardDescription></div>
        <span className="num text-xs text-text-2">{alerts.length}</span>
      </CardHeader>
      <div className="border-t border-border">
        {alerts.length ? alerts.map((f) => (
          <Link key={`${f.check_id}#${f.tunnel}`} to={`/analyses/${id}/tunnels/${f.tunnel ?? 0}`}
            className="flex items-center gap-3 border-b border-border px-5 py-3 last:border-0 hover:bg-surface-2">
            <SeverityBadge severity={f.severity} />
            <div className="min-w-0 flex-1"><p className="truncate text-sm">{f.title}</p><p className="truncate text-xs text-text-2">{f.text}</p></div>
            <span className="num shrink-0 text-xs text-muted">tunnel {f.tunnel} · {f.check_id}</span>
          </Link>
        )) : <p className="px-5 py-6 text-center text-xs text-text-2">No critical or high alert so far.</p>}
      </div>
    </Card>
  )
}

function TunnelLive({ id, t, hist }: { id: string; t: Tunnel; hist: Record<string, (number | null)[]> }) {
  const keys = shown.filter((k) => t.facts[k])
  return (
    <motion.section initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="mb-8" aria-label={`Tunnel ${t.idx}`}>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <h2 className="text-sm font-semibold">Tunnel #{t.idx}</h2>
        <span className="num text-xs text-text-2">{t.initiator ?? '?'} → {t.responder.join(', ') || '?'}</span>
        <StatusBadge status={t.handshake_status} />
        {t.risk ? <BandBadge band={t.risk.band} score={t.risk.score} /> : null}
        <Link to={`/analyses/${id}/tunnels/${t.idx}`} className="ml-auto text-xs text-accent hover:underline">Tunnel detail →</Link>
      </div>
      <Card className="mb-4">
        <CardHeader><div><CardTitle>Now</CardTitle><CardDescription>the last 10 seconds, one 2-second window per cell: ESP bytes by predicted app, and the apps present</CardDescription></div></CardHeader>
        <CardContent><NowStrip windows={t.windows ?? []} /></CardContent>
      </Card>
      <div className="grid gap-4 xl:grid-cols-3">
        <Card>
          <CardHeader><div><CardTitle>Configuration so far</CardTitle><CardDescription>cumulative facts; a line shows a confidence that changed over the chunks seen here</CardDescription></div></CardHeader>
          <CardContent className="space-y-2">
            {keys.map((k) => <FactLive key={k} name={k} f={t.facts[k]} values={hist[`${t.idx}:${k}`] ?? []} />)}
          </CardContent>
        </Card>
        <Card>
          <CardHeader><div><CardTitle>Bandwidth share so far</CardTitle><CardDescription>{num(t.esp_packets)} ESP packets</CardDescription></div></CardHeader>
          <CardContent>{t.shares.length ? <ShareBar shares={t.shares} /> : <p className="text-xs text-text-2">Waiting for ESP traffic.</p>}</CardContent>
        </Card>
        <Card>
          <CardHeader><div><CardTitle>Active time so far</CardTitle><CardDescription>share of 2-second windows each app is present in</CardDescription></div></CardHeader>
          <CardContent>{t.shares.length ? <ActiveBars shares={t.shares} /> : <p className="text-xs text-text-2">Waiting for ESP traffic.</p>}</CardContent>
        </Card>
      </div>
    </motion.section>
  )
}

function FactLive({ name, f, values }: { name: string; f: Fact; values: (number | null)[] }) {
  return (
    <div className="rounded-lg border border-border px-3 py-2">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] text-muted">{labels[name] ?? name}</span>
        <span className="flex shrink-0 gap-1.5">
          <ConfidenceBadge value={f.value === 'not determinable' ? null : f.confidence} />
          <SourceBadge source={f.source} />
        </span>
      </div>
      <div className="mt-1 flex items-center justify-between gap-3">
        <span className="num min-w-0 truncate text-xs">{factValue(f.value)}</span>
        <Trend values={values} />
      </div>
    </div>
  )
}

// confidence over the chunks seen while the page is open
function Trend({ values }: { values: (number | null)[] }) {
  const v = values.filter((x): x is number => x != null)
  // only a confidence that moved gets a line (a flat one reads as an underline)
  if (v.length < 2 || v.every((x) => x === v[0])) return null
  const w = 64
  const h = 18
  const pts = v.map((x, i) => `${((i / (v.length - 1)) * w).toFixed(1)},${(h - 1 - x * (h - 2)).toFixed(1)}`).join(' ')
  const label = `confidence ${pct(v[0])} → ${pct(v[v.length - 1])} over ${v.length} chunks`
  return (
    <Tip content={label}>
      <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} role="img" aria-label={label} className="shrink-0">
        <polyline points={pts} fill="none" stroke="var(--accent)" strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
      </svg>
    </Tip>
  )
}

// the rolling "now": the last 10 s of windows, the pairs of one window time merged
function NowStrip({ windows }: { windows: Window[] }) {
  if (!windows.length) return <p className="text-xs text-text-2">No full 2-second window yet: they appear here once ESP traffic arrives.</p>
  const tmax = Math.max(...windows.map((w) => w.t))
  const recent = windows.filter((w) => w.t > tmax - 10)
  const cells = [...new Set(recent.map((w) => w.t))].sort((x, y) => x - y).map((t) => {
    const ws = recent.filter((w) => w.t === t)
    const total = ws.reduce((acc, w) => acc + w.esp_bytes, 0)
    const by: Record<string, number> = {}
    const prob: Record<string, number> = {}
    for (const w of ws) {
      for (const [k, v] of Object.entries(w.share)) by[k] = (by[k] ?? 0) + v * w.esp_bytes
      for (const [k, v] of Object.entries(w.presence_probability)) prob[k] = Math.max(prob[k] ?? 0, v)
    }
    return { t, total, by, prob, present: [...new Set(ws.flatMap((w) => w.present))] }
  })
  return (
    <ol className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5" aria-label="The last 10 seconds, one 2-second window per cell">
      {cells.map((c) => (
        <li key={c.t} className="rounded-lg border border-border p-2.5">
          <div className="num flex justify-between text-[11px] text-muted"><span>{c.t} s</span><span>{bytes(c.total)}</span></div>
          <div className="mt-2 flex h-2.5 overflow-hidden rounded-full bg-surface-2" role="img"
            aria-label={shareNames.filter((n) => (c.by[n] ?? 0) > 0).map((n) => `${appLabel[n]} ${Math.round(((c.by[n] ?? 0) / (c.total || 1)) * 100)}%`).join(', ') || 'no bytes'}>
            {shareNames.map((n) => {
              const v = c.total ? (c.by[n] ?? 0) / c.total : 0
              return v > 0.005 ? <div key={n} style={{ width: `${v * 100}%`, background: `var(--app-${n})` }} /> : null
            })}
          </div>
          <div className="mt-2 flex min-h-5 flex-wrap gap-1">
            {c.present.length ? c.present.map((p) => (
              <span key={p} className="inline-flex items-center gap-1 rounded-md border border-border px-1.5 text-[11px] leading-5">
                <span className="size-2 rounded-sm" style={{ background: `var(--app-${p})` }} aria-hidden />
                {appLabel[p] ?? p} <span className="num text-text-2">{pct(c.prob[p] ?? 0)}</span>
              </span>
            )) : <span className="text-[11px] text-muted">no app present</span>}
          </div>
        </li>
      ))}
    </ol>
  )
}
