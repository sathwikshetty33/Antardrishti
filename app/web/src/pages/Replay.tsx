import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { Pause, Play, RotateCcw, History } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { PageHeader } from '@/components/AppShell'
import { BandBadge, ConfidenceBadge, SourceBadge, StatusBadge } from '@/components/badges'
import { Chart } from '@/components/Chart'
import { axisStyle, tooltipStyle } from '@/lib/chart'
import { ShareBar } from '@/components/ShareBar'
import { ErrorState } from '@/components/states'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Skeleton } from '@/components/ui/skeleton'
import { ApiError, api, type Analysis, type Finding, type Tunnel } from '@/lib/api'
import { token } from '@/lib/colors'
import { factValue, num } from '@/lib/format'
import { cn } from '@/lib/utils'

type Point = { t: number; suite: number | null; mode: number | null; presence: number | null; score: number | null; findings: number }

export function ReplayPage() {
  const demos = useQuery({ queryKey: ['demos'], queryFn: api.demos })
  const [demo, setDemo] = useState<string>('whatsapp')
  const [run, setRun] = useState<Analysis | null>(null)
  const [tunnel, setTunnel] = useState<Tunnel | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [hist, setHist] = useState<Point[]>([])
  const [playing, setPlaying] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const busy = useRef(false)

  const reset = () => { setRun(null); setTunnel(null); setFindings([]); setHist([]); setPlaying(false); setError(null) }

  const start = async () => {
    reset()
    try {
      const a = await api.replayStart(demo)
      setRun(a)
      setPlaying(true)
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) window.dispatchEvent(new Event('antar-need-key'))
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  useEffect(() => {
    if (!playing || !run || (run.replay && run.replay.step >= run.replay.steps)) return
    const h = setTimeout(async () => {
      if (busy.current) return
      busy.current = true
      try {
        const a = await api.replayNext(run.id)
        const [ts, fs] = await Promise.all([api.tunnels(a.id), api.findings(a.id)])
        const main = [...ts].sort((x, y) => y.esp_packets - x.esp_packets)[0] ?? null
        const det = main ? await api.tunnel(a.id, main.idx) : null
        const ws = det?.windows ?? []
        const top = det?.shares.filter((s) => s.app !== 'unknown').sort((x, y) => y.byte_share - x.byte_share)[0]
        const presence = top && ws.length ? ws.filter((w) => w.present.includes(top.app)).reduce((acc, w) => acc + w.presence_probability[top.app], 0) /
          Math.max(1, ws.filter((w) => w.present.includes(top.app)).length) : null
        setRun(a)
        if (a.replay && a.replay.step >= a.replay.steps) setPlaying(false)
        setTunnel(det)
        setFindings(fs)
        setHist((hh) => [...hh, {
          t: a.replay?.t ?? 0, suite: main?.facts.esp_suite?.confidence ?? null, mode: main?.facts.mode?.confidence ?? null,
          presence, score: a.risk, findings: fs.filter((f) => f.verdict === 'fail' || f.verdict === 'warn').length,
        }])
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e))
        setPlaying(false)
      } finally {
        busy.current = false
      }
    }, 700)
    return () => clearTimeout(h)
  }, [playing, run])

  const r = run?.replay
  const ax = axisStyle()
  const line = (name: string, key: keyof Point, color: string) => ({
    name, type: 'line', showSymbol: true, symbolSize: 6, lineStyle: { width: 2, color }, itemStyle: { color },
    data: hist.map((p) => (p[key] == null ? null : +(p[key] as number).toFixed(3))),
  })
  const option = {
    tooltip: { trigger: 'axis', ...tooltipStyle(), valueFormatter: (v: number) => (v == null ? '-' : `${Math.round(v * 100)}%`) },
    legend: { top: 0, textStyle: { color: token('text-2'), fontSize: 11 } },
    grid: { left: 48, right: 16, top: 34, bottom: 28 },
    xAxis: { type: 'category', data: hist.map((p) => `${p.t}s`), ...ax },
    yAxis: { type: 'value', min: 0, max: 1, ...ax, axisLabel: { ...ax.axisLabel, formatter: (v: number) => `${v * 100}%` } },
    series: [line('ESP suite confidence', 'suite', token('accent')), line('Mode confidence', 'mode', token('low')), line('Top app presence', 'presence', token('app-chat'))],
  }
  const facts = tunnel ? (['handshake_status', 'ike_version', 'ike_dh', 'esp_suite', 'mode', 'pfs'] as const).filter((k) => tunnel.facts[k]) : []
  return (
    <>
      <PageHeader title="Demo replay"
        description="Live capture can't run on a serverless host, so this replays a stored test capture. Each step sends the next 5 seconds of packets to the API, which keeps the evidence in Postgres and re-analyses everything received so far." />
      <div role="note" className="mb-4 flex items-center gap-3 rounded-[12px] border px-4 py-3 text-sm"
        style={{ borderColor: 'color-mix(in oklab, var(--medium) 45%, transparent)', background: 'color-mix(in oklab, var(--medium) 10%, transparent)' }}>
        <History className="size-4 shrink-0" style={{ color: 'var(--medium)' }} aria-hidden />
        <span><strong className="font-semibold">Replay, not live traffic.</strong> <span className="text-text-2">Recorded packets are replayed in 5-second chunks; timestamps are the capture's own.</span></span>
      </div>
      <div className="grid gap-4 xl:grid-cols-3">
        <Card>
          <CardHeader><div><CardTitle>Choose a demo</CardTitle><CardDescription>test-split captures</CardDescription></div></CardHeader>
          <CardContent className="space-y-2">
            {demos.isLoading ? [0, 1, 2].map((i) => <Skeleton key={i} className="h-14" />) : demos.data?.map((d) => (
              <button key={d.name} type="button" onClick={() => setDemo(d.name)} disabled={playing}
                aria-pressed={demo === d.name}
                className={cn('w-full rounded-lg border p-3 text-left transition-colors cursor-pointer disabled:opacity-60',
                  demo === d.name ? 'border-accent bg-accent-soft' : 'border-border hover:bg-surface-2')}>
                <p className="text-sm font-medium">{d.title}</p>
                <p className="mt-0.5 num text-[11px] text-muted">{d.steps} steps · {num(d.packets)} packets</p>
              </button>
            ))}
            <div className="flex gap-2 pt-2">
              {!run || (r && r.step >= r.steps) ? (
                <Button variant="primary" className="flex-1" onClick={start}><Play /> Start replay</Button>
              ) : playing ? (
                <Button className="flex-1" onClick={() => setPlaying(false)}><Pause /> Pause</Button>
              ) : (
                <Button variant="primary" className="flex-1" onClick={() => setPlaying(true)}><Play /> Resume</Button>
              )}
              <Button variant="ghost" size="icon" aria-label="Reset" onClick={reset}><RotateCcw /></Button>
            </div>
            {r ? (
              <div className="space-y-2 pt-2">
                <div className="flex justify-between text-xs text-text-2"><span>step {r.step} of {r.steps}</span><span className="num">{r.t}s · {num(r.packets)} packets</span></div>
                <Progress value={(r.step / Math.max(1, r.steps)) * 100} label="replay progress" />
              </div>
            ) : null}
            {error ? <ErrorState error={error} /> : null}
            {run && r && r.step >= r.steps ? <Link to={`/analyses/${run.id}`} className="block pt-1 text-xs text-accent hover:underline">Open the full analysis →</Link> : null}
          </CardContent>
        </Card>
        <Card className="xl:col-span-2">
          <CardHeader><div><CardTitle>Confidence as evidence accumulates</CardTitle><CardDescription>calibrated confidence after each 5 s chunk</CardDescription></div>
            {run ? <StatusBadge status={run.status} /> : null}</CardHeader>
          <CardContent>
            {hist.length ? <Chart option={option} height={260} label="Confidence over replay time" /> :
              <div className="flex h-[260px] items-center justify-center text-xs text-text-2">Start a replay to watch the evidence build up.</div>}
          </CardContent>
        </Card>
      </div>
      {tunnel ? (
        <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="mt-4 grid gap-4 xl:grid-cols-3">
          <Card>
            <CardHeader><div><CardTitle>Tunnel #{tunnel.idx}</CardTitle><CardDescription className="num">{tunnel.initiator} → {tunnel.responder.join(', ')}</CardDescription></div>
              {run?.risk != null ? <BandBadge band={run.risk_band} score={run.risk} /> : null}</CardHeader>
            <CardContent className="space-y-2">
              {facts.map((k) => (
                <div key={k} className="flex items-center justify-between gap-2 rounded-lg border border-border px-3 py-2">
                  <div className="min-w-0"><div className="text-[11px] text-muted">{k.replace(/_/g, ' ')}</div><div className="num truncate text-xs">{factValue(tunnel.facts[k].value)}</div></div>
                  <div className="flex shrink-0 gap-1.5"><ConfidenceBadge value={tunnel.facts[k].value === 'not determinable' ? null : tunnel.facts[k].confidence} /><SourceBadge source={tunnel.facts[k].source} /></div>
                </div>
              ))}
            </CardContent>
          </Card>
          <Card>
            <CardHeader><div><CardTitle>Bandwidth share so far</CardTitle><CardDescription>{num(tunnel.esp_packets)} ESP packets received</CardDescription></div></CardHeader>
            <CardContent>{tunnel.shares.length ? <ShareBar shares={tunnel.shares} /> : <p className="text-xs text-text-2">Waiting for ESP traffic.</p>}</CardContent>
          </Card>
          <Card>
            <CardHeader><div><CardTitle>Findings so far</CardTitle><CardDescription>{hist.at(-1)?.findings ?? 0} failed or warning checks</CardDescription></div></CardHeader>
            <div className="border-t border-border">
              {findings.filter((f) => f.verdict === 'fail' || f.verdict === 'warn').slice(0, 6).map((f) => (
                <div key={f.id} className="border-b border-border px-5 py-2.5 last:border-0">
                  <div className="flex items-center gap-2"><span className="num text-[11px] text-muted">{f.check_id}</span></div>
                  <p className="text-xs">{f.text}</p>
                </div>
              ))}
              {!findings.some((f) => f.verdict === 'fail' || f.verdict === 'warn') ? <p className="px-5 py-6 text-center text-xs text-text-2">None yet.</p> : null}
            </div>
          </Card>
        </motion.div>
      ) : null}
    </>
  )
}
