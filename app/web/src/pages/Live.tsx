import { useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Play, PlugZap, RadioTower, Square } from 'lucide-react'
import { useState, type FormEvent, type MouseEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { PageHeader } from '@/components/AppShell'
import { BandBadge, LiveBadge } from '@/components/badges'
import { CodeBlock } from '@/components/Code'
import { toast } from '@/lib/toast'
import { CardSkeleton, EmptyState, ErrorState } from '@/components/states'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { Modal } from '@/components/ui/sheet'
import { Table, Td, Th, Tr } from '@/components/ui/table'
import { ApiError, api, type LiveSession } from '@/lib/api'
import { demoLabel, demoRun, isDemoSession, startDemoSensor, stopDemoSensor } from '@/lib/demoSensor'
import { num, when } from '@/lib/format'
import { setSelectedRun } from '@/lib/run'
import { cn } from '@/lib/utils'
import { agentCommands, keepSensor, keptSensor, stopSession, useSensors } from '@/lib/sensors'

type Mode = 'demo' | 'agent'

// /live: every live session, newest first, and the two ways to start one
export function LivePage() {
  useSensors()
  const q = useQuery({ queryKey: ['live-sessions'], queryFn: api.liveSessions, refetchInterval: 5_000 })
  const [mode, setMode] = useState<Mode | null>(null)
  return (
    <>
      <PageHeader title="Live sessions"
        description="A sensor sends the outer IPsec traffic it sees in 5-second chunks, and each chunk is analysed as it arrives: facts, shares and alerts build up while you watch. Every run gets its own session."
        actions={<>
          <Button onClick={() => setMode('agent')}><PlugZap /> Connect a sensor</Button>
          <Button variant="primary" onClick={() => setMode('demo')}><Play /> Start demo sensor</Button>
        </>} />
      <p className="mb-4 text-xs text-text-2">
        All sessions are visible to everyone on this site, so send test traffic only.
      </p>
      <Card>
        {q.isLoading ? <div className="p-5"><CardSkeleton rows={4} /></div> : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} /> : q.data!.length ? (
          <Table>
            <thead><tr><Th>Session</Th><Th>Status</Th><Th className="text-right">Chunks</Th><Th>Last update</Th><Th>Risk</Th><Th /></tr></thead>
            <tbody>{q.data!.map((s) => <SessionRow key={s.id} s={s} />)}</tbody>
          </Table>
        ) : (
          <EmptyState icon={RadioTower} title="No live sessions yet">
            Start the demo sensor to watch recorded traffic arrive chunk by chunk, or connect a sensor of your own.
          </EmptyState>
        )}
      </Card>
      <NewSession mode={mode} onClose={() => setMode(null)} />
    </>
  )
}

function SessionRow({ s }: { s: LiveSession }) {
  const nav = useNavigate()
  const qc = useQueryClient()
  const [busy, setBusy] = useState(false)
  const mine = keptSensor(s.id)
  const run = demoRun(s.id)
  const demo = isDemoSession(s.id, s.name)
  const active = s.status === 'waiting' || s.status === 'live'
  const stop = async (e: MouseEvent) => {
    e.stopPropagation()
    setBusy(true)
    try {
      stopDemoSensor(s.id)
      await stopSession(s.id)
      await qc.invalidateQueries({ queryKey: ['live-sessions'] })
    } catch (err) {
      toast({ title: 'Could not stop the session', description: err instanceof Error ? err.message : String(err) })
    } finally {
      setBusy(false)
    }
  }
  return (
    <Tr className="cursor-pointer" onClick={() => nav(`/live/${s.id}`)}>
      <Td className="max-w-[360px]">
        <Link to={`/live/${s.id}`} className="block truncate hover:underline" onClick={(e) => e.stopPropagation()}>{s.name || 'Live session'}</Link>
        <div className="text-xs text-muted">
          {demo ? 'recorded traffic' : mine ? 'your sensor' : 'sensor'} · {when(s.created_at)}
          {run?.running ? <span className="num"> · slice {run.seq} of {run.steps ?? '…'}</span> : null}
        </div>
      </Td>
      <Td><LiveBadge status={s.status} /></Td>
      <Td className="num text-right">{num(s.chunks)}</Td>
      <Td className="text-xs text-text-2">{when(s.last_chunk_at ?? s.created_at)}</Td>
      <Td>{s.risk != null ? <BandBadge band={s.risk_band} score={s.risk} /> : <span className="text-xs text-muted">-</span>}</Td>
      <Td className="text-right">
        <div className="flex justify-end gap-2">
          {mine?.kind === 'demo' && active && !run?.running ? (
            <Button size="sm" onClick={(e) => { e.stopPropagation(); startDemoSensor(s.id, mine.demo ?? 'mixture', s.last_seq + 1) }}>
              <Play /> Resume
            </Button>
          ) : null}
          {mine && active ? <Button size="sm" variant="outline" disabled={busy} onClick={stop}><Square /> Stop</Button> : null}
        </div>
      </Td>
    </Tr>
  )
}

// both buttons ask for an optional session name, then create the session and keep its key
function NewSession({ mode, onClose }: { mode: Mode | null; onClose: () => void }) {
  const qc = useQueryClient()
  const demos = useQuery({ queryKey: ['demos'], queryFn: api.demos, enabled: mode === 'demo' })
  const [demo, setDemo] = useState('mixture')
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [created, setCreated] = useState<{ id: string; key: string } | null>(null)
  const nav = useNavigate()
  const close = () => {
    setName('')
    setError(null)
    setCreated(null)
    onClose()
  }
  const create = async (e: FormEvent) => {
    e.preventDefault()
    if (!mode) return
    setBusy(true)
    setError(null)
    try {
      // a demo session says so in its name, so everyone who sees it knows it is recorded traffic
      const title = demos.data?.find((d) => d.name === demo)?.title ?? demo
      const label = mode === 'demo' ? `${demoLabel}: ${name.trim() || title}` : name.trim() || null
      const s = await api.liveCreate(label)
      keepSensor(s.id, { key: s.key, kind: mode, demo: mode === 'demo' ? demo : undefined, created: Date.now() })
      setSelectedRun(s.id)
      await qc.invalidateQueries({ queryKey: ['live-sessions'] })
      if (mode === 'demo') {
        startDemoSensor(s.id, demo, 0)
        close()
        nav(`/live/${s.id}`)
      } else {
        setCreated({ id: s.id, key: s.key })
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) window.dispatchEvent(new Event('antar-need-key'))
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Modal open={mode !== null} onOpenChange={(o) => { if (!o) close() }} wide={!!created}
      title={created ? 'Connect your sensor to this session' : mode === 'demo' ? 'Start the demo sensor' : 'Connect a sensor'}>
      {created ? (
        <ConnectPanel id={created.id} sensorKey={created.key} onLeave={close}
          onOpen={() => { const id = created.id; close(); nav(`/live/${id}`) }} />
      ) : (
        <form className="space-y-4" onSubmit={create}>
          <label className="block space-y-1.5 text-xs text-text-2">
            <span>Session name (optional)</span>
            <Input value={name} maxLength={120} onChange={(e) => setName(e.target.value)} autoFocus
              placeholder={mode === 'demo' ? 'for example: lab walkthrough' : 'for example: branch office gateway'} />
          </label>
          {mode === 'demo' ? (
            <fieldset className="space-y-2">
              <legend className="mb-1.5 text-xs text-text-2">Recorded capture to feed, 5 seconds every 5 seconds</legend>
              {demos.isLoading ? <Skeleton className="h-14" /> : demos.data?.map((d) => (
                <button key={d.name} type="button" onClick={() => setDemo(d.name)} aria-pressed={demo === d.name}
                  className={cn('w-full cursor-pointer rounded-lg border p-3 text-left transition-colors',
                    demo === d.name ? 'border-accent bg-accent-soft' : 'border-border hover:bg-surface-2')}>
                  <p className="text-sm font-medium">{d.title}</p>
                  <p className="num mt-0.5 text-[11px] text-muted">{d.steps} slices of 5 s · {num(d.packets)} packets</p>
                </button>
              ))}
              <p className="text-[11px] text-muted">
                Labelled "{demoLabel}": the slices go through the same path as a real sensor's chunks, with the capture's own timestamps.
              </p>
            </fieldset>
          ) : null}
          {error ? <p role="alert" className="text-xs" style={{ color: 'var(--critical)' }}>{error}</p> : null}
          <div className="flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={close}>Cancel</Button>
            <Button type="submit" variant="primary" disabled={busy}>
              {mode === 'demo' ? <><Play /> Start</> : <><PlugZap /> Create session</>}
            </Button>
          </div>
        </form>
      )}
    </Modal>
  )
}

// shown once, right after "Connect a sensor" creates the session: the server keeps only a hash
// of the key, so this is the one time anyone sees it (this browser keeps a copy to stop it)
function ConnectPanel({ id, sensorKey, onOpen, onLeave }: { id: string; sensorKey: string; onOpen: () => void; onLeave: () => void }) {
  const origin = window.location.origin
  return (
    <div className="space-y-4">
      <div role="alert" className="flex gap-3 rounded-[12px] border px-4 py-3 text-sm"
        style={{ borderColor: 'color-mix(in oklab, var(--medium) 45%, transparent)', background: 'color-mix(in oklab, var(--medium) 10%, transparent)' }}>
        <AlertTriangle className="mt-0.5 size-4 shrink-0" style={{ color: 'var(--medium)' }} aria-hidden />
        <span>
          <strong className="font-semibold">Copy the sensor key now: it is shown only once.</strong>{' '}
          <span className="text-text-2">It lets a sensor feed this session and nothing else. The server keeps only a hash of it; this browser keeps a copy so it can stop the session.</span>
        </span>
      </div>
      <CodeBlock label="sensor key" code={sensorKey} />
      <CodeBlock label="session link" code={`${origin}/live/${id}`} />
      <CodeBlock label="on the sensor machine: download the agent, then run it as root" code={agentCommands(origin, id, sensorKey)} />
      <p className="text-xs text-text-2">
        The agent needs Python 3.8+ and tcpdump (Linux or macOS; Windows through WSL2). It captures on the default-route
        interface; add <span className="num">--iface</span> to pick another (<span className="num">--list-ifaces</span> lists them).
        Step by step, test traffic and troubleshooting: <Link to="/docs/live-sensor" className="text-accent hover:underline" onClick={onLeave}>the sensor docs</Link>.
      </p>
      <div className="flex justify-end">
        <Button variant="primary" onClick={onOpen}><RadioTower /> Open the live view</Button>
      </div>
    </div>
  )
}
