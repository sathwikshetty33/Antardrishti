import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Play, PlugZap, RadioTower, Square } from 'lucide-react'
import { useState, type FormEvent, type MouseEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { PageHeader } from '@/components/AppShell'
import { BandBadge, LiveBadge } from '@/components/badges'
import { toast } from '@/lib/toast'
import { CardSkeleton, EmptyState, ErrorState } from '@/components/states'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Modal } from '@/components/ui/sheet'
import { Table, Td, Th, Tr } from '@/components/ui/table'
import { ApiError, api, type LiveSession } from '@/lib/api'
import { num, when } from '@/lib/format'
import { setSelectedRun } from '@/lib/run'
import { keepSensor, keptSensor, stopSession, useSensors } from '@/lib/sensors'

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
  const active = s.status === 'waiting' || s.status === 'live'
  const stop = async (e: MouseEvent) => {
    e.stopPropagation()
    setBusy(true)
    try {
      await stopSession(s.id)
      await qc.invalidateQueries({ queryKey: ['live-sessions'] })
    } catch (err) {
      toast({ title: 'Could not stop the session', description: err instanceof Error ? err.message : String(err) })
    } finally {
      setBusy(false)
    }
  }
  return (
    <Tr className="cursor-pointer" onClick={() => nav(`/analyses/${s.id}`)}>
      <Td className="max-w-[360px]">
        <div className="truncate">{s.name || 'Live session'}</div>
        <div className="text-xs text-muted">{mine ? 'created in this browser' : 'sensor'} · {when(s.created_at)}</div>
      </Td>
      <Td><LiveBadge status={s.status} /></Td>
      <Td className="num text-right">{num(s.chunks)}</Td>
      <Td className="text-xs text-text-2">{when(s.last_chunk_at ?? s.created_at)}</Td>
      <Td>{s.risk != null ? <BandBadge band={s.risk_band} score={s.risk} /> : <span className="text-xs text-muted">-</span>}</Td>
      <Td className="text-right">
        {mine && active ? <Button size="sm" variant="outline" disabled={busy} onClick={stop}><Square /> Stop</Button> : null}
      </Td>
    </Tr>
  )
}

// both buttons ask for an optional session name, then create the session and keep its key
function NewSession({ mode, onClose }: { mode: Mode | null; onClose: () => void }) {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const close = () => {
    setName('')
    setError(null)
    onClose()
  }
  const create = async (e: FormEvent) => {
    e.preventDefault()
    if (!mode) return
    setBusy(true)
    setError(null)
    try {
      const s = await api.liveCreate(name.trim() || null)
      keepSensor(s.id, { key: s.key, kind: mode, created: Date.now() })
      setSelectedRun(s.id)
      await qc.invalidateQueries({ queryKey: ['live-sessions'] })
      close()
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) window.dispatchEvent(new Event('antar-need-key'))
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Modal open={mode !== null} onOpenChange={(o) => { if (!o) close() }}
      title={mode === 'demo' ? 'Start the demo sensor' : 'Connect a sensor'}>
      <form className="space-y-4" onSubmit={create}>
        <label className="block space-y-1.5 text-xs text-text-2">
          <span>Session name (optional)</span>
          <Input value={name} maxLength={120} onChange={(e) => setName(e.target.value)} autoFocus
            placeholder={mode === 'demo' ? 'for example: lab walkthrough' : 'for example: branch office gateway'} />
        </label>
        {error ? <p role="alert" className="text-xs" style={{ color: 'var(--critical)' }}>{error}</p> : null}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={close}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={busy}>
            {mode === 'demo' ? <><Play /> Start</> : <><PlugZap /> Create session</>}
          </Button>
        </div>
      </form>
    </Modal>
  )
}
