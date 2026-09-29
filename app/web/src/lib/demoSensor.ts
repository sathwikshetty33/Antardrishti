// the demo sensor: feeds a live session the next 5 s slice of a stored demo capture every 5 s
// (POST /api/live/{id}/demo-next, the same ingest path as a real sensor's chunks) until the
// capture ends or it is stopped. the loop lives outside any page, so it keeps running while
// you browse the other views; a reload pauses it (resume from the session's next sequence).
import { ApiError, api, type LiveChunk } from '@/lib/api'
import { emit, keptSensor } from '@/lib/sensors'

export type DemoRun = { running: boolean; demo: string; seq: number; steps: number | null; error: string | null; last: LiveChunk | null }

export const demoLabel = 'Demo sensor (recorded traffic)'
const runs: Record<string, DemoRun> = {}
const timers: Record<string, ReturnType<typeof setTimeout>> = {}

export function isDemoSession(id: string, name: string) {
  return keptSensor(id)?.kind === 'demo' || name.startsWith(demoLabel)
}

export function demoRun(id: string): DemoRun | null {
  return runs[id] ?? null
}

export function startDemoSensor(id: string, demo: string, seq: number) {
  if (runs[id]?.running) return
  runs[id] = { running: true, demo, seq, steps: runs[id]?.steps ?? null, error: null, last: runs[id]?.last ?? null }
  emit()
  void tick(id)
}

// stops the loop only; stopping the session itself is stopSession (lib/sensors.ts)
export function stopDemoSensor(id: string) {
  clearTimeout(timers[id])
  if (runs[id]) {
    runs[id].running = false
    emit()
  }
}

async function tick(id: string) {
  const r = runs[id]
  const k = keptSensor(id)
  if (!r?.running || !k) return
  const t0 = Date.now()
  let wait = 5000
  try {
    const res = await api.liveDemoNext(id, k.key, r.demo, r.seq)
    r.last = res
    r.seq = res.last_seq + 1
    r.steps = res.demo?.steps ?? r.steps
    // the last slice completes the session (and so do the caps): the loop ends with it
    if (res.status !== 'live') r.running = false
  } catch (e) {
    if (e instanceof ApiError && e.status === 429) {
      wait = 1000
    } else if (e instanceof ApiError && e.status === 409) {
      // out of order (another tab fed it too): continue from the server's sequence number
      wait = 1000
      try {
        r.seq = (await api.liveSession(id)).last_seq + 1
      } catch {
        // tried again on the next tick
      }
    } else {
      r.error = e instanceof Error ? e.message : String(e)
      r.running = false
    }
  }
  emit()
  if (r.running) timers[id] = setTimeout(() => void tick(id), Math.max(0, wait - (Date.now() - t0)))
}
