// the live sessions this browser created: their sensor keys, kept in localStorage so this
// browser can stop them (and show the agent command again). the server keeps only a hash.
import { useSyncExternalStore } from 'react'
import { api } from '@/lib/api'

export type Kept = { key: string; kind: 'demo' | 'agent'; demo?: string; created: number }

const storeKey = 'antar-sensors'
const memory: Record<string, Kept> = {}
const subs = new Set<() => void>()
let version = 0

export function emit() {
  version += 1
  subs.forEach((f) => f())
}

function stored(): Record<string, Kept> {
  try {
    return JSON.parse(localStorage.getItem(storeKey) || '{}')
  } catch {
    return {}
  }
}

// re-render on any change to the kept keys (and, through emit, the demo sensor)
export function useSensors() {
  return useSyncExternalStore((f) => {
    subs.add(f)
    return () => subs.delete(f)
  }, () => version)
}

export function keptSensor(id: string): Kept | null {
  return memory[id] ?? stored()[id] ?? null
}

export function keepSensor(id: string, k: Kept) {
  memory[id] = k
  try {
    localStorage.setItem(storeKey, JSON.stringify({ ...stored(), [id]: k }))
  } catch {
    // without storage the key lasts only for this page
  }
  emit()
}

// stop a session this browser created
export async function stopSession(id: string) {
  const k = keptSensor(id)
  if (!k) throw new Error('this browser does not hold the sensor key for this session')
  return api.liveStop(id, k.key)
}
