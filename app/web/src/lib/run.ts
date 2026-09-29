// the run the views follow (the top bar's switcher): a live session or an analysis id, or null
// for every run at once. kept per browser, a convenience that is safe to lose.
import { useSyncExternalStore } from 'react'

const storeKey = 'antar-run'
const subs = new Set<() => void>()
let current: string | null = read()

function read() {
  try {
    return localStorage.getItem(storeKey) || null
  } catch {
    return null
  }
}

export function selectedRun() {
  return current
}

export function setSelectedRun(id: string | null) {
  current = id
  try {
    if (id) localStorage.setItem(storeKey, id)
    else localStorage.removeItem(storeKey)
  } catch {
    // storage may be unavailable: the choice then lasts for this visit
  }
  subs.forEach((f) => f())
}

export function useSelectedRun() {
  return useSyncExternalStore((f) => {
    subs.add(f)
    return () => subs.delete(f)
  }, () => current)
}

// the run a route is about: /analyses/{id}/..., /live/{id}
export function routeRun(path: string) {
  const m = path.match(/^\/(analyses|live)\/([0-9a-f-]{36})(?:\/|$)/)
  return m ? m[2] : null
}
