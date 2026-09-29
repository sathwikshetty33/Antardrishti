// transient notifications (live alerts): toast() from anywhere, <Toaster /> once in the shell
import { useSyncExternalStore } from 'react'

export type Toast = { id: number; title: string; description?: string; severity?: string }

let items: Toast[] = []
let next = 1
const subs = new Set<() => void>()
const emit = () => subs.forEach((f) => f())

export function toast(t: Omit<Toast, 'id'>, ms = 8000) {
  const id = next++
  items = [...items, { ...t, id }].slice(-4)
  emit()
  setTimeout(() => dismiss(id), ms)
  return id
}

export function dismiss(id: number) {
  items = items.filter((t) => t.id !== id)
  emit()
}

export function useToasts() {
  return useSyncExternalStore((f) => {
    subs.add(f)
    return () => subs.delete(f)
  }, () => items)
}
