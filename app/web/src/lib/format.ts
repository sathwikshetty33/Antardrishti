// number formatting shared by every view (app/CLAUDE.md section 8, "numbers")

// largest-remainder rounding of percentages to integers that sum to 100
export function round100(values: Record<string, number>): Record<string, number> {
  const keys = Object.keys(values)
  const v = keys.map((k) => Math.max(0, values[k] || 0))
  const total = v.reduce((a, b) => a + b, 0)
  if (total <= 0) return Object.fromEntries(keys.map((k) => [k, 0]))
  const scaled = v.map((x) => (x / total) * 100)
  const floor = scaled.map(Math.floor)
  let rest = 100 - floor.reduce((a, b) => a + b, 0)
  const order = scaled.map((x, i) => [x - floor[i], i] as const).sort((a, b) => b[0] - a[0] || a[1] - b[1])
  for (const [, i] of order) {
    if (rest <= 0) break
    floor[i] += 1
    rest -= 1
  }
  return Object.fromEntries(keys.map((k, i) => [k, floor[i]]))
}

// an error bar around a share, clipped to 0-100
export function errorBar(share: number, err: number | null | undefined): [number, number] | null {
  if (err == null || Number.isNaN(err)) return null
  return [Math.max(0, share - err), Math.min(100, share + err)]
}

export function pct(x: number | null | undefined, digits = 0) {
  if (x == null || Number.isNaN(x)) return '-'
  return `${(x * 100).toFixed(digits)}%`
}

export function confidenceLabel(c: number | null | undefined) {
  if (c == null) return 'not determinable'
  return c < 0.8 ? `likely · ${pct(c)}` : pct(c)
}

export function bytes(n: number | null | undefined) {
  if (n == null) return '-'
  const u = ['B', 'KB', 'MB', 'GB']
  let i = 0
  let x = n
  while (x >= 1024 && i < u.length - 1) {
    x /= 1024
    i += 1
  }
  return `${x.toFixed(x >= 100 || i === 0 ? 0 : 1)} ${u[i]}`
}

export function num(n: number | null | undefined) {
  return n == null ? '-' : n.toLocaleString('en-US')
}

export function seconds(s: number | null | undefined) {
  if (s == null) return '-'
  if (s < 60) return `${s.toFixed(s < 10 ? 1 : 0)} s`
  return `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`
}

export function when(iso: string | null | undefined) {
  if (!iso) return '-'
  const d = new Date(iso)
  const diff = (Date.now() - d.getTime()) / 1000
  if (diff < 60) return 'just now'
  if (diff < 3600) return `${Math.floor(diff / 60)} min ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)} h ago`
  return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })
}

export function factValue(v: unknown): string {
  if (v == null) return '-'
  if (typeof v === 'boolean') return v ? 'yes' : 'no'
  if (typeof v === 'number') return Number.isInteger(v) ? v.toLocaleString('en-US') : v.toFixed(3)
  if (Array.isArray(v)) return v.length ? v.join(', ') : 'none'
  if (typeof v === 'object') {
    return Object.entries(v as Record<string, unknown>)
      .map(([k, x]) => `${k}: ${Array.isArray(x) ? (x.length ? x.join(', ') : 'none') : String(x)}`)
      .join(' · ')
  }
  return String(v)
}
