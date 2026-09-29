import type { Threat } from '@/lib/api'
import { cn } from '@/lib/utils'

// likelihood x impact grid; cell tint grows with likelihood x impact (one hue), text stays in ink
export function ThreatHeatmap({ threats, selected, onSelect }: {
  threats: Threat[]; selected: string | null; onSelect: (cell: string | null) => void
}) {
  const cell = (l: number, i: number) => threats.filter((t) => t.likelihood === l && t.impact === i)
  return (
    <div className="grid grid-cols-[28px_repeat(5,minmax(0,1fr))] gap-1.5">
      {[5, 4, 3, 2, 1].map((l) => (
        <div key={l} className="contents">
          <div className="flex items-center justify-center text-xs text-muted num">{l}</div>
          {[1, 2, 3, 4, 5].map((i) => {
            const ts = cell(l, i)
            const key = `${l}-${i}`
            const heat = (l * i) / 25
            return (
              <button
                key={key}
                type="button"
                onClick={() => onSelect(ts.length ? (selected === key ? null : key) : null)}
                disabled={!ts.length}
                aria-label={`likelihood ${l}, impact ${i}: ${ts.length ? ts.map((t) => t.threat).join(', ') : 'no threats'}`}
                className={cn('relative flex min-h-[76px] flex-col items-start justify-between rounded-lg border p-2 text-left transition-all',
                  ts.length ? 'cursor-pointer hover:brightness-110' : 'cursor-default',
                  selected === key ? 'border-text ring-2 ring-accent' : 'border-border')}
                style={{ background: `color-mix(in oklab, var(--critical) ${Math.round(6 + heat * 52)}%, var(--surface-2))` }}
              >
                <span className="num text-[11px] text-text-2">{l * i}</span>
                {ts.length ? (
                  <span className="flex min-w-0 flex-col gap-0.5">
                    <span className="num text-lg font-semibold leading-none text-text">{ts.length}</span>
                    <span className="num truncate text-[10px] leading-tight text-text" title={ts.map((t) => t.threat).join('; ')}>{ts.map((t) => t.threat_id.replace('T-', '')).join(' ')}</span>
                  </span>
                ) : null}
              </button>
            )
          })}
        </div>
      ))}
      <div />
      {[1, 2, 3, 4, 5].map((i) => (
        <div key={i} className="text-center text-xs text-muted num">{i}</div>
      ))}
      <div />
      <div className="col-span-5 text-center text-xs text-text-2">Impact →</div>
    </div>
  )
}
