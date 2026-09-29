import { motion } from 'framer-motion'
import { Tip } from '@/components/ui/tooltip'
import type { Share } from '@/lib/api'
import { appLabel, shareNames } from '@/lib/colors'
import { errorBar, round100 } from '@/lib/format'

// session byte share: one bar totalling 100% (largest-remainder rounding), unknown explicit,
// and per-app error bars (out-of-fold session error), clipped to 0-100
export function ShareBar({ shares }: { shares: Share[] }) {
  const by = Object.fromEntries(shares.map((s) => [s.app, s]))
  const rounded = round100(Object.fromEntries(shareNames.map((n) => [n, by[n]?.byte_share ?? 0])))
  const shown = shareNames.filter((n) => rounded[n] > 0)
  return (
    <div className="space-y-5">
      <div className="flex h-9 w-full overflow-hidden rounded-lg border border-border" role="img"
        aria-label={`Byte share: ${shown.map((n) => `${appLabel[n]} ${rounded[n]}%`).join(', ')}`}>
        {shown.map((n, i) => (
          <Tip key={n} content={`${appLabel[n]}: ${rounded[n]}% of ESP bytes`}>
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${rounded[n]}%` }}
              transition={{ duration: 0.5, delay: i * 0.04 }}
              className="flex h-full items-center justify-center text-xs font-medium text-white"
              style={{ background: `var(--app-${n})`, borderRight: i < shown.length - 1 ? '2px solid var(--surface)' : undefined,
                backgroundImage: n === 'unknown' ? 'repeating-linear-gradient(45deg, transparent 0 6px, rgb(255 255 255 / .12) 6px 12px)' : undefined }}
            >
              {rounded[n] >= 7 ? `${rounded[n]}%` : ''}
            </motion.div>
          </Tip>
        ))}
      </div>
      <div className="space-y-2.5">
        {shareNames.map((n) => {
          const s = by[n]
          const v = s?.byte_share ?? 0
          const eb = errorBar(v, s?.error_pp)
          return (
            <div key={n} className="grid grid-cols-[110px_1fr_92px] items-center gap-3 text-xs">
              <span className="flex items-center gap-2 text-text-2">
                <span className="size-2.5 rounded-sm" style={{ background: `var(--app-${n})` }} aria-hidden />
                {appLabel[n]}
              </span>
              <div className="relative h-5">
                <div className="absolute inset-y-2 left-0 right-0 rounded-full bg-surface-2" />
                <motion.div className="absolute inset-y-1.5 left-0 rounded-full" initial={{ width: 0 }} animate={{ width: `${v}%` }}
                  transition={{ duration: 0.5 }} style={{ background: `var(--app-${n})`, opacity: 0.9 }} />
                {eb ? (
                  <Tip content={`± ${s?.error_pp?.toFixed(1)} pp (out-of-fold session error for this share range), clipped to 0-100`}>
                    <div className="absolute inset-y-0" style={{ left: `${eb[0]}%`, width: `${Math.max(0.6, eb[1] - eb[0])}%` }}>
                      <div className="absolute inset-y-[9px] left-0 right-0 border-t border-text-2" />
                      <div className="absolute inset-y-1 left-0 border-l border-text-2" />
                      <div className="absolute inset-y-1 right-0 border-r border-text-2" />
                    </div>
                  </Tip>
                ) : null}
              </div>
              <span className="num text-right text-text">
                {rounded[n]}%{s?.error_pp != null && n !== 'unknown' ? <span className="text-muted"> ±{Math.round(s.error_pp)}</span> : null}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// active-time share: separate bars per app; apps overlap in time, so they need not sum to 100
export function ActiveBars({ shares }: { shares: Share[] }) {
  const rows = shares.filter((s) => s.app !== 'unknown')
  return (
    <div className="space-y-2.5">
      {rows.map((s) => {
        const v = Math.max(0, Math.min(100, s.active_share ?? 0))
        return (
          <div key={s.app} className="grid grid-cols-[110px_1fr_48px] items-center gap-3 text-xs">
            <span className="text-text-2">{appLabel[s.app]}</span>
            <div className="h-2.5 rounded-full bg-surface-2">
              <motion.div className="h-full rounded-full" initial={{ width: 0 }} animate={{ width: `${v}%` }}
                transition={{ duration: 0.5 }} style={{ background: `var(--app-${s.app})` }} />
            </div>
            <span className="num text-right">{s.active_rounded ?? Math.round(v)}%</span>
          </div>
        )
      })}
      <p className="pt-1 text-xs text-muted">
        Share of 2-second windows in which each app is present. Apps overlap in time, so these bars do not add up to 100%.
      </p>
    </div>
  )
}
