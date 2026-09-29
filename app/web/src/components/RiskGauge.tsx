import { motion } from 'framer-motion'

const bandOf = (s: number) => (s >= 90 ? 'critical' : s >= 60 ? 'high' : s >= 30 ? 'medium' : s > 0 ? 'low' : 'none')
const colorOf = (b: string) => (b === 'none' ? 'var(--pass)' : `var(--${b})`)

// a semicircle 0-100 risk gauge (svg: crisp in print, readable in both themes)
export function RiskGauge({ score, size = 220, caption }: { score: number | null | undefined; size?: number; caption?: string }) {
  const s = score ?? 0
  const band = bandOf(s)
  const r = 80
  const len = Math.PI * r
  const frac = Math.max(0, Math.min(1, s / 100))
  return (
    <div className="flex flex-col items-center" role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={score ?? undefined}
      aria-label={`Risk score ${score ?? 'not available'} of 100, ${band}`}>
      <svg width={size} height={size * 0.62} viewBox="0 0 200 124">
        <path d="M 20 110 A 80 80 0 0 1 180 110" fill="none" stroke="var(--surface-3)" strokeWidth="14" strokeLinecap="round" />
        <motion.path
          d="M 20 110 A 80 80 0 0 1 180 110"
          fill="none"
          stroke={colorOf(band)}
          strokeWidth="14"
          strokeLinecap="round"
          strokeDasharray={len}
          initial={{ strokeDashoffset: len }}
          animate={{ strokeDashoffset: len * (1 - frac) }}
          transition={{ duration: 0.8, ease: 'easeOut' }}
        />
        {[30, 60, 90].map((t) => {
          const a = Math.PI * (1 - t / 100)
          return <line key={t} x1={100 + 66 * Math.cos(a)} y1={110 - 66 * Math.sin(a)} x2={100 + 72 * Math.cos(a)}
            y2={110 - 72 * Math.sin(a)} stroke="var(--border-strong)" strokeWidth="2" />
        })}
        <text x="100" y="98" textAnchor="middle" className="num" fontSize="44" fontWeight="600" fill="var(--text)">
          {score == null ? '–' : s}
        </text>
        <text x="100" y="120" textAnchor="middle" fontSize="12" fill="var(--text-2)" style={{ textTransform: 'capitalize' }}>
          {score == null ? 'no analysis yet' : `${band} risk`}
        </text>
      </svg>
      {caption ? <p className="mt-1 text-center text-xs text-muted">{caption}</p> : null}
    </div>
  )
}
