import { AlertOctagon, AlertTriangle, CheckCircle2, CircleDashed, Eye, FileKey2, HelpCircle, Hourglass, Info, Radio, ShieldAlert, Sparkles, Square, TimerOff } from 'lucide-react'
import { Tip } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import { pct } from '@/lib/format'

const sevIcon = { critical: AlertOctagon, high: ShieldAlert, medium: AlertTriangle, low: Info, info: Info }

// severity never relies on colour alone: icon + label
export function SeverityBadge({ severity, className }: { severity: string; className?: string }) {
  const I = sevIcon[severity as keyof typeof sevIcon] ?? Info
  return (
    <span className={cn('chip capitalize', className)} style={{ '--c': `var(--${severity})` } as React.CSSProperties}>
      <I className="size-3.5" aria-hidden />
      {severity}
    </span>
  )
}

const verdictStyle: Record<string, { c: string; I: typeof Info; label: string }> = {
  fail: { c: 'var(--critical)', I: AlertOctagon, label: 'Fail' },
  warn: { c: 'var(--medium)', I: AlertTriangle, label: 'Warn' },
  pass: { c: 'var(--pass)', I: CheckCircle2, label: 'Pass' },
  info: { c: 'var(--info)', I: Info, label: 'Info' },
  'not determinable': { c: 'var(--muted)', I: CircleDashed, label: 'Not determinable' },
}

export function VerdictBadge({ verdict }: { verdict: string }) {
  const v = verdictStyle[verdict] ?? verdictStyle.info
  return (
    <span className="chip" style={{ '--c': v.c } as React.CSSProperties}>
      <v.I className="size-3.5" aria-hidden />
      {v.label}
    </span>
  )
}

// confidence: a percentage, "likely" below 80%, "n/d" when not determinable
export function ConfidenceBadge({ value }: { value: number | null | undefined }) {
  if (value == null) {
    return (
      <Tip content="Not determinable from this capture">
        <span className="chip" style={{ '--c': 'var(--muted)' } as React.CSSProperties}>
          <HelpCircle className="size-3.5" aria-hidden />n/d
        </span>
      </Tip>
    )
  }
  const c = value >= 0.95 ? 'var(--pass)' : value >= 0.8 ? 'var(--low)' : 'var(--medium)'
  return (
    <Tip content={value < 0.8 ? 'Below 80%: the finding is worded as "likely"' : 'Calibrated model confidence'}>
      <span className="chip num" style={{ '--c': c } as React.CSSProperties}>
        {value < 0.8 ? 'likely ' : ''}
        {pct(value)}
      </span>
    </Tip>
  )
}

const srcStyle: Record<string, { I: typeof Info; c: string; tip: string }> = {
  'read from IKE': { I: FileKey2, c: 'var(--accent)', tip: 'Read from cleartext IKE messages on the wire' },
  observed: { I: Eye, c: 'var(--low)', tip: 'Observed directly in the outer headers' },
  inferred: { I: Sparkles, c: 'var(--app-chat)', tip: 'Inferred by a model from sizes and timing (never decrypted)' },
}

export function SourceBadge({ source }: { source: string }) {
  const s = srcStyle[source] ?? srcStyle.observed
  return (
    <Tip content={s.tip}>
      <span className="chip" style={{ '--c': s.c } as React.CSSProperties}>
        <s.I className="size-3.5" aria-hidden />
        {source}
      </span>
    </Tip>
  )
}

const statusStyle: Record<string, string> = {
  done: 'var(--pass)', failed: 'var(--critical)', running: 'var(--accent)', replaying: 'var(--accent)',
  queued: 'var(--muted)', pending: 'var(--muted)', full: 'var(--pass)', 'esp-only': 'var(--low)',
  'rekey-only': 'var(--low)', 'ike-only': 'var(--medium)',
}

export function StatusBadge({ status }: { status: string }) {
  const live = status === 'running' || status === 'replaying'
  return (
    <span className="chip" style={{ '--c': statusStyle[status] ?? 'var(--info)' } as React.CSSProperties}>
      {live ? <Radio className="size-3.5 animate-pulse" aria-hidden /> : null}
      {status}
    </span>
  )
}

const liveStyle: Record<string, { c: string; I: typeof Info; label: string }> = {
  waiting: { c: 'var(--muted)', I: Hourglass, label: 'waiting' },
  live: { c: 'var(--accent)', I: Radio, label: 'LIVE' },
  stopped: { c: 'var(--info)', I: Square, label: 'stopped' },
  completed: { c: 'var(--pass)', I: CheckCircle2, label: 'completed' },
  expired: { c: 'var(--medium)', I: TimerOff, label: 'expired' },
}

// a live session's state; LIVE pulses
export function LiveBadge({ status }: { status: string }) {
  const s = liveStyle[status] ?? liveStyle.waiting
  return (
    <span className={cn('chip', status === 'live' && 'font-semibold tracking-wide')} style={{ '--c': s.c } as React.CSSProperties}>
      <s.I className={cn('size-3.5', status === 'live' && 'animate-pulse')} aria-hidden />
      {s.label}
    </span>
  )
}

export function BandBadge({ band, score }: { band: string | null | undefined; score?: number | null }) {
  const c = band === 'critical' ? 'var(--critical)' : band === 'high' ? 'var(--high)' : band === 'medium'
    ? 'var(--medium)' : band === 'low' ? 'var(--low)' : 'var(--pass)'
  return (
    <span className="chip num" style={{ '--c': c } as React.CSSProperties}>
      {score != null ? score : '-'}
      <span className="font-sans capitalize">{band ?? 'n/a'}</span>
    </span>
  )
}
