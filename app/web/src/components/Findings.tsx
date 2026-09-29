import { ChevronRight } from 'lucide-react'
import { useState } from 'react'
import { ConfidenceBadge, SeverityBadge, SourceBadge, VerdictBadge } from '@/components/badges'
import { Sheet } from '@/components/ui/sheet'
import type { Finding } from '@/lib/api'
import { factValue } from '@/lib/format'

export function FindingRow({ f, onOpen, showTunnel }: { f: Finding; onOpen: () => void; showTunnel?: boolean }) {
  return (
    <button type="button" onClick={onOpen}
      className="group flex w-full items-center gap-3 border-b border-border px-4 py-3 text-left transition-colors last:border-0 hover:bg-surface-2 cursor-pointer">
      <div className="w-[140px] shrink-0">
        {f.verdict === 'fail' || f.verdict === 'warn' ? <SeverityBadge severity={f.severity} /> : <VerdictBadge verdict={f.verdict} />}
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 text-xs text-muted">
          <span className="num">{f.check_id}</span>
          {showTunnel && f.tunnel != null ? <span>· tunnel {f.tunnel}</span> : null}
        </div>
        <p className="truncate text-sm text-text">{f.text}</p>
      </div>
      <div className="hidden shrink-0 sm:block"><ConfidenceBadge value={f.confidence} /></div>
      <ChevronRight className="size-4 shrink-0 text-muted group-hover:text-text" aria-hidden />
    </button>
  )
}

export function FindingDetail({ f }: { f: Finding }) {
  return (
    <div className="space-y-5 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <VerdictBadge verdict={f.verdict} />
        <SeverityBadge severity={f.severity} />
        <ConfidenceBadge value={f.confidence} />
      </div>
      <p className="text-text">{f.text}</p>
      {f.recommendation ? (
        <div className="rounded-lg border border-border bg-surface-2 p-3">
          <p className="text-xs font-medium text-muted">Recommendation</p>
          <p className="mt-1 text-text">{f.recommendation}</p>
        </div>
      ) : null}
      <div>
        <p className="text-xs font-medium text-muted">Evidence</p>
        {f.evidence.length ? (
          <ul className="mt-2 space-y-2">
            {f.evidence.map((e, i) => (
              <li key={i} className="rounded-lg border border-border p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="num text-xs text-text-2">{e.fact}</span>
                  <SourceBadge source={e.source} />
                </div>
                <p className="mt-1 num break-words text-text">{factValue(e.value)}</p>
              </li>
            ))}
          </ul>
        ) : (
          <p className="mt-1 text-text-2">No fact in the capture supports a verdict, so none is given.</p>
        )}
      </div>
      <div>
        <p className="text-xs font-medium text-muted">Standards</p>
        <ul className="mt-1 list-disc space-y-1 pl-5 text-text-2">
          {f.standard.map((s) => <li key={s}>{s}</li>)}
        </ul>
      </div>
      {f.threats.length ? (
        <p className="text-xs text-text-2">Feeds threats: <span className="num">{f.threats.join(', ')}</span></p>
      ) : null}
    </div>
  )
}

export function FindingList({ findings, showTunnel, empty }: { findings: Finding[]; showTunnel?: boolean; empty?: string }) {
  const [open, setOpen] = useState<Finding | null>(null)
  if (!findings.length) return <p className="px-4 py-6 text-center text-xs text-text-2">{empty ?? 'No findings.'}</p>
  return (
    <>
      <div>{findings.map((f) => <FindingRow key={f.id} f={f} showTunnel={showTunnel} onOpen={() => setOpen(f)} />)}</div>
      <Sheet open={!!open} onOpenChange={(o) => !o && setOpen(null)} title={open?.title ?? ''} description={open ? `${open.check_id}${open.tunnel != null ? ` · tunnel ${open.tunnel}` : ''}` : ''}>
        {open ? <FindingDetail f={open} /> : null}
      </Sheet>
    </>
  )
}
