import { AlertCircle, Inbox, RefreshCw } from 'lucide-react'
import * as React from 'react'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'

export function EmptyState({ icon: I = Inbox, title, children, action }: {
  icon?: typeof Inbox; title: string; children?: React.ReactNode; action?: React.ReactNode
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-12 text-center">
      <div className="rounded-full border border-border bg-surface-2 p-3 text-text-2">
        <I className="size-5" aria-hidden />
      </div>
      <div>
        <p className="text-sm font-medium text-text">{title}</p>
        {children ? <div className="mt-1 max-w-md text-xs text-text-2">{children}</div> : null}
      </div>
      {action}
    </div>
  )
}

export function ErrorState({ error, retry }: { error: unknown; retry?: () => void }) {
  const msg = error instanceof Error ? error.message : String(error)
  return (
    <div role="alert" className="flex flex-col items-center gap-3 px-6 py-10 text-center">
      <div className="rounded-full p-3" style={{ background: 'color-mix(in oklab, var(--critical) 14%, transparent)', color: 'var(--critical)' }}>
        <AlertCircle className="size-5" aria-hidden />
      </div>
      <div>
        <p className="text-sm font-medium">Something went wrong</p>
        <p className="mt-1 max-w-md text-xs text-text-2 break-words">{msg}</p>
      </div>
      {retry ? (
        <Button size="sm" onClick={retry}>
          <RefreshCw /> Try again
        </Button>
      ) : null}
    </div>
  )
}

export function CardSkeleton({ rows = 4, className }: { rows?: number; className?: string }) {
  return (
    <Card className={className}>
      <div className="space-y-3 p-5">
        <Skeleton className="h-4 w-40" />
        {Array.from({ length: rows }).map((_, i) => (
          <Skeleton key={i} className="h-3.5" />
        ))}
      </div>
    </Card>
  )
}
