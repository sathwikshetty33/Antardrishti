import type { LucideIcon } from 'lucide-react'
import * as React from 'react'
import { Card } from '@/components/ui/card'

export function StatTile({ label, value, hint, icon: I }: { label: string; value: React.ReactNode; hint?: React.ReactNode; icon?: LucideIcon }) {
  return (
    <Card className="p-4">
      <div className="flex items-center justify-between text-xs text-text-2">
        <span>{label}</span>
        {I ? <I className="size-4 text-muted" aria-hidden /> : null}
      </div>
      <div className="mt-2 num text-xl font-semibold text-text">{value}</div>
      {hint ? <div className="mt-1 text-xs text-muted">{hint}</div> : null}
    </Card>
  )
}
