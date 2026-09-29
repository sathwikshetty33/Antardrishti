import * as P from '@radix-ui/react-progress'
import { cn } from '@/lib/utils'

export function Progress({ value, className, label }: { value: number; className?: string; label?: string }) {
  const v = Math.max(0, Math.min(100, value))
  return (
    <P.Root value={v} aria-label={label} className={cn('relative h-2 w-full overflow-hidden rounded-full bg-surface-3', className)}>
      <P.Indicator className="h-full bg-accent transition-[width] duration-300 ease-out" style={{ width: `${v}%` }} />
    </P.Root>
  )
}
