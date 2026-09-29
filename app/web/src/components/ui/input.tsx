import * as React from 'react'
import { cn } from '@/lib/utils'

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...p }, ref) => (
    <input
      ref={ref}
      className={cn('h-9 w-full rounded-lg border border-border-strong bg-surface-2 px-3 text-sm text-text placeholder:text-muted focus-visible:outline-2', className)}
      {...p}
    />
  ),
)
Input.displayName = 'Input'
