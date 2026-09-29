import * as T from '@radix-ui/react-tabs'
import * as React from 'react'
import { cn } from '@/lib/utils'

export const Tabs = T.Root

export function TabsList({ className, ...p }: React.ComponentProps<typeof T.List>) {
  return <T.List className={cn('inline-flex h-9 items-center gap-1 rounded-lg border border-border bg-surface-2 p-1', className)} {...p} />
}

export function TabsTrigger({ className, ...p }: React.ComponentProps<typeof T.Trigger>) {
  return (
    <T.Trigger
      className={cn(
        'inline-flex h-7 items-center rounded-md px-3 text-xs font-medium text-text-2 transition-colors hover:text-text data-[state=active]:bg-surface data-[state=active]:text-text data-[state=active]:shadow-sm cursor-pointer',
        className,
      )}
      {...p}
    />
  )
}

export const TabsContent = T.Content
