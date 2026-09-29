import * as React from 'react'
import { cn } from '@/lib/utils'

export function Card({ className, ...p }: React.HTMLAttributes<HTMLDivElement>) {
  // glass over the page grid, from the theme tokens; min-w-0 lets a card shrink in a grid or flex
  // track (a wide table then scrolls inside it instead of widening the page). the heavy blur
  // only from md up: every card blurs what is behind it, which phones pay for on each scroll
  return <div className={cn('min-w-0 rounded-[16px] border border-edge bg-glass shadow-glow backdrop-blur-md backdrop-saturate-150 transition-all duration-300 hover:-translate-y-1 hover:border-edge-strong hover:bg-glass-hover hover:shadow-glow-hover md:backdrop-blur-3xl', className)} {...p} />
}

export function CardHeader({ className, ...p }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('flex items-start justify-between gap-4 px-5 pt-4 pb-3', className)} {...p} />
}

export function CardTitle({ className, ...p }: React.HTMLAttributes<HTMLHeadingElement>) {
  return <h2 className={cn('text-sm font-semibold tracking-tight text-text', className)} {...p} />
}

export function CardDescription({ className, ...p }: React.HTMLAttributes<HTMLParagraphElement>) {
  return <p className={cn('mt-0.5 text-xs text-text-2', className)} {...p} />
}

export function CardContent({ className, ...p }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('px-5 pb-5', className)} {...p} />
}
