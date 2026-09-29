import * as React from 'react'
import { cn } from '@/lib/utils'

export function Card({ className, ...p }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('rounded-[16px] border border-accent/40 bg-black/60 shadow-[0_0_15px_rgba(20,184,166,0.1)] backdrop-blur-3xl backdrop-saturate-150 transition-all duration-300 hover:shadow-[0_0_25px_rgba(20,184,166,0.25)] hover:border-accent/80 hover:bg-black/50 hover:-translate-y-1', className)} {...p} />
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
