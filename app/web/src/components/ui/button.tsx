import { Slot } from '@radix-ui/react-slot'
import { cva, type VariantProps } from 'class-variance-authority'
import * as React from 'react'
import { cn } from '@/lib/utils'

const variants = cva(
  'inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-lg text-sm font-medium transition-all duration-300 active:scale-95 disabled:pointer-events-none disabled:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0 cursor-pointer',
  {
    variants: {
      variant: {
        primary: 'bg-accent text-accent-ink shadow-md shadow-accent/20 hover:shadow-lg hover:shadow-accent/40 hover:-translate-y-0.5 hover:brightness-110',
        secondary: 'bg-surface-2/80 text-text border border-border/50 backdrop-blur-md hover:bg-surface-3 hover:-translate-y-0.5 hover:shadow-md',
        ghost: 'text-text-2 hover:bg-surface-2/50 hover:text-text',
        outline: 'border border-border-strong/50 text-text hover:bg-surface-2/80 backdrop-blur-md hover:-translate-y-0.5',
        danger: 'bg-critical text-white shadow-md shadow-critical/20 hover:shadow-lg hover:shadow-critical/40 hover:-translate-y-0.5 hover:brightness-110',
      },
      size: { sm: 'h-8 px-3 text-xs', md: 'h-9 px-4', lg: 'h-11 px-5 text-base', icon: 'size-9' },
    },
    defaultVariants: { variant: 'secondary', size: 'md' },
  },
)

export type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> &
  VariantProps<typeof variants> & { asChild?: boolean }

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const C = asChild ? Slot : 'button'
    return <C ref={ref} className={cn(variants({ variant, size }), className)} {...props} />
  },
)
Button.displayName = 'Button'
