import { useEffect, useState } from 'react'
import { currentTheme, type Theme } from '@/lib/theme'
import { cn } from '@/lib/utils'

// the brand assets (app/web/brand, derived by scripts/brand.py): the mark for the shell and the
// full lockup, light or dark to match the theme (the dark one has a transparent background)
export function BrandMark({ className }: { className?: string }) {
  return <img src="/brand/mark-128.png" alt="" aria-hidden width={32} height={32} className={cn('size-8 shrink-0 select-none', className)} draggable={false} />
}

function useTheme() {
  const [t, setT] = useState<Theme>(currentTheme())
  useEffect(() => {
    const f = () => setT(currentTheme())
    window.addEventListener('antar-theme', f)
    return () => window.removeEventListener('antar-theme', f)
  }, [])
  return t
}

export function BrandLogo({ className, variant }: { className?: string; variant?: Theme }) {
  const theme = useTheme()
  const t = variant ?? theme
  return (
    <img
      src={t === 'light' ? '/brand/logo-light.png' : '/brand/logo-dark.png'}
      alt="Antardrishti: see inside the tunnel"
      width={720}
      height={675}
      className={cn('h-auto select-none', className)}
      draggable={false}
    />
  )
}
