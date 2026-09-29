// chart styling from the css tokens, and a key that changes with the theme
import { useEffect, useState } from 'react'
import { token } from '@/lib/colors'

// re-render charts when the theme changes, so they read the new css tokens
export function useThemeKey() {
  const [k, setK] = useState(0)
  useEffect(() => {
    const f = () => setK((x) => x + 1)
    window.addEventListener('antar-theme', f)
    return () => window.removeEventListener('antar-theme', f)
  }, [])
  return k
}

export function axisStyle() {
  return {
    axisLine: { lineStyle: { color: token('border-strong') } },
    axisTick: { show: false },
    axisLabel: { color: token('muted'), fontSize: 11, fontFamily: 'JetBrains Mono Variable, monospace' },
    splitLine: { lineStyle: { color: token('grid') } },
    nameTextStyle: { color: token('muted'), fontSize: 11 },
  }
}

export function tooltipStyle() {
  return {
    backgroundColor: token('surface-3'),
    borderColor: token('border-strong'),
    textStyle: { color: token('text'), fontSize: 12 },
    extraCssText: 'border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.25);',
  }
}

