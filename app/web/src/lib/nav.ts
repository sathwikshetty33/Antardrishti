// the sidebar's collapsed state, kept per browser (a convenience, safe to lose). with no stored
// choice it follows the width: icons only below 1280 px (app/CLAUDE.md section 8)
import { useState } from 'react'

const storeKey = 'antar-nav'

function initial() {
  try {
    const v = localStorage.getItem(storeKey)
    if (v) return v === 'collapsed'
  } catch {
    // storage may be unavailable: fall back to the width
  }
  return window.matchMedia('(max-width: 1279px)').matches
}

export function useNavCollapsed() {
  const [c, setC] = useState(initial)
  const toggle = () => {
    const n = !c
    setC(n)
    try {
      localStorage.setItem(storeKey, n ? 'collapsed' : 'expanded')
    } catch {
      // the choice then lasts for this visit
    }
  }
  return [c, toggle] as const
}
