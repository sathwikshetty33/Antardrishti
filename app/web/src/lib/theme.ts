// dark first; the choice is kept per browser (a convenience, safe to lose)
export type Theme = 'dark' | 'light'

export function currentTheme(): Theme {
  return document.documentElement.dataset.theme === 'light' ? 'light' : 'dark'
}

export function setTheme(t: Theme) {
  document.documentElement.dataset.theme = t
  try {
    localStorage.setItem('antar-theme', t)
  } catch {
    // storage may be unavailable (private mode): the theme still applies for this visit
  }
  window.dispatchEvent(new CustomEvent('antar-theme', { detail: t }))
}

export function initTheme() {
  let t: Theme = 'dark'
  try {
    if (localStorage.getItem('antar-theme') === 'light') t = 'light'
  } catch {
    // ignore
  }
  document.documentElement.dataset.theme = t
}
