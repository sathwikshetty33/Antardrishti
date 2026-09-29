// dark first; the choice is kept per browser (a convenience, safe to lose)
export type Theme = 'dark' | 'light'

export function currentTheme(): Theme {
  return document.documentElement.dataset.theme === 'light' ? 'light' : 'dark'
}

// the phone browser's toolbar follows the page background (index.html sets it before the first paint)
function toolbar(t: Theme) {
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', t === 'light' ? '#f8fafc' : '#000000')
}

export function setTheme(t: Theme) {
  document.documentElement.dataset.theme = t
  toolbar(t)
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
  toolbar(t)
}
