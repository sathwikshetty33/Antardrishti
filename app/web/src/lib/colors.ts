// app and severity colours: read from the css tokens so charts follow the theme
export const apps = ['voip', 'video', 'web', 'email', 'icmp', 'bulk', 'chat'] as const
export type App = (typeof apps)[number]
export const shareNames = [...apps, 'unknown'] as const

export const appLabel: Record<string, string> = {
  voip: 'VoIP', video: 'Video', web: 'Web', email: 'Email', icmp: 'ICMP', bulk: 'Bulk transfer', chat: 'Chat',
  unknown: 'Unknown',
}

export const severities = ['critical', 'high', 'medium', 'low', 'info'] as const
export type Severity = (typeof severities)[number]

export function token(name: string) {
  return getComputedStyle(document.documentElement).getPropertyValue(`--${name}`).trim() || '#888'
}

export function appColor(app: string) {
  return token(`app-${app}`)
}

export function severityColor(s: string) {
  return token(s)
}
