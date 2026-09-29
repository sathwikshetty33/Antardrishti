import { useQuery } from '@tanstack/react-query'
import { useEffect } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { api } from '@/lib/api'
import { when } from '@/lib/format'
import { routeRun, setSelectedRun, useSelectedRun } from '@/lib/run'

// the top bar's run switcher: every run at once, or one live session or analysis. overview,
// threat matrix and reports follow the choice; on a run's own page, switching opens the same
// view of the other run.
export function RunSwitcher() {
  const loc = useLocation()
  const nav = useNavigate()
  const sel = useSelectedRun()
  const sessions = useQuery({ queryKey: ['live-sessions'], queryFn: api.liveSessions, refetchInterval: 15_000 })
  const analyses = useQuery({ queryKey: ['analyses'], queryFn: api.analyses, refetchInterval: 15_000 })
  const onRoute = routeRun(loc.pathname)
  const value = onRoute ?? sel ?? 'all'
  const live = sessions.data ?? []
  const runs = (analyses.data ?? []).filter((a) => a.source !== 'live')
  const listed = value === 'all' || live.some((x) => x.id === value) || runs.some((x) => x.id === value)
  const loaded = !!sessions.data && !!analyses.data
  const extra = useQuery({ queryKey: ['analysis', value], queryFn: () => api.analysis(value), enabled: loaded && !listed })

  // a stored choice that no longer exists (another database) falls back to every run
  useEffect(() => {
    if (sel && !onRoute && extra.data && extra.data.status === 'pending' && !extra.data.name) setSelectedRun(null)
  }, [sel, onRoute, extra.data])

  const choose = (v: string) => {
    const id = v === 'all' ? null : v
    setSelectedRun(id)
    if (!onRoute) return
    if (!id) {
      nav('/')
      return
    }
    const session = live.find((x) => x.id === id)
    const tunnels = session?.tunnel_count ?? runs.find((x) => x.id === id)?.tunnel_count ?? 0
    const path = loc.pathname
    if (path.startsWith('/live/')) nav(session ? `/live/${id}` : `/analyses/${id}`)
    else if (path.endsWith('/threats')) nav(`/analyses/${id}/threats`)
    else if (path.includes('/tunnels/')) nav(tunnels > 0 ? `/analyses/${id}/tunnels/0` : `/analyses/${id}`)
    else nav(`/analyses/${id}`)
  }

  return (
    <label className="flex min-w-0 items-center gap-2 text-xs text-text-2">
      <span className="hidden lg:inline">Run</span>
      <select value={value} onChange={(e) => choose(e.target.value)} aria-label="Run the views show"
        className="h-8 w-[170px] min-w-0 truncate rounded-lg border border-border-strong bg-surface-2 px-2 text-xs text-text sm:w-[240px] xl:w-[300px]">
        <option value="all">All runs</option>
        {live.length ? (
          <optgroup label="Live sessions">
            {live.map((x) => (
              <option key={x.id} value={x.id}>
                {x.status === 'live' ? '● ' : ''}{x.name || 'Live session'} · {x.status} · {when(x.created_at)}
              </option>
            ))}
          </optgroup>
        ) : null}
        {runs.length ? (
          <optgroup label="Analyses">
            {runs.map((a) => <option key={a.id} value={a.id}>{a.name} · {a.source} · {when(a.created_at)}</option>)}
          </optgroup>
        ) : null}
        {!listed ? <option value={value}>{extra.data?.name || 'Selected run'}</option> : null}
      </select>
    </label>
  )
}
