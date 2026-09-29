import { useQuery } from '@tanstack/react-query'
import { Activity, FileText, Gauge, Grid3x3, KeyRound, ListChecks, Moon, PlayCircle, Sun, UploadCloud } from 'lucide-react'
import * as React from 'react'
import { useEffect, useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Modal } from '@/components/ui/sheet'
import { Tip } from '@/components/ui/tooltip'
import { BrandMark } from '@/components/Brand'
import { accessKey, api, setAccessKey } from '@/lib/api'
import { currentTheme, setTheme, type Theme } from '@/lib/theme'
import { cn } from '@/lib/utils'

const nav = [
  { to: '/', label: 'Overview', icon: Gauge, end: true },
  { to: '/upload', label: 'Analyze capture', icon: UploadCloud },
  { to: '/analyses', label: 'Analyses', icon: ListChecks },
  { to: '/threats', label: 'Threat matrix', icon: Grid3x3 },
  { to: '/replay', label: 'Demo replay', icon: PlayCircle },
  { to: '/reports', label: 'Reports', icon: FileText },
]

export function Sidebar() {
  return (
    <aside className="no-print sticky top-0 hidden h-screen w-[72px] shrink-0 flex-col border-r border-border bg-surface md:flex xl:w-[232px]">
      <div className="flex h-14 items-center gap-2.5 border-b border-border px-5">
        <BrandMark />
        <div className="hidden leading-tight xl:block">
          <div className="text-sm font-semibold tracking-tight">Antardrishti</div>
          <div className="text-[11px] text-muted">See inside the tunnel</div>
        </div>
      </div>
      <nav className="flex flex-1 flex-col gap-1 p-3" aria-label="Main">
        {nav.map((n) => (
          <NavLink key={n.to} to={n.to} end={n.end}
            className={({ isActive }) => cn('flex h-9 items-center gap-3 rounded-lg px-3 text-sm transition-colors',
              isActive ? 'bg-accent-soft font-medium text-text' : 'text-text-2 hover:bg-surface-2 hover:text-text')}>
            {({ isActive }) => (
              <>
                <n.icon className={cn('size-4 shrink-0', isActive ? 'text-accent' : '')} aria-hidden />
                <span className="hidden xl:inline">{n.label}</span>
              </>
            )}
          </NavLink>
        ))}
      </nav>
      <div className="hidden border-t border-border p-4 text-[11px] leading-relaxed text-muted xl:block">
        Passive analysis of outer headers only. Nothing is decrypted.
      </div>
    </aside>
  )
}

function MobileNav() {
  return (
    <nav className="no-print flex gap-1 overflow-x-auto border-b border-border bg-surface px-3 py-2 md:hidden" aria-label="Main">
      {nav.map((n) => (
        <NavLink key={n.to} to={n.to} end={n.end}
          className={({ isActive }) => cn('flex h-8 shrink-0 items-center gap-2 rounded-md px-2.5 text-xs',
            isActive ? 'bg-accent-soft text-text' : 'text-text-2')}>
          <n.icon className="size-4" aria-hidden />
          {n.label}
        </NavLink>
      ))}
    </nav>
  )
}

function ThemeToggle() {
  const [t, setT] = useState<Theme>(currentTheme())
  const next = t === 'dark' ? 'light' : 'dark'
  return (
    <Tip content={`Switch to ${next} theme`}>
      <Button variant="ghost" size="icon" aria-label={`Switch to ${next} theme`} onClick={() => { setTheme(next); setT(next) }}>
        {t === 'dark' ? <Sun /> : <Moon />}
      </Button>
    </Tip>
  )
}

function AccessKey() {
  const cfg = useQuery({ queryKey: ['config'], queryFn: api.config, staleTime: 60_000 })
  const [open, setOpen] = useState(false)
  const [v, setV] = useState(accessKey())
  useEffect(() => {
    const f = () => setOpen(true)
    window.addEventListener('antar-need-key', f)
    return () => window.removeEventListener('antar-need-key', f)
  }, [])
  if (!cfg.data?.access_key_required) return null
  return (
    <>
      <Tip content={accessKey() ? 'Access key set' : 'Set the access key to upload and analyse'}>
        <Button variant="ghost" size="icon" aria-label="Access key" onClick={() => setOpen(true)}>
          <KeyRound className={accessKey() ? 'text-accent' : ''} />
        </Button>
      </Tip>
      <Modal open={open} onOpenChange={setOpen} title="Access key">
        <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); setAccessKey(v.trim()); setOpen(false) }}>
          <p className="text-xs text-text-2">This deployment requires its access key (APP_ACCESS_KEY) to upload captures and start analyses. It is kept in this browser only.</p>
          <Input type="password" autoComplete="off" value={v} onChange={(e) => setV(e.target.value)} placeholder="access key" aria-label="Access key" />
          <div className="flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
            <Button type="submit" variant="primary">Save</Button>
          </div>
        </form>
      </Modal>
    </>
  )
}

function TopBar() {
  const model = useQuery({ queryKey: ['model'], queryFn: api.model, staleTime: 300_000 })
  const health = useQuery({ queryKey: ['health'], queryFn: api.health, refetchInterval: 60_000 })
  const ok = health.data?.ok
  return (
    <header className="no-print sticky top-0 z-30 flex h-14 items-center justify-between gap-4 border-b border-border bg-bg/85 px-4 backdrop-blur md:px-6">
      <div className="flex items-center gap-3 text-xs text-text-2 md:hidden">
        <BrandMark />
        <span className="text-sm font-semibold text-text">Antardrishti</span>
      </div>
      <div className="hidden text-xs text-muted md:block">IPsec VPN analysis · config inference · traffic classification · security assessment</div>
      <div className="flex items-center gap-1.5">
        <Tip content={health.data ? `API ${ok ? 'healthy' : 'degraded'} · database ${health.data.db} · storage ${health.data.storage}` : 'Checking API'}>
          <span className="mr-1 flex items-center gap-1.5 text-xs text-text-2">
            <Activity className="size-3.5" style={{ color: ok ? 'var(--pass)' : ok === false ? 'var(--critical)' : 'var(--muted)' }} aria-hidden />
            <span className="hidden sm:inline">{ok ? 'online' : ok === false ? 'degraded' : '…'}</span>
          </span>
        </Tip>
        {model.data ? (
          <Tip content={`Model bundle ${model.data.version} (commit ${model.data.commit?.slice(0, 7)}), ${model.data.models} LightGBM models, contract ${model.data.schema_version}`}>
            <span className="chip num" style={{ '--c': 'var(--accent)' } as React.CSSProperties}>
              models {model.data.version}·{model.data.commit?.slice(0, 7)}
            </span>
          </Tip>
        ) : null}
        <AccessKey />
        <ThemeToggle />
      </div>
    </header>
  )
}

export function AppShell() {
  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar />
        <MobileNav />
        <main className="mx-auto w-full max-w-[1600px] flex-1 px-4 py-6 md:px-6 xl:px-8">
          <Outlet />
        </main>
      </div>
    </div>
  )
}

export function PageHeader({ title, description, actions, eyebrow }: {
  title: React.ReactNode; description?: React.ReactNode; actions?: React.ReactNode; eyebrow?: React.ReactNode
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        {eyebrow ? <div className="mb-1 text-xs text-muted">{eyebrow}</div> : null}
        <h1 className="text-xl font-semibold tracking-tight text-text">{title}</h1>
        {description ? <p className="mt-1 max-w-3xl text-sm text-text-2">{description}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  )
}
