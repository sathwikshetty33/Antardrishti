import { useQuery } from '@tanstack/react-query'
import * as D from '@radix-ui/react-dialog'
import { Activity, BookOpen, FileText, Gauge, Grid3x3, KeyRound, ListChecks, Menu, Moon, PanelLeftClose, PanelLeftOpen, PlayCircle, RadioTower, Sun, UploadCloud, X } from 'lucide-react'
import * as React from 'react'
import { useEffect, useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Modal } from '@/components/ui/sheet'
import { Tip } from '@/components/ui/tooltip'
import { BrandMark } from '@/components/Brand'
import { RunSwitcher } from '@/components/RunSwitcher'
import { Toaster } from '@/components/Toaster'
import { accessKey, api, setAccessKey } from '@/lib/api'
import { useNavCollapsed } from '@/lib/nav'
import { currentTheme, setTheme, type Theme } from '@/lib/theme'
import { cn } from '@/lib/utils'

const nav = [
  { to: '/', label: 'Overview', icon: Gauge, end: true },
  { to: '/live', label: 'Live', icon: RadioTower },
  { to: '/upload', label: 'Analyze capture', icon: UploadCloud },
  { to: '/analyses', label: 'Analyses', icon: ListChecks },
  { to: '/threats', label: 'Threat matrix', icon: Grid3x3 },
  { to: '/replay', label: 'Demo replay', icon: PlayCircle },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/docs/live-sensor', label: 'Sensor docs', icon: BookOpen },
]

// the nav links: icons only in the collapsed sidebar (each with its label as a tooltip), larger
// touch targets in the phone drawer
function NavItems({ collapsed, large, onNavigate }: { collapsed?: boolean; large?: boolean; onNavigate?: () => void }) {
  return (
    <nav className="flex flex-1 flex-col gap-1 overflow-y-auto p-3" aria-label="Main">
      {nav.map((n) => {
        const link = (
          <NavLink key={n.to} to={n.to} end={n.end} onClick={onNavigate} aria-label={collapsed ? n.label : undefined}
            className={({ isActive }) => cn('flex items-center gap-3 rounded-lg text-sm transition-all duration-300',
              large ? 'h-11 px-3' : 'h-9', collapsed ? 'justify-center px-0' : 'px-3',
              isActive ? 'bg-accent-soft font-medium text-text shadow-sm' : 'text-text-2 hover:bg-surface-2/50 hover:text-text')}>
            {({ isActive }) => (
              <>
                <n.icon className={cn('size-4 shrink-0', isActive ? 'text-accent' : '')} aria-hidden />
                {collapsed ? null : <span className="truncate">{n.label}</span>}
              </>
            )}
          </NavLink>
        )
        // the tooltip wraps a div: its trigger merges className as a string, which would break
        // NavLink's className function
        return collapsed ? <Tip key={n.to} content={n.label} side="right"><div>{link}</div></Tip> : link
      })}
    </nav>
  )
}

function Tagline() {
  return (
    <div className="min-w-0 leading-tight">
      <div className="text-sm font-semibold tracking-tight text-text">Antardrishti</div>
      <div className="text-[11px] text-muted">See inside the tunnel</div>
    </div>
  )
}

const passive = 'Passive analysis of outer headers only. Nothing is decrypted.'

// md and up: a sidebar that collapses to icons (the choice is kept per browser)
export function Sidebar({ collapsed, onToggle }: { collapsed: boolean; onToggle: () => void }) {
  const Icon = collapsed ? PanelLeftOpen : PanelLeftClose
  const label = collapsed ? 'Expand the sidebar' : 'Collapse the sidebar'
  return (
    <aside className={cn('no-print sticky top-0 z-20 hidden h-dvh shrink-0 flex-col overflow-hidden border-r border-edge bg-glass backdrop-blur-3xl backdrop-saturate-150 transition-[width] duration-200 md:flex',
      collapsed ? 'w-[72px]' : 'w-[232px]')}>
      <div className={cn('flex h-14 shrink-0 items-center gap-2.5 border-b border-edge', collapsed ? 'justify-center' : 'px-5')}>
        <BrandMark />
        {collapsed ? null : <Tagline />}
      </div>
      <NavItems collapsed={collapsed} />
      {collapsed ? null : <div className="border-t border-edge p-4 text-[11px] leading-relaxed text-accent/80">{passive}</div>}
      <div className="border-t border-edge p-3">
        <Tip content={label} side="right">
          <button type="button" onClick={onToggle} aria-label={label} aria-expanded={!collapsed}
            className={cn('flex h-9 w-full cursor-pointer items-center gap-3 rounded-lg text-sm text-text-2 transition-colors hover:bg-surface-2/50 hover:text-text',
              collapsed ? 'justify-center' : 'px-3')}>
            <Icon className="size-4 shrink-0" aria-hidden />
            {collapsed ? null : <span>Collapse</span>}
          </button>
        </Tip>
      </div>
    </aside>
  )
}

// below md: the same links in a drawer, opened from the top bar's menu button
function MobileNav({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  return (
    <D.Root open={open} onOpenChange={onOpenChange}>
      <D.Portal>
        <D.Overlay className="no-print fixed inset-0 z-40 animate-[fade-in_150ms_ease-out] bg-black/50 md:hidden" />
        <D.Content aria-describedby={undefined}
          className="no-print fixed inset-y-0 left-0 z-50 flex w-[min(84vw,300px)] animate-[drawer-in_200ms_ease-out] flex-col border-r border-edge bg-surface shadow-2xl focus:outline-none md:hidden">
          <div className="flex h-14 shrink-0 items-center justify-between gap-2 border-b border-edge pl-4 pr-2">
            <div className="flex min-w-0 items-center gap-2.5">
              <BrandMark />
              <D.Title asChild><div><Tagline /></div></D.Title>
            </div>
            <D.Close asChild>
              <Button variant="ghost" size="icon" aria-label="Close the menu"><X /></Button>
            </D.Close>
          </div>
          <NavItems large onNavigate={() => onOpenChange(false)} />
          <div className="border-t border-edge p-4 pb-[max(16px,env(safe-area-inset-bottom))] text-[11px] leading-relaxed text-text-2">{passive}</div>
        </D.Content>
      </D.Portal>
    </D.Root>
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

function TopBar({ onMenu }: { onMenu: () => void }) {
  const model = useQuery({ queryKey: ['model'], queryFn: api.model, staleTime: 300_000 })
  const health = useQuery({ queryKey: ['health'], queryFn: api.health, refetchInterval: 60_000 })
  const ok = health.data?.ok
  return (
    <header className="no-print sticky top-0 z-30 flex h-14 items-center justify-between gap-2 border-b border-edge bg-glass px-3 backdrop-blur-3xl backdrop-saturate-150 transition-all duration-300 sm:gap-4 sm:px-4 md:px-6">
      <div className="flex min-w-0 flex-1 items-center gap-2 sm:gap-3">
        <Button variant="ghost" size="icon" className="shrink-0 md:hidden" aria-label="Open the menu" onClick={onMenu}><Menu /></Button>
        <span className="shrink-0 md:hidden"><BrandMark /></span>
        <RunSwitcher />
        <div className="hidden truncate text-xs text-muted 2xl:block">IPsec VPN analysis · config inference · traffic classification · security assessment</div>
      </div>
      <div className="flex shrink-0 items-center gap-1 sm:gap-1.5">
        <Tip content={health.data ? `API ${ok ? 'healthy' : 'degraded'} · database ${health.data.db} · storage ${health.data.storage}` : 'Checking API'}>
          <span className="mr-1 flex items-center gap-1.5 text-xs text-text-2">
            <Activity className="size-3.5" style={{ color: ok ? 'var(--pass)' : ok === false ? 'var(--critical)' : 'var(--muted)' }} aria-hidden />
            <span className="hidden sm:inline">{ok ? 'online' : ok === false ? 'degraded' : '…'}</span>
          </span>
        </Tip>
        {model.data ? (
          <span className="hidden sm:inline-flex">
            <Tip content={`Model bundle ${model.data.version} (commit ${model.data.commit?.slice(0, 7)}), ${model.data.models} LightGBM models, contract ${model.data.schema_version}`}>
              <span className="chip num" style={{ '--c': 'var(--accent)' } as React.CSSProperties}>
                models {model.data.version}·{model.data.commit?.slice(0, 7)}
              </span>
            </Tip>
          </span>
        ) : null}
        <AccessKey />
        <ThemeToggle />
      </div>
    </header>
  )
}

export function AppShell() {
  const [collapsed, toggle] = useNavCollapsed()
  const [menu, setMenu] = useState(false)
  // the drawer is for phones only: close it when the window widens past md
  useEffect(() => {
    const mq = window.matchMedia('(min-width: 768px)')
    const f = () => {
      if (mq.matches) setMenu(false)
    }
    mq.addEventListener('change', f)
    return () => mq.removeEventListener('change', f)
  }, [])
  return (
    <div className="flex min-h-dvh">
      <Sidebar collapsed={collapsed} onToggle={toggle} />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar onMenu={() => setMenu(true)} />
        <MobileNav open={menu} onOpenChange={setMenu} />
        <main className="mx-auto w-full max-w-[1600px] flex-1 px-4 py-5 md:px-6 md:py-6 xl:px-8">
          <Outlet />
        </main>
      </div>
      <Toaster />
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
