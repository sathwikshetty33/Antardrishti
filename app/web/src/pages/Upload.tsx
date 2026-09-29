import { useQuery, useQueryClient } from '@tanstack/react-query'
import { AnimatePresence, motion } from 'framer-motion'
import { CheckCircle2, CircleDashed, FileArchive, Loader2, Play, UploadCloud, X, XCircle } from 'lucide-react'
import { useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { PageHeader } from '@/components/AppShell'
import { ErrorState } from '@/components/states'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Skeleton } from '@/components/ui/skeleton'
import { useAnalysisPoll } from '@/hooks/usePoll'
import { ApiError, api, uploadCapture, type Analysis } from '@/lib/api'
import { bytes, num, seconds } from '@/lib/format'
import { cn } from '@/lib/utils'

const accept = /\.(pcap|pcapng|cap)(\.zst)?$/i
const stages = [
  { key: 'upload', label: 'Upload to storage' },
  { key: 'fetching', label: 'Fetch capture' },
  { key: 'parsing', label: 'Parse and group tunnels' },
  { key: 'inferring', label: 'Infer config and traffic' },
  { key: 'rules', label: 'Check against standards' },
  { key: 'saving', label: 'Save results' },
]

export function StatusSteps({ uploading, analysis }: { uploading: boolean; analysis?: Analysis }) {
  const current = uploading ? 'upload' : analysis?.stage ?? 'fetching'
  const idx = analysis?.status === 'done' ? stages.length : stages.findIndex((s) => s.key === current)
  const failed = analysis?.status === 'failed'
  return (
    <ol className="space-y-2.5" aria-label="Analysis progress">
      {stages.map((s, i) => {
        const state = failed && i === Math.max(idx, 1) ? 'failed' : i < idx ? 'done' : i === idx ? 'active' : 'todo'
        return (
          <li key={s.key} className="flex items-center gap-3 text-sm">
            {state === 'done' ? <CheckCircle2 className="size-4 text-pass" aria-hidden />
              : state === 'active' ? <Loader2 className="size-4 animate-spin text-accent" aria-hidden />
                : state === 'failed' ? <XCircle className="size-4 text-critical" aria-hidden />
                  : <CircleDashed className="size-4 text-muted" aria-hidden />}
            <span className={cn(state === 'todo' ? 'text-muted' : 'text-text')}>{s.label}</span>
            <span className="sr-only">{state}</span>
          </li>
        )
      })}
    </ol>
  )
}

export function Upload() {
  const cfg = useQuery({ queryKey: ['config'], queryFn: api.config })
  const demos = useQuery({ queryKey: ['demos'], queryFn: api.demos })
  const [files, setFiles] = useState<File[]>([])
  const [prog, setProg] = useState<Record<string, number>>({})
  const [busy, setBusy] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [id, setId] = useState<string>()
  const [drag, setDrag] = useState(false)
  const input = useRef<HTMLInputElement>(null)
  const poll = useAnalysisPoll(id, busy || !!id)
  const nav = useNavigate()
  const qc = useQueryClient()
  const limit = cfg.data?.upload_limit_mb ?? 100

  const add = (list: FileList | null) => {
    if (!list) return
    const ok = Array.from(list).filter((f) => accept.test(f.name))
    const bad = Array.from(list).filter((f) => !accept.test(f.name))
    setError(bad.length ? `Not a capture: ${bad.map((f) => f.name).join(', ')} (use .pcap, .pcapng or .cap, optionally .zst)` : null)
    setFiles((f) => [...f, ...ok].slice(0, 4))
  }

  const run = async (body: { uploads?: { url: string; name: string }[]; demo?: string }) => {
    const aid = crypto.randomUUID()
    setId(aid)
    setUploading(false)
    try {
      await api.start({ id: aid, ...body })
      qc.invalidateQueries({ queryKey: ['overview'] })
      await poll.refetch()
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) window.dispatchEvent(new Event('antar-need-key'))
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const start = async () => {
    if (!cfg.data || !files.length) return
    setBusy(true)
    setError(null)
    setUploading(true)
    try {
      const ups = []
      for (const f of files) {
        ups.push(await uploadCapture(f, cfg.data, (x) => setProg((p) => ({ ...p, [f.name]: x }))))
      }
      await run({ uploads: ups })
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) window.dispatchEvent(new Event('antar-need-key'))
      setError(e instanceof Error ? e.message : String(e))
      setBusy(false)
      setUploading(false)
    }
  }

  const a = poll.data
  const finished = a && (a.status === 'done' || a.status === 'failed')
  return (
    <>
      <PageHeader title="Analyze a capture"
        description="Captures go straight from your browser to storage, then the analysis runs on the server. Only outer headers are read; nothing is decrypted." />
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <div>
              <CardTitle>Upload</CardTitle>
              <CardDescription>
                pcap or pcapng, optionally zstd-compressed; up to {limit} MB per file and {cfg.data?.max_pcap_mb ?? '…'} MB uncompressed per analysis. Add the IKE capture next to a truncated outer capture if you have both.
              </CardDescription>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div
              role="button"
              tabIndex={0}
              aria-label="Drop captures here or press Enter to choose files"
              onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && input.current?.click()}
              onClick={() => input.current?.click()}
              onDragOver={(e) => { e.preventDefault(); setDrag(true) }}
              onDragLeave={() => setDrag(false)}
              onDrop={(e) => { e.preventDefault(); setDrag(false); add(e.dataTransfer.files) }}
              className={cn('flex cursor-pointer flex-col items-center justify-center gap-3 rounded-[12px] border-2 border-dashed px-6 py-12 text-center transition-colors',
                drag ? 'border-accent bg-accent-soft' : 'border-border-strong hover:border-accent hover:bg-surface-2')}
            >
              <div className="rounded-full bg-accent-soft p-3 text-accent"><UploadCloud className="size-6" aria-hidden /></div>
              <div>
                <p className="text-sm font-medium">Drop captures here, or click to choose</p>
                <p className="mt-1 text-xs text-text-2">.pcap · .pcapng · .cap · .zst</p>
              </div>
              <input ref={input} type="file" multiple accept=".pcap,.pcapng,.cap,.zst" className="hidden"
                onChange={(e) => { add(e.target.files); e.target.value = '' }} />
            </div>
            <AnimatePresence initial={false}>
              {files.map((f) => (
                <motion.div key={f.name} initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}
                  className="flex items-center gap-3 rounded-lg border border-border bg-surface-2 px-3 py-2.5">
                  <FileArchive className="size-4 text-text-2" aria-hidden />
                  <div className="min-w-0 flex-1">
                    <div className="flex justify-between gap-2 text-xs">
                      <span className="truncate text-text">{f.name}</span>
                      <span className="num text-muted">{bytes(f.size)}</span>
                    </div>
                    {prog[f.name] != null ? <Progress className="mt-2" value={prog[f.name] * 100} label={`upload ${f.name}`} /> : null}
                  </div>
                  {!busy ? (
                    <button type="button" aria-label={`Remove ${f.name}`} className="rounded p-1 text-muted hover:text-text cursor-pointer"
                      onClick={() => setFiles((x) => x.filter((y) => y !== f))}><X className="size-4" /></button>
                  ) : null}
                </motion.div>
              ))}
            </AnimatePresence>
            {error ? <p role="alert" className="rounded-lg border px-3 py-2 text-xs" style={{ borderColor: 'color-mix(in oklab, var(--critical) 40%, transparent)', color: 'var(--critical)' }}>{error}</p> : null}
            <div className="flex items-center justify-between gap-3">
              <p className="text-xs text-muted">Storage: {cfg.data?.storage === 'blob' ? 'Vercel Blob (private)' : 'local server folder'}</p>
              <Button variant="primary" disabled={!files.length || busy} onClick={start}>
                {busy ? <Loader2 className="animate-spin" /> : <Play />} Analyze {files.length ? `${files.length} file${files.length > 1 ? 's' : ''}` : ''}
              </Button>
            </div>
          </CardContent>
        </Card>
        <div className="space-y-4">
          <Card>
            <CardHeader><div><CardTitle>Status</CardTitle><CardDescription>{id ? <span className="num">{id.slice(0, 8)}</span> : 'Nothing running'}</CardDescription></div></CardHeader>
            <CardContent>
              {id || busy ? (
                <div className="space-y-4">
                  <StatusSteps uploading={uploading} analysis={a} />
                  {a && a.status !== 'pending' ? <Progress value={(a.progress ?? 0) * 100} label="analysis progress" /> : null}
                  {a?.status === 'failed' ? <p role="alert" className="text-xs" style={{ color: 'var(--critical)' }}>{a.error}</p> : null}
                  {a?.status === 'done' ? (
                    <div className="space-y-3">
                      <p className="text-xs text-text-2">Done in {seconds(a.timings?.total_s)} for {seconds(a.timings?.traffic_s)} of traffic.</p>
                      <Button variant="primary" className="w-full" onClick={() => nav(`/analyses/${a.id}`)}>Open the results</Button>
                    </div>
                  ) : null}
                  {finished ? null : <p className="text-xs text-muted">Status is polled with backoff (1 s up to 8 s).</p>}
                </div>
              ) : <p className="text-xs text-text-2">Upload a capture or pick a demo to start.</p>}
            </CardContent>
          </Card>
          <Card>
            <CardHeader><div><CardTitle>Demo captures</CardTitle><CardDescription>Test-split runs from the dataset, one click each</CardDescription></div></CardHeader>
            <CardContent className="space-y-2">
              {demos.isLoading ? [0, 1, 2].map((i) => <Skeleton key={i} className="h-14" />) : demos.error ? <ErrorState error={demos.error} /> :
                demos.data?.map((d) => (
                  <button key={d.name} type="button" disabled={busy}
                    onClick={() => { setBusy(true); setError(null); run({ demo: d.name }) }}
                    className="flex w-full items-start gap-3 rounded-lg border border-border p-3 text-left transition-colors hover:border-accent hover:bg-surface-2 disabled:opacity-50 cursor-pointer">
                    <Play className="mt-0.5 size-4 text-accent" aria-hidden />
                    <div className="min-w-0">
                      <p className="text-sm font-medium">{d.title}</p>
                      <p className="mt-0.5 line-clamp-2 text-xs text-text-2">{d.description}</p>
                      <p className="mt-1 num text-[11px] text-muted">{bytes(d.bytes)} · {num(d.packets)} packets · {seconds(d.duration_s)}</p>
                    </div>
                  </button>
                ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </>
  )
}
