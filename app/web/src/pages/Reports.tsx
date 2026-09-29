import { useQuery } from '@tanstack/react-query'
import { ArrowLeft, FileText, Printer } from 'lucide-react'
import * as React from 'react'
import { useEffect } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { PageHeader } from '@/components/AppShell'
import { BandBadge, ConfidenceBadge, SeverityBadge, SourceBadge, StatusBadge, VerdictBadge } from '@/components/badges'
import { BrandLogo } from '@/components/Brand'
import { RiskGauge } from '@/components/RiskGauge'
import { ShareBar } from '@/components/ShareBar'
import { WindowTimeline } from '@/components/WindowTimeline'
import { CardSkeleton, EmptyState, ErrorState } from '@/components/states'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Table, Td, Th, Tr } from '@/components/ui/table'
import { api, type Finding, type Report } from '@/lib/api'
import { appLabel, shareNames } from '@/lib/colors'
import { errorBar, factValue, num, round100, seconds, when } from '@/lib/format'
import { currentTheme, setTheme } from '@/lib/theme'

export function ReportsPage() {
  const q = useQuery({ queryKey: ['analyses'], queryFn: api.analyses })
  const nav = useNavigate()
  const done = (q.data ?? []).filter((a) => a.status === 'done')
  return (
    <>
      <PageHeader title="Reports" description="Executive and technical reports, generated in the browser from the API. Use Print → Save as PDF." />
      <Card>
        {q.isLoading ? <div className="p-5"><CardSkeleton rows={5} /></div> : q.error ? <ErrorState error={q.error} /> : done.length ? (
          <Table>
            <thead><tr><Th>Analysis</Th><Th>Risk</Th><Th className="text-right">Tunnels</Th><Th className="text-right">Created</Th><Th /></tr></thead>
            <tbody>
              {done.map((a) => (
                <Tr key={a.id}>
                  <Td className="max-w-[360px] truncate">{a.name}</Td>
                  <Td><BandBadge band={a.risk_band} score={a.risk} /></Td>
                  <Td className="num text-right">{a.tunnel_count}</Td>
                  <Td className="text-right text-xs text-muted">{when(a.created_at)}</Td>
                  <Td className="text-right">
                    <div className="flex justify-end gap-2">
                      <Button size="sm" onClick={() => nav(`/reports/${a.id}/executive`)}><FileText /> Executive</Button>
                      <Button size="sm" onClick={() => nav(`/reports/${a.id}/technical`)}><FileText /> Technical</Button>
                    </div>
                  </Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        ) : <EmptyState title="No finished analyses">Reports appear once an analysis is done.</EmptyState>}
      </Card>
    </>
  )
}

const rank = (f: Finding) => ({ critical: 0, high: 1, medium: 2, low: 3, info: 4 })[f.severity] ?? 5

function Section({ title, children, className }: { title: string; children: React.ReactNode; className?: string }) {
  return (
    <section className={`avoid-break mt-8 ${className ?? ''}`}>
      <h2 className="mb-3 border-b border-border pb-1.5 text-base font-semibold">{title}</h2>
      {children}
    </section>
  )
}

function ReportFrame({ r, kind, children }: { r: Report; kind: string; children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-bg">
      <div className="no-print sticky top-0 z-10 flex items-center justify-between border-b border-border bg-surface px-6 py-3">
        <Link to={`/analyses/${r.analysis.id}`} className="inline-flex items-center gap-1.5 text-sm text-text-2 hover:text-text"><ArrowLeft className="size-4" /> Back to the analysis</Link>
        <Button variant="primary" onClick={() => window.print()}><Printer /> Print or save as PDF</Button>
      </div>
      <article className="mx-auto max-w-[900px] px-8 py-10 text-sm">
        <header className="flex items-start justify-between gap-6 border-b border-border pb-5">
          <div>
            <p className="text-xs uppercase tracking-wider text-muted">{kind} report</p>
            <h1 className="mt-1 text-2xl font-semibold tracking-tight">{r.analysis.name}</h1>
            <p className="mt-1 text-xs text-text-2">
              Analysed {r.analysis.finished_at ? new Date(r.analysis.finished_at).toLocaleString('en-GB') : '-'} · {r.tunnels.length} tunnel{r.tunnels.length === 1 ? '' : 's'} ·
              model bundle {r.model.version} ({r.model.commit?.slice(0, 7)}) · contract {r.model.schema_version}
            </p>
          </div>
          <div className="flex shrink-0 flex-col items-end gap-2">
            <BrandLogo variant="light" className="w-40" />
            <span className="text-xs text-muted num">{r.analysis.id.slice(0, 8)}</span>
          </div>
        </header>
        {children}
        <footer className="mt-10 border-t border-border pt-3 text-[11px] text-muted">
          Passive analysis of the outer capture only: no traffic was decrypted and no keys were used. Facts marked "inferred" come from models
          trained on the Antardrishti dataset; their confidence is calibrated, and findings below 80% confidence are worded "likely".
        </footer>
      </article>
    </div>
  )
}

function useLightForPrint() {
  useEffect(() => {
    const was = currentTheme()
    setTheme('light')
    return () => setTheme(was)
  }, [])
}

function sharesOf(t: Report['tunnels'][number]) {
  const by = Object.fromEntries(t.shares.map((s) => [s.app, s.byte_share]))
  return round100(Object.fromEntries(shareNames.map((n) => [n, by[n] ?? 0])))
}

export function ExecutiveReport() {
  const { id = '' } = useParams()
  useLightForPrint()
  const q = useQuery({ queryKey: ['report', id], queryFn: () => api.report(id) })
  if (q.isLoading) return <div className="p-10"><CardSkeleton rows={10} /></div>
  if (q.error) return <div className="p-10"><ErrorState error={q.error} retry={() => q.refetch()} /></div>
  const r = q.data!
  const bad = r.findings.filter((f) => f.verdict === 'fail' || f.verdict === 'warn').sort((a, b) => rank(a) - rank(b))
  const fixes = [...new Map(bad.filter((f) => f.recommendation).map((f) => [f.recommendation, f])).values()]
  const nd = r.findings.filter((f) => f.verdict === 'not determinable')
  return (
    <ReportFrame r={r} kind="Executive">
      <div className="mt-6 grid grid-cols-[240px_1fr] items-center gap-8">
        <RiskGauge score={r.overall?.score ?? null} caption="0-100, worst tunnel; confident critical findings set a floor of 90" />
        <div className="space-y-2">
          <p className="text-base">
            {bad.length ? `${bad.length} check${bad.length > 1 ? 's' : ''} failed or raised a warning across ${r.tunnels.length} tunnel${r.tunnels.length > 1 ? 's' : ''}.`
              : 'No check failed across the analysed tunnels.'}
            {' '}{bad.filter((f) => f.severity === 'critical').length ? `${bad.filter((f) => f.severity === 'critical').length} are critical.` : ''}
          </p>
          <p className="text-text-2">{nd.length} checks could not be decided from this capture (for example, PFS needs a rekey in the capture); they are listed as not determinable, never guessed.</p>
        </div>
      </div>
      <Section title="Top findings">
        {bad.length ? (
          <ol className="space-y-3">
            {bad.slice(0, 6).map((f) => (
              <li key={f.id} className="rounded-lg border border-border p-3">
                <div className="flex items-center gap-2"><SeverityBadge severity={f.severity} /><span className="text-xs text-muted">tunnel {f.tunnel} · {f.title}</span></div>
                <p className="mt-1.5">{f.text}</p>
              </li>
            ))}
          </ol>
        ) : <p className="text-text-2">Nothing to report.</p>}
      </Section>
      <Section title="Traffic overview">
        <Table>
          <thead><tr><Th>Tunnel</Th><Th>Handshake</Th><Th>What it carries (share of bytes)</Th><Th>Risk</Th></tr></thead>
          <tbody>
            {r.tunnels.map((t) => {
              const s = sharesOf(t)
              const top = shareNames.filter((n) => s[n] > 0).sort((a, b) => s[b] - s[a])
              return (
                <Tr key={t.idx}>
                  <Td className="num">#{t.idx}</Td>
                  <Td><StatusBadge status={t.handshake_status} /></Td>
                  <Td className="text-xs">{t.shares.length ? top.map((n) => `${appLabel[n]} ${s[n]}%`).join(' · ') : 'no traffic'}</Td>
                  <Td>{t.risk ? <BandBadge band={t.risk.band} score={t.risk.score} /> : '-'}</Td>
                </Tr>
              )
            })}
          </tbody>
        </Table>
      </Section>
      <Section title="Recommendations">
        {fixes.length ? (
          <ol className="list-decimal space-y-2 pl-5">
            {fixes.map((f) => <li key={f.recommendation}><span className="font-medium">{f.title}:</span> {f.recommendation}</li>)}
          </ol>
        ) : <p className="text-text-2">Keep the current configuration; re-analyse after any change.</p>}
      </Section>
    </ReportFrame>
  )
}

export function TechnicalReport() {
  const { id = '' } = useParams()
  useLightForPrint()
  const q = useQuery({ queryKey: ['report', id], queryFn: () => api.report(id) })
  if (q.isLoading) return <div className="p-10"><CardSkeleton rows={10} /></div>
  if (q.error) return <div className="p-10"><ErrorState error={q.error} retry={() => q.refetch()} /></div>
  const r = q.data!
  return (
    <ReportFrame r={r} kind="Technical">
      <Section title="Summary">
        <div className="grid grid-cols-4 gap-3 text-xs">
          <div><div className="text-muted">Overall risk</div><div className="num text-lg font-semibold">{r.overall?.score ?? '-'}</div></div>
          <div><div className="text-muted">Tunnels</div><div className="num text-lg font-semibold">{r.tunnels.length}</div></div>
          <div><div className="text-muted">Analysis time</div><div className="num text-lg font-semibold">{seconds(r.analysis.timings?.total_s)}</div></div>
          <div><div className="text-muted">Packets</div><div className="num text-lg font-semibold">{num(Number(r.counts?.packets ?? 0))}</div></div>
        </div>
        <p className="mt-2 text-xs text-text-2">Inputs: {r.inputs.join(', ')}</p>
      </Section>
      {r.tunnels.map((t) => (
        <div key={t.idx} className="print-page">
          <Section title={`Tunnel #${t.idx}: ${t.initiator ?? '?'} → ${t.responder.join(', ') || '?'}`}>
            <p className="mb-3 text-xs text-text-2">Handshake {t.handshake_status} · {num(t.esp_packets)} ESP packets · direction from {t.direction_from} · risk {t.risk?.score ?? '-'} ({t.risk?.band})</p>
            <Table>
              <thead><tr><Th>Fact</Th><Th>Value</Th><Th>Confidence</Th><Th>Source</Th></tr></thead>
              <tbody>
                {Object.entries(t.facts).map(([k, f]) => (
                  <Tr key={k}><Td className="text-xs text-text-2">{k}</Td><Td className="num text-xs break-words">{factValue(f.value)}</Td>
                    <Td><ConfidenceBadge value={f.value === 'not determinable' ? null : f.confidence} /></Td><Td><SourceBadge source={f.source} /></Td></Tr>
                ))}
              </tbody>
            </Table>
          </Section>
          {t.shares.length ? (
            <Section title="Traffic shares">
              <div className="grid grid-cols-2 gap-6">
                <ShareBar shares={t.shares} />
                <Table>
                  <thead><tr><Th>App</Th><Th className="text-right">Bytes</Th><Th className="text-right">Error bar</Th><Th className="text-right">Active time</Th></tr></thead>
                  <tbody>
                    {t.shares.map((s) => {
                      const eb = errorBar(s.byte_share, s.error_pp)
                      return (
                        <Tr key={s.app}><Td className="text-xs">{appLabel[s.app]}</Td><Td className="num text-right text-xs">{s.byte_rounded}%</Td>
                          <Td className="num text-right text-xs">{eb ? `${eb[0].toFixed(0)}-${eb[1].toFixed(0)}%` : '-'}</Td>
                          <Td className="num text-right text-xs">{s.app === 'unknown' ? '-' : `${s.active_rounded ?? '-'}%`}</Td></Tr>
                      )
                    })}
                  </tbody>
                </Table>
              </div>
            </Section>
          ) : null}
          {t.windows?.length ? <Section title="Window timeline"><WindowTimeline windows={t.windows} height={280} /></Section> : null}
        </div>
      ))}
      <Section title="Findings">
        <Table>
          <thead><tr><Th>Check</Th><Th>Verdict</Th><Th>Finding, evidence and standard</Th><Th>Confidence</Th></tr></thead>
          <tbody>
            {r.findings.map((f) => (
              <Tr key={f.id} className="avoid-break">
                <Td className="num align-top text-xs">{f.check_id}<div className="text-muted">tunnel {f.tunnel}</div></Td>
                <Td className="align-top"><div className="flex flex-col items-start gap-1"><VerdictBadge verdict={f.verdict} />{f.verdict === 'fail' || f.verdict === 'warn' ? <SeverityBadge severity={f.severity} /> : null}</div></Td>
                <Td className="text-xs">
                  <p>{f.text}</p>
                  {f.evidence.map((e, i) => <p key={i} className="mt-1 num text-text-2">{e.fact} = {factValue(e.value)} ({e.source})</p>)}
                  <p className="mt-1 text-muted">{f.standard.join('; ')}</p>
                  {f.recommendation ? <p className="mt-1">Fix: {f.recommendation}</p> : null}
                </Td>
                <Td className="align-top"><ConfidenceBadge value={f.confidence} /></Td>
              </Tr>
            ))}
          </tbody>
        </Table>
      </Section>
      <Section title="Threat matrix">
        {r.threats.length ? (
          <Table>
            <thead><tr><Th>Threat</Th><Th className="text-right">Likelihood</Th><Th className="text-right">Impact</Th><Th>Tunnels</Th><Th>Linked findings</Th></tr></thead>
            <tbody>{r.threats.map((t) => (
              <Tr key={t.threat_id}><Td className="text-xs">{t.threat} <span className="num text-muted">{t.threat_id}</span></Td><Td className="num text-right">{t.likelihood}</Td>
                <Td className="num text-right">{t.impact}</Td><Td className="num text-xs">{t.tunnels.join(', ')}</Td><Td className="num text-xs">{t.findings.join(', ')}</Td></Tr>
            ))}</tbody>
          </Table>
        ) : <p className="text-text-2">No threats: no check failed or warned.</p>}
      </Section>
      <Section title="Model and methodology">
        <ul className="list-disc space-y-1.5 pl-5 text-xs text-text-2">
          <li>Model bundle {r.model.version}, commit {r.model.commit}, {r.model.models} LightGBM models (3 config, 7 presence, 7 share), seed {r.model.seed}; data releases {r.model.data_releases.join(', ')}.</li>
          <li>Parser: outer IP fragments reassembled; packets grouped into tunnels by address pair, NAT-T ports, IKE SPIs and ESP SPIs; IKE read in the clear where captured.</li>
          <li>Config models read ESP length residues and minimum sizes (suite, mode) and CREATE_CHILD_SA sizes (PFS). Traffic models classify 2-second windows from sizes, timing, bursts and FFT; shares are byte-weighted, absent apps zeroed, rounded to 100 by largest remainder.</li>
          <li>Error bars: out-of-fold session share error per app and share range, clipped to 0-100.</li>
          <li>Rules: {r.model.rules.length} checks against RFC 8221, RFC 8247, NIST SP 800-77r1, RFC 7296 and RFC 4303. Risk: weights {Object.entries(r.model.weights).map(([k, v]) => `${k} ${v}`).join(', ')} times confidence, capped at 100, a confident critical sets a floor of {r.model.critical_floor}; overall is the worst tunnel.</li>
        </ul>
      </Section>
    </ReportFrame>
  )
}
