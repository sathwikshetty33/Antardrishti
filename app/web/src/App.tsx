import { lazy, Suspense } from 'react'
import { Route, Routes } from 'react-router-dom'
import { AppShell } from '@/components/AppShell'
import { Card } from '@/components/ui/card'
import { CardSkeleton, EmptyState } from '@/components/states'
import { AnalysesPage, AnalysisPage } from '@/pages/Analysis'
import { Overview } from '@/pages/Overview'
import { Upload } from '@/pages/Upload'

// chart-heavy pages load on demand
const TunnelPage = lazy(() => import('@/pages/Tunnel').then((m) => ({ default: m.TunnelPage })))
const ReplayPage = lazy(() => import('@/pages/Replay').then((m) => ({ default: m.ReplayPage })))
const ThreatsPage = lazy(() => import('@/pages/Threats').then((m) => ({ default: m.ThreatsPage })))
const LatestThreats = lazy(() => import('@/pages/Threats').then((m) => ({ default: m.LatestThreats })))
const ReportsPage = lazy(() => import('@/pages/Reports').then((m) => ({ default: m.ReportsPage })))
const ExecutiveReport = lazy(() => import('@/pages/Reports').then((m) => ({ default: m.ExecutiveReport })))
const TechnicalReport = lazy(() => import('@/pages/Reports').then((m) => ({ default: m.TechnicalReport })))
const LivePage = lazy(() => import('@/pages/Live').then((m) => ({ default: m.LivePage })))
const LiveSessionPage = lazy(() => import('@/pages/LiveSession').then((m) => ({ default: m.LiveSessionPage })))
const LiveSensorDocs = lazy(() => import('@/pages/Docs').then((m) => ({ default: m.LiveSensorDocs })))

function NotFound() {
  return <Card><EmptyState title="Page not found">Check the address, or go back to the overview.</EmptyState></Card>
}

export default function App() {
  return (
    <Suspense fallback={<div className="p-8"><CardSkeleton rows={6} /></div>}>
    <Routes>
      <Route path="/reports/:id/executive" element={<ExecutiveReport />} />
      <Route path="/reports/:id/technical" element={<TechnicalReport />} />
      <Route element={<AppShell />}>
        <Route index element={<Overview />} />
        <Route path="upload" element={<Upload />} />
        <Route path="analyses" element={<AnalysesPage />} />
        <Route path="analyses/:id" element={<AnalysisPage />} />
        <Route path="analyses/:id/tunnels/:idx" element={<TunnelPage />} />
        <Route path="analyses/:id/threats" element={<ThreatsPage />} />
        <Route path="threats" element={<LatestThreats />} />
        <Route path="replay" element={<ReplayPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="live" element={<LivePage />} />
        <Route path="live/:id" element={<LiveSessionPage />} />
        <Route path="docs/live-sensor" element={<LiveSensorDocs />} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
    </Suspense>
  )
}
