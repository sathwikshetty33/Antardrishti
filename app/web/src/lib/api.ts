// the api client: every number the ui shows comes from these endpoints (app/api/index.py)
import { upload as blobUpload } from '@vercel/blob/client'

export type Fact = { value: unknown; confidence: number | null; source: 'read from IKE' | 'observed' | 'inferred' }
export type Risk = { score: number; band: string; breakdown: Record<string, number | string> }
export type Share = {
  app: string; byte_share: number; byte_rounded: number; error_pp: number | null
  active_share: number | null; active_rounded: number | null
}
export type Window = {
  t: number; pair: number; esp_bytes: number; packets: number; present: string[]
  presence_probability: Record<string, number>; share: Record<string, number>
}
export type Evidence = { fact: string; value: unknown; source: string; confidence: number | null }
export type Finding = {
  id: number; tunnel: number | null; check_id: string; title: string
  verdict: 'pass' | 'fail' | 'warn' | 'info' | 'not determinable'
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'; standard: string[]; evidence: Evidence[]
  confidence: number | null; text: string; recommendation: string; threats: string[]
}
export type Tunnel = {
  idx: number; initiator: string | null; responder: string[]; direction_from: string; handshake_status: string
  esp_packets: number; start_s: number | null; end_s: number | null; has_traffic: boolean
  esp_suite_probabilities: Record<string, number> | null; facts: Record<string, Fact>; shares: Share[]
  risk: Risk | null; windows?: Window[]; findings?: Finding[]
}
export type Analysis = {
  id: string; created_at: string | null; finished_at: string | null
  status: 'pending' | 'queued' | 'running' | 'replaying' | 'done' | 'failed'; progress: number; stage: string
  error: string | null; source: 'upload' | 'demo' | 'replay'; name: string; size_bytes: number
  bundle_version: string; schema_version: string; timings: Record<string, number>; risk: number | null
  risk_band: string | null; replay: { demo: string; step: number; steps: number; t: number; packets: number } | null
  tunnel_count: number; packets: number | null
}
export type Threat = {
  threat_id: string; threat: string; likelihood: number; impact: number; tunnels: number[]; findings: string[]
}
export type Model = {
  version: string; commit: string; dir: string; seed: number; models: number; apps: string[]; suites: string[]
  results: Record<string, unknown> | null; data_releases: string[]; schema_version: string
  rules: { id: string; title: string; standard: string[] }[]; weights: Record<string, number>
  critical_floor: number; confident: number; threats: Record<string, { threat: string; impact: number }>
}
export type Config = {
  storage: 'blob' | 'local'; upload_limit_mb: number; max_pcap_mb: number; access_key_required: boolean
  blob_access: string; replay_chunk_s: number; schema_version: string
}
export type Demo = { name: string; title: string; description: string; bytes: number; packets: number; duration_s: number; steps: number }
export type Overview = {
  recent: Analysis[]; alerts: (Finding & { analysis_id: string; analysis: string })[]
  inventory: {
    analysis_id: string; analysis: string; created_at: string; idx: number; initiator: string | null
    responder: string[]; handshake_status: string; esp_packets: number; esp_suite?: Fact; mode?: Fact
    ike_version?: Fact; risk: Risk | null
  }[]
  overall: { score: number | null; rule: string }; analyses_done: number
}
export type Report = {
  analysis: Analysis; overall: Risk | null; tunnels: Tunnel[]; findings: Finding[]; threats: Threat[]; model: Model
  counts: Record<string, unknown>; inputs: string[]
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

export function accessKey() {
  try {
    return localStorage.getItem('antar-access-key') || ''
  } catch {
    return ''
  }
}

export function setAccessKey(k: string) {
  try {
    localStorage.setItem('antar-access-key', k)
  } catch {
    // the key then lasts only for this page
  }
}

function headers(extra: Record<string, string> = {}) {
  const k = accessKey()
  return { ...(k ? { 'x-access-key': k } : {}), ...extra }
}

async function call<T>(path: string, init: RequestInit = {}): Promise<T> {
  const r = await fetch(path, { ...init, headers: headers((init.headers as Record<string, string>) || {}) })
  if (!r.ok) {
    let msg = `${r.status} ${r.statusText}`
    try {
      const j = await r.json()
      msg = typeof j.detail === 'string' ? j.detail : JSON.stringify(j.detail ?? j)
    } catch {
      // not json
    }
    throw new ApiError(r.status, msg)
  }
  return r.json() as Promise<T>
}

const post = <T>(path: string, body: unknown) =>
  call<T>(path, { method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json' } })

export const api = {
  health: () => call<{ ok: boolean; db: string; bundle: string; storage: string }>('/api/health'),
  model: () => call<Model>('/api/model'),
  config: () => call<Config>('/api/config'),
  overview: () => call<Overview>('/api/overview'),
  analyses: () => call<Analysis[]>('/api/analyses'),
  analysis: (id: string) => call<Analysis>(`/api/analyses/${id}`),
  tunnels: (id: string) => call<Tunnel[]>(`/api/analyses/${id}/tunnels`),
  tunnel: (id: string, idx: number) => call<Tunnel>(`/api/analyses/${id}/tunnels/${idx}`),
  findings: (id: string) => call<Finding[]>(`/api/analyses/${id}/findings`),
  threats: (id: string) => call<{ threats: Threat[] }>(`/api/analyses/${id}/threats`),
  report: (id: string) => call<Report>(`/api/analyses/${id}/report`),
  demos: () => call<Demo[]>('/api/demos'),
  start: (body: { id: string; uploads?: { url: string; name: string }[]; demo?: string }) =>
    post<Analysis>('/api/analyses', body),
  replayStart: (demo: string) => post<Analysis>('/api/replays', { demo }),
  replayNext: (id: string) => post<Analysis>(`/api/replays/${id}/next`, {}),
}

// upload one capture: straight to vercel blob (client upload), or to the local api in local mode
export async function uploadCapture(file: File, cfg: Config, onProgress: (frac: number) => void) {
  if (file.size > cfg.upload_limit_mb * 2 ** 20) {
    throw new ApiError(413, `${file.name} is ${(file.size / 2 ** 20).toFixed(1)} MB; the limit is ${cfg.upload_limit_mb} MB`)
  }
  if (cfg.storage === 'blob') {
    const b = await blobUpload(`captures/${file.name}`, file, {
      access: cfg.blob_access === 'public' ? 'public' : 'private',
      handleUploadUrl: '/api/uploads',
      headers: headers(),
      multipart: file.size > 8 * 2 ** 20,
      onUploadProgress: (e) => onProgress(e.percentage / 100),
    })
    return { url: b.url, name: file.name }
  }
  return new Promise<{ url: string; name: string }>((resolve, reject) => {
    const x = new XMLHttpRequest()
    x.open('PUT', `/api/uploads/local/${encodeURIComponent(file.name)}`)
    for (const [k, v] of Object.entries(headers())) x.setRequestHeader(k, v)
    x.upload.onprogress = (e) => e.lengthComputable && onProgress(e.loaded / e.total)
    x.onload = () => {
      if (x.status >= 200 && x.status < 300) {
        const j = JSON.parse(x.responseText)
        resolve({ url: j.url, name: file.name })
      } else {
        let msg = `${x.status}`
        try {
          msg = JSON.parse(x.responseText).detail
        } catch {
          // keep status
        }
        reject(new ApiError(x.status, msg))
      }
    }
    x.onerror = () => reject(new ApiError(0, 'network error during upload'))
    x.send(file)
  })
}
