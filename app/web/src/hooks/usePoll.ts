import { useQuery } from '@tanstack/react-query'
import { api, type Analysis } from '@/lib/api'

// poll an analysis while it runs, backing off from 1 s to 8 s; stops when it is done or failed
export function useAnalysisPoll(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ['analysis', id],
    queryFn: () => api.analysis(id as string),
    enabled: !!id && enabled,
    refetchInterval: (q) => {
      const a = q.state.data as Analysis | undefined
      if (a && (a.status === 'done' || a.status === 'failed')) return false
      const n = q.state.dataUpdateCount
      return Math.min(8000, 1000 * 1.5 ** Math.min(n, 6))
    },
  })
}
