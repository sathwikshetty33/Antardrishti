import { Chart } from '@/components/Chart'
import { axisStyle, tooltipStyle } from '@/lib/chart'
import type { Window } from '@/lib/api'
import { appColor, appLabel, apps, token } from '@/lib/colors'
import { bytes } from '@/lib/format'

// per-window esp bytes split by the predicted shares (stacked), and per-app presence probability
export function WindowTimeline({ windows, height = 300 }: { windows: Window[]; height?: number }) {
  const ws = [...windows].sort((a, b) => a.t - b.t)
  const x = ws.map((w) => w.t)
  const names = [...apps, 'unknown'] as string[]
  const bar = names.map((n) => ({
    name: appLabel[n], type: 'bar', stack: 'b', barCategoryGap: '12%', xAxisIndex: 0, yAxisIndex: 0,
    itemStyle: { color: appColor(n) }, emphasis: { focus: 'series' },
    data: ws.map((w) => Math.round(w.esp_bytes * (w.share[n] ?? 0))),
  }))
  const line = apps.filter((a) => ws.some((w) => (w.presence_probability[a] ?? 0) > 0.2)).map((a) => ({
    name: appLabel[a], type: 'line', xAxisIndex: 1, yAxisIndex: 1, showSymbol: false, smooth: 0.2,
    lineStyle: { width: 2, color: appColor(a) }, itemStyle: { color: appColor(a) },
    data: ws.map((w) => +(w.presence_probability[a] ?? 0).toFixed(3)),
  }))
  const ax = axisStyle()
  const option = {
    animationDuration: 400,
    tooltip: { trigger: 'axis', ...tooltipStyle(), valueFormatter: (v: number) => (v <= 1 ? `${Math.round(v * 100)}%` : bytes(v)) },
    legend: { top: 0, textStyle: { color: token('text-2'), fontSize: 11 }, itemWidth: 10, itemHeight: 10, icon: 'roundRect' },
    grid: [{ left: 56, right: 16, top: 34, height: '46%' }, { left: 56, right: 16, top: '68%', bottom: 26 }],
    xAxis: [
      { type: 'category', data: x, gridIndex: 0, ...ax, axisLabel: { show: false } },
      { type: 'category', data: x, gridIndex: 1, ...ax, axisLabel: { ...ax.axisLabel, formatter: (v: string) => `${v}s` } },
    ],
    yAxis: [
      { type: 'value', gridIndex: 0, name: 'ESP bytes', ...ax, axisLabel: { ...ax.axisLabel, formatter: (v: number) => bytes(v) } },
      { type: 'value', gridIndex: 1, min: 0, max: 1, name: 'presence', ...ax, axisLabel: { ...ax.axisLabel, formatter: (v: number) => `${v * 100}%` } },
    ],
    series: [...bar, ...line],
  }
  return <Chart option={option} height={height} label={`Window timeline of ${ws.length} two-second windows`} />
}
