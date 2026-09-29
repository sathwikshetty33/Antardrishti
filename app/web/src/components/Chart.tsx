import { BarChart, LineChart } from 'echarts/charts'
import { DataZoomComponent, GridComponent, LegendComponent, MarkAreaComponent, TooltipComponent } from 'echarts/components'
import * as echarts from 'echarts/core'
import { SVGRenderer } from 'echarts/renderers'
import core from 'echarts-for-react/lib/core'
import { useThemeKey } from '@/lib/chart'

// the package is commonjs: under esm interop its default export can arrive wrapped
const ReactECharts = ((core as unknown as { default?: typeof core }).default ?? core) as typeof core

echarts.use([BarChart, LineChart, GridComponent, TooltipComponent, LegendComponent, DataZoomComponent, MarkAreaComponent, SVGRenderer])

export function Chart({ option, height = 260, label }: { option: object; height?: number; label: string }) {
  const k = useThemeKey()
  return (
    <div role="img" aria-label={label}>
      <ReactECharts
        key={k}
        echarts={echarts}
        option={option}
        style={{ height, width: '100%' }}
        opts={{ renderer: 'svg' }}
        notMerge
        lazyUpdate
      />
    </div>
  )
}
