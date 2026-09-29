import { Check, Copy } from 'lucide-react'
import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

async function copyText(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

export function CopyButton({ text, label = 'Copy', className }: { text: string; label?: string; className?: string }) {
  const [done, setDone] = useState<boolean | null>(null)
  const click = async () => {
    setDone(await copyText(text))
    setTimeout(() => setDone(null), 1600)
  }
  return (
    <Button type="button" size="sm" variant="ghost" className={className} onClick={click} aria-label={`${label} (to the clipboard)`}>
      {done ? <Check /> : <Copy />}
      {done ? 'Copied' : done === false ? 'Select and copy' : label}
    </Button>
  )
}

// a command or value in a copyable block (commands, keys, links)
export function CodeBlock({ code, label = 'shell', className }: { code: string; label?: string; className?: string }) {
  return (
    <div className={cn('rounded-lg border border-border bg-surface-2', className)}>
      <div className="flex items-center justify-between gap-2 border-b border-border py-1 pl-3 pr-1">
        <span className="text-[11px] text-muted">{label}</span>
        <CopyButton text={code} />
      </div>
      <pre className="num overflow-x-auto whitespace-pre px-3 py-2.5 text-xs leading-relaxed text-text"><code>{code}</code></pre>
    </div>
  )
}
