import { AnimatePresence, motion } from 'framer-motion'
import { X } from 'lucide-react'
import { SeverityBadge } from '@/components/badges'
import { dismiss, useToasts } from '@/lib/toast'

// the toasts raised with toast() (lib/toast.ts), bottom right
export function Toaster() {
  const list = useToasts()
  return (
    <div className="no-print pointer-events-none fixed bottom-4 right-4 z-50 flex w-[min(92vw,380px)] flex-col gap-2"
      role="status" aria-live="polite">
      <AnimatePresence initial={false}>
        {list.map((t) => (
          <motion.div key={t.id} layout initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, x: 24 }}
            transition={{ duration: 0.2 }} className="pointer-events-auto rounded-[12px] border border-border bg-surface p-3 shadow-2xl">
            <div className="flex items-start gap-3">
              {t.severity ? <SeverityBadge severity={t.severity} /> : null}
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium">{t.title}</p>
                {t.description ? <p className="mt-0.5 text-xs text-text-2">{t.description}</p> : null}
              </div>
              <button type="button" onClick={() => dismiss(t.id)} aria-label="Dismiss"
                className="cursor-pointer rounded-md p-1 text-text-2 hover:bg-surface-2 hover:text-text">
                <X className="size-4" />
              </button>
            </div>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  )
}
