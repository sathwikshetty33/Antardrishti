import * as D from '@radix-ui/react-dialog'
import { X } from 'lucide-react'
import * as React from 'react'

export function Sheet({ open, onOpenChange, title, description, children }: {
  open: boolean; onOpenChange: (o: boolean) => void; title: React.ReactNode; description?: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <D.Root open={open} onOpenChange={onOpenChange}>
      <D.Portal>
        <D.Overlay className="fixed inset-0 z-40 bg-black/50 data-[state=open]:animate-in" />
        <D.Content className="fixed inset-y-0 right-0 z-50 flex w-full max-w-lg flex-col border-l border-border bg-surface shadow-2xl focus:outline-none">
          <div className="flex items-start justify-between gap-4 border-b border-border px-6 py-4">
            <div>
              <D.Title className="text-base font-semibold">{title}</D.Title>
              {description ? <D.Description className="mt-1 text-xs text-text-2">{description}</D.Description> : null}
            </div>
            <D.Close className="rounded-md p-1 text-text-2 hover:bg-surface-2 hover:text-text cursor-pointer" aria-label="Close">
              <X className="size-4" />
            </D.Close>
          </div>
          <div className="flex-1 overflow-y-auto px-6 py-5">{children}</div>
        </D.Content>
      </D.Portal>
    </D.Root>
  )
}

export function Modal({ open, onOpenChange, title, children }: {
  open: boolean; onOpenChange: (o: boolean) => void; title: React.ReactNode; children: React.ReactNode
}) {
  return (
    <D.Root open={open} onOpenChange={onOpenChange}>
      <D.Portal>
        <D.Overlay className="fixed inset-0 z-40 bg-black/50" />
        <D.Content className="fixed left-1/2 top-1/2 z-50 w-[min(92vw,440px)] -translate-x-1/2 -translate-y-1/2 rounded-[12px] border border-border bg-surface p-6 shadow-2xl focus:outline-none">
          <D.Title className="text-base font-semibold">{title}</D.Title>
          <D.Description className="sr-only">dialog</D.Description>
          <div className="mt-4">{children}</div>
        </D.Content>
      </D.Portal>
    </D.Root>
  )
}
