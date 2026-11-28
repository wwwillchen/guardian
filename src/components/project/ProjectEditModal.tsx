import { useEffect, useRef, useState } from 'react'
import { updateProjectAction } from '../../actions.ts'
import { FormError, useAction } from '../common.tsx'
import { Icon } from '../run/icons.tsx'
import { Button } from '../ui/button.tsx'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/dialog.tsx'
import { Input, NativeSelect } from '../ui/input.tsx'
import { mergeOrigins, OriginChipInput, summarizeOrigins } from './OriginChipInput.tsx'
import type { ProjectLoaderData } from './types.ts'

interface Props {
  open: boolean
  project: ProjectLoaderData['project']
  onClose: () => void
  onSaved?: () => void
}

export function ProjectEditModal({ open, project, onClose, onSaved }: Props) {
  const [name, setName] = useState(() => project.name)
  const [environment, setEnvironment] = useState<'public' | 'local-lab'>(() => project.environment)
  const [seeds, setSeeds] = useState<string[]>(() => mergeOrigins([], project.seeds))
  const action = useAction()
  const nameRef = useRef<HTMLInputElement | null>(null)

  useEffect(() => {
    if (!open) return
    setName(project.name)
    setEnvironment(project.environment)
    setSeeds(mergeOrigins([], project.seeds))
  }, [open, project.id, project.name, project.environment, project.seeds])

  const parsedSeeds = seeds
  const invalidSeeds = summarizeOrigins(seeds).invalidTokens
  const nameMissing = !name.trim()
  const switchingToPublicWithLab = project.environment === 'local-lab' && environment === 'public' && Boolean(project.labConfig)

  return (
    <Dialog
      open={open}
      closeOnEscape={!action.pending}
      onOpenChange={nextOpen => {
        if (!nextOpen && !action.pending) {
          onClose()
        }
      }}
    >
      <DialogContent
        aria-label="Edit project"
        initialFocus={nameRef}
        className="mb-auto mt-[min(12vh,96px)] flex max-h-[calc(100vh-min(12vh,96px)-32px)] max-w-[520px] flex-col overflow-hidden rounded-2xl border-line-2 bg-panel p-0"
      >
        <form
          className="flex min-h-0 flex-1 flex-col"
          onSubmit={event => {
            event.preventDefault()
            if (nameMissing || parsedSeeds.length === 0 || invalidSeeds.length > 0) return
            void action.submit(() => updateProjectAction({
              data: {
                requestId: crypto.randomUUID(),
                projectId: project.id,
                name: name.trim(),
                environment,
                seeds: parsedSeeds,
              },
            }), () => {
              onSaved?.()
              onClose()
            })
          }}
        >
          <DialogHeader className="flex-row items-center justify-between gap-2.5 border-b border-line bg-raise px-4 py-2.5">
            <DialogTitle className="text-[13px] font-semibold text-fg">Edit project</DialogTitle>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="size-[26px]"
              disabled={action.pending}
              onClick={onClose}
              aria-label="Close"
            >
              <Icon name="close" size={14} />
            </Button>
          </DialogHeader>
          <DialogBody className="flex min-h-0 flex-1 flex-col gap-3.5 overflow-y-auto p-4">
            <label className="grid gap-1.5 text-[12px] font-medium text-fg-muted">
              Project name
              <Input
                ref={nameRef}
                className="w-full"
                name="name"
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="e.g. Acme Web"
                maxLength={160}
                required
                aria-invalid={nameMissing ? true : undefined}
                aria-describedby={nameMissing ? 'edit-project-name-err' : undefined}
                disabled={action.pending}
              />
              {nameMissing && (
                <span id="edit-project-name-err" className="form-error text-[11.5px] font-normal">
                  Name is required
                </span>
              )}
            </label>
            <OriginChipInput
              values={seeds}
              onChange={setSeeds}
              name="seeds"
              disabled={action.pending}
              placeholder={environment === 'local-lab' ? 'http://localhost:3000' : 'https://app.example.com'}
            />
            <label className="grid gap-1.5 text-[12px] font-medium text-fg-muted">
              Environment
              <NativeSelect
                className="w-full"
                name="environment"
                value={environment}
                disabled={action.pending}
                onChange={e => setEnvironment(e.target.value === 'local-lab' ? 'local-lab' : 'public')}
              >
                <option value="public">Public website</option>
                <option value="local-lab">Local lab (localhost / private staging)</option>
              </NativeSelect>
            </label>
            {switchingToPublicWithLab && (
              <p
                role="status"
                className="m-0 rounded-lg border border-warn-line bg-warn-soft px-3 py-2 text-[12px] text-fg"
              >
                Switching to a public project will clear this project&apos;s local lab configuration.
              </p>
            )}
            <FormError error={action.error} />
          </DialogBody>
          <DialogFooter>
            <Button
              type="button"
              variant="ghost"
              disabled={action.pending}
              onClick={onClose}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="default"
              disabled={action.pending || nameMissing || parsedSeeds.length === 0 || invalidSeeds.length > 0}
            >
              {action.pending ? 'Saving…' : 'Save changes'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
