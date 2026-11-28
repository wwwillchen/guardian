// Micro-interaction primitives ([U20]): a warm-up tooltip group over
// @base-ui/react Tooltip and a mouse-only sliding hover highlight for nav lists.
//
// Tooltips: mount ONE <TooltipProvider> around a surface (AppShell, run Rail).
// Individual tooltips never carry their own provider, so siblings share the
// warm-up group: the first label waits `delay` (500ms) and fades + scales in
// over 125ms; any sibling hovered within `timeout` (300ms) of the last close
// opens at once with no transition (`data-instant`), and every label hides the
// instant the pointer leaves (closeDelay 0, no exit transition, not hoverable).
import { Tooltip as BaseTooltip } from '@base-ui/react/tooltip'
import { useCallback, useEffect, useRef, useState } from 'react'
import type { CSSProperties, PointerEvent as ReactPointerEvent, ReactElement, ReactNode } from 'react'
import { cn } from '../../lib/cn.ts'

export const TOOLTIP_DELAY_MS = 500
export const TOOLTIP_WARM_TIMEOUT_MS = 300

export function TooltipProvider({
  delay = TOOLTIP_DELAY_MS,
  timeout = TOOLTIP_WARM_TIMEOUT_MS,
  children,
}: {
  delay?: number
  timeout?: number
  children: ReactNode
}) {
  return <BaseTooltip.Provider delay={delay} timeout={timeout} closeDelay={0}>{children}</BaseTooltip.Provider>
}

/** Tooltip root. Labels are never hoverable, so leaving the trigger hides them at once. */
export function Tooltip({ disableHoverablePopup = true, ...props }: BaseTooltip.Root.Props) {
  return <BaseTooltip.Root disableHoverablePopup={disableHoverablePopup} {...props} />
}

export function TooltipTrigger(props: BaseTooltip.Trigger.Props) {
  return <BaseTooltip.Trigger data-slot="tooltip-trigger" {...props} />
}

// Tailwind v4 `scale-*` sets the individual `scale` property, so the transition
// lists `scale` (never `transform`). Warm (`data-instant`) opens and every exit
// skip the transition entirely; app.css drops the scale under reduced motion.
const TOOLTIP_MOTION = [
  'origin-[var(--transform-origin)] transition-[opacity,scale] duration-[125ms] ease-kovo',
  'data-[starting-style]:scale-[.97] data-[starting-style]:opacity-0',
  'data-[ending-style]:opacity-0 data-[ending-style]:transition-none data-[ending-style]:duration-0',
  'data-[instant]:transition-none data-[instant]:duration-0',
].join(' ')

export function TooltipContent({
  side = 'top',
  align = 'center',
  sideOffset = 6,
  className,
  children,
  ...props
}: BaseTooltip.Popup.Props & {
  side?: BaseTooltip.Positioner.Props['side']
  align?: BaseTooltip.Positioner.Props['align']
  sideOffset?: number
}) {
  return (
    <BaseTooltip.Portal>
      <BaseTooltip.Positioner side={side} align={align} sideOffset={sideOffset} className="z-[70]">
        <BaseTooltip.Popup
          data-slot="tooltip-content"
          className={cn(
            'pointer-events-none flex max-w-[280px] items-center gap-2 rounded-[6px] bg-raise px-2 py-[3px] text-[11.5px] font-medium leading-4 text-fg shadow-popover',
            TOOLTIP_MOTION,
            className,
          )}
          {...props}
        >
          {children}
        </BaseTooltip.Popup>
      </BaseTooltip.Positioner>
    </BaseTooltip.Portal>
  )
}

/**
 * One-line label for an icon-only or compact control. `children` is the
 * trigger element itself (button or router link); drop its native `title`
 * so the OS tooltip never doubles up. `shortcut` renders as a quiet suffix.
 */
export function HintTooltip({ label, shortcut, side, align, children }: {
  label: ReactNode
  shortcut?: string
  side?: BaseTooltip.Positioner.Props['side']
  align?: BaseTooltip.Positioner.Props['align']
  children: ReactElement<Record<string, unknown>>
}) {
  return (
    <Tooltip>
      <TooltipTrigger render={children} />
      <TooltipContent side={side} align={align}>
        <span className="min-w-0">{label}</span>
        {shortcut ? <span className="flex-none font-normal tabular-nums text-fg-subtle" data-slot="tooltip-shortcut">{shortcut}</span> : null}
      </TooltipContent>
    </Tooltip>
  )
}

// ---------------------------------------------------------------------------
// Mouse-only hover highlight
// ---------------------------------------------------------------------------

/** iOS/Android fire an emulated `pointerType: "mouse"` enter right after a tap. */
export const SYNTHETIC_MOUSE_AFTER_TOUCH_MS = 100

export interface HoverBox {
  y: number
  height: number
}

interface HoverHighlightState {
  box: HoverBox | null
  visible: boolean
  glide: boolean
}

const HIDDEN: HoverHighlightState = { box: null, visible: false, glide: false }

/** Hover UI only follows a real mouse, never touch/pen or the mouse emulated after a tap. */
export function isMouseHover(pointerType: string, at: number, lastTouchAt: number): boolean {
  return pointerType === 'mouse' && at - lastTouchAt > SYNTHETIC_MOUSE_AFTER_TOUCH_MS
}

/** GPU-composited placement: `translate3d` for position, height set without transition. */
export function hoverHighlightStyle(box: HoverBox | null): CSSProperties {
  return box ? { height: `${box.height}px`, transform: `translate3d(0, ${box.y}px, 0)` } : {}
}

/** Row under the pointer; gaps and padding between rows keep the current one (no flicker). */
function hoverItemAt(list: HTMLElement, target: EventTarget | null): Element | null {
  if (!(target instanceof Element)) return null
  const item = target.closest('[data-hover-item]')
  return item && list.contains(item) ? item : null
}

function measureItem(list: HTMLElement, item: Element): HoverBox {
  const listRect = list.getBoundingClientRect()
  const rect = item.getBoundingClientRect()
  return { y: Math.round(rect.top - listRect.top), height: Math.round(rect.height) }
}

/**
 * Sliding hover highlight for a vertical nav list. Spread `listProps` on the
 * list, render `highlight` as its first child and mark rows `data-hover-item`.
 * Mouse-only (touch, pen and post-tap emulated mouse never light it), cleared
 * on pointer leave and on any key press so keyboard users never see a stale
 * hover; it appears in place (no travel) and only glides between rows.
 * app.css hides it unless `(hover: hover) and (pointer: fine)` and reduced
 * motion snaps the glide.
 */
export function useMouseHoverHighlight() {
  const itemRef = useRef<Element | null>(null)
  const lastTouchRef = useRef(Number.NEGATIVE_INFINITY)
  const [state, setState] = useState<HoverHighlightState>(HIDDEN)

  const clear = useCallback(() => {
    itemRef.current = null
    setState(s => (s.visible ? { ...s, visible: false, glide: false } : s))
  }, [])

  useEffect(() => {
    window.addEventListener('keydown', clear, true)
    return () => window.removeEventListener('keydown', clear, true)
  }, [clear])

  const onPointerMove = useCallback((e: ReactPointerEvent<HTMLElement>) => {
    if (!isMouseHover(e.pointerType, e.timeStamp, lastTouchRef.current)) return
    const item = hoverItemAt(e.currentTarget, e.target)
    if (!item || item === itemRef.current) return
    const glide = itemRef.current !== null
    itemRef.current = item
    setState({ box: measureItem(e.currentTarget, item), visible: true, glide })
  }, [clear])

  const onNonMousePointer = useCallback((e: ReactPointerEvent<HTMLElement>) => {
    if (e.pointerType === 'mouse') return
    lastTouchRef.current = e.timeStamp
    clear()
  }, [clear])

  const listProps = {
    'data-hover-list': '',
    onPointerMove,
    onPointerDown: onNonMousePointer,
    onPointerUp: onNonMousePointer,
    onPointerLeave: clear,
  }
  const highlight = (
    <span
      aria-hidden="true"
      data-slot="hover-highlight"
      data-visible={state.visible ? '' : undefined}
      data-glide={state.glide ? '' : undefined}
      style={hoverHighlightStyle(state.box)}
    />
  )
  return { listProps, highlight, hovering: state.visible }
}
