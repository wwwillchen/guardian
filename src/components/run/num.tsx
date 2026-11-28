// <Num>: the one numeric primitive for run telemetry ([U7]). Every value renders with
// tabular figures and a `ch` min-width reservation so live ticks never jump or wrap; compact
// mode switches to "10.5k" / "1.0M" / "1.0B" above 9,999 and keeps the exact grouped value in
// the tooltip. Never prints NaN, undefined, null, "1000.0k" or a sliced digit.
import type { CSSProperties } from 'react'
import { fmtDur } from './format.ts'
import { cn } from './tw.ts'

export type NumKind = 'count' | 'usd' | 'ms' | 'turns' | 'pct' | 'rel' | 'tokens'

export interface FormattedNum {
  /** Rendered text ("1.0M"). */
  text: string
  /** Exact grouped value for the tooltip ("999,999"). Equals `text` when nothing was abbreviated. */
  exact: string
  /** `text` is an abbreviation of `exact`. */
  compacted: boolean
}

const GROUP = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 })
const GROUP_1 = new Intl.NumberFormat('en-US', { maximumFractionDigits: 1 })
const USD = new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' })
const EMPTY: FormattedNum = { text: '—', exact: '—', compacted: false }
/** Values above this switch to the compact form when `compact` is set. */
export const COMPACT_ABOVE = 9_999
const TIERS: [number, string][] = [[1e9, 'B'], [1e6, 'M'], [1e3, 'k']]

/**
 * Abbreviate |n| ≥ 1,000 to one decimal on the largest tier that does not round up to "1000.0":
 * 10,500 → "10.5k", 999,999 → "1.0M", 999,999,999 → "1.0B".
 */
export function compactNumber(n: number): string {
  const abs = Math.abs(n)
  if (abs < 1_000) return GROUP.format(n)
  let i = abs >= 1e9 ? 0 : abs >= 1e6 ? 1 : 2
  // Promote to the next tier when one-decimal rounding would read "1000.0k" / "1000.0M".
  while (i > 0 && Math.round(abs / TIERS[i]![0] * 10) / 10 >= 1_000) i -= 1
  return (n < 0 ? '-' : '') + (abs / TIERS[i]![0]).toFixed(1) + TIERS[i]![1]
}

/** Pure formatter behind `<Num>` (unit-tested; safe for any input). */
export function formatNum(value: number | null | undefined, kind: NumKind = 'count', opts: { compact?: boolean } = {}): FormattedNum {
  if (value == null || typeof value !== 'number' || !Number.isFinite(value)) return EMPTY
  const big = Math.abs(value) > COMPACT_ABOVE
  switch (kind) {
    case 'count':
    case 'turns': {
      const exact = GROUP.format(Math.round(value))
      return opts.compact && big ? { text: compactNumber(Math.round(value)), exact, compacted: true } : { text: exact, exact, compacted: false }
    }
    case 'tokens': {
      // Token totals always read compact ("1.0B"); the tooltip carries the grouped count.
      const exact = GROUP.format(Math.round(value)) + ' tokens'
      const text = Math.abs(value) < 1_000 ? GROUP.format(Math.round(value)) : compactNumber(Math.round(value))
      return { text, exact, compacted: Math.abs(value) >= 1_000 }
    }
    case 'usd': {
      const exact = value > 0 && value < 0.01 ? '<$0.01' : USD.format(value)
      if (!(opts.compact && big)) return { text: exact, exact, compacted: false }
      return { text: (value < 0 ? '-$' : '$') + compactNumber(Math.abs(value)), exact, compacted: true }
    }
    case 'pct': {
      // Ratio in, percent out: 0.452 → "45%" (exact "45.2%"). Clamped so a stale denominator never reads "-3%".
      const p = Math.max(0, value) * 100
      const exact = GROUP_1.format(p) + '%'
      const text = (p > 0 && p < 1 ? '<1' : GROUP.format(Math.floor(p + 1e-9))) + '%'
      return { text, exact, compacted: text !== exact }
    }
    case 'ms': {
      const exact = GROUP.format(Math.round(value)) + ' ms'
      if (!opts.compact || Math.abs(value) < 1_000) return { text: exact, exact, compacted: false }
      const text = Math.abs(value) < 60_000 ? (value / 1000).toFixed(1) + 's' : fmtDur(value)
      return { text, exact, compacted: true }
    }
    case 'rel': {
      const text = fmtDur(Math.max(0, value))
      return { text, exact: text, compacted: false }
    }
    default: {
      const never: never = kind
      return never
    }
  }
}

/** Width (in `ch`) a value needs; `max` reserves the widest value the slot will ever show. */
export function numWidthCh(value: number | null | undefined, kind: NumKind, opts: { compact?: boolean; max?: number } = {}): number {
  const own = formatNum(value, kind, opts).text.length
  const widest = opts.max == null ? 0 : formatNum(opts.max, kind, opts).text.length
  return Math.max(own, widest, 1)
}

export function Num({ value, kind = 'count', compact, max, unit, title, className, style }: {
  value: number | null | undefined
  kind?: NumKind
  compact?: boolean
  /** Reserve room for this value so the slot never grows as the number climbs. */
  max?: number
  unit?: string
  title?: string
  className?: string
  style?: CSSProperties
}) {
  const f = formatNum(value, kind, { compact })
  const ch = numWidthCh(value, kind, { compact, max })
  const tip = title ?? (f.compacted ? f.exact : undefined)
  // Inline (not flex) so the unit keeps a real space in text content: "999,999 req" copies and reads correctly.
  return <span className={cn('whitespace-nowrap tabular-nums', className)} title={tip} data-num={kind} style={style}>
    <span className="inline-block text-right" style={{ minWidth: `${ch}ch` }}>{f.text}</span>
    {unit ? <span className="text-fg-subtle">{' ' + unit}</span> : null}
  </span>
}
