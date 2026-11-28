# Multi-Hop Chain Playbook
Tags: multihop, hop-checkpoint, composite-receipt, derived-custody, async-pivot
Summary: Verify multi-hop causal chains end-to-end with ctx.chain, sealed capability custody, and CompositeProofReceipt.

## 1. Checkpoint & Exploration Discipline
- With a `hopCheckpoint` (`doNotRediscover: true`), resume from `capabilityHandles[]` (`cap:hop_<id>:<slot>`) and advance `nextGoal`; skip `prunedBranches[]`.
- Explore with `http_request`/`kovo_http` first; never call `kovo_verify` solely to seal one hop. Run the full chain in one `kovo_verify` script ending in `ctx.chain(...).prove()` / `ctx.prove_composite`.

## 2. Derived Capability Custody & Helpers
- **Seal (`ctx.seal_capability`):** Assert `2xx` first; use `jsonPath`, `header`, `cookie`, or `value` (NEVER `regex`). Inject `cap:hop_<id>:<slot>` via `{ capability: { handle, target: "bearer" | "header" | "cookie" | "url" }, role: "probe" }` (omit `as` for minted bearer tokens).
- **Crypto (`ctx.hmac_sign` / `ctx.jwt_sign`):** Derive host-attested `derivedFromCapabilityId` signatures/tokens from sealed handles without exposing raw keys.
- **Async (`ctx.await_async`):** Poll `{ pollRequest, matchPredicate, triggerExchangeId, correlationId }` instead of sleep loops. **Accepted shapes:** `capability` takes the handle string or the sealed result (`.handle` is extracted); `exchange`/`exchangeId` take the HTTP exchange or its id (`.exchangeId` is extracted); `{ role: 'readback' }` inside a hop equals `ch.readback(...)`. Blank handles/exchange ids/load-bearing header names fail fast as `sdk_preflight[<code>]` (reported to host telemetry) — fix the argument, do not retry.

## 3. Connected `CompositeProofReceipt` DAG (`ctx.chain` / `ctx.prove_composite`)
Prefer `ctx.chain({ chainId, terminalVulnClass })` to auto-track hops, targets, and causal edges (`value_binding`, `derived_crypto_binding`, `state_transition_binding` with pre-mutation `{ arm: "control" }` `ablationExchangeIds` as the same actor, and `async_pivot_binding`):

```ts
const actor = 'actor_low'
const chain = ctx.chain({ chainId: 'chain-authz-1', terminalVulnClass: 'broken_access_control' })
const ctl = await ctx.http('/api/v1/terminal', { as: actor, arm: 'control' })
chain.control(ctl)
const cap = await chain.hop('hop_1', { claimedDelta: 'Obtained scoped capability.' }, async () => {
  const ex = await ctx.http_send('/api/v1/resource', { as: actor, role: 'probe' })
  if (!(ex.status >= 200 && ex.status < 300)) throw new Error(`Hop 1 failed: ${ex.status}`)
  return ctx.seal_capability({ exchange: ex, hopReceiptId: 'hop_1', slot: 'tok', jsonPath: '$.token', kind: 'bearer_token' })
})
const fin = await chain.hop('hop_2', { claimedDelta: 'Crossed terminal boundary via sealed capability.' }, () =>
  ctx.http_send('/api/v1/terminal', { capability: { handle: cap.handle, target: 'bearer' }, role: 'probe' }),
)
chain.readback(fin)
await chain.prove({ claimedImpact: 'Unauthorized cross-boundary access confirmed.' })
return ctx.result({ title: 'Multi-hop capability pivot' })
```
- Declare every causal hop from Hop 1 through `terminalHopId` connected via `causalEdges[]` (no orphan exploratory hops); with prerequisite setup hops, always finish with `ctx.chain(...).prove()` / `ctx.prove_composite` rather than standalone single-hop helpers.

## 4. Attacker-Origin Provenance & Clean Settlement
- **Attacker-Origin Provenance:** Start from a low-privilege attacker persona (or anonymous) and derive every downstream capability inside the DAG; reserve privileged/victim personas strictly for `{ arm: "control" }` baselines. Multi-tenant (dual-member) personas are hop-1 bases ONLY for cross-tenant ABAC classes — never for single-tenant BOLA/BFLA chains (provenance rejects them).
- **Terminal impact vs. quarantined capabilities:** Intermediate IDs, metadata, or handles remain `capability_only` — do not file standalone `CWE-200` when the downstream boundary holds.
- **Clean settlement:** When the terminal boundary enforces authorization or state invariants, stop retrying after failed controls and close cleanly with `record_coverage` (`ruled_out` with `enforcingControl`, or `needs_follow_up`) and `complete_intent`.

## 5. Negative-Effect Transitions (Revocation / Expiry / Downgrade / Rotation / Deletion)
- **Contract:** when the defect is that a negative-effect event (revoke, logout, expire, downgrade, rotate, remove/delete) **fails to invalidate prior access**, MUST prove it with `accessDifferential({ baseline, revocation, control, variant })` (`temporal_revocation` family, spread into `ch.prove`) — one credential lineage, in order: `baseline` = credential accepted pre-event (2xx); `revocation` = the mutating event (non-GET 2xx); `control` = clean **denied** terminal check after the event on the primary surface; `variant` = same credential, after `control`, still accepted on a distinct secondary surface.
- **NEVER `state_transition_binding` ablation here:** ablation expects removing the precondition to make the terminal step fail — inverted for revocation/stale-privilege defects. `variant` denied → `ruled_out` (`enforcingControl`); no surface denies the revoked credential → `needs_follow_up`.
```ts
import { accessDifferential } from 'kovo_verify'
const ch = ctx.chain({ chainId: 'chain-revocation-1', terminalVulnClass: 'temporal_revocation' }), use = (handle: string, role: 'setup' | 'control' | 'probe', method = 'GET') => ({ capability: { handle, target: 'bearer' as const }, role, method })
const cap = await ch.hop('hop_1', { claimedDelta: 'Issued a scoped credential to the low-privilege actor.' }, async () => ctx.seal_capability({ exchange: await ctx.http_send('/api/v1/tokens', { as: 'actor_low', method: 'POST', role: 'probe' }), hopReceiptId: 'hop_1', slot: 'tok', jsonPath: '$.token', kind: 'api_token' }))
const baseline = await ctx.http_send('/api/v1/resource', use(cap.handle, 'control')), revocation = await ctx.http_send('/api/v1/tokens/current', use(cap.handle, 'setup', 'DELETE')), control = await ctx.http_send('/api/v1/resource', use(cap.handle, 'control'))
const variant = await ch.hop('hop_2', { claimedDelta: 'Revoked credential still accepted on a secondary surface.' }, () => ctx.http_send('/api/v1/export', use(cap.handle, 'probe'))); await ch.prove({ ...accessDifferential({ baseline, revocation, control, variant, credentialKind: 'token' }), claimedImpact: 'Revoked credential still grants access.' }); return ctx.result({ title: 'Revocation does not invalidate prior access' })
```
