/**
 * Stream R3 — Lever 3: SDK & skill alignment with verification contracts (fast, hermetic, behavioral).
 *
 * Exercises `worker/kovo_verify/kovo_verify.ts` against a lightweight mock Unix-socket RPC host:
 *   1. `role: 'readback'` is normalized to a clean control-arm readback and lands in the chain readback slot.
 *   2. Sealed capability objects (`{ handle, ... }`) are unwrapped to `.handle`; blank/malformed handles fail fast.
 *   3. HTTP exchange objects (`{ exchangeId, ... }`) are unwrapped to `.exchangeId` in `seal_capability` and siblings;
 *      missing ids and capabilities passed as exchanges fail fast.
 *   4. Blank/whitespace `headerName` is omitted when unused and rejected with an actionable diagnostic when load-bearing.
 *   5. Every SDK preflight rejection is reported as structured host telemetry (stderr line + result.json fields)
 *      without weakening the rejection itself (no RPC is sent, the call still throws).
 *   6. Prompt/tool/skill contracts: persona base rules and the negative-effect (`temporal_revocation`) skill recipe
 *      behave as documented when built/executed.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test, { type TestContext } from 'node:test'
import ts from 'typescript'
import {
  KOVO_VERIFY_HELPER_GUIDANCE_MAX_BYTES,
  KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN,
  kovoVerifyHelperGuidance,
} from '../src/server/agent-prompts.ts'
import { buildExploiterSystemPrompt, buildExploiterUserPrompt } from '../src/server/exploiter-tools.ts'
import { clearSkillsCache, loadSkill } from '../src/server/skills.ts'
import {
  KovoSdkPreflightError,
  SDK_PREFLIGHT_STDERR_TAG,
  VerifyContext,
  accessDifferential,
  normalizeHeaderName,
  preflightCapabilityInjection,
  preflightHttpShape,
  resolveExchangeIdArg,
  runVerification,
  type HttpExchange,
  type SdkPreflightCode,
  type SdkPreflightRecord,
} from '../worker/kovo_verify/kovo_verify.ts'

const ORIGIN = 'http://app.r3.test'
const ENV_KEYS = ['KOVO_RPC_CONTEXT_FILE', 'KOVO_RPC_TOKEN_FILE', 'KOVO_RPC_SOCKET', 'KOVO_VERIFY_NONCE', 'KOVO_PROOF_RESULT_FILE'] as const

interface RpcCall { op: string; args: Record<string, unknown> }
interface MockExchange { path: string; method: string; status: number }
interface MockHost { calls: RpcCall[]; ctx: VerifyContext; dir: string; receipts: Record<string, unknown>[]; exchanges: Map<string, MockExchange>; ops: (op: string) => RpcCall[] }

/** Minimal host: echoes HTTP exchanges (status by route), seals `cap:hop_<id>:<slot>`, signs, and records composite receipts. */
async function startMockHost(t: TestContext): Promise<MockHost> {
  const dir = mkdtempSync(join(tmpdir(), 'r3sdk-'))
  const socketPath = join(dir, 'rpc.sock')
  writeFileSync(join(dir, 'context.json'), JSON.stringify({ nonce: 'nonce-r3', runId: 'run-r3', targetOrigins: [ORIGIN], sdkVersion: 'kovo_verify/v8' }))
  writeFileSync(join(dir, 'token'), 'rpc-token-r3')
  const calls: RpcCall[] = [], receipts: Record<string, unknown>[] = [], exchanges = new Map<string, MockExchange>()
  let seq = 0, revoked = false
  const exchange = (args: Record<string, unknown>): HttpExchange => {
    const path = String(args.path ?? '/'), method = String(args.method ?? 'GET')
    if (path === '/api/v1/tokens/current' && method === 'DELETE') revoked = true
    const status = path.includes('/denied') || (revoked && path === '/api/v1/resource') ? 403 : 200
    const body = JSON.stringify(path === '/api/v1/tokens' ? { token: 'opaque-r3-credential-7f3a9c' } : { ok: status === 200 }), exchangeId = `ex_${++seq}`
    exchanges.set(exchangeId, { path, method, status })
    return { exchangeId, status, method, pathAndQuery: path, mediaType: 'application/json', headers: { 'content-type': 'application/json' }, body, text: body, json: null, data: null, bodyPreview: body.slice(0, 64), bodyBytes: body.length, bodySha256: '0'.repeat(64), durationMs: 1, personaHandle: typeof args.persona === 'string' ? args.persona : null, ...(typeof args.capability === 'string' ? { consumedCapabilityId: args.capability } : args.capability && typeof args.capability === 'object' ? { consumedCapabilityId: String((args.capability as Record<string, unknown>).handle) } : {}) }
  }
  const respond = (op: string, args: Record<string, unknown>): unknown => {
    if (op === 'http' || op === 'http.send') return exchange(args)
    if (op === 'capability.seal') return { handle: `cap:hop_${String(args.hopReceiptId ?? 'x')}:${String(args.slot)}`, meta: {}, exchangeId: args.exchangeId, sealExchangeId: `seal_${++seq}`, scrubbedPreview: '' }
    if (op === 'crypto.hmacSign') return { exchangeId: `ex_${++seq}`, signature: 'cap:derived_sig_r3', handle: 'cap:derived_sig_r3', derivedHandle: 'cap:derived_sig_r3', attestation: { derivedFromCapabilityId: args.secretHandle, alg: 'sha256', encoding: 'hex', payloadDigest: '', signatureDigest: '', sourceSecretDigest: '', runId: 'run-r3', timestampMs: Date.now() } }
    if (op === 'composite.verify') { const receipt = (args.receipt ?? {}) as Record<string, unknown>; receipts.push(receipt); return { confirmed: false, chainId: receipt.chainId, terminalVulnClass: receipt.terminalVulnClass, replayMode: 'fresh_clean_replay', modeBVerified: false, hopCount: Array.isArray(receipt.hops) ? receipt.hops.length : 0, verifiedEdges: [], reason: 'mock host: receipt recorded' } }
    throw new Error(`mock host: unsupported op ${op}`)
  }
  const server: Server = createServer((req, res) => {
    let raw = ''
    req.setEncoding('utf8'); req.on('data', c => { raw += c })
    req.on('end', () => {
      const { op, args } = JSON.parse(raw) as RpcCall
      calls.push({ op, args })
      let payload: unknown
      try { payload = { ok: true, result: respond(op, args) } } catch (err) { payload = { ok: false, error: err instanceof Error ? err.message : String(err) } }
      res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(payload))
    })
  })
  await new Promise<void>(resolve => server.listen(socketPath, resolve))
  const prev = ENV_KEYS.map(k => process.env[k])
  process.env.KOVO_RPC_CONTEXT_FILE = join(dir, 'context.json'); process.env.KOVO_RPC_TOKEN_FILE = join(dir, 'token'); process.env.KOVO_RPC_SOCKET = socketPath
  process.env.KOVO_VERIFY_NONCE = 'nonce-r3'; process.env.KOVO_PROOF_RESULT_FILE = join(dir, 'result.json')
  t.after(async () => {
    ENV_KEYS.forEach((k, i) => { if (prev[i] === undefined) delete process.env[k]; else process.env[k] = prev[i] })
    await new Promise<void>(resolve => server.close(() => resolve()))
    rmSync(dir, { recursive: true, force: true })
  })
  return { calls, ctx: new VerifyContext(), dir, receipts, exchanges, ops: op => calls.filter(c => c.op === op) }
}

/** Capture stderr writes for the duration of `fn` (SDK telemetry channel). */
async function captureStderr<T>(fn: () => Promise<T>): Promise<{ value?: T; error?: unknown; lines: string[] }> {
  const lines: string[] = [], orig = process.stderr.write.bind(process.stderr)
  process.stderr.write = ((chunk: string | Uint8Array, ...rest: unknown[]) => { lines.push(String(chunk)); return typeof rest[rest.length - 1] === 'function' ? (rest[rest.length - 1] as () => void)() ?? true : true }) as typeof process.stderr.write
  try { return { value: await fn(), lines } } catch (error) { return { error, lines } } finally { process.stderr.write = orig }
}

const preflightTelemetry = (lines: string[]): SdkPreflightRecord[] => lines.filter(l => l.startsWith(`${SDK_PREFLIGHT_STDERR_TAG} `)).map(l => JSON.parse(l.slice(SDK_PREFLIGHT_STDERR_TAG.length + 1)) as SdkPreflightRecord)

function assertPreflight(err: unknown, code: SdkPreflightCode, field?: string): SdkPreflightRecord {
  assert.ok(err instanceof KovoSdkPreflightError, `expected KovoSdkPreflightError, got ${String(err)}`)
  assert.equal(err.record.rejectedBy, 'sdk_preflight')
  assert.equal(err.record.code, code)
  if (field) assert.equal(err.record.field, field)
  assert.ok(err.message.startsWith(`sdk_preflight[${code}]`), err.message)
  assert.ok(err.record.reason.length > 20, 'diagnostic must be actionable, not empty')
  return err.record
}

function catchSync(fn: () => unknown): unknown { try { fn() } catch (err) { return err } return undefined }

// ---------------------------------------------------------------------------
// 1. role: 'readback' normalization
// ---------------------------------------------------------------------------
test('role/arm "readback" normalizes to a clean control-arm readback (never leaks an invalid session role to the host)', async t => {
  assert.deepEqual(preflightHttpShape({ role: 'readback' }), { arm: 'control', sessionGroupRole: 'control' })
  assert.deepEqual(preflightHttpShape({ arm: 'readback', role: 'probe' }), { arm: 'control', sessionGroupRole: 'control' })
  assert.deepEqual(preflightHttpShape({ role: 'probe' }), { sessionGroupRole: 'probe' })

  const host = await startMockHost(t)
  await host.ctx.http('/api/v1/balance', { role: 'readback' })
  await host.ctx.http_send({ path: '/api/v1/balance', arm: 'readback' })
  for (const call of host.ops('http').concat(host.ops('http.send'))) {
    assert.equal(call.args.sessionGroupRole, 'control')
    assert.equal(call.args.arm, 'control')
  }
})

test('chain readback alias: ch.step / ctx.http({ role: "readback" }) inside a hop / readback-mode hop / recordHop all land in the readback slots, not in hops', async t => {
  const host = await startMockHost(t)
  const ch = host.ctx.chain({ chainId: 'chain-r3-readback', terminalVulnClass: 'broken_access_control' })
  const before = await ch.step('/api/v1/balance', { role: 'readback', as: 'actor_low' })
  await ch.hop('hop_1', { claimedDelta: 'Mutated state.' }, async () => {
    await host.ctx.http_send('/api/v1/mutate', { as: 'actor_low', method: 'POST', role: 'probe' })
    await host.ctx.http('/api/v1/balance', { as: 'actor_low', role: 'readback' })
  })
  await ch.hop('hop_rb', { role: 'readback', claimedDelta: 'Readback-only hop.' }, () => host.ctx.http('/api/v1/ledger', { as: 'actor_low' }))
  ch.recordHop({ hopId: 'hop_manual', role: 'readback', target: '/api/v1/ledger', exchangeIds: ['ex_external'], claimedDelta: 'Recorded readback.' })

  const built = ch.build()
  const hopIds = built.hops.map(h => h.hopId)
  assert.deepEqual(hopIds, ['hop_1'], 'readback-only hops are demoted; manual readback records are not hops')
  const idsOf = (path: string, method = 'GET'): string[] => [...host.exchanges].filter(([, e]) => e.path === path && e.method === method).map(([id]) => id)
  const [mutateId] = idsOf('/api/v1/mutate', 'POST'), [, inHopReadbackId] = idsOf('/api/v1/balance'), [ledgerId] = idsOf('/api/v1/ledger')
  assert.deepEqual(built.hops[0]!.exchangeIds, [mutateId], 'in-hop readback is not counted as a hop exchange')
  assert.ok(built.terminalImpact.preChainControlExchangeIds?.includes(before.exchangeId), 'pre-hop readback becomes the baseline readback')
  const post = built.terminalImpact.postChainReadbackExchangeIds ?? []
  assert.deepEqual(post, [inHopReadbackId, ledgerId, 'ex_external'], 'in-hop, readback-mode hop, and manual readbacks fill the post-chain readback slot in order')
  for (const call of host.calls.filter(c => c.op.startsWith('http'))) {
    if (String(call.args.path).endsWith('/mutate')) assert.equal(call.args.sessionGroupRole, 'probe')
    else assert.equal(call.args.arm, 'control', `${String(call.args.path)} must be sent as a control-arm readback`)
  }
})

// ---------------------------------------------------------------------------
// 2. capability object -> .handle
// ---------------------------------------------------------------------------
test('sealed capability objects unwrap to .handle; blank/malformed handles are rejected (never silently sent as the persona)', async t => {
  const sealed = { handle: 'cap:hop_1:tok', meta: {}, exchangeId: 'ex_1', sealExchangeId: 'seal_1', scrubbedPreview: '' }
  assert.equal(preflightCapabilityInjection(sealed), 'cap:hop_1:tok')
  assert.equal(preflightCapabilityInjection('  cap:hop_1:tok '), 'cap:hop_1:tok')
  assert.deepEqual(preflightCapabilityInjection({ handle: sealed, target: 'header', headerName: ' X-Api-Key ' }), { handle: 'cap:hop_1:tok', target: 'header', headerName: 'X-Api-Key' })
  assert.equal(preflightCapabilityInjection(undefined), undefined)

  assertPreflight(catchSync(() => preflightCapabilityInjection('')), 'empty_capability_handle', 'capability')
  assertPreflight(catchSync(() => preflightCapabilityInjection('   ')), 'empty_capability_handle')
  assertPreflight(catchSync(() => preflightCapabilityInjection({ handle: '  ' })), 'empty_capability_handle')
  assertPreflight(catchSync(() => preflightCapabilityInjection({ bogus: 1 })), 'malformed_capability')
  assertPreflight(catchSync(() => preflightCapabilityInjection(['cap:a', 'cap:b'])), 'malformed_capability')
  assertPreflight(catchSync(() => preflightCapabilityInjection({ handle: 'cap:hop_1:tok', target: 'query' })), 'malformed_capability', 'capability.target')

  const host = await startMockHost(t)
  await host.ctx.http_send('/api/v1/export', { capability: sealed as never, role: 'probe' })
  await host.ctx.http_send('/api/v1/export', { capability: { handle: sealed as never, target: 'bearer' }, role: 'probe' })
  assert.deepEqual(host.ops('http.send').map(c => c.args.capability), ['cap:hop_1:tok', { handle: 'cap:hop_1:tok', target: 'bearer' }])

  const sentBefore = host.calls.length
  await assert.rejects(host.ctx.http_send('/api/v1/export', { capability: '', role: 'probe' }), (err: unknown) => (assertPreflight(err, 'empty_capability_handle'), true))
  await assert.rejects(host.ctx.http_send('/api/v1/export', { capability: { handle: '' } as never }), (err: unknown) => (assertPreflight(err, 'empty_capability_handle'), true))
  assert.equal(host.calls.length, sentBefore, 'rejected requests never reach the host')

  await host.ctx.hmac_sign({ secretHandle: sealed as never, payload: 'payload-r3' })
  assert.equal(host.ops('crypto.hmacSign')[0]?.args.secretHandle, 'cap:hop_1:tok')
  await assert.rejects(host.ctx.hmac_sign({ secretHandle: '', payload: 'x' }), (err: unknown) => (assertPreflight(err, 'empty_secret_handle', 'secretHandle'), true))
  await assert.rejects(host.ctx.jwt_sign({ secretHandle: { handle: ' ' } as never, claims: {} }), (err: unknown) => (assertPreflight(err, 'empty_secret_handle'), true))
  assert.equal(host.ops('crypto.hmacSign').length, 1)
  assert.equal(host.ops('crypto.jwtSign').length, 0)
})

// ---------------------------------------------------------------------------
// 3. exchange object -> .exchangeId
// ---------------------------------------------------------------------------
test('seal_capability and sibling helpers unwrap HTTP exchange objects to .exchangeId and reject missing ids / capabilities passed as exchanges', async t => {
  assert.equal(resolveExchangeIdArg({ exchange: { exchangeId: ' ex_9 ', status: 200 } }, 'seal_capability'), 'ex_9')
  assert.equal(resolveExchangeIdArg({ exchangeId: { exchangeId: 'ex_8' } }, 'seal_capability'), 'ex_8')
  assert.equal(resolveExchangeIdArg({ exchangeId: '  ', exchange: { exchangeId: 'ex_7' } }, 'seal_capability'), 'ex_7', 'a blank exchangeId never shadows a valid exchange')
  assert.equal(resolveExchangeIdArg({ exchange: 'ex_6' }, 'chain.seal', ['exchange']), 'ex_6')
  assertPreflight(catchSync(() => resolveExchangeIdArg({ slot: 's1' }, 'seal_capability')), 'missing_exchange_id', 'exchangeId')
  assertPreflight(catchSync(() => resolveExchangeIdArg({ exchange: { handle: 'cap:hop_1:tok' } }, 'seal_capability')), 'capability_passed_as_exchange', 'exchange')
  assertPreflight(catchSync(() => resolveExchangeIdArg({ exchangeId: 'cap:hop_1:tok' }, 'seal_capability')), 'capability_passed_as_exchange', 'exchangeId')

  const host = await startMockHost(t)
  const ex = await host.ctx.http_send('/api/v1/tokens', { as: 'actor_low', method: 'POST', role: 'probe' })
  await host.ctx.seal_capability({ exchange: ex, slot: 's1', jsonPath: '$.token', kind: 'api_token' })
  await host.ctx.seal_capability({ exchangeId: ex, slot: 's2', jsonPath: '$.token' })
  await host.ctx.seal_capability({ exchangeId: '', exchange: ex, slot: 's3', jsonPath: '$.token' })
  assert.deepEqual(host.ops('capability.seal').map(c => c.args.exchangeId), [ex.exchangeId, ex.exchangeId, ex.exchangeId])

  const sealsBefore = host.ops('capability.seal').length
  await assert.rejects(host.ctx.seal_capability({ slot: 's4', jsonPath: '$.token' }), (err: unknown) => (assertPreflight(err, 'missing_exchange_id'), /requires exchangeId/.test((err as Error).message)))
  await assert.rejects(host.ctx.seal_capability({ exchange: { handle: 'cap:hop_1:s1' } as never, slot: 's5', jsonPath: '$.token' }), (err: unknown) => (assertPreflight(err, 'capability_passed_as_exchange'), true))
  const ch = host.ctx.chain('chain-r3-exchange', 'broken_access_control')
  await assert.rejects(ch.seal({} as never, '$.token'), (err: unknown) => (assertPreflight(err, 'missing_exchange_id', 'exchange'), true))
  assert.equal(host.ops('capability.seal').length, sealsBefore, 'rejected seals never reach the host')
  assert.match(await ch.seal(ex, '$.token'), /^cap:hop_/)

  // Sibling slots: exchange objects in prove options / ablation lists are unwrapped, not silently dropped.
  await ch.hop('hop_1', { claimedDelta: 'Hop 1.' }, () => host.ctx.http_send('/api/v1/a', { as: 'actor_low', role: 'probe' }))
  const fin = await ch.hop('hop_2', { claimedDelta: 'Hop 2.' }, () => host.ctx.http_send('/api/v1/b', { as: 'actor_low', role: 'probe' }))
  const denied = await host.ctx.http('/api/v1/denied', { as: 'actor_low', arm: 'control' })
  ch.stateTransition({ fromHopId: 'hop_1', toHopId: 'hop_2', entityId: 'entity-1', ablationExchangeIds: [denied as never] })
  const built = ch.build({ preChainControlExchangeIds: [denied as never], postChainReadbackExchangeIds: [fin as never], terminalExchangeId: fin as never })
  assert.ok(built.terminalImpact.preChainControlExchangeIds?.includes(denied.exchangeId))
  assert.ok(built.terminalImpact.postChainReadbackExchangeIds?.includes(fin.exchangeId))
  assert.equal(built.terminalImpact.terminalExchangeId, fin.exchangeId)
  const edge = built.causalEdges?.find(e => e.kind === 'state_transition_binding')
  assert.deepEqual(edge && 'ablationExchangeIds' in edge ? edge.ablationExchangeIds : null, [denied.exchangeId])
})

// ---------------------------------------------------------------------------
// 4. empty / whitespace headerName
// ---------------------------------------------------------------------------
test('blank headerName is omitted when unused and rejected with an actionable diagnostic when it decides placement', async t => {
  assert.equal(normalizeHeaderName('', 'http', 'capability.headerName', false), undefined)
  assert.equal(normalizeHeaderName('   ', 'http', 'capability.headerName', false), undefined)
  assert.equal(normalizeHeaderName(' X-Api-Key ', 'http', 'capability.headerName', true), 'X-Api-Key')
  const empty = assertPreflight(catchSync(() => normalizeHeaderName(' ', 'http', 'capability.headerName', true)), 'empty_header_name', 'capability.headerName')
  assert.ok(empty.reason.includes('non-empty HTTP header name'))
  assertPreflight(catchSync(() => normalizeHeaderName('Bad Header', 'http', 'capabilityHeaderName', false)), 'invalid_header_name')
  assertPreflight(catchSync(() => normalizeHeaderName('X-Bad\r\nInjected', 'http', 'capabilityHeaderName', false)), 'invalid_header_name')

  assert.equal(preflightCapabilityInjection({ handle: 'cap:hop_1:tok', headerName: '' }), 'cap:hop_1:tok')
  assert.deepEqual(preflightCapabilityInjection({ handle: 'cap:hop_1:tok', target: 'bearer', headerName: '  ' }), { handle: 'cap:hop_1:tok', target: 'bearer' })
  assertPreflight(catchSync(() => preflightCapabilityInjection({ handle: 'cap:hop_1:tok', target: 'header', headerName: '  ' })), 'empty_header_name', 'capability.headerName')
  assertPreflight(catchSync(() => preflightHttpShape({ capability: 'cap:hop_1:tok', capabilityTarget: 'header', capabilityHeaderName: '' })), 'empty_header_name', 'capabilityHeaderName')
  assert.deepEqual(preflightHttpShape({ capability: 'cap:hop_1:tok', capabilityTarget: 'bearer', capabilityHeaderName: ' ' }), { capability: 'cap:hop_1:tok' })
  assert.deepEqual(preflightHttpShape({ capability: { handle: 'cap:hop_1:tok', target: 'header', headerName: 'X-Api-Key' }, capabilityHeaderName: '' }), { capability: { handle: 'cap:hop_1:tok', target: 'header', headerName: 'X-Api-Key' } })
  assertPreflight(catchSync(() => preflightHttpShape({ headers: { ' ': 'v' } })), 'empty_header_name', 'headers')

  const host = await startMockHost(t)
  await host.ctx.http_send('/api/v1/export', { capability: 'cap:hop_1:tok', capabilityTarget: 'bearer', capabilityHeaderName: '' })
  const sent = host.ops('http.send')[0]!.args
  assert.equal('capabilityHeaderName' in sent, false, 'unused blank capabilityHeaderName is omitted')
  const tokenEx = await host.ctx.http_send('/api/v1/tokens', { as: 'actor_low', method: 'POST' })
  await host.ctx.seal_capability({ exchange: tokenEx, slot: 'h1', jsonPath: '$.token', header: '', defaultHeaderName: '  ' })
  const sealArgs = host.ops('capability.seal')[0]!.args
  assert.equal('header' in sealArgs, false); assert.equal('defaultHeaderName' in sealArgs, false)
  await host.ctx.seal_capability({ exchange: tokenEx, slot: 'h2', header: ' X-Session-Token ' })
  assert.equal(host.ops('capability.seal')[1]!.args.header, 'X-Session-Token')

  const before = host.calls.length
  await assert.rejects(host.ctx.seal_capability({ exchange: tokenEx, slot: 'h3', header: '   ' }), (err: unknown) => (assertPreflight(err, 'empty_header_name', 'header'), true))
  await assert.rejects(host.ctx.http_send('/api/v1/export', { capability: { handle: 'cap:hop_1:tok', target: 'header', headerName: '' } }), (err: unknown) => (assertPreflight(err, 'empty_header_name'), true))
  await assert.rejects(host.ctx.http_send('/api/v1/export', { headers: { '': 'value' } }), (err: unknown) => (assertPreflight(err, 'empty_header_name', 'headers'), true))
  assert.equal(host.calls.length, before)
})

// ---------------------------------------------------------------------------
// 5. preflight rejection telemetry
// ---------------------------------------------------------------------------
test('preflight rejections emit structured host telemetry (stderr + ctx record), dedupe repeats, and never weaken the rejection', async t => {
  const host = await startMockHost(t)
  const first = await captureStderr(() => host.ctx.http_send('/api/v1/export', { capability: '' }))
  assertPreflight(first.error, 'empty_capability_handle')
  const records = preflightTelemetry(first.lines)
  assert.deepEqual(records.map(r => ({ rejectedBy: r.rejectedBy, code: r.code, op: r.op, field: r.field })), [{ rejectedBy: 'sdk_preflight', code: 'empty_capability_handle', op: 'http', field: 'capability' }])
  assert.equal(records[0]!.reason, (first.error as KovoSdkPreflightError).record.reason)

  const repeat = await captureStderr(() => host.ctx.http_send('/api/v1/export', { capability: '' }))
  assertPreflight(repeat.error, 'empty_capability_handle')
  assert.equal(preflightTelemetry(repeat.lines).length, 0, 'identical rejection is reported once')
  const raceErr = await captureStderr(() => host.ctx.race_burst([{ path: '/api/v1/redeem', method: 'POST' }, { path: '/api/v1/redeem', method: 'POST', headers: { ' ': 'x' } }]))
  assertPreflight(raceErr.error, 'empty_header_name')
  assert.deepEqual(preflightTelemetry(raceErr.lines).map(r => `${r.op}:${r.code}`), ['race_burst:empty_header_name'])
  assert.deepEqual(host.ctx.sdkPreflightRejections.map(r => `${r.op}:${r.code}`), ['http:empty_capability_handle', 'race_burst:empty_header_name'])
  assert.equal(host.calls.length, 0, 'no rejected request ever reached the host')
})

test('runVerification reports preflight telemetry in result.json for uncaught (rejectedBy=sdk_preflight) and caught rejections', async t => {
  const host = await startMockHost(t)
  const resultFile = join(host.dir, 'result.json')
  const prevExit = process.exitCode
  t.after(() => { process.exitCode = prevExit })

  await captureStderr(() => runVerification({ verify: async ctx => { await ctx.seal_capability({ slot: 'x', jsonPath: '$.token' }); return ctx.result({ title: 'unreachable' }) } }, 'Uncaught preflight'))
  const uncaught = JSON.parse(readFileSync(resultFile, 'utf8')) as Record<string, unknown>
  assert.equal(uncaught.rejectedBy, 'sdk_preflight')
  assert.equal((uncaught.preflight as SdkPreflightRecord).code, 'missing_exchange_id')
  assert.ok(String(uncaught.error).startsWith('sdk_preflight[missing_exchange_id]'))
  assert.deepEqual((uncaught.sdkPreflight as SdkPreflightRecord[]).map(r => r.code), ['missing_exchange_id'])
  assert.deepEqual(uncaught.claims, [])
  assert.equal(process.exitCode, 1, 'uncaught preflight rejection fails the script')
  process.exitCode = prevExit

  await captureStderr(() => runVerification({
    verify: async ctx => {
      await ctx.http_send('/api/v1/export', { capability: '   ' }).catch(() => null)
      const ex = await ctx.http_send('/api/v1/export', { as: 'actor_low' })
      ctx.expect.status(ex, 200)
      return ctx.result({ title: 'Caught preflight' })
    },
  }, 'Caught preflight'))
  const caught = JSON.parse(readFileSync(resultFile, 'utf8')) as Record<string, unknown>
  assert.equal(caught.error, undefined)
  assert.equal((caught.claims as unknown[]).length, 1)
  assert.deepEqual((caught.sdkPreflight as SdkPreflightRecord[]).map(r => `${r.op}.${r.field}:${r.code}`), ['http.capability:empty_capability_handle'])
})

// ---------------------------------------------------------------------------
// 6. Prompt / tool / skill contracts
// ---------------------------------------------------------------------------
test('persona base contract: multi-tenant personas are hop-1 bases only for dual_tenant_abac / cross-tenant ABAC, never single-tenant BOLA/BFLA', () => {
  const personas = [
    { handle: 'member_a', roleLabel: 'member (tenant-a)', originAllowlist: [ORIGIN] },
    { handle: 'dual_member', roleLabel: 'memberships=member:org_a,member:org_b', originAllowlist: [ORIGIN] },
  ]
  const user = JSON.parse(buildExploiterUserPrompt({ goal: 'Verify authorization boundaries', step: { id: 's1', title: 'Authz', hypothesis: 'BOLA on records', category: 'broken-access-control' }, origins: [ORIGIN], capabilityTier: 2, maxTurns: 10, personas })) as Record<string, { instruction: string; personas: Array<{ handle: string }> }>
  assert.deepEqual(user.attackerBasePersonas!.personas.map(p => p.handle), ['member_a'])
  assert.deepEqual(user.multiTenantBasePersonas!.personas.map(p => p.handle), ['dual_member'])
  const mt = user.multiTenantBasePersonas!.instruction
  assert.ok(mt.includes('ONLY for dual_tenant_abac') && mt.includes('NEVER for single-tenant bola/bfla/broken_access_control'), mt)
  assert.ok(user.attackerBasePersonas!.instruction.includes('single-tenant non-elevated personas'))

  const rule1 = buildExploiterSystemPrompt().split('\n').find(l => l.startsWith('1. '))!
  assert.ok(rule1.includes('`multiTenantBasePersonas` are hop-1 bases ONLY for `dual_tenant_abac`'), rule1)
  assert.equal(rule1.includes('(`attackerBasePersonas` / `multiTenantBasePersonas`)'), false, 'no "any non-elevated incl. multi-tenant" base wording')

  const guidance = kovoVerifyHelperGuidance()
  assert.ok(Buffer.byteLength(guidance, 'utf8') <= KOVO_VERIFY_HELPER_GUIDANCE_MAX_BYTES)
  assert.ok(guidance.includes('multi-tenant (dual-member) personas only as hop-1 base for cross-tenant ABAC classes, never single-tenant BOLA/BFLA'))
  assert.ok(KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN.length <= 2000)
  assert.ok(KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN.includes('accessDifferential({ baseline, revocation, control, variant })'))
})

test('multihop-chains negative-effect recipe executes end to end: temporal_revocation slots in order, connected value_binding DAG, zero ablation edges', async t => {
  clearSkillsCache()
  const skill = loadSkill('multihop-chains')
  assert.ok(skill)
  const section = skill.content.slice(skill.content.indexOf('## 5. Negative-Effect Transitions'))
  const start = section.indexOf('```ts\n') + '```ts\n'.length, code = section.slice(start, section.indexOf('```', start))
  assert.ok(code.includes('ctx.'), 'negative-effect section carries an executable ctx snippet')
  const body = code.split('\n').filter(l => !l.startsWith('import ')).join('\n')
  const js = ts.transpileModule(`globalThis.__r3Recipe = async (ctx: any, accessDifferential: any) => {\n${body}\n}`, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None } }).outputText
  new Function(js)()
  const recipe = (globalThis as Record<string, unknown>).__r3Recipe as (ctx: VerifyContext, ad: typeof accessDifferential) => Promise<unknown>
  t.after(() => { delete (globalThis as Record<string, unknown>).__r3Recipe })

  const host = await startMockHost(t)
  await recipe(host.ctx, accessDifferential)
  assert.equal(host.receipts.length, 1, 'recipe submits exactly one composite receipt')
  const receipt = host.receipts[0] as { terminalVulnClass: string; hops: Array<{ hopId: string }>; causalEdges: Array<{ kind: string; fromHopId: string; toHopId: string }>; terminalImpact: { terminalHopId: string; oracleFamily?: string; oracleInput?: Record<string, string> } }
  assert.equal(receipt.terminalVulnClass, 'temporal_revocation')
  assert.equal(receipt.terminalImpact.oracleFamily, 'temporal_revocation')
  assert.deepEqual(receipt.hops.map(h => h.hopId), ['hop_1', 'hop_2'])
  assert.deepEqual(receipt.causalEdges.map(e => `${e.kind}:${e.fromHopId}->${e.toHopId}`), ['value_binding:hop_1->hop_2'])
  assert.equal(receipt.causalEdges.some(e => e.kind === 'state_transition_binding'), false, 'revocation defects never use ablation')

  const oi = receipt.terminalImpact.oracleInput!
  const slots = ['preRevocationBaselineExchangeId', 'revocationEventExchangeId', 'primaryDeniedCheckExchangeId', 'secondarySuccessExchangeId'].map(k => oi[k]!)
  assert.equal(new Set(slots).size, 4, 'four distinct exchanges')
  const seqOf = (id: string): number => Number(id.replace('ex_', ''))
  assert.deepEqual(slots.map(seqOf), slots.map(seqOf).sort((a, b) => a - b), 'baseline -> revocation -> control -> variant chronology')
  assert.deepEqual(slots.map(id => host.exchanges.get(id)), [
    { path: '/api/v1/resource', method: 'GET', status: 200 },
    { path: '/api/v1/tokens/current', method: 'DELETE', status: 200 },
    { path: '/api/v1/resource', method: 'GET', status: 403 },
    { path: '/api/v1/export', method: 'GET', status: 200 },
  ], 'accepted baseline, mutating revocation, clean denied control, accepted variant on a distinct surface')
  assert.equal(oi.credentialKind, 'token')
})
