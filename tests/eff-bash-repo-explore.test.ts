/**
 * Stream E2-B — code-first `/repos/*` exploration via `sandbox_exec` (bash/node/python).
 *
 * Purely behavioral (no source-text assertions). Pins:
 *   (a) Docker worker sandbox active (`derive_evidence` + `run_offline_script`) with `/repos` mounted →
 *       the redundant `repo` / `read_repo_file` / `search_repo` / `list_repo_files` schemas are omitted
 *       and `sandbox_exec` / `derive_evidence` advertise `/repos/*` bash/node/python exploration;
 *   (b) host-only sessions (no sandbox handlers) keep the host repo fallback, which reads/searches/lists
 *       a temp fixture repo;
 *   (c) sandbox output renders as compact plain text (no JSON-escaped newlines) and caps inline output
 *       at <= 10 KiB with a clear truncation / spill pointer.
 */
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test, { describe } from 'node:test'

import type { WorkerToolHandlers } from '../src/server/agent-prompts.ts'
import {
  SANDBOX_EXEC_INLINE_BYTES,
  buildWorkerTools,
  formatToolOutput,
  hasSandboxRepoExplorer,
  renderSandboxExecText,
} from '../src/server/agent-session.ts'
import {
  buildConsolidatedExploiterToolset,
  buildExploiterSystemPrompt,
  prepareDecoupledExploiterSession,
} from '../src/server/exploiter-tools.ts'
import type { ToolRegistration } from '@earendil-works/pi-durable'

const RETIRED_REPO_TOOLS = ['repo', 'read_repo_file', 'search_repo', 'list_repo_files'] as const
const INLINE_CEILING_BYTES = 10 * 1024
const ORIGIN = 'http://app.local'

type SandboxCall = { tool: 'derive_evidence' | 'run_offline_script'; args: Record<string, unknown> }

function sandboxHandlers(calls: SandboxCall[], result: (call: SandboxCall) => unknown = () => ({ exitCode: 0, stdout: 'ok\n', stderr: '' })): WorkerToolHandlers {
  return {
    derive_evidence: async args => { const call: SandboxCall = { tool: 'derive_evidence', args }; calls.push(call); return result(call) },
    run_offline_script: async args => { const call: SandboxCall = { tool: 'run_offline_script', args: { ...args } }; calls.push(call); return result(call) },
    read_repo_file: async args => ({ path: args.path, content: 'host' }),
    search_repo: async args => ({ query: args.query, matches: [] }),
    record_fact: async () => ({ recorded: true }),
    complete_intent: async c => ({ ok: true, status: c.status }),
  }
}

function hostOnlyHandlers(): WorkerToolHandlers {
  return { record_fact: async () => ({ recorded: true }), complete_intent: async c => ({ ok: true, status: c.status }) }
}

function makeFixtureRepos(t: { after: (fn: () => void) => void }): string {
  const reposDir = mkdtempSync(join(tmpdir(), 'kovo-e2b-repos-'))
  t.after(() => rmSync(reposDir, { recursive: true, force: true }))
  mkdirSync(join(reposDir, 'acme', 'svc', 'src'), { recursive: true })
  writeFileSync(join(reposDir, 'acme', 'svc', 'src', 'routes.ts'), 'export const ROUTE = "/api/v1/reports"\nexport function checkTenantAccess() { return true }\n', 'utf8')
  return reposDir
}

function exploiterTools(handlers: WorkerToolHandlers, opts: { reposDir?: string; hasMountedRepos?: boolean; inlineLimit?: number; spillOutput?: WorkerToolHandlers['spillOutput'] } = {}): ToolRegistration[] {
  return buildConsolidatedExploiterToolset({
    handlers: { ...handlers, ...(opts.spillOutput ? { spillOutput: opts.spillOutput } : {}) },
    runId: 'run-e2b',
    assignmentId: 'asg-e2b',
    publicOrigins: [ORIGIN],
    personasPub: [{ handle: 'member_b', role: 'member' }],
    recordedExchanges: new Map(),
    hasMountedRepos: opts.hasMountedRepos ?? true,
    allowWebSearch: false,
    scrub: v => v.replaceAll('sk_live_CANARY', '[REDACTED]'),
    rootSignal: new AbortController().signal,
    inlineLimit: opts.inlineLimit ?? 16_384,
    onCompleteIntent: () => undefined,
    ...(opts.reposDir ? { specSubmission: { reposDir: opts.reposDir } } : {}),
    runKovoVerify: async () => ({ confirmed: false }),
  })
}

async function run(tool: ToolRegistration | undefined, args: Record<string, unknown>): Promise<{ text: string; isError?: boolean }> {
  assert.ok(tool, 'tool must be registered')
  const res = await tool.execute(args as never, {} as never, { abortSignal: new AbortController().signal } as never) as { output?: Array<{ type: string; text?: string }>; isError?: boolean }
  return { text: (res.output ?? []).map(p => p.text ?? '').join('\n'), ...(res.isError ? { isError: true } : {}) }
}

const named = (tools: readonly ToolRegistration[], name: string) => tools.find(t => t.name === name)

describe('(a) Docker sandbox active: /repos explored via sandbox_exec, redundant repo tools retired', () => {
  test('consolidated exploiter toolset omits repo schemas and sandbox_exec advertises /repos bash/node/python', t => {
    const reposDir = makeFixtureRepos(t)
    const handlers = sandboxHandlers([])
    assert.equal(hasSandboxRepoExplorer(handlers), true)
    const tools = exploiterTools(handlers, { reposDir })
    const names = tools.map(tool => tool.name)
    for (const retired of RETIRED_REPO_TOOLS) assert.equal(names.includes(retired), false, `${retired} must be omitted in Docker sandbox mode`)
    const sandbox = named(tools, 'sandbox_exec')
    assert.ok(sandbox)
    for (const needle of ['/repos/*', 'runtime="bash"', 'runtime="node"', '"python"', 'rg', 'sed -n', 'never cat whole files', '8 KiB']) {
      assert.ok(sandbox.description.includes(needle), `sandbox_exec description must mention ${needle}`)
    }
  })

  test('legacy worker toolset omits read_repo_file/search_repo while derive_evidence is the /repos explorer', t => {
    const reposDir = makeFixtureRepos(t)
    const tools = buildWorkerTools(sandboxHandlers([]), v => v, new AbortController().signal, 16_384, () => {}, { reposDir })
    const names = tools.map(tool => tool.name)
    for (const retired of RETIRED_REPO_TOOLS) assert.equal(names.includes(retired), false, `${retired} must be omitted in Docker sandbox mode`)
    const derive = named(tools, 'derive_evidence')
    assert.ok(derive)
    assert.ok(derive.description.includes('/repos'))
    assert.ok(derive.description.includes('never cat whole files'))
    assert.ok(named(tools, 'run_offline_script')?.description.includes('/repos'))
  })

  test('decoupled exploiter session prompt and tools steer /repos exploration to sandbox_exec', () => {
    const session = prepareDecoupledExploiterSession({
      handlers: sandboxHandlers([]),
      storage: { listEndpoints: () => [], getExchange: () => { throw new Error('missing') } },
      runId: 'run-e2b-sess',
      assignmentId: 'asg-e2b-sess',
      publicOrigins: [ORIGIN],
      personasPub: [{ handle: 'member_b', roleLabel: 'member', originAllowlist: [ORIGIN] }],
      recordedExchanges: new Map(),
      mountedRepos: ['acme/svc'],
      userPromptInput: {
        goal: 'Verify tenant boundaries',
        step: { id: 's-e2b', title: 'Source-first chain', hypothesis: 'Tenant check missing', category: 'bola' },
        origins: [ORIGIN],
        capabilityTier: 2,
        maxTurns: 10,
        personas: [{ handle: 'member_b', roleLabel: 'member', originAllowlist: [ORIGIN] }],
      },
      runKovoVerify: async () => ({ confirmed: false }),
      proofWriterDeps: { profiles: [] },
      onProofConfirmed: () => undefined,
      onToolExecuted: () => undefined,
    })
    assert.ok(session.instructions.includes('White-box source-first'))
    assert.ok(session.instructions.includes('`sandbox_exec`'))
    assert.ok(session.instructions.includes('/repos/*'))
    assert.equal(session.instructions.includes('repo({ action'), false, 'retired repo tool must not be advertised')
    assert.equal(session.instructions.includes('`repo` ('), false, 'retired repo tool must not be listed as an extra')
    const tools = session.overrideTools({
      scrubbers: { scrubForDisplay: v => v, scrubExact: v => v },
      signal: new AbortController().signal,
      inlineLimit: 16_384,
      onCompleteIntent: () => undefined,
      specSubmission: {},
    })
    assert.equal(tools.some(tool => tool.name === 'repo'), false)
    assert.ok(named(tools, 'sandbox_exec'))
  })

  test('sandbox_exec routes bash to derive_evidence and node/python to run_offline_script unchanged', async t => {
    const reposDir = makeFixtureRepos(t)
    const calls: SandboxCall[] = []
    const tools = exploiterTools(sandboxHandlers(calls, call => ({ exitCode: 0, stdout: `${call.tool}:${String(call.args.runtime ?? 'bash')}\n`, stderr: '' })), { reposDir })
    const sandbox = named(tools, 'sandbox_exec')
    const bash = await run(sandbox, { runtime: 'bash', code: 'rg -n checkTenantAccess /repos/acme/svc/src | head -20', timeoutMs: 5_000 })
    const node = await run(sandbox, { runtime: 'node', code: 'console.log(process.env.KOVO_REPOS)' })
    const python = await run(sandbox, { runtime: 'python', code: 'print(1)' })
    assert.deepEqual(calls.map(c => [c.tool, c.args.runtime ?? 'bash']), [['derive_evidence', 'bash'], ['run_offline_script', 'node'], ['run_offline_script', 'python']])
    assert.equal(calls[0]!.args.command, 'rg -n checkTenantAccess /repos/acme/svc/src | head -20')
    assert.equal(calls[0]!.args.timeoutMs, 5_000)
    assert.ok(bash.text.includes('derive_evidence:bash'))
    assert.ok(node.text.includes('run_offline_script:node'))
    assert.ok(python.text.includes('run_offline_script:python'))
  })
})

describe('(b) host-only fallback (no Docker sandbox handlers) keeps host repo access', () => {
  test('consolidated exploiter repo tool reads, searches, and lists the fixture repo', async t => {
    const reposDir = makeFixtureRepos(t)
    const handlers = hostOnlyHandlers()
    assert.equal(hasSandboxRepoExplorer(handlers), false)
    const tools = exploiterTools(handlers, { reposDir })
    const repo = named(tools, 'repo')
    assert.ok(repo, 'host-only sessions keep the repo fallback')
    const read = JSON.parse((await run(repo, { action: 'read', repo: 'acme/svc', path: 'src/routes.ts' })).text) as { path: string; content: string }
    assert.equal(read.path, '/repos/acme/svc/src/routes.ts')
    assert.ok(read.content.includes('checkTenantAccess'))
    const search = JSON.parse((await run(repo, { action: 'search', repo: 'acme/svc', query: 'checkTenantAccess' })).text) as { matches: Array<{ path: string }> }
    assert.deepEqual(search.matches.map(m => m.path), ['/repos/acme/svc/src/routes.ts'])
    const list = JSON.parse((await run(repo, { action: 'list', repo: 'acme/svc' })).text) as { files: string[] }
    assert.deepEqual(list.files, ['/repos/acme/svc/src/routes.ts'])
    const prompt = buildExploiterSystemPrompt({ hasMountedRepos: true, allowWebSearch: false, sandboxRepoExplorer: false })
    assert.ok(prompt.includes('repo({ action: "search" | "read" })'))
  })

  test('legacy worker read_repo_file and search_repo register and work over the fixture repo', async t => {
    const reposDir = makeFixtureRepos(t)
    const tools = buildWorkerTools(hostOnlyHandlers(), v => v, new AbortController().signal, 16_384, () => {}, { reposDir })
    const read = await run(named(tools, 'read_repo_file'), { path: '/repos/acme/svc/src/routes.ts', startLine: 1, endLine: 2 })
    assert.equal(read.isError, undefined)
    assert.ok(read.text.includes('checkTenantAccess'))
    const search = await run(named(tools, 'search_repo'), { query: 'checkTenantAccess' })
    assert.equal(search.isError, undefined)
    assert.ok(search.text.includes('/repos/acme/svc/src/routes.ts'))
    assert.equal(named(tools, 'derive_evidence'), undefined)
  })

  test('grey-box runs without mounted repos expose no repo tool in either mode', () => {
    for (const handlers of [sandboxHandlers([]), hostOnlyHandlers()]) {
      assert.equal(exploiterTools(handlers, { hasMountedRepos: false }).some(tool => tool.name === 'repo'), false)
    }
  })
})

describe('(c) compact plain-text sandbox output with a crisp inline cap', () => {
  test('sandbox_exec renders raw stdout/stderr/outputs as plain text, not escaped JSON', async () => {
    const tools = exploiterTools(sandboxHandlers([], () => ({
      exitCode: 2, stdout: 'src/a.ts:12: router.get("/x")\nsrc/b.ts:40: requireAuth()\n', stderr: 'warn: "partial"\n',
      outputs: { 'result.txt': 'summary=2 routes', 'empty.txt': '' }, evidenceId: 'ev-1',
    })), { hasMountedRepos: true })
    const { text } = await run(named(tools, 'sandbox_exec'), { runtime: 'bash', code: 'rg -n router /repos' })
    assert.ok(text.startsWith('[sandbox exitCode=2 evidenceId=ev-1]'))
    assert.ok(text.includes('--- stdout ---\nsrc/a.ts:12: router.get("/x")\nsrc/b.ts:40: requireAuth()'))
    assert.ok(text.includes('--- stderr ---\nwarn: "partial"'))
    assert.ok(text.includes('--- /work/result.txt ---\nsummary=2 routes'))
    assert.equal(text.includes('empty.txt'), false, 'empty outputs are skipped')
    assert.equal(text.includes('\\n'), false, 'no JSON-escaped newlines')
    assert.equal(text.includes('\\"'), false, 'no JSON-escaped quotes')
    assert.equal(text.includes('"stdout":'), false, 'no JSON envelope')
  })

  test('node/python script results carry runtime/timeout metadata and still scrub secrets', async () => {
    const tools = exploiterTools(sandboxHandlers([], () => ({ runtime: 'python', exitCode: 124, timedOut: true, durationMs: 60_000, stdout: 'token=sk_live_CANARY\n', stderr: '' })))
    const { text } = await run(named(tools, 'sandbox_exec'), { runtime: 'python', code: 'print(1)' })
    assert.ok(text.startsWith('[sandbox exitCode=124 runtime=python timedOut=true durationMs=60000]'))
    assert.ok(text.includes('token=[REDACTED]'))
    assert.equal(text.includes('sk_live_CANARY'), false)
    assert.equal(text.includes('--- stderr ---'), false, 'empty stderr is omitted')
  })

  test('oversized sandbox_exec output is capped <= 10 KiB inline with a spill pointer holding the full text', async () => {
    const spilled: Array<{ id: string; content: string }> = []
    const big = Array.from({ length: 4000 }, (_, i) => `src/file-${i}.ts:${i}: handler()`).join('\n')
    const tools = exploiterTools(sandboxHandlers([], () => ({ exitCode: 0, stdout: big, stderr: 'TAIL_MARKER' })), {
      inlineLimit: 64 * 1024,
      spillOutput: async (id, content) => { spilled.push({ id, content }); return `/evidence/tool-output/${id}.txt` },
    })
    const { text } = await run(named(tools, 'sandbox_exec'), { runtime: 'bash', code: 'rg -n handler /repos' })
    assert.ok(Buffer.byteLength(text, 'utf8') <= INLINE_CEILING_BYTES, `inline output ${Buffer.byteLength(text, 'utf8')} bytes exceeds 10 KiB`)
    assert.ok(Buffer.byteLength(text, 'utf8') <= SANDBOX_EXEC_INLINE_BYTES)
    assert.equal(spilled.length, 1)
    assert.ok(text.includes(`spilled to /evidence/tool-output/${spilled[0]!.id}.txt`))
    assert.ok(text.includes('sandbox inline cap'))
    assert.ok(text.includes("sed -n '1,120p'"))
    assert.ok(text.startsWith('[sandbox exitCode=0]'), 'header survives truncation')
    assert.ok(text.includes('TAIL_MARKER'), 'stderr tail survives truncation')
    assert.ok(spilled[0]!.content.includes('src/file-3999.ts:3999: handler()'), 'spill holds the full plain-text output')
    assert.equal(spilled[0]!.content.includes('\\n'), false)
  })

  test('legacy derive_evidence caps at the sandbox limit and the host spill pages via read_evidence_slice', async () => {
    const big = `${'x'.repeat(30_000)}\nEND_OF_OUTPUT`
    const tools = buildWorkerTools(
      { derive_evidence: async () => ({ exitCode: 0, stdout: big, stderr: '', outputs: {} }) },
      v => v, new AbortController().signal, 32 * 1024, () => {},
    )
    const { text } = await run(named(tools, 'derive_evidence'), { command: 'find /repos -name "*.ts"' })
    assert.ok(Buffer.byteLength(text, 'utf8') <= SANDBOX_EXEC_INLINE_BYTES)
    const artifactId = /artifactId="([^"]+)"/.exec(text)?.[1]
    assert.ok(artifactId, 'truncation notice must carry an artifactId spill pointer')
    const page = await run(named(tools, 'read_evidence_slice'), { artifactId, offset: 29_000, limit: 4096 })
    assert.ok(page.text.includes('END_OF_OUTPUT'))
  })

  test('without a spill sink the cap still applies with an explicit truncation notice', async () => {
    const out = await formatToolOutput({ exitCode: 0, stdout: 'y'.repeat(50_000), stderr: '' }, 'sandbox_exec', v => v, 64 * 1024, undefined, new AbortController().signal)
    assert.ok(Buffer.byteLength(out, 'utf8') <= SANDBOX_EXEC_INLINE_BYTES)
    assert.ok(out.includes(`-byte inline cap`))
  })

  test('non-sandbox results and non-sandbox tools keep their existing JSON rendering', async () => {
    assert.equal(renderSandboxExecText({ error: 'nope' }), null)
    assert.equal(renderSandboxExecText(['stdout']), null)
    assert.equal(renderSandboxExecText({ exitCode: 0, stdout: '', stderr: '' }), '[sandbox exitCode=0]\n(no output)')
    const factOut = await formatToolOutput({ stdout: 'a\nb' }, 'record_fact', v => v, 16_384, undefined, new AbortController().signal)
    assert.deepEqual(JSON.parse(factOut), { stdout: 'a\nb' })
  })
})
