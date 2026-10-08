// Real-activation probe for dsh-syslog-alert against the genuine cordis 4.0.4
// runtime extracted from the host asar.
//
// Every other test in this plugin exercises functions it imports directly. That
// misses the failure mode that actually bites plugins: `apply()` throwing on a
// service read, leaving the HTTP port unserved while the plugin looks perfectly
// healthy from the outside. The symptom of that is "no alerts ever arrive",
// which is indistinguishable from a firewall problem.
//
// So this loads dist/index.mjs through ctx.plugin() — the same path the host
// uses — then proves the whole path works: UDP datagram in, alert out, over
// the plugin's own loopback API.
//
//   node test/activation.probe.mjs [port]
import { Context } from '@deepseek-ai/cordis'
import { createSocket } from 'node:dgram'
import { createServer } from 'node:http'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const API_PORT = Number(process.argv[2] ?? 18794)
const SYSLOG_PORT = API_PORT + 1
// hillstone's fixed loopback port. The plugin reads its device list from
// `/ops-api/devices`, so a stand-in is what lets the probe frame a frame from a
// *managed* source. Unmapped frames are correctly dropped before analysis, so
// without a device here the probe could only ever prove the drop path.
//
// If that port is already bound, the REAL dsh-hillstone-cli-ops is running in
// this DSH session and must not be disturbed: we refuse to run rather than send
// probe commands over its SSH to the user's actual network gear.
const OPS_PORT = Number(process.argv[3] ?? 18797)
const opsPortFree = await new Promise((resolve) => {
  const probe = createServer()
  probe.once('error', () => resolve(false))
  probe.listen(OPS_PORT, '127.0.0.1', () => probe.close(() => resolve(true)))
})
if (!opsPortFree) {
  console.error(`\nACTIVATION SKIPPED — 127.0.0.1:${OPS_PORT} is in use, so the real dsh-hillstone-cli-ops is live.`)
  console.error('Running the probe now would issue its test frames through that bridge and SSH into real devices.')
  console.error('Stop the host (or that plugin) and re-run to exercise the full ingestion path.')
  process.exit(2)
}
const dataDir = mkdtempSync(join(tmpdir(), 'syslog-activation-'))
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const mod = await import(new URL('../dist/index.mjs', import.meta.url).href)

let bad = 0
const check = (name, hit, detail) => {
  if (!hit) bad++
  console.log(`${hit ? '  ok  ' : '  MISS'} ${name}${hit || detail === undefined ? '' : ` — ${detail}`}`)
}
// `eq` takes a message, so a failed assertion says what it compared. Used where
// the check above carries its own description and the numbers carry the detail.
const eq = (name, actual, expected) => check(`${name} (got ${JSON.stringify(actual)}, want ${JSON.stringify(expected)})`, actual === expected)

// Host `agents` stand-in. Nothing here runs a turn: `start` throws on purpose,
// which turns "the probe accidentally spent an agent turn" into a loud failure
// rather than a silent token spend.
const fakeAgents = {
  withoutInitiator(fn) { return fn() },
}

// The host's ordinary-Session service, registered as a sibling fiber exactly
// like the real one. Recording-only, so nothing here can spawn a turn: the probe
// proves the plugin *addresses* a real session (create -> rename -> prompt) but
// never spends a token.
const autoCalls = { created: [], renamed: [], prompted: [], signals: [] }
const fakeSessionController = {
  async create(request) {
    autoCalls.created.push(request)
    return { sessionId: `auto-session-${autoCalls.created.length}` }
  },
  async rename(request) {
    autoCalls.renamed.push(request)
    return { title: request.title, seq: 1 }
  },
  // The host's prompt() takes a REQUIRED AbortSignal and dereferences it on
  // entry. A fake that ignores the argument accepts calls the real host would
  // reject, which is how the live run ended up with an empty session.
  async prompt(request, signal) {
    signal.throwIfAborted()
    autoCalls.signals.push(signal)
    autoCalls.prompted.push(request)
    return { accepted: true }
  },
}

const ctx = new Context()
// A bare Context's default exporter threshold is 1 (info), which silently drops
// `warn` (level 2). The plugin reports every degradation through logger.warn, so
// without this the probe cannot see the reason a fiber failed.
ctx.logger.exporter({ colors: 0, levels: { default: 3 }, export: (m) => console.error('[LOG]', m.level, m.name, ...m.args) })
await ctx.plugin({ name: 'fake-agents', apply: (c) => c.provide('agents', fakeAgents) })
await ctx.plugin({ name: 'fake-session-controller', apply: (c) => c.provide('sessionController', fakeSessionController) })
// The expected day key comes from the plugin's own rule rather than a copy of
// it here: a re-implementation in the probe would keep agreeing with itself
// after the plugin's day boundary moved.
const { dateKey } = await import(new URL('../src/prompt-kit.ts', import.meta.url).href)

// A stand-in for hillstone's loopback API: one managed device, and an analyze
// route that answers with canned device output. Only /devices and /analyze are
// reachable from this plugin, so nothing here can become a real SSH path.
const opsRequests = []
const opsBridge = createServer((req, res) => {
  let body = ''
  req.on('data', (c) => (body += c))
  req.on('end', () => {
    opsRequests.push({ url: req.url, auth: req.headers['x-ops-token'] ?? null, body })
    const json = (payload) => {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify(payload))
    }
    if (req.url === '/ops-api/devices') {
      json({ ok: true, devices: [{ id: 'dev-1', name: 'SW1', ip: '127.0.0.1', account: 'admin', port: 22, deviceType: 'StoneOS SG-6000' }] })
      return
    }
    if (req.url === '/ops-api/analyze') {
      const parsed = JSON.parse(body || '{}')
      json({
        ok: true,
        deviceId: parsed.deviceId,
        deviceName: 'SW1',
        results: (parsed.commands ?? []).map((command) => ({
          command,
          exitCode: null,
          stdout: 'GE1/0/1 current state : DOWN\nLine protocol state : DOWN',
          stderr: '',
          timedOut: false,
        })),
        analysis: 'interface is down',
      })
      return
    }
    res.writeHead(404, { 'content-type': 'application/json' })
    res.end('{"ok":false}')
  })
})
await new Promise((resolve, reject) => {
  opsBridge.once('error', reject)
  opsBridge.listen(OPS_PORT, '127.0.0.1', resolve)
})

let fiber = null
try {
  fiber = await ctx.plugin(mod, {
    dataDir,
    apiPort: API_PORT,
    syslogPorts: [SYSLOG_PORT],
    opsApiPort: OPS_PORT,
    apiTokenEnabled: true,
    // A frame at severity 4 (warning) clears the default floor of 5.
    autoTriage: true,
    // The panel's day-session fields, passed the way the settings store would.
    // A workspace is pinned so the probe can prove it reaches the host's
    // create(); the instruction is the operator's own text, with placeholders
    // left in, so the substitution is exercised through real activation rather
    // than only in a unit test.
    autoSessionWorkspace: dataDir,
    autoSessionPrompt: '排查 {device} 上的 {id}',
  })
  check('the plugin fiber reaches ACTIVE', fiber?.state === 2, `state=${fiber?.state}`)
} catch (e) {
  check('the plugin loads without throwing', false, String(e?.stack ?? e))
  console.error(e?.stack ?? e)
  process.exit(1)
}

const warnings = (ctx.logger?.buffer ?? [])
  .filter((m) => m.level === 2)
  .map((m) => `${m.name}: ${(m.args ?? []).join(' ')}`)
check('activation logged no degradation warning', warnings.length === 0, warnings.join(' | '))

await sleep(700)

// --- the loopback API answers ------------------------------------------------
const base = `http://127.0.0.1:${API_PORT}/syslog-api`
const session = await fetch(`${base}/_session`).then((r) => r.json()).catch((e) => ({ error: String(e) }))
const token = typeof session.token === 'string' ? session.token : ''
check('the api port serves /_session', token.length > 0, JSON.stringify(session).slice(0, 120))

// Auth is on, so an unauthenticated read must be refused. A loopback API that
// answers anyone means any page the user visits can read their alerts.
//
// The request has to carry a *remote* Origin: Node's fetch sends none, and the
// API deliberately treats an absent Origin as the local desktop app (that is
// how the panel is allowed through). A same-origin-less fetch would therefore
// be waved past and the check would pass for the wrong reason.
const unauth = await fetch(`${base}/alerts`, { headers: { origin: 'https://evil.example' } })
  .then((r) => r.status)
  .catch(() => 0)
check('an unauthenticated read from a remote origin is refused', unauth === 401 || unauth === 403, `status=${unauth}`)
const unauthWrite = await fetch(`${base}/settings`, {
  method: 'PUT',
  headers: { origin: 'https://evil.example', 'content-type': 'application/json' },
  body: JSON.stringify({ minSeverity: 0 }),
}).then((r) => r.status).catch(() => 0)
check('an unauthenticated write from a remote origin is refused', unauthWrite === 401 || unauthWrite === 403, `status=${unauthWrite}`)
const headers = { 'X-Syslog-Token': token }

const status = await fetch(`${base}/status`, { headers }).then((r) => r.json())
// /status wraps everything in {ok, listener, stats} — reading status.listening
// off the top level would silently test undefined.
const listener = status.listener ?? status
check('the receiver reports listening', listener.listening === true, JSON.stringify(listener).slice(0, 200))
check('the configured port is bound', (listener.boundPorts ?? []).includes(SYSLOG_PORT), JSON.stringify(listener.boundPorts))

// --- a real datagram travels the whole path ----------------------------------
const send = (text) =>
  new Promise((resolve, reject) => {
    const s = createSocket('udp4')
    s.send(Buffer.from(text), SYSLOG_PORT, '127.0.0.1', (err) => (err ? reject(err) : s.close(resolve)))
  })

// Severity 4 = warning (facility 16 x 8 + 4), which clears the default floor.
await send('<132>Oct  7 10:12:33 127.0.0.1 LINK-3: Interface GE1/0/1 link status changed to DOWN')
await sleep(500)

const listed = await fetch(`${base}/alerts`, { headers }).then((r) => r.json())
const alerts = listed.alerts ?? []
check('the datagram produced an alert', alerts.length >= 1, `alerts=${alerts.length} stats=${JSON.stringify(listed.stats ?? {})}`)
const alert = alerts[0]
if (alert) {
  const detail = await fetch(`${base}/alerts/${alert.id}`, { headers }).then((r) => r.json())
  const a = detail.alert ?? detail
  check('the alert keeps the raw syslog', String(a.message?.raw ?? '').includes('link status changed to DOWN'))
  check('the alert records where it came from', a.transport === 'udp' && a.sourceIp === '127.0.0.1', `transport=${a.transport} sourceIp=${a.sourceIp}`)
  check('the frame is bound to its device', a.deviceId === 'dev-1', `deviceId=${a.deviceId}`)
}

// Only read-only verbs could ever reach the ops bridge — and since the automatic
// analysis pipeline is gone, nothing in this plugin even calls it during
// ingestion. Asserted against the running plugin rather than any unit test.
const forwarded = opsRequests.filter((r) => r.url === '/ops-api/analyze').flatMap((r) => (r.body ? JSON.parse(r.body).commands ?? [] : []))
check('only read-only commands ever reached the bridge', forwarded.length === 0 || forwarded.every((c) => /^\s*(show|display|get|diagnose)\s/i.test(c)), JSON.stringify(forwarded))

const stats = await fetch(`${base}/stats`, { headers }).then((r) => r.json())
const st = stats.stats ?? stats
check('the receiver counted the packet', (st.received ?? 0) >= 1, JSON.stringify(st).slice(0, 160))
check('the listener is reported', (stats.listener?.listening ?? listener.listening) === true)

// --- the alert opens an ordinary Session for the day -------------------------
// This is the path the user asked for: no subagent provider, no provider
// configuration at all — just the host's Session service, which every DSH
// install has. The deep-analysis path above is off by default, so both
// mechanisms being independently switchable is what lets an operator run this
// one alone.
const auto = await fetch(`${base}/auto-session`, { headers }).then((r) => r.json())
check('GET /auto-session reports the day session', auto.ok && auto.autoSession?.enabled === true, JSON.stringify(auto).slice(0, 200))
check('exactly one ordinary session was created for the day', autoCalls.created.length === 1, JSON.stringify(autoCalls.created))
// A settings panel that shows a workspace but never sends it leaves the session
// in whatever directory the host happened to be in, and the agent's file tools
// then point at the wrong tree.
check('the configured workspace was passed to create()',
  autoCalls.created[0]?.cwd === dataDir, JSON.stringify(autoCalls.created[0]))
check('the status reports where the session actually lives', auto.autoSession?.workspace === dataDir, JSON.stringify(auto.autoSession))
check('the ordinary session was titled for the local day',
  autoCalls.renamed[0]?.title === `告警分析 ${dateKey(Date.now())}`,
  JSON.stringify(autoCalls.renamed.map((r) => r.title)))
check('the rename addressed the session that was created',
  autoCalls.renamed[0]?.sessionId === 'auto-session-1',
  JSON.stringify({ created: autoCalls.created, renamed: autoCalls.renamed }))
check('one prompt was admitted per alert', autoCalls.prompted.length === 1, JSON.stringify(autoCalls.prompted.length))
check("the operator's own instruction line leads the prompt",
  String(autoCalls.prompted[0]?.content?.[0]?.text ?? '').startsWith(`排查 SW1 上的 ${alert.id}`),
  JSON.stringify(autoCalls.prompted[0]?.content?.[0]?.text ?? '').slice(0, 120))
check('the plugin still appends the identity it can vouch for',
  String(autoCalls.prompted[0]?.content?.[0]?.text ?? '').includes(`告警 id：${alert.id}`),
  JSON.stringify(autoCalls.prompted[0]?.content?.[0]?.text ?? '').slice(0, 200))
check('the prompt carries the raw syslog line',
  String(autoCalls.prompted[0]?.content?.[0]?.text ?? '').includes('link status changed to DOWN'),
  JSON.stringify(autoCalls.prompted[0]?.content?.[0]?.text ?? '').slice(0, 200))
check('the prompt is a queued text part, not a steer',
  autoCalls.prompted.every((p) => p.mode === 'queue' && p.content?.length === 1 && p.content[0].type === 'text'),
  JSON.stringify(autoCalls.prompted.map((p) => ({ mode: p.mode, parts: p.content?.map((c) => c.type) }))))
check('every prompt carries its own request id',
  typeof autoCalls.prompted[0]?.requestId === 'string', JSON.stringify(autoCalls.prompted.map((p) => p.requestId)))
check('every prompt carries the signal the host dereferences on entry',
  autoCalls.signals.length === autoCalls.prompted.length
  && autoCalls.signals.every((s) => s instanceof AbortSignal && s.aborted === false),
  JSON.stringify(autoCalls.signals.map((s) => Object.prototype.toString.call(s))))
check('the alert landed in that session', autoCalls.prompted[0]?.sessionId === 'auto-session-1', JSON.stringify(autoCalls.prompted.map((p) => p.sessionId)))
check('the status reports the live session and its count',
  auto.autoSession?.sessionId === 'auto-session-1' && auto.autoSession?.dateKey === dateKey(Date.now()) && auto.autoSession?.postedToday === 1,
  JSON.stringify(auto.autoSession))

// A second alert of the same day must land in the SAME session, not a new one,
// and must carry its own request id so the host queues rather than overwrites.
await send('<132>Oct  7 10:12:35 127.0.0.1 LINK-4: Interface GE1/0/2 link status changed to DOWN')
await sleep(900)
check('a second alert reuses the same session', autoCalls.created.length === 1 && autoCalls.prompted.length === 2, `created=${autoCalls.created.length} prompted=${autoCalls.prompted.length}`)
check('each prompt carries its own request id',
  autoCalls.prompted[0]?.requestId !== autoCalls.prompted[1]?.requestId,
  JSON.stringify(autoCalls.prompted.map((p) => p.requestId)))
// `alerts` was snapshotted before this frame arrived, so the second prompt is
// checked against the first: a shared placeholder would render both lines
// identically, which is the bug a per-alert substitution rules out.
const secondLine = String(autoCalls.prompted[1]?.content?.[0]?.text ?? '').split('\n')[0] ?? ''
const firstLine = String(autoCalls.prompted[0]?.content?.[0]?.text ?? '').split('\n')[0] ?? ''
check('the second alert substitutes its own id into the instruction',
  secondLine.startsWith('排查 SW1 上的 ') && secondLine !== firstLine,
  JSON.stringify({ first: firstLine, second: secondLine }))

// --- feature 3: the receiver can be stopped and started without unloading -----
const stopped = await fetch(`${base}/listener`, {
  method: 'POST', headers: { ...headers, 'content-type': 'application/json' }, body: JSON.stringify({ action: 'stop' }),
}).then((r) => r.json())
check('POST /listener stop reports the receiver down', stopped.ok && stopped.status.listening === false, JSON.stringify(stopped))
eq('the port is released', (stopped.status.boundPorts ?? []).length, 0)
// Baseline taken *after* the stop: earlier reads are stale by now (the second
// alert above arrived in between), and comparing against them would prove
// nothing about whether the closed socket counts packets.
const atStop = await fetch(`${base}/stats`, { headers }).then((r) => r.json())
const receivedAtStop = (atStop.stats ?? atStop).received ?? 0
await send('<132>Oct  7 10:12:40 127.0.0.1 LINK-5: this frame must arrive while stopped')
await sleep(400)
const whileStopped = await fetch(`${base}/stats`, { headers }).then((r) => r.json())
eq('a stopped receiver counts nothing', (whileStopped.stats ?? whileStopped).received, receivedAtStop, 'packets arrived while the socket was closed')

const restarted = await fetch(`${base}/listener`, {
  method: 'POST', headers: { ...headers, 'content-type': 'application/json' }, body: JSON.stringify({ action: 'start' }),
}).then((r) => r.json())
check('POST /listener start rebinds the same port', restarted.ok && (restarted.status.boundPorts ?? []).includes(SYSLOG_PORT), JSON.stringify(restarted))
await send('<132>Oct  7 10:12:45 127.0.0.1 LINK-6: Interface GE1/0/3 link status changed to DOWN')
await sleep(600)
const afterRestart = await fetch(`${base}/stats`, { headers }).then((r) => r.json())
check('frames are received again after a restart', ((afterRestart.stats ?? afterRestart).received ?? 0) > st.received, `before=${st.received} after=${(afterRestart.stats ?? afterRestart).received}`)

await fiber?.dispose?.()
opsBridge.close()
await sleep(300)
rmSync(dataDir, { recursive: true, force: true })
console.log(`\n${bad === 0 ? 'ACTIVATION OK' : `ACTIVATION MISSING ${bad}`}`)
process.exit(bad === 0 ? 0 : 1)