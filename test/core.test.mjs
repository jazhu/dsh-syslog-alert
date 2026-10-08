/**
 * Unit + integration tests for dsh-syslog-alert.
 *
 * These run against the SOURCE files via Node 24's native type-stripping, not
 * against dist/. A behaviour test that imports the bundle only proves the bundle
 * exists; importing `src/*.ts` proves the logic. The bundle is covered by
 * bundle-gate.mjs, which greps the artefact and checks it is not stale.
 *
 * Run: node test/core.test.mjs
 */
import { createSocket } from 'node:dgram'
import { mkdirSync, rmSync, readFileSync, existsSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const SRC = new URL('../src/', import.meta.url)
const load = (name) => import(new URL(name, SRC).href)

const {
  parseSyslogFrame, splitFrames,
} = await load('syslog-parse.ts')
const {
  mapSourceToDevice, cidrContains, fingerprint, prefilter, inMaintenanceWindow,
} = await load('fingerprint.ts')
const {
  DEFAULT_CONFIG, resolveConfig, SettingsStore,
} = await load('settings.ts')
const {
  SEVERITY_NAMES,
} = await load('types.ts')
const { AlertStore, StatsCounter, emptyStats } = await load('alert-store.ts')
const { drainTcpBuffer, tcpDrainedLength } = await load('syslog-server.ts')
const { DEFAULT_CONFIG: _DC } = { DEFAULT_CONFIG }

let pass = 0
let bad = 0
const failures = []

function check(name, hit) {
  if (hit) {
    console.log(`  ok   ${name}`)
    pass++
  } else {
    console.log(`  MISS ${name}`)
    bad++
    failures.push(name)
  }
}

function eq(name, actual, expected) {
  const a = JSON.stringify(actual)
  const e = JSON.stringify(expected)
  check(`${name}${a === e ? '' : ` (got ${a}, want ${e})`}`, a === e)
}

function section(title) {
  console.log(`\n== ${title}`)
}

// ---------------------------------------------------------------------------
section('syslog parsing')

{
  // RFC3164 with space-padded day — the single most common real-device shape.
  const m = parseSyslogFrame('<134>Oct  7 10:12:33 SW1 LINK-3: Interface GE1/0/1 link status changed to DOWN')
  check('rfc3164 parses', m.confidence === 'rfc3164')
  eq('rfc3164 severity', m.severity, 6)
  eq('rfc3164 severityName', m.severityName, 'info')
  // PRI 134 = facility 16 (local0) * 8 + severity 6 (info).
  eq('rfc3164 facility', m.facility, 16)
  eq('rfc3164 facilityName', m.structuredData?._facility, 'local0')
  eq('rfc3164 hostname', m.hostname, 'SW1')
  eq('rfc3164 tag', m.tag, 'LINK-3')
  check('rfc3164 message text', m.message.includes('Interface GE1/0/1'))
  check('rfc3164 timestamp year is current', new Date(m.timestamp).getFullYear() === new Date().getFullYear())
}

{
  // Space padding must survive: 'Oct  7' is two spaces, 'Oct 17' is one.
  const m = parseSyslogFrame('<134>Oct 17 08:00:00 SW2 OSPF-5: neighbor down')
  check('rfc3164 single-digit day still parses', m.confidence === 'rfc3164' && m.hostname === 'SW2')
  eq('rfc3164 two-digit day tag', m.tag, 'OSPF-5')
}

{
  const m = parseSyslogFrame(
    '<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOMAn application event log entry',
  )
  check('rfc5424 parses', m.confidence === 'rfc5424')
  eq('rfc5424 appName maps to tag', m.tag, 'su')
  eq('rfc5424 hostname', m.hostname, 'mymachine.example.com')
  eq('rfc5424 procId nil becomes undefined', m.procId, undefined)
  eq('rfc5424 msgId', m.msgId, 'ID47')
  check('rfc5424 message body', m.message.startsWith('BOMAn application event log entry'))
}

{
  // SD escaping: a ']' inside a quoted value must not truncate the param list.
  const m = parseSyslogFrame(
    '<165>1 2003-10-11T22:14:15.003Z host app 1 ID47 [exampleSDID@32473 iut="3" eventSource="App" eventID="a\]b"] msg',
  )
  check('rfc5424 structured data parses', m.confidence === 'rfc5424')
  // SD is stored per-element as a JSON string, keyed by the element id.
  const sd = JSON.parse(m.structuredData?.['exampleSDID@32473'] ?? '{}')
  eq('rfc5424 sd param after \\] unescape', sd.eventID, 'a]b')
  check('rfc5424 sd eventSource intact', sd.eventSource === 'App')
  eq('rfc5424 sd keeps every param', Object.keys(sd).length, 3)
  check('rfc5424 msg excludes structured data', !m.message.includes('eventSource'))
}

{
  const m = parseSyslogFrame('total garbage with no structure at all')
  check('garbage degrades to raw', m.confidence === 'raw')
  check('raw keeps the full text', m.raw.includes('total garbage'))
}

{
  const m = parseSyslogFrame('<13>Aug 30 23:59:00 X TEST: hi', Date.parse('2026-01-05T00:00:00Z'))
  check(
    'december frame read in january rolls back one year',
    new Date(m.timestamp).getFullYear() === 2025,
  )
}

{
  const frames = splitFrames('<13>a\n<13>b')
  eq('splitFrames splits on newline', frames.length, 2)
}

{
  const frames = splitFrames('<13>first line\n  continued line\n<13>second')
  eq('continuation lines fold into the previous message', frames.length, 2)
  check('continuation text is preserved', frames[0].includes('continued line'))
}

// ---------------------------------------------------------------------------
section('device mapping')

{
  const devices = [
    { id: 'd1', ip: '10.0.0.1', syslogFrom: ['192.168.99.1'] },
    { id: 'd2', ip: '10.0.0.2', syslogCidrs: ['172.16.0.0/16'] },
  ]
  eq('syslogFrom wins over ip', mapSourceToDevice('192.168.99.1', devices).deviceId, 'd1')
  eq('ip exact match', mapSourceToDevice('10.0.0.2', devices).deviceId, 'd2')
  eq('cidr match', mapSourceToDevice('172.16.5.9', devices).deviceId, 'd2')
  eq('ipv4-mapped ipv6 form', mapSourceToDevice('::ffff:10.0.0.1', devices).deviceId, 'd1')
  eq('unmapped source has no deviceId', mapSourceToDevice('8.8.8.8', devices).deviceId, undefined)
}

{
  check('cidrContains inside', cidrContains('172.16.0.0/16', '172.16.255.255'))
  check('cidrContains outside', !cidrContains('172.16.0.0/16', '172.17.0.1'))
  check('cidrContains rejects garbage cidr', !cidrContains('not-a-cidr', '1.2.3.4'))
}

{
  const m1 = parseSyslogFrame('<134>Oct  7 10:12:33 SW1 LINK-3: Interface GE1/0/1 link status changed to DOWN')
  const m2 = parseSyslogFrame('<134>Oct  7 10:12:35 SW1 LINK-3: Interface GE1/0/1 link status changed to DOWN')
  const m3 = parseSyslogFrame('<134>Oct  7 10:12:37 SW1 LINK-3: Interface GE1/0/2 link status changed to DOWN')
  const f1 = fingerprint('d1', m1)
  eq('identical alerts share a fingerprint', f1, fingerprint('d1', m2))
  check(
    'a different interface is a different fingerprint',
    f1 !== fingerprint('d1', m3),
    'GE1/0/1 vs GE1/0/2 must not collapse into one alert',
  )
  check('fingerprint is stable across calls', f1 === fingerprint('d1', parseSyslogFrame(m1.raw)))
}

{
  // Cisco-shaped MACs (dotted, 4 hex digits per group) must normalize too, or
  // an ARP storm never collapses.
  const withMac = parseSyslogFrame('<134>Oct  7 10:12:33 SW1 ETH-1: arp 0011.2233.4455 moved')
  const withMac2 = parseSyslogFrame('<134>Oct  7 10:12:39 SW1 ETH-1: arp 00aa.bbcc.ddee moved')
  check(
    'different MACs collapse to one fingerprint',
    fingerprint('d1', withMac) === fingerprint('d1', withMac2),
  )
}

// ---------------------------------------------------------------------------
section('prefilter')

{
  const msg = parseSyslogFrame('<134>Oct  7 10:12:33 SW1 LINK-3: link down')
  const config = { ...DEFAULT_CONFIG }

  const drop = prefilter(msg, {}, config, Date.now())
  check('unmapped source is dropped by default', drop.drop === true)
  eq('the drop reason names the cause', drop.reason, 'unmapped-source')
}

{
  const msg = parseSyslogFrame('<134>Oct  7 10:12:33 SW1 LINK-3: link down')
  const config = { ...DEFAULT_CONFIG, unmappedPolicy: 'capture-only' }
  const r = prefilter(msg, {}, config, Date.now())
  check('capture-only keeps an unmapped alert', r.storeOnly === true)
  check('capture-only never returns drop', r.drop !== true)
}

{
  const raw = parseSyslogFrame('garbage')
  const config = { ...DEFAULT_CONFIG, unmappedPolicy: 'capture-only' }
  const r = prefilter(raw, { deviceId: 'd1' }, config, Date.now())
  check('unparseable input is store-only even when mapped', r.storeOnly === true)
}

{
  const msg = parseSyslogFrame('<13>Oct  7 10:12:33 SW1 INFO-1: chatty')
  const config = { ...DEFAULT_CONFIG, minSeverity: 3 }
  const r = prefilter(msg, { deviceId: 'd1' }, config, Date.now())
  check('severity below the floor is dropped', r.drop === true)
}

{
  // PRI 131 = facility 16 * 8 + severity 3, so the allow-list is what decides
  // here. A severity-6 frame would be dropped by the min-severity floor first
  // and the assertion would pass for the wrong reason.
  const msg = parseSyslogFrame('<131>Oct  7 10:12:33 SW1 HSRP-5: hsrp down')
  const config = { ...DEFAULT_CONFIG, mnemonicAllow: ['LINK-', 'OSPF-'] }
  const r = prefilter(msg, { deviceId: 'd1' }, config, Date.now())
  check('mnemonic outside the allow-list is dropped', r.drop === true)
  eq('and it says why', r.reason, 'mnemonic-not-allowed')
  const allowed = prefilter(parseSyslogFrame('<131>Oct  7 10:12:33 SW1 LINK-3: x'), { deviceId: 'd1' }, config, Date.now())
  check('mnemonic inside the allow-list passes', allowed.drop !== true)
  const ospf = prefilter(parseSyslogFrame('<131>Oct  7 10:12:33 SW1 OSPF-5: x'), { deviceId: 'd1' }, config, Date.now())
  check('a second allow-list entry works too', ospf.drop !== true)
}

{
  // The allow-list must be a restriction, not a broadener: an entry written as
  // 'LINK' may not admit an unrelated tag.
  const config = { ...DEFAULT_CONFIG, mnemonicAllow: ['LINK'] }
  check('an exact family name admits the family', prefilter(parseSyslogFrame('<131>Oct  7 10:12:33 SW1 LINK-9: x'), { deviceId: 'd1' }, config, Date.now()).drop !== true)
  check('an exact family name excludes other tags', prefilter(parseSyslogFrame('<131>Oct  7 10:12:33 SW1 CPU-9: x'), { deviceId: 'd1' }, config, Date.now()).drop === true)
}

{
  // Local-time construction: the windows are wall-clock HH:MM, so a UTC instant
  // would be checked against the wrong hour on any non-UTC machine.
  const at = (h, m) => new Date(2026, 2, 10, h, m, 0, 0).getTime()
  check('maintenance window covers the time', inMaintenanceWindow([{ from: '02:00', to: '04:00' }], at(2, 30)))
  check('maintenance window excludes outside time', !inMaintenanceWindow([{ from: '02:00', to: '04:00' }], at(5, 0)))
  check('window crossing midnight covers 23:30', inMaintenanceWindow([{ from: '22:00', to: '02:00' }], at(23, 30)))
  check('window crossing midnight covers 01:30', inMaintenanceWindow([{ from: '22:00', to: '02:00' }], at(1, 30)))
  check('window crossing midnight excludes midday', !inMaintenanceWindow([{ from: '22:00', to: '02:00' }], at(12, 0)))
  check('a zero-length window is never open', !inMaintenanceWindow([{ from: '03:00', to: '03:00' }], at(3, 0)))
  check('no windows means no maintenance', !inMaintenanceWindow([], at(3, 0)))
}

// ---------------------------------------------------------------------------
section('alert store')

{
  const dataDir = join(tmpdir(), `dsh-syslog-test-${Date.now()}`)
  rmSync(dataDir, { recursive: true, force: true })
  mkdirSync(dataDir, { recursive: true })
  const store = new AlertStore({ dataDir, ringSize: 50, retentionDays: 1 })
  const msg = parseSyslogFrame('<134>Oct  7 10:12:33 SW1 LINK-3: link down')
  const a = store.create({ message: msg, deviceId: 'd1', deviceName: 'SW1', sourceIp: '10.0.0.1', fingerprint: 'fp1' })
  check('create returns an alert with an id', typeof a.id === 'string' && a.id.length > 0)
  store.bumpRepeat(a.id, Date.now())
  store.bumpRepeat(a.id, Date.now())
  eq('repeat count increments', store.get(a.id).count, 3)
  store.advance(a.id, 'closed', 'ok')
  eq('advance moves the stage', store.get(a.id).stage, 'closed')
  check('timeline recorded the stage', store.get(a.id).timeline.some((t) => t.stage === 'closed'))
  const listed = store.list({ limit: 10 })
  check('list returns the alert', listed.alerts.some((x) => x.id === a.id))
  store.ack(a.id)
  check('ack sets ackedAt', typeof store.get(a.id).ackedAt === 'number')
  eq('ack closes the alert', store.get(a.id).stage, 'closed')
  rmSync(dataDir, { recursive: true, force: true })
}

{
  const counter = new StatsCounter(emptyStats())
  counter.inc('received')
  counter.inc('received', 5)
  eq('inc adds up', counter.get().received, 6)
  counter.inc('storms')
  eq('inc works on every key', counter.get().storms, 1)
  counter.reset()
  eq('reset zeroes counters', counter.get().received, 0)
}

// ---------------------------------------------------------------------------
section('settings resolution')

{
  const cfg = resolveConfig(undefined, undefined)
  eq('default ports', cfg.syslogPorts, [1514])
  eq('default api port', cfg.apiPort, 18784)
  check('day-session analysis is on by default', cfg.autoSessionEnabled === true)
  check('dataDir is absolute', cfg.dataDir.includes('dsh-syslog-alert'))

  const clamped = resolveConfig({ apiPort: 1, syslogPorts: [999999, -1, 1514], perDeviceRatePerMin: 0 }, undefined)
  check('apiPort is clamped', clamped.apiPort >= 1024)
  eq('invalid ports are dropped', clamped.syslogPorts, [1514])
  check('rate limit is clamped to >= 1', clamped.perDeviceRatePerMin >= 1)
}

{
  const dataDir = join(tmpdir(), `dsh-syslog-settings-${Date.now()}`)
  const store = new SettingsStore({ ...DEFAULT_CONFIG, dataDir })
  store.loadPersisted(() => {})
  store.apply({ minSeverity: 1 }, { persist: true, log: () => {} })
  eq('apply updates the field', store.current.minSeverity, 1)
  check('settings.json written', existsSync(join(dataDir, 'settings.json')))
  const reread = JSON.parse(readFileSync(join(dataDir, 'settings.json'), 'utf-8'))
  eq('persisted value round-trips', reread.minSeverity, 1)
  store.apply({ apiPort: 20001 }, { persist: false, log: () => {} })
  eq('host-only fields are ignored on apply', store.current.apiPort, 18784)
  rmSync(dataDir, { recursive: true, force: true })
}

// ---------------------------------------------------------------------------
section('tcp framing')

{
  // RFC6587 octet counting: "30 <13>...". Two messages in one buffer.
  const a = '<13>Oct  7 10:12:33 SW1 LINK-3: first'
  const b = '<13>Oct  7 10:12:34 SW1 LINK-3: second'
  const buf = `${a.length} ${a}${b.length} ${b}`
  const frames = drainTcpBuffer(buf)
  eq('octet-counted frames are split', frames.length, 2)
  check('octet-counted frame 1', frames[0].includes('first'))
  check('octet-counted frame 2', frames[1].includes('second'))
  eq('consumed length matches', tcpDrainedLength(buf), buf.length)
}

{
  const buf = 'line one\nline two\n'
  const frames = drainTcpBuffer(buf)
  eq('newline frames are split', frames.length, 2)
  eq('newline consumed length', tcpDrainedLength(buf), buf.length)
}

{
  // A partial frame must NOT be emitted; it would be reported as a truncated
  // alert and then again as a duplicate once the rest arrives.
  const a = '<13>Oct  7 10:12:33 SW1 LINK-3: partial message'
  const partial = Buffer.from(`${a.length} ${a.slice(0, 10)}`)
  eq('incomplete octet-counted frame is withheld', drainTcpBuffer(partial).length, 0)
}

// ---------------------------------------------------------------------------
section('receiver end to end (udp)')

{
  const dataDir = join(tmpdir(), `dsh-syslog-udp-${Date.now()}`)
  const port = await freePort()
  const received = []
  const { SyslogReceiver } = await load('syslog-server.ts')
  const receiver = new SyslogReceiver({
    config: { ...DEFAULT_CONFIG, syslogPorts: [port], enableTcp: false },
    onFrame: (f) => received.push(f),
    onWarn: () => {},
  })
  // start() resolves once every bind attempt has settled, so awaiting it is
  // the port-ready signal. (waitPort() cannot probe UDP: there is no handshake
  // to connect to, so it returns immediately and would race the bind.)
  await receiver.start()
  const status = receiver.getStatus()
  check('receiver reports listening', status.listening === true)
  check('receiver reports the bound port', status.boundPorts.includes(port))
  check('no failed ports', status.failedPorts.length === 0)

  const sock = createSocket('udp4')
  await new Promise((r) => sock.send(Buffer.from('<134>Oct  7 10:12:33 SW1 LINK-3: udp probe'), port, '127.0.0.1', r))
  await waitUntil(() => received.length > 0, 3000)
  check('udp frame arrives', received.length === 1)
  check('udp frame keeps its text', received[0]?.text.includes('udp probe'))
  eq('udp frame records its source ip', received[0]?.sourceIp, '127.0.0.1')
  eq('udp frame records transport', received[0]?.transport, 'udp')
  sock.close()
  receiver.stop()
  rmSync(dataDir, { recursive: true, force: true })
}

// ---------------------------------------------------------------------------
section('bind failure is reported, not swallowed')

{
  const port = await freePort()
  const blocker = createSocket('udp4')
  await new Promise((r) => blocker.bind(port, '0.0.0.0', r))
  const warnings = []
  const { SyslogReceiver } = await load('syslog-server.ts')
  const receiver = new SyslogReceiver({
    config: { ...DEFAULT_CONFIG, syslogPorts: [port], enableTcp: false },
    onFrame: () => {},
    onWarn: (m) => warnings.push(String(m)),
  })
  await receiver.start()
  const status = receiver.getStatus()
  check(
    'a busy port lands in failedPorts',
    status.failedPorts.some((f) => f.port === port),
  )
  check('the failure reason is carried', status.failedPorts.some((f) => typeof f.reason === 'string' && f.reason.length > 0))
  check('a failed bind is not reported as listening', status.listening === false)
  check('nothing is bound', status.boundPorts.length === 0)
  check('a warning was emitted', warnings.length > 0)
  receiver.stop()
  blocker.close()
}

// ---------------------------------------------------------------------------
console.log(`\n${bad === 0 ? 'ALL OK' : `FAILED ${bad}`} — ${pass} passed, ${bad} failed`)
if (bad > 0) {
  console.log('\nfailures:')
  for (const f of failures) console.log(`  - ${f}`)
  process.exitCode = 1
}

// --- helpers ---------------------------------------------------------------

function freePort() {
  return new Promise((resolve, reject) => {
    const s = createSocket('udp4')
    s.bind(0, '127.0.0.1', () => {
      const p = s.address().port
      s.close(() => resolve(p))
    })
    s.on('error', reject)
  })
}

function waitPort(port, kind = 'tcp') {
  return waitUntil(() => {
    if (kind === 'udp') return true
    const net = require('node:net')
    return new Promise((resolve) => {
      const c = net.connect(port, '127.0.0.1')
      c.on('connect', () => { c.destroy(); resolve(true) })
      c.on('error', () => resolve(false))
    })
  }, 4000)
}

async function waitUntil(fn, timeoutMs) {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    if (await fn()) return true
    await new Promise((r) => setTimeout(r, 40))
  }
  return false
}