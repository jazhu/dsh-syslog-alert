// dsh-syslog-alert — device mapping, fingerprinting, and prefiltering.
//
// These three live together because they are the "does this frame deserve an
// LLM call?" gate, and they all run before any token is spent. Getting this
// layer wrong is how a link flap becomes 4000 LLM calls.

import type { Config, MaintenanceWindow, SyslogMessage } from './types.ts'

// ---- device mapping ---------------------------------------------------------

/** The slice of a hillstone Device this plugin needs. */
export interface DeviceLike {
  id: string
  name?: string
  ip?: string
  /** Optional explicit syslog source IPs (a device's syslog source is often its
   *  management-port address, which need not equal its SSH address). */
  syslogFrom?: string[]
  /** Optional CIDRs this device answers from. */
  syslogCidrs?: string[]
}

export interface MappingResult {
  deviceId?: string
  deviceName?: string
}

/**
 * Resolve the sending IP to a managed device.
 *
 * Order matters: an explicit `syslogFrom` entry beats a bare `ip` match, because
 * two devices can sit behind one address while their syslog sources differ, and
 * a CIDR is the loosest of the three by design.
 */
export function mapSourceToDevice(sourceIp: string, devices: readonly DeviceLike[]): MappingResult {
  if (!sourceIp) return {}
  // Strip an IPv6 zone / bracket form so ::ffff:10.0.0.1 matches 10.0.0.1.
  const ip = sourceIp.replace(/^\[|\]$/g, '').split('%')[0] ?? ''
  const v4 = ip.startsWith('::ffff:') ? ip.slice(7) : ip

  for (const d of devices) {
    for (const candidate of d.syslogFrom ?? []) {
      if (candidate && candidate === ip) return { deviceId: d.id, deviceName: d.name }
    }
  }
  for (const d of devices) {
    if (d.ip && (d.ip === ip || d.ip === v4)) return { deviceId: d.id, deviceName: d.name }
  }
  for (const d of devices) {
    for (const cidr of d.syslogCidrs ?? []) {
      if (cidrContains(cidr, v4)) return { deviceId: d.id, deviceName: d.name }
    }
  }
  return {}
}

function ipv4ToInt(ip: string): number | undefined {
  const parts = ip.split('.')
  if (parts.length !== 4) return undefined
  let n = 0
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return undefined
    const v = Number(p)
    if (v > 255) return undefined
    n = (n << 8) | v
  }
  return n >>> 0
}

/** True when `ip` falls inside `cidr` (e.g. `10.0.1.0/24`). Malformed → false. */
export function cidrContains(cidr: string, ip: string): boolean {
  const slash = cidr.indexOf('/')
  if (slash < 0) return cidr === ip
  const base = ipv4ToInt(cidr.slice(0, slash))
  const target = ipv4ToInt(ip)
  const bits = Number(cidr.slice(slash + 1))
  if (base === undefined || target === undefined || !Number.isInteger(bits) || bits < 0 || bits > 32) {
    return false
  }
  if (bits === 0) return true
  const mask = (0xffffffff << (32 - bits)) >>> 0
  return (base & mask) === (target & mask)
}

// ---- fingerprint ------------------------------------------------------------

/**
 * Strip addresses only, keeping every other token verbatim.
 *
 * Used for the head of a fingerprint: `ge0/0` has to survive so two different
 * ports stay two different alerts, but a MAC that happens to land in the first
 * few words (`arp 0011.2233.4455 moved`) must not, or a storm never collapses.
 */
function stripAddresses(text: string): string {
  return text
    .replace(/[0-9a-fA-F]{4}(?:[.\-][0-9a-fA-F]{4}){2}/g, '<mac>')
    .replace(/[0-9a-fA-F]{2}(?:[:\-][0-9a-fA-F]{2}){5}/g, '<mac>')
    .replace(/0x[0-9a-fA-F]+/g, '<hex>')
}

/** Hex blobs, MACs, and bare numbers carry no dedup value but all vary. */
function normalizeNoise(text: string): string {
  return stripAddresses(text)
    .replace(/\b\d+\b/g, '<n>')
    .replace(/\s+/g, ' ')
    .trim()
}

/**
 * A stable key for "this is the same alert again".
 *
 * Built from device + tag + the message with every varying token normalized
 * away. `LINK-3: Interface ge0/0 down` flaps across minutes and must collapse to
 * one alert; `LINK-3: Interface ge0/1 down` is a different port and must not.
 * Port identity usually survives normalization as a non-numeric token
 * (`ge0/0` → `ge<n>/<n>` loses it), so the tag and the leading noun phrase are
 * kept verbatim and only the tail is normalized.
 */
export function fingerprint(deviceId: string | undefined, msg: SyslogMessage): string {
  const tag = (msg.tag ?? 'NOTAG').toUpperCase()
  const head = stripAddresses(msg.message.split(/\s+/).slice(0, 4).join(' '))
  const tail = normalizeNoise(msg.message)
  return [deviceId ?? 'unmapped', tag, head, tail].join('|').slice(0, 512)
}

// ---- prefilter --------------------------------------------------------------

export interface PrefilterVerdict {
  /** Drop out of analysis entirely. */
  drop?: boolean
  /**
   * Keep the alert visible but never analyse it. This is the `capture-only`
   * path for unmapped sources: the operator needs to SEE that a device's logs
   * are arriving but must not let an unidentified sender drive SSH commands.
   */
  storeOnly?: boolean
  reason?: string
  detail?: string
}

/**
 * Zero-LLM rejection. Runs before fingerprinting so a device spamming debug
 * noise never fills the dedup table with keys nobody will ever read.
 */
/**
 * Decide whether a parsed frame is worth keeping.
 *
 * `now` is a timestamp in ms so the maintenance-window check runs against the
 * log's own time, not the wall clock — a 03:00 line that reaches us at 10:00
 * belongs to the 03:00 window.
 */
export function prefilter(
  msg: SyslogMessage,
  mapping: MappingResult,
  config: Pick<Config, 'minSeverity' | 'mnemonicAllow' | 'maintenanceWindows' | 'unmappedPolicy'>,
  now: number = Date.now(),
): PrefilterVerdict {
  if (!mapping.deviceId) {
    if (config.unmappedPolicy === 'ignore') {
      return { drop: true, reason: 'unmapped-source', detail: '来源 IP 未映射到任何已管设备' }
    }
    // capture-only: store it and flag it, but never let it into the pipeline —
    // an unidentified sender must never drive an SSH command against a guessed host.
    return {
      storeOnly: true,
      reason: 'unmapped-source',
      detail: '来源未映射到已管设备，仅留存不进分析',
    }
  }

  // A frame we could not structurally parse must not reach the LLM: its
  // structured fields would be fabricated from the front of the line.
  if (msg.confidence === 'raw') {
    return { storeOnly: true, reason: 'parse-failed', detail: '无法结构化解析，按纯文本留存' }
  }

  const sev = msg.severity ?? 7
  if (sev > config.minSeverity) {
    return {
      drop: true,
      reason: 'below-min-severity',
      detail: `级别 ${msg.severityName ?? sev} 低于阈值 ${config.minSeverity}`,
    }
  }

  if (config.mnemonicAllow.length > 0) {
    const tag = (msg.tag ?? '').toUpperCase()
    const allowed = config.mnemonicAllow.some((m) => {
      const up = m.trim().toUpperCase()
      if (!up) return false
      // An entry is a tag or a family prefix: "LINK" or "LINK-" admits LINK-3,
      // LINK-7 and anything else in that family. It must NOT admit unrelated
      // tags — a sloppy split('-')[0] comparison turned a filter the user
      // wrote as a restriction into one that also passes unrelated severities.
      return tag === up || (up.endsWith('-') ? tag.startsWith(up) : tag.split('-')[0] === up)
    })
    if (!allowed) {
      return { drop: true, reason: 'mnemonic-not-allowed', detail: `mnemonic ${tag || '(无)'} 不在白名单` }
    }
  }

  if (inMaintenanceWindow(config.maintenanceWindows, now)) {
    return { drop: true, reason: 'maintenance-window', detail: '处于维护窗口' }
  }

  return {}
}

function parseHhMm(text: string): number | undefined {
  const m = /^(\d{1,2}):(\d{2})$/.exec(text)
  if (!m) return undefined
  const h = Number(m[1])
  const min = Number(m[2])
  if (h > 23 || min > 59) return undefined
  return h * 60 + min
}

/** True when `now` falls in any window. A window whose end <= start wraps midnight. */
export function inMaintenanceWindow(windows: readonly MaintenanceWindow[], now: number = Date.now()): boolean {
  if (!windows.length) return false
  const d = new Date(now)
  const cur = d.getHours() * 60 + d.getMinutes()
  for (const w of windows) {
    const from = parseHhMm(w.from)
    const to = parseHhMm(w.to)
    if (from === undefined || to === undefined) continue
    if (from === to) continue // zero-length window: never open
    if (from < to) {
      if (cur >= from && cur < to) return true
    } else if (cur >= from || cur < to) {
      return true // wraps midnight
    }
  }
  return false
}