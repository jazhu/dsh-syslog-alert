// dsh-syslog-alert — tolerant syslog frame parser.
//
// Devices in the field emit RFC3164, RFC5424, vendor dialects, and outright
// malformed lines. A parser that throws on the malformed ones loses exactly the
// events worth seeing, so this one never throws: the worst case is a `raw`
// confidence message whose `raw` field is the verbatim frame.
//
// Confidence is carried on the result (not guessed by the caller) because the
// analysis pipeline needs to know how much to trust the structured fields: a
// `raw` parse must not feed the LLM's structured fields, because they would be
// fabricated from whatever happened to sit at the front of the line.

import type { ParseConfidence, SyslogMessage } from './types.ts'
import { FACILITY_NAMES, SEVERITY_NAMES } from './types.ts'

const MONTHS: Record<string, number> = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
  Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
}

const PRI_RE = /^<(\d{1,3})>/

/** Split PRI into facility/severity, or undefined when absent. */
function readPri(raw: string): { priority?: number; facility?: number; severity?: number; severityName?: string; rest: string } {
  const m = PRI_RE.exec(raw)
  if (!m) return { rest: raw }
  const priority = Number(m[1])
  if (!Number.isFinite(priority) || priority < 0 || priority > 191) {
    // Out-of-range PRI: keep the text, drop the number rather than guess.
    return { rest: raw }
  }
  const facility = Math.floor(priority / 8)
  const severity = priority % 8
  return {
    priority,
    facility,
    severity,
    severityName: SEVERITY_NAMES[severity],
    rest: raw.slice(m[0].length),
  }
}

function facilityName(facility: number): string | undefined {
  return FACILITY_NAMES[facility]
}

/**
 * RFC3164 timestamp: `MMM DD HH:MM:SS`, where DD is SPACE-padded, not
 * zero-padded — `Oct  7` is two spaces in the wild, and a parser that expects
 * `\d\d` silently falls back to `raw` on exactly the single-digit days.
 *
 * RFC3164 carries no year, so the timestamp is relative to the receiver: we use
 * the current year and roll back when that lands in the future (a December
 * frame read in January).
 */
function parseRfc3164Timestamp(text: string, now: number): { timestamp: number; rest: string } | undefined {
  const m = /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+/.exec(text)
  if (!m) return undefined
  const month = MONTHS[m[1] as string]
  if (month === undefined) return undefined
  const [, , dd, hh, mm, ss] = m
  const year = new Date(now).getFullYear()
  let ts = new Date(year, month, Number(dd), Number(hh), Number(mm), Number(ss)).getTime()
  if (ts - now > 7 * 24 * 3600 * 1000) {
    // A December frame observed in January: subtract a year rather than
    // reporting an alert that is 11 months in the future.
    ts = new Date(year - 1, month, Number(dd), Number(hh), Number(mm), Number(ss)).getTime()
  }
  return { timestamp: ts, rest: text.slice(m[0].length) }
}

/** RFC5424 timestamp is `2003-10-11T22:14:15.003Z` or `-` when absent. */
function parseRfc5424Timestamp(text: string): { timestamp?: number; rest: string } {
  const m = /^(\S+)\s+/.exec(text)
  const token = m?.[1]
  if (!token || token === '-') return { rest: text }
  const parsed = Date.parse(token)
  if (!Number.isFinite(parsed)) return { rest: text }
  return { timestamp: parsed, rest: text.slice(m[0].length) }
}

/**
 * RFC5424 STRUCTURED-DATA: one or more `[id param="value" ...]` elements,
 * possibly `-` when absent. Escapes inside quoted values are `\"`, `\\` and
 * `\]`; getting them wrong turns `key="a\]b"` into a truncated param list.
 */
function parseStructuredData(text: string): { data: Record<string, string>; rest: string; present: boolean } {
  const out: Record<string, string> = {}
  if (text.startsWith('-')) return { data: out, rest: text.slice(1).replace(/^ /, ''), present: false }

  let i = 0
  const n = text.length
  while (i < n && text[i] === '[') {
    i++
    const idStart = i
    while (i < n && text[i] !== ' ' && text[i] !== ']') i++
    const id = text.slice(idStart, i)
    if (!id) break
    const params: Record<string, string> = {}
    while (i < n && text[i] === ' ') {
      i++
      const keyStart = i
      while (i < n && text[i] !== '=' && text[i] !== ']') i++
      const key = text.slice(keyStart, i)
      if (text[i] !== '=') break
      i++ // '='
      if (text[i] !== '"') break
      i++ // opening quote
      let value = ''
      while (i < n && text[i] !== '"') {
        if (text[i] === '\\' && i + 1 < n) {
          value += text[i + 1]
          i += 2
          continue
        }
        value += text[i]
        i++
      }
      if (text[i] !== '"') break
      i++ // closing quote
      if (key) params[key] = value
    }
    if (text[i] !== ']') break
    i++ // ']'
    out[id] = Object.keys(params).length ? JSON.stringify(params) : ''
    // Elements may be adjacent or space-separated.
    if (text[i] === ' ') i++
  }
  return { data: out, rest: text.slice(i), present: true }
}

/** RFC5424: `<PRI>VER TIMESTAMP HOST APP PROCID MSGID SD MSG`. */
function parseRfc5424(text: string, now: number): SyslogMessage | undefined {
  // VER is 1-3 digits, non-zero first. Requiring it keeps us from swallowing a
  // vendor line that merely starts with digits.
  const head = /^(1|2)\d{0,2}\s+/.exec(text)
  if (!head) return undefined
  const { rest: afterVer } = parseRfc5424Timestamp(text.slice(head[0].length))
  const parts = afterVer.split(' ')
  // HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
  if (parts.length < 6) return undefined

  const [hostname, app, procId, msgId] = parts
  const sdStart = afterVer.indexOf(`${hostname} ${app} ${procId} ${msgId} `)
  if (sdStart < 0) return undefined
  const sdText = afterVer.slice(sdStart + `${hostname} ${app} ${procId} ${msgId} `.length)
  const { data: structuredData, rest } = parseStructuredData(sdText)

  const base = {
    priority: undefined as number | undefined,
    facility: undefined as number | undefined,
    severity: undefined as number | undefined,
    severityName: undefined as string | undefined,
  }
  return {
    ...base,
    timestamp: now,
    structuredData: Object.keys(structuredData).length ? structuredData : undefined,
    hostname: hostname === '-' ? undefined : hostname,
    tag: app === '-' ? undefined : app,
    procId: procId === '-' ? undefined : procId,
    msgId: msgId === '-' ? undefined : msgId,
    message: rest.replace(/^\[?-?\d+\]?\s*/, '').replace(/^\s*/, ''),
    confidence: 'rfc5424',
  } as unknown as SyslogMessage
}

/**
 * Parse one syslog frame.
 *
 * Never throws. Returns confidence `rfc5424` | `rfc3164` | `raw`, and `raw` is
 * always the verbatim frame so an unparsed line is still displayable and still
 * auditable.
 */
export function parseSyslogFrame(frame: string, now = Date.now()): SyslogMessage {
  // Strip a trailing newline and any NUL padding some devices append.
  const text = frame.replace(/\0+$/, '').replace(/\r?\n$/, '')
  const pri = readPri(text)

  const finish = (
    rest: string,
    confidence: ParseConfidence,
    extra: Partial<SyslogMessage> = {},
  ): SyslogMessage => {
    const message: SyslogMessage = {
      raw: text,
      confidence,
      message: rest,
      ...extra,
    }
    if (pri.priority !== undefined) {
      message.priority = pri.priority
      message.facility = pri.facility
      message.severity = pri.severity
      message.severityName = pri.severityName
      if (pri.facility !== undefined) {
        const name = facilityName(pri.facility)
        if (name) message.structuredData = { ...(message.structuredData ?? {}), _facility: name }
      }
    }
    return message
  }

  // Try RFC5424 first: it is unambiguous, and misreading a 5424 frame as 3164
  // would put PROCID and MSGID into the message body.
  const as5424 = parseRfc5424(pri.rest, now)
  if (as5424) {
    return {
      ...as5424,
      raw: text,
      message: as5424.message ?? '',
      confidence: 'rfc5424',
      priority: pri.priority,
      facility: pri.facility,
      severity: pri.severity,
      severityName: pri.severityName,
    }
  }

  // RFC3164: `MMM DD HH:MM:SS HOST TAG[pid]: MSG`
  const ts = parseRfc3164Timestamp(pri.rest, now)
  if (ts) {
    let rest = ts.rest
    const spaceIdx = rest.indexOf(' ')
    const host = spaceIdx < 0 ? '' : rest.slice(0, spaceIdx)
    rest = spaceIdx < 0 ? '' : rest.slice(spaceIdx + 1)

    // TAG runs up to the first `:` and may carry `NAME[1234]:`.
    let tag = ''
    const colon = rest.indexOf(':')
    if (colon >= 0) {
      tag = rest.slice(0, colon).trim()
      rest = rest.slice(colon + 1)
    }
    const pidMatch = /^\s*\[(\d+)\]/.exec(rest)
    if (pidMatch) rest = rest.slice(pidMatch[0].length)

    return finish(rest.replace(/^\s+/, ''), 'rfc3164', {
      timestamp: ts.timestamp,
      timestampApproximate: true,
      hostname: host || undefined,
      tag: tag || undefined,
    })
  }

  // Not a recognizable structure. Keep PRI if we had one and hand back the
  // remainder verbatim. The caller must treat this as untrusted text only.
  return finish(pri.rest, 'raw')
}

/**
 * Split a byte payload into individual frames.
 *
 * UDP gives exactly one frame per datagram in practice, but a datagram can
 * carry several newline-separated messages and some agents batch them. A
 * continuation line (no leading timestamp/Pri) is appended to the previous
 * message rather than becoming its own alert: multi-line device output must
 * stay in one alert or the LLM sees half a story.
 */
export function splitFrames(payload: string): string[] {
  const lines = payload.split(/\r?\n/).filter((l) => l.trim().length > 0)
  if (lines.length <= 1) return lines

  const frames: string[] = []
  let current = ''
  for (const line of lines) {
    const startsNewMessage =
      PRI_RE.test(line) || /^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s/.test(line)
    if (startsNewMessage && current) {
      frames.push(current)
      current = line
    } else if (current) {
      current += '\n' + line
    } else {
      current = line
    }
  }
  if (current) frames.push(current)
  return frames
}