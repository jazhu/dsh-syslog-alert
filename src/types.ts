// dsh-syslog-alert — shared types (host half types are re-exported to the client).

// ---- syslog wire ------------------------------------------------------------

/** How confidently we understood a received frame. Ordered best → worst. */
export type ParseConfidence = 'rfc5424' | 'rfc3164' | 'raw'

/** A received syslog frame, after parsing. `raw` is always present verbatim. */
export interface SyslogMessage {
  /** Verbatim frame text (newline-stripped). Never interpreted. */
  raw: string
  /** Confidence of the structural parse. `raw` means we only got PRI + message. */
  confidence: ParseConfidence
  /** RFC5424 <PRI> only, 0–191. Undefined when there is no leading `<n>`. */
  priority?: number
  /** PRI = facility * 8 + severity. */
  facility?: number
  /** PRI % 8 — 0 emerg … 7 debug. Lower is worse. */
  severity?: number
  /** Human name for `severity`. */
  severityName?: string
  /** RFC5424 structured-data fields, decoded. */
  structuredData?: Record<string, string>
  /** RFC5424 APP-NAME / RFC3164 TAG, e.g. `LINK-3`. */
  tag?: string
  /** RFC5424 HOSTNAME / RFC3164 HOST. The device's idea of its own name. */
  hostname?: string
  /** RFC5424 PROCID. */
  procId?: string
  /** RFC5424 MSGID. */
  msgId?: string
  /** The MSG part. Everything after the header. */
  message: string
  /** Device timestamp parsed from the frame, when present. */
  timestamp?: number
  /** Set when a timestamp was present but not full ISO — trust `timestamp` less. */
  timestampApproximate?: boolean
}

// ---- alerts -----------------------------------------------------------------

/** Lifecycle of one alert. Monotonic — never moves backwards. */
export type AlertStage =
  | 'received'
  | 'mapped'
  | 'filtered'
  | 'deduped'
  | 'closed'
  | 'failed'

export const ALERT_STAGES: readonly AlertStage[] = [
  'received',
  'mapped',
  'filtered',
  'deduped',
  'closed',
  'failed',
]

/** Why an alert was dropped before analysis. */
export type DropReason =
  | 'unmapped-source'
  | 'below-min-severity'
  | 'mnemonic-not-allowed'
  | 'maintenance-window'
  | 'rate-limited'
  | 'duplicate'
  | 'parse-failed'

export interface Alert {
  id: string
  /** ms epoch when the frame hit our socket. */
  receivedAt: number
  stage: AlertStage
  /** The parsed frame, kept verbatim and in full. */
  message: SyslogMessage
  /** Mapped device id, when the source IP matched a known device. */
  deviceId?: string
  deviceName?: string
  /** Source IP the datagram came from — the only reliable device identity. */
  sourceIp?: string
  sourcePort?: number
  /** Transport the frame arrived on. */
  transport?: 'udp' | 'tcp'
  /** Syslog facility name when known. */
  facilityName?: string
  /** Stable dedup key (see fingerprint.ts). */
  fingerprint?: string
  /** Times this fingerprint was seen inside the dedup window. */
  count: number
  /** First/last time this fingerprint was seen. */
  firstSeenAt?: number
  lastSeenAt?: number
  /** Why this alert was dropped (only when it never entered analysis). */
  dropReason?: DropReason
  /** Human-facing reason for the drop, with specifics. */
  dropDetail?: string
  /** Set when a human acknowledged this alert. */
  ackedAt?: number
  /** Per-stage timing, so a slow or failed run can be explained after the fact. */
  timeline: TimelineEntry[]
  /**
   * The day-session this alert was admitted into, so its conclusion can be read
   * back out of the conversation later. Absent when the alert never reached a
   * session (feature off, no host service, or a delivery failure).
   */
  sessionId?: string
  /**
   * The agent's reply about THIS alert, lifted out of the day session and
   * written back here. Filled by the poller, not by the post itself: the turn is
   * asynchronous, so there is nothing to read at delivery time.
   */
  sessionConclusion?: string
  /** When we lifted the conclusion out of the session. */
  sessionConclusionAt?: number
  /** True while the alert sits in the day session waiting for its turn to answer. */
  analysisPending?: boolean
}

export interface TimelineEntry {
  at: number
  stage: AlertStage
  note: string
  durationMs?: number
}

// ---- runtime counters -------------------------------------------------------

export interface Stats {
  /** Datagrams/frames received across all transports. */
  received: number
  /** Frames that reached alert creation. */
  alertsCreated: number
  /** Frames suppressed by fingerprint dedup. */
  deduped: number
  /** Frames suppressed by per-device rate limit. */
  rateLimited: number
  /** Frames dropped by prefilter (severity / mnemonic / window / unmapped). */
  filtered: number
  /** Collectors promoted to a synthesized storm alert. */
  storms: number
}

// ---- configuration ----------------------------------------------------------

export interface Config {
  /** Directory for alerts/*.jsonl and settings.json. */
  dataDir: string
  /** UDP ports to listen on. First bindable wins; failures are surfaced, not swallowed. */
  syslogPorts: number[]
  /** Also listen on TCP. Devices that cannot use UDP need this. */
  enableTcp: boolean
  /** Fixed loopback port for /syslog-api. Must not collide with hillstone's 18783. */
  apiPort: number
  /** Require the loopback token on non-local Origins. */
  apiTokenEnabled: boolean
  /**
   * Loopback port of dsh-hillstone-cli-ops's `/ops-api`. 0 = discover it.
   *
   * Hillstone's own apiPort is a user setting, so a hardcoded 18783 silently
   * reports "no devices" for anyone who moved it — the alert pipeline would look
   * alive and simply never map anything. 0 probes the default first, then scans
   * a small candidate range, then gives up loudly instead of guessing.
   */
  opsApiPort: number
  /** What to do with a frame whose source IP maps to no known device. */
  unmappedPolicy: 'ignore' | 'capture-only'
  /** Drop anything with PRI severity above this number (7 = debug). */
  minSeverity: number
  /** Empty = allow every mnemonic. */
  mnemonicAllow: string[]
  /** Local-time maintenance windows during which everything is dropped. */
  maintenanceWindows: MaintenanceWindow[]
  /** Fingerprint dedup window, seconds. */
  dedupWindowSec: number
  /** Per-device alert budget per minute before extra frames only bump a counter. */
  perDeviceRatePerMin: number
  /** Repeats inside the dedup window that turn one alert into a storm alert. */
  stormThreshold: number
  /**
   * Create one ordinary DSH session per calendar day and admit every alert of
   * that day into it as a prompt, so the analysis is a visible agent turn
   * instead of an unreadable log line.
   *
   * The session comes straight from the host's `sessionController`, so it needs
   * no subagent provider — that is the whole point of this mechanism over the
   * subagent one it replaced. On by default; off leaves Path A as the only
   * analysis.
   */
  autoSessionEnabled: boolean
  /**
   * Title prefix of the day's session: `"<prefix> YYYY-MM-DD"` in LOCAL time.
   * Empty falls back to 告警分析 rather than producing a session named "… 2026-10-07".
   */
  autoSessionTitle: string
  /**
   * Absolute workspace directory the day's session is created in; empty means
   * "the host's current workspace".
   *
   * DSH rejects a non-absolute `cwd` outright, so a relative value is treated as
   * unset rather than as an error the operator cannot act on.
   */
  autoSessionWorkspace: string
  /**
   * Instruction line opening every posted message; blank falls back to
   * 分析这条日志.
   *
   * Only the first line is configurable. The alert id, the device and the fenced
   * raw log are always appended by the plugin: without the id the session agent
   * cannot tell which alert it was asked about.
   */
  autoSessionPrompt: string
  /** JSONL day files older than this are deleted at startup. */
  retentionDays: number
  /** In-memory alerts kept for the list view. */
  ringSize: number
}

export interface MaintenanceWindow {
  /** `HH:MM` local. */
  from: string
  /** `HH:MM` local. Wraps midnight when `to` <= `from`. */
  to: string
}

/** Listener health, surfaced in the UI so "0 alerts" is never ambiguous. */
export interface ListenerStatus {
  /** True when at least one socket is bound. */
  listening: boolean
  /** Ports actually bound. Empty when nothing bound. */
  boundPorts: number[]
  /** Ports requested but not bound, with the reason. Never silent. */
  failedPorts: { port: number; reason: string }[]
  transports: ('udp' | 'tcp')[]
  /** Frames since start. */
  packets: number
  startedAt: number
  lastPacketAt?: number
}

// ---- settings over the wire -------------------------------------------------

/** The subset of Config the browser may change. */
export type EditableSettings = Partial<
  Pick<
    Config,
    | 'syslogPorts'
    | 'enableTcp'
    | 'opsApiPort'
    | 'unmappedPolicy'
    | 'minSeverity'
    | 'mnemonicAllow'
    | 'maintenanceWindows'
    | 'dedupWindowSec'
    | 'perDeviceRatePerMin'
    | 'stormThreshold'
    | 'autoSessionEnabled'
    | 'autoSessionTitle'
    | 'autoSessionWorkspace'
    | 'autoSessionPrompt'
    | 'retentionDays'
  >
>

export const SEVERITY_NAMES = [
  'emerg',
  'alert',
  'crit',
  'err',
  'warning',
  'notice',
  'info',
  'debug',
] as const

export const FACILITY_NAMES = [
  'kern',
  'user',
  'mail',
  'daemon',
  'auth',
  'syslog',
  'lpr',
  'news',
  'uucp',
  'cron',
  'authpriv',
  'ftp',
  'ntp',
  'security',
  'console',
  'solaris-cron',
  'local0',
  'local1',
  'local2',
  'local3',
  'local4',
  'local5',
  'local6',
  'local7',
] as const
