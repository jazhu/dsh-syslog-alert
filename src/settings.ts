// dsh-syslog-alert — configuration resolution and settings.json persistence.
//
// Two separate concerns on purpose:
//   - `resolveConfig` mirrors the sibling plugin's pattern (options → env →
//     profile data dir → homedir fallback) so a user who moves one plugin's
//     directory does not have to learn a second convention;
//   - `EditableSettings` is the ONLY surface the browser may write. Ports,
//     dataDir and the token are host-owned: a panel request must not be able to
//     move the listening socket or relocate the audit trail.

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { isAbsolute, join } from 'node:path'
import type { Config, EditableSettings } from './types.ts'
import { AUTO_SESSION_PROMPT } from './auto-session.ts'

export const DEFAULT_CONFIG: Config = {
  dataDir: '',
  syslogPorts: [1514],
  enableTcp: false,
  // 18784 sits next to hillstone's 18783 without colliding with it.
  apiPort: 18784,
  apiTokenEnabled: true,
  // 0 = auto-discover the hillstone bridge (see Config.opsApiPort).
  opsApiPort: 0,
  unmappedPolicy: 'ignore',
  minSeverity: 5,
  mnemonicAllow: [],
  maintenanceWindows: [],
  dedupWindowSec: 120,
  perDeviceRatePerMin: 20,
  stormThreshold: 5,
  // On by default: one ordinary session per day, titled 告警分析 <date>, fed by
  // the incoming alerts so the analysis is visible instead of a log line.
  autoSessionEnabled: true,
  autoSessionTitle: '告警分析',
  // Empty = the host's current workspace; only an absolute path is honoured.
  autoSessionWorkspace: '',
  autoSessionPrompt: AUTO_SESSION_PROMPT,
  retentionDays: 14,
  ringSize: 2000,
}

function envInt(name: string): number | undefined {
  const raw = process.env[name]
  if (!raw) return undefined
  const n = Number(raw)
  return Number.isFinite(n) ? n : undefined
}

/** `DSH_SYSLOG_PORTS=1514,514` — parsed to numbers before it reaches Config. */
function envPorts(name: string): number[] | undefined {
  const raw = process.env[name]
  if (!raw) return undefined
  const parts = raw
    .split(',')
    .map((s) => Number(s.trim()))
    .filter((n) => Number.isFinite(n) && n > 0 && n < 65536)
  return parts.length > 0 ? parts : undefined
}

export function resolveConfig(options: Partial<Config> | undefined, profileDir: string | undefined): Config {
  const portsFromEnv = envPorts('DSH_SYSLOG_PORTS')
  const envApiPort = envInt('DSH_SYSLOG_API_PORT')
  const dataDir =
    options?.dataDir ||
    process.env.DSH_SYSLOG_DATA_DIR ||
    (profileDir ? join(profileDir, 'dsh-syslog-alert') : '') ||
    join(homedir(), '.dsh', 'dsh-syslog-alert')

  const base: Config = {
    ...DEFAULT_CONFIG,
    ...options,
    dataDir,
    syslogPorts: options?.syslogPorts ?? portsFromEnv ?? [...DEFAULT_CONFIG.syslogPorts],
    apiPort: options?.apiPort ?? envApiPort ?? DEFAULT_CONFIG.apiPort,
  }

  // Clamp rather than trust: these numbers bound resource use, and a typo in a
  // settings file must not turn into an unbounded queue or a 24-port listener.
  base.syslogPorts = [...new Set(base.syslogPorts.map((p) => Math.round(p)).filter((p) => p > 0 && p < 65536))].slice(0, 8)
  if (base.syslogPorts.length === 0) base.syslogPorts = [...DEFAULT_CONFIG.syslogPorts]
  base.apiPort = clampInt(base.apiPort, 1024, 65535, DEFAULT_CONFIG.apiPort)
  // 0 means "auto-discover"; anything else is an explicit port.
  base.opsApiPort = Number.isFinite(Number(base.opsApiPort)) && Number(base.opsApiPort) > 0 ? Math.round(Number(base.opsApiPort)) : 0
  base.minSeverity = clampInt(base.minSeverity, 0, 7, DEFAULT_CONFIG.minSeverity)
  base.dedupWindowSec = clampInt(base.dedupWindowSec, 5, 3600, DEFAULT_CONFIG.dedupWindowSec)
  base.perDeviceRatePerMin = clampInt(base.perDeviceRatePerMin, 1, 600, DEFAULT_CONFIG.perDeviceRatePerMin)
  base.stormThreshold = clampInt(base.stormThreshold, 2, 500, DEFAULT_CONFIG.stormThreshold)
  base.retentionDays = clampInt(base.retentionDays, 1, 365, DEFAULT_CONFIG.retentionDays)
  base.ringSize = clampInt(base.ringSize, 50, 100_000, DEFAULT_CONFIG.ringSize)
  base.autoSessionWorkspace = String(base.autoSessionWorkspace ?? '').trim().slice(0, 1024)
  // Not defaulted here: an empty instruction is a legitimate "use the built-in
  // line", and `buildLogPrompt` owns that fallback so both paths agree.
  base.autoSessionPrompt = String(base.autoSessionPrompt ?? '').trim().slice(0, 2000)
  return base
}

function clampInt(value: number, min: number, max: number, fallback: number): number {
  const n = Math.round(Number(value))
  if (!Number.isFinite(n)) return fallback
  return Math.max(min, Math.min(max, n))
}

// ---- persisted editable settings ---------------------------------------------

export type SettingsListener = (config: Config) => void

export class SettingsStore {
  private file: string
  private config: Config
  private listeners = new Set<SettingsListener>()
  /** Snapshot of the listener-affecting fields, captured before each apply. */
  private lastPersistedListenerBits?: { ports: number[]; tcp: boolean }

  constructor(config: Config) {
    this.config = config
    this.file = join(config.dataDir, 'settings.json')
  }

  get current(): Config {
    return this.config
  }

  onChange(fn: SettingsListener): () => void {
    this.listeners.add(fn)
    return () => this.listeners.delete(fn)
  }

  /**
   * Load `settings.json` over the resolved config. A malformed file is reported
   * and ignored rather than thrown: losing the editable settings must not stop
   * the receiver from bringing the alert socket up.
   */
  loadPersisted(log?: (message: string) => void): void {
    let raw: string
    try {
      raw = readFileSync(this.file, 'utf-8')
    } catch {
      return
    }
    try {
      const parsed = JSON.parse(raw) as EditableSettings
      this.apply(parsed, { persist: false, log })
    } catch (err) {
      log?.(`settings.json 解析失败，已忽略：${err instanceof Error ? err.message : String(err)}`)
    }
  }

  /**
   * Merge an editable patch. Only keys on the whitelist are read — a request
   * carrying `apiPort` or `dataDir` is ignored field by field rather than
   * rejected, so the panel can round-trip a full settings object without the
   * host-owned fields taking effect.
   */
  apply(patch: EditableSettings, opts: { persist?: boolean; log?: (message: string) => void } = {}): Config {
    const next: Config = { ...this.config }

    if (Array.isArray(patch.syslogPorts)) next.syslogPorts = [...new Set(patch.syslogPorts.map(Number).filter((p) => Number.isFinite(p) && p > 0 && p < 65536))].slice(0, 8)
    if (typeof patch.enableTcp === 'boolean') next.enableTcp = patch.enableTcp
    if (Number.isFinite(Number(patch.opsApiPort))) next.opsApiPort = Number(patch.opsApiPort) > 0 ? Math.round(Number(patch.opsApiPort)) : 0
    if (patch.unmappedPolicy === 'ignore' || patch.unmappedPolicy === 'capture-only') next.unmappedPolicy = patch.unmappedPolicy
    if (typeof patch.minSeverity === 'number') next.minSeverity = clampInt(patch.minSeverity, 0, 7, next.minSeverity)
    if (Array.isArray(patch.mnemonicAllow)) next.mnemonicAllow = patch.mnemonicAllow.map((m) => String(m).toUpperCase().trim()).filter(Boolean).slice(0, 100)
    if (Array.isArray(patch.maintenanceWindows)) {
      next.maintenanceWindows = patch.maintenanceWindows
        .filter((w) => /^\d{1,2}:\d{2}$/.test(w?.from ?? '') && /^\d{1,2}:\d{2}$/.test(w?.to ?? ''))
        .slice(0, 20)
    }
    if (typeof patch.dedupWindowSec === 'number') next.dedupWindowSec = clampInt(patch.dedupWindowSec, 5, 3600, next.dedupWindowSec)
    if (typeof patch.perDeviceRatePerMin === 'number') next.perDeviceRatePerMin = clampInt(patch.perDeviceRatePerMin, 1, 600, next.perDeviceRatePerMin)
    if (typeof patch.stormThreshold === 'number') next.stormThreshold = clampInt(patch.stormThreshold, 2, 500, next.stormThreshold)
    if (typeof patch.autoSessionEnabled === 'boolean') next.autoSessionEnabled = patch.autoSessionEnabled
    if (typeof patch.autoSessionTitle === 'string') next.autoSessionTitle = patch.autoSessionTitle.trim().slice(0, 80) || DEFAULT_CONFIG.autoSessionTitle
    if (typeof patch.autoSessionWorkspace === 'string') next.autoSessionWorkspace = patch.autoSessionWorkspace.trim().slice(0, 1024)
    if (typeof patch.autoSessionPrompt === 'string') next.autoSessionPrompt = patch.autoSessionPrompt.trim().slice(0, 2000)
    if (typeof patch.retentionDays === 'number') next.retentionDays = clampInt(patch.retentionDays, 1, 365, next.retentionDays)

    if (next.syslogPorts.length === 0) next.syslogPorts = [...DEFAULT_CONFIG.syslogPorts]

    this.lastPersistedListenerBits = { ports: [...this.config.syslogPorts], tcp: this.config.enableTcp }
    this.config = next
    if (opts.persist !== false) this.persist()
    for (const fn of this.listeners) {
      try {
        fn(next)
      } catch {
        /* ignore */
      }
    }
    return next
  }

  /**
   * Whether the last `apply()` changed something the socket layer must act on.
   * Recomputed rather than returned inline so callers get a plain `Config` back
   * and cannot accidentally serialise the extra field into settings.json.
   */
  needsListenerRestart(): boolean {
    const persisted = this.lastPersistedListenerBits
    return (
      persisted !== undefined &&
      (JSON.stringify(persisted.ports) !== JSON.stringify(this.config.syslogPorts) || persisted.tcp !== this.config.enableTcp)
    )
  }

  private persist(): void {
    const editable: EditableSettings = {
      syslogPorts: this.config.syslogPorts,
      enableTcp: this.config.enableTcp,
      opsApiPort: this.config.opsApiPort,
      unmappedPolicy: this.config.unmappedPolicy,
      minSeverity: this.config.minSeverity,
      mnemonicAllow: this.config.mnemonicAllow,
      maintenanceWindows: this.config.maintenanceWindows,
      dedupWindowSec: this.config.dedupWindowSec,
      perDeviceRatePerMin: this.config.perDeviceRatePerMin,
      stormThreshold: this.config.stormThreshold,
      autoSessionEnabled: this.config.autoSessionEnabled,
      autoSessionTitle: this.config.autoSessionTitle,
      autoSessionWorkspace: this.config.autoSessionWorkspace,
      autoSessionPrompt: this.config.autoSessionPrompt,
      retentionDays: this.config.retentionDays,
    }
    try {
      mkdirSync(this.config.dataDir, { recursive: true })
      writeFileSync(this.file, JSON.stringify(editable, null, 2), 'utf-8')
    } catch {
      // Persistence is a convenience; the in-memory config stays authoritative.
    }
  }

  /** Where the loopback token lives. Kept beside settings.json, host-only. */
  static tokenPath(config: Config): string {
    return join(config.dataDir, 'api-token')
  }

  static dataDirIsSane(dir: string): boolean {
    return !!dir && !dir.includes('\0') && (isAbsolute(dir) || dir.includes('/') || dir.includes('\\'))
  }
}