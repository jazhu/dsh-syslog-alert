// dsh-syslog-alert — UDP/TCP syslog receiver.
//
// Node built-ins only (dgram/net); no dependency. Two responsibilities beyond
// "accept bytes":
//   1. TCP framing. RFC6587 defines both octet-counting (`<len> <msg>`) and
//      non-transparent framing (newline-delimited); devices in the field use
//      both, and treating one as the other silently truncates every message.
//   2. Surfacing bind failures instead of swallowing them. A listener that came
//      up on the wrong port is the single most common "I configured syslog but
//      nothing arrives" cause, so the reason travels to the UI.

import dgram from 'node:dgram'
import net from 'node:net'
import type { AddressInfo } from 'node:net'
import type { Config, ListenerStatus } from './types.ts'

export interface ReceivedFrame {
  /** Payload with framing removed. */
  text: string
  sourceIp?: string
  sourcePort?: number
  transport: 'udp' | 'tcp'
  at: number
}

export interface ReceiverDeps {
  config: Config
  onFrame(frame: ReceivedFrame): void
  onWarn(message: string): void
}

export class SyslogReceiver {
  private udpSockets: dgram.Socket[] = []
  private tcpServer: net.Server | null = null
  private status: ListenerStatus = {
    listening: false,
    boundPorts: [],
    failedPorts: [],
    transports: [],
    packets: 0,
    startedAt: Date.now(),
  }
  private deps: ReceiverDeps

  constructor(deps: ReceiverDeps) {
    this.deps = deps
  }

  getStatus(): ListenerStatus {
    return {
      ...this.status,
      // Derived from the live socket lists rather than latched at the end of
      // start(): with several configured ports, one slow or failing bind would
      // otherwise keep reporting "not listening" while packets are already
      // arriving on the ports that did bind.
      listening: this.udpSockets.length > 0 || this.tcpServer !== null,
      boundPorts: [...this.status.boundPorts],
      failedPorts: [...this.status.failedPorts],
    }
  }

  /** Bind every configured port. Resolves once all attempts have settled. */
  async start(): Promise<ListenerStatus> {
    const ports = this.deps.config.syslogPorts.length
      ? this.deps.config.syslogPorts
      : [1514]
    for (const port of ports) {
      await this.bindUdp(port)
    }
    if (this.deps.config.enableTcp) {
      this.bindTcp(ports[0] ?? 1514)
    }
    return this.getStatus()
  }

  private bindUdp(port: number): Promise<void> {
    return new Promise((resolve) => {
      const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true })
      let settled = false
      const finish = (): void => {
        if (!settled) {
          settled = true
          resolve()
        }
      }

      socket.on('error', (err: Error) => {
        // EACCES on Linux for 514 is the expected reason to surface verbatim;
        // the operator needs to see "permission denied", not a silent retry loop.
        this.status.failedPorts.push({ port, reason: err.message })
        this.deps.onWarn(`UDP ${port} 绑定失败：${err.message}`)
        try {
          socket.close()
        } catch {
          /* ignore */
        }
        finish()
      })

      socket.on('message', (buf, rinfo) => {
        this.status.packets += 1
        this.status.lastPacketAt = Date.now()
        this.emit(buf.toString('utf-8'), rinfo.address, rinfo.port, 'udp')
      })

      socket.bind(port, () => {
        this.udpSockets.push(socket)
        this.status.boundPorts.push(port)
        if (!this.status.transports.includes('udp')) this.status.transports.push('udp')
        finish()
      })
    })
  }

  private bindTcp(port: number): void {
    const server = net.createServer((socket) => {
      let buffer = ''
      socket.setEncoding('utf-8')
      socket.on('data', (chunk: string) => {
        buffer += chunk
        for (const frame of drainTcpBuffer(buffer)) {
          const address = socket.remoteAddress ?? undefined
          const sourcePort = (socket.remotePort as AddressInfo | number | undefined) as number | undefined
          this.status.packets += 1
          this.status.lastPacketAt = Date.now()
          this.emit(frame, address, sourcePort, 'tcp')
        }
        buffer = buffer.slice(tcpDrainedLength(buffer))
      })
      socket.on('error', () => {
        /* a dead client must not take the listener down */
      })
    })
    server.on('error', (err: Error) => {
      this.status.failedPorts.push({ port, reason: `TCP: ${err.message}` })
      this.deps.onWarn(`TCP ${port} 监听失败：${err.message}`)
    })
    server.listen(port, () => {
      this.tcpServer = server
      if (!this.status.transports.includes('tcp')) this.status.transports.push('tcp')
      this.deps.onWarn(`TCP syslog 监听在 :${port}`)
    })
  }

  private emit(text: string, ip: string | undefined, port: number | undefined, transport: 'udp' | 'tcp'): void {
    try {
      this.deps.onFrame({ text, sourceIp: ip, sourcePort: port, transport, at: Date.now() })
    } catch (err) {
      this.deps.onWarn(`frame handler 抛错：${err instanceof Error ? err.message : String(err)}`)
    }
  }

  async stop(): Promise<void> {
    const udp = this.udpSockets
    this.udpSockets = []
    for (const s of udp) {
      try {
        s.close()
      } catch {
        /* ignore */
      }
    }
    const tcp = this.tcpServer
    this.tcpServer = null
    if (tcp) {
      await new Promise<void>((resolve) => tcp.close(() => resolve()))
    }
    this.status.listening = false
    this.status.boundPorts = []
    this.status.transports = []
  }

  /** Rebind after a settings change (ports / tcp toggle). */
  async restart(): Promise<ListenerStatus> {
    await this.stop()
    this.status.failedPorts = []
    this.status.packets = 0
    this.status.startedAt = Date.now()
    delete this.status.lastPacketAt
    return this.start()
  }
}

/**
 * Pull complete frames out of a TCP byte buffer.
 *
 * Handles both RFC6587 framings:
 *   - octet counting: `<len> <msg>` where len counts the message bytes;
 *   - non-transparent: newline-delimited.
 *
 * The discriminator is the head of the buffer: digits followed by a space mean
 * octet counting. A message body may itself start with digits and a space
 * (e.g. `2023 ...`), which is why the length prefix is consumed positionally
 * rather than by a loose regex over the whole line.
 */
export function drainTcpBuffer(buffer: string): string[] {
  const frames: string[] = []
  let rest = buffer
  for (;;) {
    const m = /^(\d{1,10}) /.exec(rest)
    if (m) {
      const len = Number(m[1])
      const start = m[0].length
      if (Number.isFinite(len) && len >= 0) {
        if (rest.length < start + len) break // wait for the rest
        frames.push(rest.slice(start, start + len))
        rest = rest.slice(start + len)
        continue
      }
    }
    const nl = rest.indexOf('\n')
    if (nl < 0) break
    const line = rest.slice(0, nl).replace(/\r$/, '')
    if (line.trim()) frames.push(line)
    rest = rest.slice(nl + 1)
  }
  return frames
}

/**
 * How much of `buffer` the caller should keep. Everything consumed by
 * `drainTcpBuffer` except a trailing partial frame.
 *
 * Kept as a separate function so the receiver can find the same split point
 * without re-running the parse; a mismatch between drain and drain-length is
 * the classic way to duplicate or drop every TCP message.
 */
export function tcpDrainedLength(buffer: string): number {
  let consumed = 0
  let rest = buffer
  for (;;) {
    const m = /^(\d{1,10}) /.exec(rest)
    if (m) {
      const len = Number(m[1])
      const start = m[0].length
      if (Number.isFinite(len) && len >= 0) {
        if (rest.length < start + len) return consumed
        consumed += start + len
        rest = rest.slice(start + len)
        continue
      }
    }
    const nl = rest.indexOf('\n')
    if (nl < 0) return consumed
    const line = rest.slice(0, nl).replace(/\r$/, '')
    if (line.trim()) consumed += nl + 1
    else consumed += nl + 1
    rest = rest.slice(nl + 1)
  }
}