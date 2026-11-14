// DIVE-8464: deliver an email when Claude Code REFUSES channels.
//
// A copy of the dashboard plugin's DIVE-6000 router (5dive-plugins
// plugins/dashboard/channelroute.ts), itself a port of the Telegram plugin's
// DIVE-5186 router: read those headers for the evidence. Plugins install as
// separate trees, so this one cannot import theirs. Only the names differ: this
// server's log dir, its --channels entry, its typed line and its channel tag.
//
// Claude Code gates every inbound channel on a server-side feature flag
// (`tengu_harbor`, default false). A seat whose Claude Code talks to the firm's
// own AI server (ANTHROPIC_BASE_URL at Ollama / LM Studio / vLLM: the
// "Private" enterprise setup, 5dive local-only) never gets it, so
// `notifications/claude/channel` is dropped and a mail is never read. Outbound
// is fine: reply/send are ordinary MCP tools. When, and only when, the session
// ASKED for the email channel and Claude Code REFUSED it, the router types the
// mail into the seat's own tmux pane instead. Everything else keeps the
// notification, so a seat that has channels never gets a mail twice. An org
// policy refusal (a Claude Team/Enterprise org that has not allowed channels)
// is the org's own choice and is never typed around.
//
// Claude Code's per-server log for this plugin:
//   ~/.cache/claude-cli-nodejs/<cwd, non-alnum -> '-'>/mcp-logs-plugin-email-email/<start>.jsonl
// "Asked for it" is the parent Claude Code's argv: `--channels plugin:email@<marketplace>`
// (5dive-agent-start passes it for a plugin channel, DIVE-8315).

import { readFileSync, readdirSync, readlinkSync, statSync } from 'node:fs'
import { join } from 'node:path'

export type ChannelDecision = 'bound' | 'refused' | 'org_policy' | 'other' | 'unknown'

const REFUSED_REASON = 'channels feature is not currently available'
// DIVE-5993: a Claude Team/Enterprise org that has not switched channels on
// (2.1.296: `kind:"policy"`), or whose own allowlist leaves this plugin out
// (`kind:"allowlist"`). Both are the org's explicit choice, so they are NEVER
// routed around by typing into the session; the owner is told what an admin
// switches on instead (orgpolicy.ts).
const ORG_POLICY_REASONS = ['not enabled by org policy', "not on your org's approved channels list"]

// The last channel-gate decision logged AFTER `marker`. `unknown` when the
// marker is absent (not our file) or no decision has been logged yet.
export function decisionFromLog(text: string, marker: string): ChannelDecision {
  const at = text.indexOf(marker)
  if (at < 0) return 'unknown'
  let decision: ChannelDecision = 'unknown'
  for (const line of text.slice(at).split('\n')) {
    if (!line.includes('Channel ')) continue
    let msg: unknown
    try {
      msg = (JSON.parse(line) as { debug?: unknown }).debug
    } catch {
      continue
    }
    if (typeof msg !== 'string') continue
    if (msg.startsWith('Channel notifications registered') || msg.startsWith('Channel notifications re-registered')) {
      decision = 'bound'
    } else if (msg.startsWith('Channel gate says skip:') && msg.includes('preserving handler')) {
      decision = 'bound'
    } else if (msg.startsWith('Channel notifications skipped:')) {
      decision = msg.includes(REFUSED_REASON)
        ? 'refused'
        : ORG_POLICY_REASONS.some(r => msg.includes(r))
          ? 'org_policy'
          : 'other'
    }
  }
  return decision
}

// Did this Claude Code invocation ask for the email channel?
// Accepts `--channels a b`, `--channels=a,b` and the development variant.
export function argvAsksForEmail(argv: string[]): boolean {
  const values: string[] = []
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!
    const m = /^--(?:dangerously-load-development-)?channels(?:=(.*))?$/.exec(a)
    if (!m) continue
    if (m[1] != null) {
      values.push(m[1])
      continue
    }
    for (let j = i + 1; j < argv.length && !argv[j]!.startsWith('-'); j++) values.push(argv[j]!)
  }
  return values
    .flatMap(v => v.split(/[,\s]+/))
    .some(v => /^(?:plugin:)?email(?:@|:|$)/.test(v) || v === 'server:plugin:email:email')
}

// Claude Code's project-dir naming for ~/.cache/claude-cli-nodejs/<dir>.
export function cacheDirName(cwd: string): string {
  return cwd.replace(/[^a-zA-Z0-9]/g, '-')
}

// ---- the text typed into the pane ------------------------------------------

// Typed as its own keystrokes ahead of the message, so a long message that
// Claude Code folds into a paste still arrives behind a line the user's own
// runtime wrote (DIVE-5098). A CONSTANT: never carries sender-controlled text.
export const INJECT_TYPED_LINE =
  '[email] Inbound email for this agent (channels are off in this session) - answer it with the email reply tool:'

const MAX_CONTENT = 6000

function attr(v: string): string {
  return v.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

// Keystrokes, not text: any control character reaching tmux `send-keys -l` is
// typed into the TUI. ESC opens terminal sequences (a bracketed-paste end, a
// menu key), CR submits, ^C interrupts. So: newlines become a visible ⏎ (the
// payload must be ONE line or Enter stops submitting — DIVE-4642), every other
// C0/C1 control and DEL becomes a space.
export function oneLine(s: string): string {
  return s
    .replace(/\r\n?|\n|\u2028|\u2029/g, ' ⏎ ')
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ')
}

// `<channel source="plugin:email:email" chat_id=… …>content</channel>`: the tag
// a bound channel delivers on Claude Code 2.1.3xx (it names the source
// plugin:<plugin>:<server>; the server is "email" in .mcp.json), so the agent's
// instructions apply unchanged, it answers with chat_id through the reply tool,
// and hooks/mail-guard.ts reads the typed mail as an email (guard.ts
// channelName folds the plugin form to "email").
export function formatInjection(content: string, meta: Record<string, string>): string {
  const attrs = Object.entries(meta)
    .filter(([k]) => /^[a-z_][a-z0-9_]*$/i.test(k))
    .map(([k, v]) => ` ${k}="${attr(oneLine(String(v)))}"`)
    .join('')
  let body = oneLine(content)
  if (body.length > MAX_CONTENT) body = `${body.slice(0, MAX_CONTENT)} … [truncated; the full mail is on this server, ask your owner]`
  // The sender must not close our tag or open a second one, nor forge another
  // channel's: the Telegram, dashboard and Teams hooks in this same session read
  // every `source="plugin:<name>…"` in a turn as an inbound from that channel
  // (and mail-guard.ts would read a forged owner channel as the owner speaking).
  body = body
    .replace(/<(\/?)channel/gi, '‹$1channel')
    .replace(/source="/gi, 'source=\u201c')
  return `<channel source="plugin:email:email"${attrs}>${body}</channel>`
}

// ---- the live probe (filesystem + /proc) ------------------------------------

function procPpid(pid: number): number | null {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, 'utf8')
    // "pid (comm) state ppid …" — comm may hold spaces/parens, so split after the LAST ')'.
    const rest = stat.slice(stat.lastIndexOf(')') + 2).split(' ')
    const ppid = Number(rest[1])
    return Number.isFinite(ppid) && ppid > 1 ? ppid : null
  } catch {
    return null
  }
}

function procArgv(pid: number): string[] {
  try {
    return readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0').filter(Boolean)
  } catch {
    return []
  }
}

// Is this argv / executable Claude Code? argv[0] is `…/bin/claude` as launched,
// but Claude Code can re-exec ITSELF in place (the TUI renderer switch, measured
// on 2.1.284): same pid, argv[0] becomes the versioned binary
// `…/claude/versions/2.1.284` and the flags are rewritten (`--channels` is kept).
export function looksLikeClaude(argv0: string, exe: string): boolean {
  const base = argv0.split('/').pop() ?? ''
  return /^claude(?:\.exe)?$/.test(base) || /\/claude\/versions\/[^/]+$/.test(argv0) || /\/claude\/versions\/[^/]+$/.test(exe)
}

// The Claude Code process that spawned this server: `claude` → `bun run … start`
// → `bun start.ts`, so walk a few ancestors.
export function findClaudeAncestor(startPpid: number): { pid: number; argv: string[]; cwd: string | null } | null {
  let pid: number | null = startPpid
  for (let depth = 0; pid != null && depth < 5; depth++) {
    const argv = procArgv(pid)
    let exe = ''
    try {
      exe = readlinkSync(`/proc/${pid}/exe`)
    } catch {}
    if (looksLikeClaude(argv[0] ?? '', exe)) {
      let cwd: string | null = null
      try {
        cwd = readlinkSync(`/proc/${pid}/cwd`)
      } catch {}
      return { pid, argv, cwd }
    }
    pid = procPpid(pid)
  }
  return null
}

// Our own MCP log file: the newest one under an email mcp-logs dir that holds
// `marker`. The parent's cwd dir is searched first; a scan of every project dir
// (newest files only) is the fallback for a cwd whose dir name we mis-derive.
export function findOwnLog(cacheRoot: string, cwd: string | null, marker: string, notBeforeMs: number): string | null {
  const dirs: string[] = []
  try {
    const all = readdirSync(cacheRoot)
    const own = cwd ? cacheDirName(cwd) : null
    if (own && all.includes(own)) dirs.push(own)
    for (const d of all) if (d !== own) dirs.push(d)
  } catch {
    return null
  }
  for (const d of dirs) {
    let logDirs: string[]
    try {
      logDirs = readdirSync(join(cacheRoot, d)).filter(n => n.startsWith('mcp-logs-plugin-email-'))
    } catch {
      continue
    }
    for (const ld of logDirs) {
      const full = join(cacheRoot, d, ld)
      let files: { p: string; m: number }[]
      try {
        files = readdirSync(full)
          .filter(n => n.endsWith('.jsonl'))
          .map(n => ({ p: join(full, n), m: statSync(join(full, n)).mtimeMs }))
          .filter(f => f.m >= notBeforeMs)
          .sort((a, b) => b.m - a.m)
          .slice(0, 5)
      } catch {
        continue
      }
      for (const f of files) {
        try {
          if (readFileSync(f.p, 'utf8').includes(marker)) return f.p
        } catch {}
      }
    }
  }
  return null
}

export interface RouteProbe {
  // 'inject' only when the session asked for email AND Claude Code refused it.
  route(): 'inject' | 'mcp'
  // Asked for email, no decision logged yet, and still inside the boot
  // window: a message arriving now should wait for the decision, not guess.
  pending(): boolean
  // Why, for the lifecycle log / diagnostics.
  describe(): string
  // The last gate decision Claude Code logged for this process (DIVE-5993).
  decision(): ChannelDecision
}

// Stateful, cached probe. Re-reads the log at most every `recheckMs`, and only
// when the file changed, because the gate is re-evaluated during a session.
export function makeRouteProbe(opts: {
  marker: string
  bootPpid: number
  cacheRoot: string
  bootMs: number
  recheckMs?: number
  now?: () => number
  // Test seam: the parent Claude Code process (default: walk /proc from bootPpid).
  findParent?: () => ReturnType<typeof findClaudeAncestor>
}): RouteProbe {
  const now = opts.now ?? Date.now
  const recheckMs = opts.recheckMs ?? 5000
  let parent: ReturnType<typeof findClaudeAncestor> | undefined
  let asked: boolean | undefined
  let logPath: string | null = null
  let lastRead = 0
  let lastSig = ''
  let decision: ChannelDecision = 'unknown'

  function refresh(): void {
    if (!parent) {
      // Not cached until found: a miss is re-walked, never remembered as "not asked".
      parent = opts.findParent ? opts.findParent() : findClaudeAncestor(opts.bootPpid)
      asked = parent ? argvAsksForEmail(parent.argv) : false
    }
    if (!asked) return
    const t = now()
    if (t - lastRead < recheckMs && decision !== 'unknown') return
    lastRead = t
    if (!logPath) logPath = findOwnLog(opts.cacheRoot, parent?.cwd ?? null, opts.marker, opts.bootMs - 120_000)
    if (!logPath) return
    try {
      const st = statSync(logPath)
      const sig = `${st.size}:${st.mtimeMs}`
      if (sig === lastSig) return
      lastSig = sig
      decision = decisionFromLog(readFileSync(logPath, 'utf8'), opts.marker)
    } catch {
      logPath = null
    }
  }

  return {
    route() {
      refresh()
      return asked && decision === 'refused' ? 'inject' : 'mcp'
    },
    pending() {
      refresh()
      return asked === true && decision === 'unknown' && now() - opts.bootMs < 60_000
    },
    describe() {
      return `asked=${asked ?? '?'} decision=${decision} log=${logPath ?? 'none'} claude=${parent?.pid ?? 'none'}`
    },
    decision() {
      refresh()
      return asked ? decision : 'unknown'
    },
  }
}

// ---- did the Enter take? ------------------------------------------------------

// The text after the LAST composer glyph in `tmux capture-pane -e -p`, with the
// dim ghost-suggestion runs and every other SGR/CSI sequence removed. Same read
// as the CLI's `_hb_composer_unsent` (DIVE-4242), minus the parts only it needs.
export function composerText(raw: string): string {
  const lines = raw.split('\n').filter(l => l.includes('❯'))
  const last = lines[lines.length - 1]
  if (last == null) return ''
  return last
    .slice(last.lastIndexOf('❯') + 1)
    .replace(/\x1b\[2m[^\x1b]*(?:\x1b\[0m|\x1b\[22m)/g, '')
    .replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '')
    .replace(/\u00a0/g, ' ')
    .trim()
}

// Our message is still sitting unsent: the typed line, or the paste placeholder
// Claude Code shows for a long payload. Anything else in the composer is not
// ours, so it never earns a second Enter from us.
export function composerHoldsInjection(raw: string): boolean {
  const t = composerText(raw)
  return t.startsWith(INJECT_TYPED_LINE.slice(0, 24)) || /^\[Pasted text #\d+/.test(t)
}

// ---- the keystrokes -----------------------------------------------------------

type Exec = (bin: string, args: string[]) => Promise<{ stdout: string }>

// Type one inbound into the seat's pane and submit it. Serialised, so two
// messages arriving together never interleave their keystrokes. The typed line
// goes first as its own keystrokes (DIVE-5098: a long payload folds into a
// paste, and pasted text is acted on only behind a line the user's side typed),
// the payload is ONE line (DIVE-4642: a multi-line composer eats the Enter), and
// the Enter is verified and retried (DIVE-4242) — only while the composer still
// visibly holds OUR text, so a stray Enter never lands on anything else.
export function makeSessionInjector(opts: {
  tmuxBin: string
  socket: string
  target: string
  exec: Exec
  pauseMs?: number
  verifyMs?: number
}): (text: string) => Promise<void> {
  let chain: Promise<void> = Promise.resolve()
  const pauseMs = opts.pauseMs ?? 300
  const verifyMs = opts.verifyMs ?? 700
  const tmux = (...args: string[]) => opts.exec(opts.tmuxBin, [...(opts.socket ? ['-S', opts.socket] : []), ...args])
  const pause = (ms: number) => new Promise(r => setTimeout(r, ms))
  return (text: string) => {
    if (!opts.target) return Promise.reject(new Error('no tmux pane for this session'))
    const line = oneLine(text)
    const run = chain.then(async () => {
      await tmux('send-keys', '-t', opts.target, '-l', '--', `${INJECT_TYPED_LINE} `)
      await pause(pauseMs)
      await tmux('send-keys', '-t', opts.target, '-l', '--', line)
      await pause(pauseMs)
      await tmux('send-keys', '-t', opts.target, 'Enter')
      for (let retry = 0; retry < 2; retry++) {
        await pause(verifyMs)
        const { stdout } = await tmux('capture-pane', '-e', '-p', '-t', opts.target)
        if (!composerHoldsInjection(stdout)) return
        await tmux('send-keys', '-t', opts.target, 'Enter')
      }
    })
    chain = run.catch(() => {})
    return run
  }
}
