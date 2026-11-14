// email/mail.ts — the pure half of the email channel (DIVE-8315).
//
// Node builtins only, so repo CI's bare `bun test` (no plugin dependencies
// installed) executes every decision here: threading, who the agent may mail
// without asking, the daily cap, what an inbound mail looks like to the agent,
// and the local-only rule. server.ts does the I/O (IMAP, SMTP, the maildir).

import { createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'

// ── config ───────────────────────────────────────────────────────────────────
// ~/.claude/channels/email/config.json, 0600 and the agent's own, written by
// `sudo 5dive email connect`. The password arrives through a one-time
// secret link (or `secret write` at a terminal), never as an argument.
//
//   mode "imap"  — a mailbox the firm already runs (Google Workspace, Exchange,
//                  any IMAP+SMTP server): read over IMAP,
//                  send through the firm's own SMTP.
//   mode "local" — the box's own mail server (OpenAgent Mail, mailserver.ts):
//                  mail lands in a maildir the agent owns, and goes out through
//                  the server's submission port on 127.0.0.1.

/** pass is absent on a mailbox signed in through Microsoft (Config.oauth): the token stands in for it. */
export type Endpoint = { host: string; port: number; secure: boolean; user: string; pass?: string }
export type Config = {
  address: string
  name?: string
  mode: 'imap' | 'local'
  imap?: Endpoint
  smtp: Endpoint
  maildir?: string
  /** true (default) = a mail to an address that never wrote to the agent waits for the owner's OK. */
  approve_new?: boolean
  /** true (default) = a first mail FROM an unknown address is held, unseen by the agent, until the owner taps Allow. */
  approve_inbound?: boolean
  /** Addresses (or "@domain") the owner allowed ahead of time: they mail and are mailed without asking. */
  allowed?: string[]
  /** Domains the agent mails without asking (default: its own address's domain — colleagues). */
  free_domains?: string[]
  /** Mails a day, all recipients counted once per mail (default 50). */
  daily_cap?: number
  poll_seconds?: number
  /** DIVE-8407: a Microsoft 365 / Outlook mailbox, signed in through the firm's own Microsoft app (msauth.ts). */
  oauth?: OAuth
  /** true (default) = only a mail whose sender is CONFIRMED (SPF/DKIM/DMARC, see senderCheck) counts as a colleague, a listed or a known sender; any other mail waits at the door. */
  check_sender?: boolean
}

// ── DIVE-8407: a Microsoft sign-in in the config (msauth.ts does the signing in) ──
// Here, not in msauth.ts: the box's mail server copies only this file (email server setup).
const GUID_RX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const DOMAIN_RX = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i
export const clientIdOk = (s: unknown): s is string => typeof s === 'string' && GUID_RX.test(s)
/** A tenant is its id (a GUID) or any domain verified in it (yourfirm.com, yourfirm.onmicrosoft.com). Never "common": the app is the firm's. */
export const tenantOk = (s: unknown): s is string => typeof s === 'string' && (GUID_RX.test(s) || DOMAIN_RX.test(s))

export type OAuth = { provider: 'microsoft'; tenant: string; client_id: string; refresh_token: string }

export function oauthOk(o: any): o is OAuth {
  return !!o && o.provider === 'microsoft' && tenantOk(o.tenant) && clientIdOk(o.client_id)
    && typeof o.refresh_token === 'string' && o.refresh_token.length > 0
}

const HOST_RX = /^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/

function endpointOk(e: any, token = false): e is Endpoint {
  return !!e && typeof e.host === 'string' && HOST_RX.test(e.host) && Number.isInteger(e.port) && e.port > 0 && e.port < 65536
    && typeof e.secure === 'boolean' && typeof e.user === 'string' && (token ? e.user.length > 0 : typeof e.pass === 'string')
}

export function parseConfig(raw: unknown): Config | null {
  const c = raw && typeof raw === 'object' ? (raw as any) : null
  if (!c) return null
  if (!normAddr(c.address)) return null
  if (c.mode !== 'imap' && c.mode !== 'local') return null
  // A Microsoft sign-in is for the firm's mailbox only, and then it is the only way in.
  const token = c.oauth !== undefined
  if (token && (c.mode !== 'imap' || !oauthOk(c.oauth))) return null
  if (!endpointOk(c.smtp, token)) return null
  if (c.mode === 'imap' && !endpointOk(c.imap, token)) return null
  if (c.mode === 'local' && (typeof c.maildir !== 'string' || !c.maildir.startsWith('/'))) return null
  return { ...c, address: normAddr(c.address)! } as Config
}

// ── addresses ────────────────────────────────────────────────────────────────
const ADDR_RX = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/

/** A bare, lower-cased address, or null. Accepts "Name <a@b.c>". */
export function normAddr(s: unknown): string | null {
  if (typeof s !== 'string') return null
  let a = s.trim()
  const m = a.match(/<([^<>]+)>\s*$/)
  if (m) a = m[1]
  a = a.trim().toLowerCase()
  return a.length <= 254 && ADDR_RX.test(a) ? a : null
}

export const domainOf = (addr: string) => addr.slice(addr.lastIndexOf('@') + 1)

// ── threads ──────────────────────────────────────────────────────────────────
// A reply chain is ONE conversation: its chat_id is derived from the root
// Message-ID (the first id in References, else In-Reply-To, else the mail's
// own id), so every mail in the chain lands in the same chat.

const MID_RX = /<[^<>\s]+>/g
export function messageIds(s: unknown): string[] {
  if (Array.isArray(s)) return s.flatMap(messageIds)
  if (typeof s !== 'string') return []
  const ids = s.match(MID_RX)
  if (ids) return ids
  const t = s.trim()
  return t && !/\s/.test(t) ? [`<${t.replace(/^<|>$/g, '')}>`] : []
}

export function threadRoot(messageId: string | undefined, inReplyTo: unknown, references: unknown): string | null {
  const refs = messageIds(references)
  if (refs.length) return refs[0]
  const irt = messageIds(inReplyTo)
  if (irt.length) return irt[0]
  const own = messageIds(messageId)
  return own[0] ?? null
}

export const chatIdOf = (root: string) => 'm' + createHash('sha256').update(root.toLowerCase()).digest('hex').slice(0, 16)

export function replySubject(s: string | undefined): string {
  const t = (s ?? '').replace(/[\r\n]+/g, ' ').trim()
  if (!t) return 'Re: (no subject)'
  return /^(re|aw|sv|antw)\s*:/i.test(t) ? t : `Re: ${t}`
}

/** References for a reply: the chain so far plus the mail being answered, the
 *  newest 20 (RFC 5322 lets them grow; servers choke on very long headers). */
export function nextReferences(refs: string[], answering: string | undefined): string[] {
  const out = [...refs]
  if (answering && !out.includes(answering)) out.push(answering)
  return out.slice(-20)
}

// ── what the agent sees ──────────────────────────────────────────────────────
// The text the person wrote this time: the quoted history below an
// "On … wrote:" line or a block of "> " lines is cut (the agent has the
// earlier mails in this chat already), and the whole is capped.
export const MAX_TEXT = 12_000
export function freshText(text: string): string {
  const lines = (text ?? '').replace(/\r\n/g, '\n').split('\n')
  let end = lines.length
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]
    if (/^On .{4,200} wrote:\s*$/.test(l) || /^-{2,}\s*Original Message\s*-{2,}/i.test(l) || /^_{8,}$/.test(l) && /^From:/i.test(lines[i + 1] ?? '')) { end = i; break }
    if (/^>/.test(l) && lines.slice(i).every(x => /^>/.test(x) || !x.trim())) { end = i; break }
  }
  let t = lines.slice(0, end).join('\n').trim()
  if (t.length > MAX_TEXT) t = t.slice(0, MAX_TEXT) + '\n[… cut: the mail is longer]'
  return t
}

export type Inbound = {
  messageId: string
  from: { address: string; name: string }
  to: string[]
  cc: string[]
  subject: string
  text: string
  date: string
  files: string[]
}

/** The channel notification for one mail. Every field the agent sees about the
 *  sender comes from the headers; nothing marks the mail as trusted. */
export function renderInbound(m: Inbound, chatId: string, shortId: string, self: string): { content: string; meta: Record<string, string> } {
  const others = [...m.to, ...m.cc].filter(a => a !== self && a !== m.from.address)
  const head = [`Subject: ${m.subject || '(no subject)'}`]
  if (others.length) head.push(`Also to: ${others.slice(0, 10).join(', ')}${others.length > 10 ? ` (+${others.length - 10})` : ''}`)
  const body = freshText(m.text) || '(no text)'
  const content = `${head.join('\n')}\n\n${body}`
  const meta: Record<string, string> = {
    chat_id: chatId,
    message_id: shortId,
    user: (m.from.name || m.from.address).replace(/[\r\n"]/g, ' ').slice(0, 80),
    user_id: m.from.address,
    subject: (m.subject || '').replace(/[\r\n"]/g, ' ').slice(0, 200),
    ts: m.date,
    sender_role: 'outside',
  }
  if (m.files.length) meta.file_path = m.files[0]
  if (m.files.length > 1) meta.more_files = m.files.slice(1).join(',')
  return { content, meta }
}

// ── state ────────────────────────────────────────────────────────────────────
export type Thread = { root: string; subject: string; last: string; refs: string[]; with: string; name: string; cc: string[]; at: string }
export type Held = { id: string; to: string[]; cc: string[]; subject: string; text: string; files: string[]; chat?: string; waiting: string[]; knocks: Record<string, number | null>; at: string }
export type State = {
  uid_validity?: string
  last_uid?: number
  seen: string[]
  threads: Record<string, Thread>
  /** Addresses that have mailed the agent: it may answer them without asking. */
  known: string[]
  /** Addresses the owner allowed (a knock answered Allow). */
  approved: string[]
  /** Addresses the owner said No to: mail to them is refused at once. */
  refused: string[]
  held: Record<string, Held>
  /** Inbound mail from unknown senders, waiting for the owner (never shown to the agent). */
  held_in: Record<string, HeldIn>
  sent: { day: string; n: number }
  /** DIVE-8405: when the last "someone new wrote" card was filed, and when the owner last answered one. */
  door_carded_at?: string
  door_answered_at?: string
  /** The newest filtered.log time already told to the owner, and when they were last told. */
  filter_told_upto?: string
  filter_told_at?: string
  /** DIVE-8407: when the owner was told the Microsoft sign-in needs doing again (cleared once it works). */
  signin_told_at?: string
}

export function emptyState(): State {
  return { seen: [], threads: {}, known: [], approved: [], refused: [], held: {}, held_in: {}, sent: { day: '', n: 0 } }
}

export function readState(raw: any): State {
  const s = emptyState()
  if (!raw || typeof raw !== 'object') return s
  for (const k of ['seen', 'known', 'approved', 'refused'] as const) if (Array.isArray(raw[k])) s[k] = raw[k].filter((x: unknown) => typeof x === 'string')
  if (raw.threads && typeof raw.threads === 'object') s.threads = raw.threads
  if (raw.held && typeof raw.held === 'object') s.held = raw.held
  if (raw.held_in && typeof raw.held_in === 'object') s.held_in = raw.held_in
  if (raw.sent && typeof raw.sent.day === 'string' && Number.isInteger(raw.sent.n)) s.sent = raw.sent
  for (const k of ['door_carded_at', 'door_answered_at', 'filter_told_upto', 'filter_told_at', 'signin_told_at'] as const) if (typeof raw[k] === 'string') s[k] = raw[k]
  if (typeof raw.uid_validity === 'string') s.uid_validity = raw.uid_validity
  if (Number.isInteger(raw.last_uid)) s.last_uid = raw.last_uid
  return s
}

const MAX_SEEN = 2000
const MAX_THREADS = 500
const MAX_KNOWN = 5000
export function trimState(s: State) {
  if (s.seen.length > MAX_SEEN) s.seen = s.seen.slice(-MAX_SEEN)
  if (s.known.length > MAX_KNOWN) s.known = s.known.slice(-MAX_KNOWN)
  const t = Object.entries(s.threads)
  if (t.length > MAX_THREADS) {
    t.sort((a, b) => a[1].at.localeCompare(b[1].at))
    for (const [id] of t.slice(0, t.length - MAX_THREADS)) delete s.threads[id]
  }
}

export function remember(list: string[], addr: string) {
  const i = list.indexOf(addr)
  if (i >= 0) list.splice(i, 1)
  list.push(addr)
}

// ── the send gate ────────────────────────────────────────────────────────────
// lodar 11-11/11-13: replies to people who wrote in go out freely (that is not
// cold mail). The first mail to a NEW address waits for one owner tap, after
// which the address joins the list. The owner can switch the tap off per agent
// (approve_new:false). Colleagues on the agent's own domain are not "outside".
// A No is remembered, and the daily cap holds either way.

export function freeDomains(cfg: Config): string[] {
  const d = Array.isArray(cfg.free_domains) ? cfg.free_domains : [domainOf(cfg.address)]
  return d.map(x => String(x).trim().toLowerCase()).filter(Boolean)
}

/** On the owner's list ahead of time: an address, or a whole "@domain". */
export function preAllowed(cfg: Config, addr: string): boolean {
  const list = Array.isArray(cfg.allowed) ? cfg.allowed.map(x => String(x).trim().toLowerCase()) : []
  return list.includes(addr) || list.includes(`@${domainOf(addr)}`)
}

export type Gate = 'free' | 'ask' | 'refused'
export function gateFor(cfg: Config, s: State, addr: string): Gate {
  if (s.refused.includes(addr)) return 'refused'
  if (cfg.approve_new === false) return 'free'
  if (s.known.includes(addr) || s.approved.includes(addr)) return 'free'
  if (freeDomains(cfg).includes(domainOf(addr)) || preAllowed(cfg, addr)) return 'free'
  return 'ask'
}

// ── the inbound gate (lodar 11-13: «whose email can the agent read?») ─────────
// Anyone can mail an address, and a mail is text the agent reads. So a first
// mail from someone unknown is HELD on this server, unseen by the agent, until
// the owner taps Allow on the same card as the send gate. Allow = it is handed
// over and the sender is known from then on; No = it is deleted and the sender
// stays unknown (their next mail is dropped too). The agent's own domain, the
// owner's allowed list and anyone the agent already mailed pass. The owner can
// switch it off per agent (approve_inbound:false).
// DIVE-8405: the door trusts the From line only when the sender is confirmed
// (senderCheck). A mail whose sender could not be confirmed is never "free" as
// a colleague, a listed or a known sender: it waits like a stranger's, and its
// card says so. `check` is that verdict; omitted = not checked (owner switch off).
export function inboundGate(cfg: Config, s: State, addr: string, check?: SenderCheck): Gate {
  if (s.refused.includes(addr)) return 'refused'
  if (cfg.approve_inbound === false) return 'free'
  if (check && !check.ok && cfg.check_sender !== false) return 'ask'
  if (s.known.includes(addr) || s.approved.includes(addr)) return 'free'
  if (freeDomains(cfg).includes(domainOf(addr)) || preAllowed(cfg, addr)) return 'free'
  return 'ask'
}

/** A mail held at the door: its raw file waits in the spool until the owner answers. */
export type HeldIn = {
  id: string; from: string; file: string; kid: number | null; tried: string; at: string
  /** The sender could not be confirmed: its card says so, and only the owner's answer about THIS hold releases it. */
  unconfirmed?: string
  /** The owner answered Allow while this mail waited. */
  released?: boolean
  /** The owner answered No on THIS mail's card (an unconfirmed sender): drop it, refuse nobody. */
  dropped?: boolean
  /** Its card waits for the hourly slot (doorSlotFree). */
  paced?: boolean
}
export const MAX_HELD_IN = 200

export const DEFAULT_CAP = 50
export function capLeft(cfg: Config, s: State, now = new Date()): number {
  const day = now.toISOString().slice(0, 10)
  const used = s.sent.day === day ? s.sent.n : 0
  const cap = Number.isInteger(cfg.daily_cap) && cfg.daily_cap! >= 0 ? cfg.daily_cap! : DEFAULT_CAP
  return cap - used
}
export function countSent(s: State, now = new Date()) {
  const day = now.toISOString().slice(0, 10)
  s.sent = s.sent.day === day ? { day, n: s.sent.n + 1 } : { day, n: 1 }
}

/** One held mail after an owner answer about `addr`: 'send' when nobody it
 *  waits on is left, 'drop' on a No, else 'wait'. */
export function afterAnswer(h: Held, addr: string, answer: 'allow' | 'admin' | 'no'): 'send' | 'drop' | 'wait' {
  if (!h.waiting.includes(addr)) return 'wait'
  if (answer === 'no') return 'drop'
  h.waiting = h.waiting.filter(a => a !== addr)
  return h.waiting.length ? 'wait' : 'send'
}

// ── local-only ───────────────────────────────────────────────────────────────
// A local-only box is fully offline. Mail stays allowed when the mail server
// is on the office network (a LAN address), because nothing then leaves the
// building. A cloud mailbox (Microsoft 365, Google) needs IT to open email
// alone: `sudo 5dive config local-only allow email`.

export function localOnlyPaths(env: Record<string, string | undefined> = process.env) {
  const flag = env.FIVE_LOCAL_ONLY_FILE || '/etc/5dive/local-only'
  const allow = env.FIVE_LOCAL_ONLY_ALLOW_FILE || join(dirname(flag), 'local-only.allow')
  return { flag, allow }
}

export function emailOpenedOffline(paths = localOnlyPaths()): boolean {
  if (!existsSync(paths.flag)) return true
  try {
    return readFileSync(paths.allow, 'utf8').split('\n').some(l => l.trim() === 'email')
  } catch {
    return false
  }
}

export function isPrivateAddress(ip: string): boolean {
  const a = ip.toLowerCase()
  if (a === '::1' || a.startsWith('fe80:') || a.startsWith('fc') || a.startsWith('fd')) return true
  const v4 = a.startsWith('::ffff:') ? a.slice(7) : a
  const p = v4.split('.').map(Number)
  if (p.length !== 4 || p.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return false
  return p[0] === 10 || p[0] === 127 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127)
}

export const SHUT_LINE =
  "Email to an outside mail server is shut on this local-only box. A mail server on the office network works as it is; for Microsoft 365 or Google your IT opens email alone: sudo 5dive config local-only allow email"

/** May this box talk to a mail server at these resolved addresses? */
export function mayReach(addrs: string[], paths = localOnlyPaths()): boolean {
  if (emailOpenedOffline(paths)) return true
  return addrs.length > 0 && addrs.every(isPrivateAddress)
}

// ── the owner's tap: `sudo -n 5dive people knock file --channel=email …` ─────
// The same owner card Teams uses (DIVE-8036), on the address the agent wants to
// mail. Allow = the address joins the send list and the held mail goes out;
// No = the mail is dropped and the address stays refused. The CLI drops the
// answer into this agent's state dir as knocks/<kid>.json.

export type KnockKind = 'send' | 'receive' | 'receive_unconfirmed'
export function knockFileArgs(addr: string, name = '', kind: KnockKind = 'send'): string[] | null {
  const a = normAddr(addr)
  if (!a || a.length > 120) return null
  const clean = name.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 80)
  const args = ['5dive', 'people', 'knock', 'file', '--channel=email', `--kind=${kind}`, `--sender=${a}`, `--email=${a}`]
  if (clean) args.push(`--name=${clean}`)
  args.push('--json')
  return args
}

export type Filed = { kid: string | null; status: 'pending' | 'denied' | 'allowed' | 'error'; why?: string }
export function knockFiled(stdout: string): Filed {
  let r: any = null
  try {
    r = JSON.parse(stdout.trim().split('\n').filter(Boolean).pop() ?? '')
  } catch {
    r = null
  }
  if (r?.ok === true) {
    const st = r.data?.status
    const kid = r.data?.id == null ? null : String(r.data.id)
    if ((st === 'pending' || st === 'denied') && kid && /^\d+$/.test(kid)) return { kid, status: st }
    if (st === 'allowed') return { kid, status: 'allowed' }
  }
  return { kid: null, status: 'error', why: r?.error?.message ? String(r.error.message) : 'no answer from 5dive' }
}

export type Answer = { id: string; sender: string; answer: 'allow' | 'admin' | 'no' }
export function parseAnswer(raw: unknown, file: string): Answer | null {
  const a = raw as any
  if (!a || typeof a !== 'object' || a.channel !== 'email') return null
  const id = String(a.id ?? '')
  const sender = normAddr(a.sender)
  if (!/^\d+$/.test(id) || `${id}.json` !== file || !sender) return null
  if (a.answer !== 'allow' && a.answer !== 'admin' && a.answer !== 'no') return null
  return { id, sender, answer: a.answer }
}

// ── voice messages (DIVE-8315, lodar 11-13: «send voice mails to your ai employee») ──
// An audio attachment — a voicemail an office phone system mailed, or any
// recorded memo — is heard ON THE BOX (5dive-transcribe --backend=local, never
// the cloud fallback) and handed to the agent as a voice note with its text.
const AUDIO_EXT = /\.(wav|mp3|m4a|mp4a|aac|ogg|oga|opus|amr|awb|flac|webm|wma|gsm)$/i
export function isAudio(filename: string | undefined, contentType: string | undefined): boolean {
  const ct = String(contentType ?? '').toLowerCase()
  if (ct.startsWith('audio/')) return true
  return AUDIO_EXT.test(String(filename ?? ''))
}
export const MAX_VOICE_NOTES = 3

/** The lines the agent reads about one voice attachment. */
export function voiceLine(name: string, heard: { text: string } | { why: string }): string {
  if ('text' in heard) {
    const t = heard.text.trim() || '(nothing could be heard in it)'
    return `[Voice message "${name}" — transcript, heard on this server:]\n${t.length > 8000 ? t.slice(0, 8000) + ' [… cut]' : t}`
  }
  return `[Voice message "${name}" attached, not transcribed: ${heard.why}]`
}

// ── DIVE-8405: is the sender real? ───────────────────────────────────────────
// lodar 11-13: «will there be spam filter and how will we protect from the
// prompting hacks? … viruses and phishing … whitelisting mostly?» The list is
// only as strong as the From line it matches, and a From line is free text. So
// a mail counts as FROM an address only when the server that took it confirmed
// it, in its Authentication-Results header (RFC 8601):
//   * own server (mode local): mailserver.ts checks SPF, DKIM and DMARC itself
//     on receipt and puts its result on TOP of the mail (and strips any
//     look-alike header a sender wrote in);
//   * the firm's mailbox (mode imap): Google / Microsoft / the firm's server put
//     theirs on top the same way; the topmost one is the provider's.
// Confirmed = DMARC pass, or a DKIM signature or an SPF pass whose domain matches
// the From domain (relaxed alignment: same organisational domain), or a sender
// that logged in as that very address (auth=pass, a colleague agent on this box).

export type SenderCheck = { ok: boolean; why: string }

/** The raw header block of a mail, without the body. */
export function headerBlock(raw: Buffer | string): string {
  const s = typeof raw === 'string' ? raw : raw.subarray(0, 256 * 1024).toString('latin1')
  const m = s.match(/\r?\n\r?\n/)
  return m ? s.slice(0, m.index) : s
}

/** Every value of a header, unfolded, topmost first. */
export function headerValues(raw: Buffer | string, name: string): string[] {
  const out: string[] = []
  const want = name.toLowerCase()
  for (const h of headerBlock(raw).split(/\r?\n(?![ \t])/)) {
    const i = h.indexOf(':')
    if (i > 0 && h.slice(0, i).trim().toLowerCase() === want) out.push(h.slice(i + 1).replace(/\r?\n[ \t]+/g, ' ').trim())
  }
  return out
}

/** The mail with every header `drop` matches removed (the body untouched). */
export function stripHeaders(raw: Buffer, drop: (name: string, value: string) => boolean): Buffer {
  const s = raw.toString('latin1')
  const m = s.match(/\r?\n\r?\n/)
  const head = m ? s.slice(0, m.index) : s
  const rest = m ? s.slice(m.index) : ''
  const kept = head.split(/(?<=\n)(?![ \t])/).filter(h => {
    const i = h.indexOf(':')
    return !(i > 0 && drop(h.slice(0, i).trim().toLowerCase(), h.slice(i + 1).replace(/\r?\n[ \t]+/g, ' ').trim()))
  })
  return Buffer.from(kept.join('') + rest, 'latin1')
}

const TWO_LEVEL = /^(co|com|net|org|gov|ac|edu|ltd|plc|or|ne|go|gv)$/
/** The organisational domain, close enough for alignment: mail.firm.co.uk → firm.co.uk. */
export function orgDomain(d: string): string {
  const p = d.toLowerCase().replace(/\.$/, '').split('.').filter(Boolean)
  if (p.length <= 2) return p.join('.')
  const n = p.length >= 3 && p[p.length - 1].length === 2 && TWO_LEVEL.test(p[p.length - 2]) ? 3 : 2
  return p.slice(-n).join('.')
}
const aligned = (a: string, b: string) => !!a && !!b && orgDomain(a) === orgDomain(b)

/** One Authentication-Results value: its authserv-id and its method results. */
export function parseAuthResults(v: string): { id: string; results: { method: string; result: string; props: Record<string, string> }[] } {
  let t = v
  for (let i = 0; i < 4; i++) t = t.replace(/\([^()]*\)/g, ' ') // comments, nested a little
  const parts = t.split(';').map(x => x.trim()).filter(Boolean)
  let id = ''
  if (parts.length && !/^[a-z0-9_.-]+\s*=/i.test(parts[0])) id = parts.shift()!.split(/\s+/)[0].toLowerCase()
  const results = parts.map(p => {
    const toks = p.split(/\s+/).filter(Boolean)
    const [method, result] = (toks.shift() ?? '').toLowerCase().split('=')
    const props: Record<string, string> = {}
    for (const k of toks) { const j = k.indexOf('='); if (j > 0) props[k.slice(0, j).toLowerCase()] = k.slice(j + 1).replace(/^"|"$/g, '').toLowerCase() }
    return { method: method ?? '', result: result ?? '', props }
  }).filter(r => r.method && r.result)
  return { id, results }
}

/** Is the From address confirmed by this (topmost) Authentication-Results value? */
export function senderCheck(authResults: string | undefined, from: string): SenderCheck {
  if (!authResults) return { ok: false, why: 'the mail carries no sender check' }
  const fd = domainOf(from)
  const { results } = parseAuthResults(authResults)
  const dom = (s: string | undefined) => (s ?? '').replace(/^.*@/, '')
  for (const r of results) {
    if (r.method === 'dmarc' && r.result === 'pass' && (!r.props['header.from'] || aligned(r.props['header.from'], fd))) return { ok: true, why: 'dmarc=pass' }
    if (r.method === 'dkim' && r.result === 'pass' && aligned(r.props['header.d'] || dom(r.props['header.i']), fd)) return { ok: true, why: 'dkim=pass' }
    if (r.method === 'spf' && r.result === 'pass' && aligned(dom(r.props['smtp.mailfrom']), fd)) return { ok: true, why: 'spf=pass' }
    if (r.method === 'auth' && r.result === 'pass' && r.props['smtp.auth'] === from) return { ok: true, why: 'auth=pass' }
  }
  const dm = results.find(r => r.method === 'dmarc')
  if (dm && dm.result === 'fail') return { ok: false, why: `${fd} says this server may not send its mail (dmarc=fail)` }
  if (results.some(r => /^(temperror|permerror)$/.test(r.result))) return { ok: false, why: 'the sender check could not finish (DNS)' }
  return { ok: false, why: `nothing proves the mail came from ${fd}` }
}

// ── DIVE-8405: spam, viruses, phishing (own server) ──────────────────────────
// mailserver.ts asks a filter running ON THE BOX (rspamd, ClamAV: no mail
// leaves the server) and writes what it found on top of the mail in one header
// of its own, X-OpenAgent-Filter, after stripping any a sender wrote in.
export const FILTER_HEADER = 'x-openagent-filter'
export const GTUBE = 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'

export type SpamVerdict = { spam: boolean; score: number | null; phishing: string[]; by: string }
/** rspamd's /checkv2 answer → our verdict. Spam = any action that would not let it through plainly. */
export function rspamdVerdict(j: any): SpamVerdict {
  const action = String(j?.action ?? 'no action')
  const symbols = j?.symbols && typeof j.symbols === 'object' ? Object.keys(j.symbols) : []
  const phishing = symbols.filter(s => /PHISH|SPOOF|FREEMAIL_REPLYTO_NEQ|HTML_SHORT_LINK|REDIRECTOR|OMOGRAPH|URIBL|DBL|SURBL|SUSPICIOUS/.test(s)).slice(0, 5)
  return { spam: /^(reject|add header|rewrite subject)$/.test(action), score: Number.isFinite(Number(j?.score)) ? Number(j.score) : null, phishing, by: 'rspamd' }
}
/** No filter running: only the industry's test string is caught (the honest floor, not a spam filter). */
export function builtinSpam(raw: Buffer): SpamVerdict {
  return { spam: raw.includes(GTUBE), score: null, phishing: [], by: 'none' }
}
/** clamd's INSTREAM reply. */
export function clamdVerdict(reply: string): { infected: boolean; name?: string } | null {
  const t = reply.replace(/\0/g, '').trim()
  const m = t.match(/^stream: (.+) FOUND$/)
  if (m) return { infected: true, name: m[1].slice(0, 120) }
  if (/^stream: OK$/.test(t)) return { infected: false }
  return null
}
export function filterHeaderValue(f: { spam: SpamVerdict | null; virus: 'clean' | 'unscanned' }): string {
  const parts = [`spam=${f.spam ? (f.spam.by === 'none' ? 'unchecked' : `${f.spam.score ?? '?'}`) : 'off'}`, `virus=${f.virus}`]
  if (f.spam?.phishing.length) parts.push(`phishing=${f.spam.phishing.join(',')}`)
  return parts.join('; ')
}
export function parseFilterHeader(v: string | undefined): { virus: string; spam: string; phishing: string[] } | null {
  if (!v) return null
  const kv: Record<string, string> = {}
  for (const p of v.split(';')) { const i = p.indexOf('='); if (i > 0) kv[p.slice(0, i).trim()] = p.slice(i + 1).trim() }
  return { virus: kv.virus ?? '', spam: kv.spam ?? '', phishing: (kv.phishing ?? '').split(',').filter(Boolean) }
}

// Phishing signs the channel finds itself, on any route: a link that SHOWS one
// site and GOES to another, a look-alike of the agent's own domain, a name that
// carries a different address. Marked to the agent, never a reason to hold.
function editDistance(a: string, b: string): number {
  if (Math.abs(a.length - b.length) > 2) return 3
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)])
  for (let j = 1; j <= b.length; j++) d[0][j] = j
  for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1))
  return d[a.length][b.length]
}
const hostOf = (u: string) => { try { return new URL(/^[a-z][a-z0-9+.-]*:/i.test(u) ? u : `http://${u}`).hostname.toLowerCase().replace(/^www\./, '') } catch { return '' } }
export function lookalike(d: string, real: string): boolean {
  const a = orgDomain(d), b = orgDomain(real)
  if (!a || !b || a === b) return false
  if (a.includes('xn--')) return true
  const la = a.split('.')[0], lb = b.split('.')[0]
  return la.length >= 4 && editDistance(la, lb) <= 2
}
export function phishingSigns(m: { from: string; fromName: string; html: string; ownDomain: string; links?: number }): string[] {
  const out: string[] = []
  const fd = domainOf(m.from)
  const named = (m.fromName.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i) ?? [])[0]?.toLowerCase()
  if (named && named !== m.from) out.push(`the sender's name shows ${named}, but the mail is from ${m.from}`)
  if (lookalike(fd, m.ownDomain)) out.push(`the sender's domain ${fd} looks like ${m.ownDomain} but is not`)
  else if (fd.includes('xn--')) out.push(`the sender's domain ${fd} uses look-alike letters`)
  let n = 0
  for (const a of (m.html || '').matchAll(/<a\b[^>]*href\s*=\s*["']?([^"'\s>]+)[^>]*>([\s\S]*?)<\/a>/gi)) {
    n++
    const href = a[1], shown = a[2].replace(/<[^>]*>/g, '').trim()
    const hh = hostOf(href)
    if (!hh || out.length >= 3) continue
    if (/^\d+\.\d+\.\d+\.\d+$/.test(hh)) { out.push(`a link goes to a bare address (${hh})`); continue }
    const sm = shown.match(/^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[\/:?#]\S*)?$/i)
    if (sm && orgDomain(sm[1].replace(/^www\./, '')) !== orgDomain(hh)) out.push(`a link shows ${sm[1].toLowerCase()} but goes to ${hh}`)
    else if (hh.includes('xn--') || lookalike(hh, m.ownDomain)) out.push(`a link goes to a look-alike site (${hh})`)
  }
  if (n >= 25 && out.length < 3) out.push(`the mail is mostly links (${n})`)
  return out.slice(0, 3)
}

// ── DIVE-8405: the owner hears about a blocked virus once a day, not per mail ─
// mailserver.ts appends one line per filtered mail to <maildir>/filtered.log:
//   <iso time>\tvirus|spam\t<from>\t<detail>
export type Filtered = { at: string; kind: 'virus' | 'spam'; from: string; detail: string }
export function readFiltered(text: string, after = ''): Filtered[] {
  return text.split('\n').map(l => l.split('\t')).filter(p => p.length >= 3 && (p[1] === 'virus' || p[1] === 'spam') && p[0] > after)
    .map(p => ({ at: p[0], kind: p[1] as 'virus' | 'spam', from: p[2], detail: p[3] ?? '' }))
}
export const DAY_MS = 24 * 3600_000
/** The one line for the owner, or null when nothing is owed yet. */
export function ownerDigest(agent: string, f: Filtered[], toldAt: string | undefined, now = Date.now()): string | null {
  const v = f.filter(x => x.kind === 'virus')
  if (!v.length) return null
  if (toldAt && now - Date.parse(toldAt) < DAY_MS) return null
  const who = [...new Set(v.map(x => x.from))].slice(0, 3).join(', ')
  const spam = f.filter(x => x.kind === 'spam').length
  return `${agent}'s email blocked ${v.length} mail${v.length > 1 ? 's' : ''} with a virus (from ${who}${new Set(v.map(x => x.from)).size > 3 ? ' and others' : ''}). ${agent} never saw ${v.length > 1 ? 'them' : 'it'}.${spam ? ` ${spam} spam mail${spam > 1 ? 's' : ''} went to the spam folder.` : ''}`
}

/** May a "someone new wrote" card go out now? At most one an hour; the owner's answer frees the next at once. */
export const DOOR_EVERY_MS = 3600_000
export function doorSlotFree(s: State, now = Date.now(), every = DOOR_EVERY_MS): boolean {
  if (!s.door_carded_at) return true
  if (s.door_answered_at && s.door_answered_at >= s.door_carded_at) return true
  return now - Date.parse(s.door_carded_at) >= every
}
