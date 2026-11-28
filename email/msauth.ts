// email/msauth.ts — Microsoft 365 / Outlook sign-in for an agent's mailbox (DIVE-8407).
//
// Exchange Online refuses a password over IMAP and SMTP (basic auth was
// switched off in 2022), so an M365 mailbox is read and sent with a Microsoft
// token (XOAUTH2). The sign-in app is the FIRM'S OWN: their IT registers it in
// their own Microsoft tenant (docs/IT-GUIDE.md) and hands us two ids that are
// not secrets (the tenant and the app's client id). No 5dive app, no 5dive
// account, no "unverified app" screen. Sign-in is Microsoft's device code: a
// person opens microsoft.com/devicelogin, types a short code and signs in AS
// THE AGENT'S MAILBOX; this server never sees the password.
//
// What we keep: the refresh token, in the agent's own config.json (0600, the
// same file and mode that hold a password-mailbox's password). Access tokens
// live in memory for about an hour; Microsoft may hand back a new refresh
// token on any refresh, and it is written back at once.
//
// Used two ways: imported by server.ts (accessToken), and run by the CLI
// (`bun msauth.ts start|poll …`, JSON on stdout) for connect.

export const IMAP_HOST = 'outlook.office365.com'
export const SMTP_HOST = 'smtp.office365.com'
// The documented scopes for IMAP and SMTP AUTH with OAuth (Exchange Online),
// plus offline_access for a refresh token and openid+email to read who signed in.
export const SCOPE = 'https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send offline_access openid email'

// DIVE-9474: the owner's OneDrive and SharePoint files, asked for on top of the
// mail scopes in the SAME sign-in (Microsoft's incremental consent, same app).
// OneDrive: the signed-in person's own files. SharePoint: the sites they can open
// (search across them, list a site's libraries). Both are delegated: the agent
// sees only what that person sees. Microsoft asks consent for both resources in
// one sign-in but hands out a token for one resource at a time, so the code is
// redeemed for mail (SCOPE) and Graph tokens come from the same refresh token.
export const FILES_SCOPE = 'https://graph.microsoft.com/Files.ReadWrite'
export const SITES_SCOPE = 'https://graph.microsoft.com/Sites.ReadWrite.All'
export type FilesAsk = 'all' | 'onedrive'
export const filesScope = (f: FilesAsk | '' | undefined): string =>
  f === 'all' ? `${FILES_SCOPE} ${SITES_SCOPE}` : f === 'onedrive' ? FILES_SCOPE : ''
/** A Graph token's scope: Microsoft refreshes one resource at a time. */
export const graphScope = (sharepoint: boolean) => `${FILES_SCOPE}${sharepoint ? ` ${SITES_SCOPE}` : ''} offline_access`

/** login.microsoftonline.com, or a stand-in in tests. */
import { clientIdOk, tenantOk, type OAuth } from './mail.ts'
import { createHash, randomBytes } from 'node:crypto'
import { connect as netConnect, type Socket } from 'node:net'
import { connect as tlsConnect } from 'node:tls'
export { clientIdOk, tenantOk, oauthOk, type OAuth } from './mail.ts'

export const authority = () => (process.env.EMAIL_MS_AUTHORITY || 'https://login.microsoftonline.com').replace(/\/+$/, '')


export class SignInError extends Error {
  code: string
  /** true = only a new sign-in fixes it (revoked, expired, consent pulled); false = try again later. */
  again: boolean
  constructor(code: string, message: string, again: boolean) { super(message); this.code = code; this.again = again }
}

// Microsoft's errors that mean "the stored sign-in is no good any more".
const DEAD = new Set(['invalid_grant', 'interaction_required', 'consent_required', 'invalid_client', 'unauthorized_client', 'unauthorized_client_app'])

async function post(tenant: string, path: string, fields: Record<string, string>): Promise<{ body: any; err?: string }> {
  const r = await fetch(`${authority()}/${encodeURIComponent(tenant)}/oauth2/v2.0/${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields),
    signal: AbortSignal.timeout(20_000),
  })
  let body: any = {}
  try { body = await r.json() } catch {}
  if (!r.ok || body?.error) return { body, err: String(body?.error || `http_${r.status}`) }
  return { body }
}

function claimsOf(idToken: unknown): any {
  try {
    return JSON.parse(Buffer.from(String(idToken).split('.')[1], 'base64url').toString('utf8')) ?? {}
  } catch {
    return {}
  }
}

/** The address Microsoft signed in, read from the id_token (shown, compared; never used for access). */
export function signedInAs(idToken: unknown): string {
  const c = claimsOf(idToken)
  return String(c.preferred_username || c.email || c.upn || '').toLowerCase()
}

// DIVE-9120: the tenant id Microsoft gives every personal account (Outlook.com,
// Hotmail, Live). Such a mailbox sends through smtp-mail.outlook.com, not
// smtp.office365.com, and has no firm admin to ask.
export const CONSUMER_TENANT = '9188040d-6c67-4c5b-b112-36a304b66dad'
export const isConsumer = (idToken: unknown): boolean => String(claimsOf(idToken).tid || '').toLowerCase() === CONSUMER_TENANT

export type Pending = { tenant: string; client_id: string; address: string; device_code: string; user_code: string; link: string; interval: number; expires_at: number }

/** Step 1: Microsoft's code for a person to type at the link. */
export async function deviceStart(tenant: string, clientId: string, address: string): Promise<Pending> {
  const { body, err } = await post(tenant, 'devicecode', { client_id: clientId, scope: SCOPE })
  if (err) throw explain(err, body, clientId)
  return {
    tenant, client_id: clientId, address,
    device_code: String(body.device_code), user_code: String(body.user_code),
    link: String(body.verification_uri || 'https://microsoft.com/devicelogin'),
    interval: Math.max(1, Number(body.interval) || 5),
    expires_at: Date.now() + (Number(body.expires_in) || 900) * 1000,
  }
}

export type Done = { refresh_token: string; access_token: string; expires_at: number; who: string; consumer: boolean }

// ── The sign-in link (DIVE-8407, the default) ────────────────────────────────
// Microsoft's security defaults, on in most small tenants, refuse the device
// code sign-in (AADSTS530035) for every user, and only a paid Conditional Access
// licence could exempt one app. So the default is the ordinary sign-in link
// (authorization code + PKCE): the person signs in at Microsoft, lands on
// Microsoft's own empty page for apps with no website, and sends its address
// back. The code in it is good once, for minutes, and only with the verifier
// that never leaves this server.
export const REDIRECT = 'https://login.microsoftonline.com/common/oauth2/nativeclient'
const LINK_MS = 30 * 60_000

export type LinkPending = { kind: 'link'; tenant: string; client_id: string; address: string; verifier: string; state: string; link: string; expires_at: number; files?: FilesAsk }

export function linkStart(tenant: string, clientId: string, address: string, files?: FilesAsk): LinkPending {
  const verifier = randomBytes(48).toString('base64url')
  const state = randomBytes(12).toString('base64url')
  const challenge = createHash('sha256').update(verifier).digest('base64url')
  const q = new URLSearchParams({
    client_id: clientId, response_type: 'code', redirect_uri: REDIRECT, response_mode: 'query', scope: [SCOPE, filesScope(files)].filter(Boolean).join(' '),
    code_challenge: challenge, code_challenge_method: 'S256', state, login_hint: address, prompt: 'select_account',
  })
  return { kind: 'link', tenant, client_id: clientId, address, verifier, state, link: `${authority()}/${encodeURIComponent(tenant)}/oauth2/v2.0/authorize?${q}`, expires_at: Date.now() + LINK_MS, ...(files ? { files } : {}) }
}

/** What the person sent back: the whole address of the page they landed on, or just its code. */
export function readPasted(pasted: string): { code?: string; state?: string; error?: string; error_description?: string; error_subcode?: string } {
  const t = pasted.trim().replace(/^['"<]+|['">]+$/g, '')
  const i = t.search(/[?#]/)
  const qs = i >= 0 ? t.slice(i + 1) : /^(code|error)=/.test(t) ? t : ''
  if (!qs) return /^[A-Za-z0-9._~*-]{20,}$/.test(t) ? { code: t } : {}
  const q = new URLSearchParams(qs.replace(/#/g, '&'))
  const g = (k: string) => q.get(k) ?? undefined
  return { code: g('code'), state: g('state'), error: g('error'), error_description: g('error_description'), error_subcode: g('error_subcode') }
}

export async function linkRedeem(p: LinkPending, pasted: string): Promise<Done> {
  if (p.expires_at <= Date.now()) throw new SignInError('expired_token', 'the sign-in link expired before it was finished', true)
  const r = readPasted(pasted)
  if (r.error) throw explain(r.error, { error_description: r.error_description, error_subcode: r.error_subcode }, p.client_id, p.files)
  if (!r.code) throw new SignInError('no_code', "that is not the address of the page Microsoft showed after the sign-in (it starts with https://login.microsoftonline.com/common/oauth2/nativeclient?code=)", true)
  if (r.state !== undefined && r.state !== p.state) throw new SignInError('wrong_state', 'that address belongs to a different sign-in link than the one this server is waiting for', true)
  const { body, err } = await post(p.tenant, 'token', {
    client_id: p.client_id, grant_type: 'authorization_code', code: r.code, redirect_uri: REDIRECT, code_verifier: p.verifier, scope: SCOPE,
  })
  if (err) throw explain(err, body, p.client_id, p.files)
  if (!body.refresh_token) throw new SignInError('no_refresh_token', 'Microsoft gave no lasting sign-in (the app is missing offline_access). Your IT adds it: docs/IT-GUIDE.md', true)
  return { refresh_token: body.refresh_token, access_token: body.access_token, expires_at: Date.now() + (Number(body.expires_in) || 3600) * 1000, who: signedInAs(body.id_token), consumer: isConsumer(body.id_token) }
}

/** Step 2: wait up to `waitMs` for the person to finish. undefined = not yet. */
export async function devicePoll(p: Pending, waitMs: number, sleep = (ms: number) => new Promise(r => setTimeout(r, ms))): Promise<Done | undefined> {
  let interval = p.interval * 1000
  const deadline = Math.min(p.expires_at, Date.now() + waitMs)
  for (;;) {
    const { body, err } = await post(p.tenant, 'token', {
      client_id: p.client_id, device_code: p.device_code, grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    })
    if (!err) {
      if (!body.refresh_token) throw new SignInError('no_refresh_token', 'Microsoft gave no lasting sign-in (the app is missing offline_access). Your IT adds it: docs/IT-GUIDE.md', true)
      return { refresh_token: body.refresh_token, access_token: body.access_token, expires_at: Date.now() + (Number(body.expires_in) || 3600) * 1000, who: signedInAs(body.id_token), consumer: isConsumer(body.id_token) }
    }
    if (err === 'slow_down') interval += 5000
    else if (err !== 'authorization_pending') throw explain(err, body, p.client_id)
    if (Date.now() + interval > deadline) {
      if (Date.now() + interval > p.expires_at) throw new SignInError('expired_token', 'the code expired before the sign-in was finished', true)
      return undefined
    }
    await sleep(interval)
  }
}

// DIVE-9120: 5dive's own Microsoft app (bin/email passes its id), for firms with
// no IT to register one. Its fixes are worded for the owner, not for an IT team.
export const fivediveApp = () => (process.env.EMAIL_MS_DEFAULT_APP || '').toLowerCase()

/** The link a firm's Microsoft admin opens once to let 5dive's app read and send mail for everyone. */
export function adminConsentLink(clientId: string, files?: FilesAsk | ''): string {
  const q = new URLSearchParams({ client_id: clientId, scope: `${SCOPE} ${filesScope(files)}`.split(' ').filter(s => s.startsWith('https://')).join(' '), redirect_uri: REDIRECT })
  return `https://login.microsoftonline.com/organizations/v2.0/adminconsent?${q}`
}

export function explain(err: string, body: any, clientId = '', files?: FilesAsk | ''): SignInError {
  const d = String(body?.error_description || '').replace(/\+/g, ' ').split('\n')[0].slice(0, 300)
  const ours = !!clientId && clientId.toLowerCase() === fivediveApp()
  // DIVE-9474: a refusal of the files sign-in names files, offers OneDrive alone, and its admin link asks for files too.
  if (files && (/AADSTS(65001|90094|90095|90008)\b/.test(d) || (ours && err === 'consent_required') || (err === 'access_denied' && !/AADSTS65004\b/.test(d) && (ours || body?.error_subcode === 'cancel')))) {
    const alone = files === 'all' ? ' Or let the agent use OneDrive alone (no SharePoint): turn it on again with "OneDrive only".' : ''
    return new SignInError('admin_consent', ours
      ? `Microsoft stopped it: your company's admin has to allow this once. Send your admin this link, then turn it on again: ${adminConsentLink(clientId, files)}${alone} (if you tapped Cancel yourself, just turn it on again)`
      : `Microsoft stopped it: your company's admin has to allow files for the firm's app once (docs/IT-GUIDE.md).${alone}`, true)
  }
  // AADSTS65001 / 90094 / 90095 / 90008: only the firm's Microsoft admin can let this app in.
  // Checked before the error name: Microsoft sends these as access_denied or consent_required.
  if (/AADSTS(65001|90094|90095|90008)\b/.test(d) || (ours && err === 'consent_required')) {
    return new SignInError('admin_consent', ours
      ? `your firm lets in only apps its Microsoft admin has approved. Send your admin this link to approve 5dive's mail sign-in once, then connect again: ${adminConsentLink(clientId)}`
      : "the firm's app is missing your IT's consent for mail (docs/IT-GUIDE.md)", true)
  }
  // DIVE-9314 (live): Microsoft's "Need admin approval" page names no AADSTS code; its
  // "Return to the application" lands on error=access_denied&error_subcode=cancel. A person
  // who said no on the consent page carries AADSTS65004 and stays "declined" below.
  if (err === 'access_denied' && !/AADSTS65004\b/.test(d) && (ours || body?.error_subcode === 'cancel')) {
    return new SignInError('admin_consent', ours
      ? `Microsoft stopped the sign-in. If it said "Need admin approval", your firm lets in only apps its Microsoft admin has approved: send your admin this link to approve 5dive's mail sign-in once, then connect again: ${adminConsentLink(clientId)} (if you tapped Cancel yourself, just connect again)`
      : `Microsoft stopped the sign-in. If it said "Need admin approval", the firm's app is missing your IT's consent for mail (docs/IT-GUIDE.md); if you tapped Cancel yourself, just connect again`, true)
  }
  const say: Record<string, string> = {
    authorization_declined: 'the sign-in was declined at Microsoft',
    access_denied: 'the sign-in was declined at Microsoft',
    expired_token: 'the code expired before the sign-in was finished',
    invalid_client: "Microsoft does not know this app id in this tenant (check --client-id and --tenant with your IT)",
    unauthorized_client: "the firm's app does not allow this sign-in: your IT turns on \"Allow public client flows\" (docs/IT-GUIDE.md)",
    invalid_grant: 'Microsoft wants the mailbox signed in again',
    interaction_required: 'Microsoft wants the mailbox signed in again',
    consent_required: "the firm's app is missing your IT's consent for mail (docs/IT-GUIDE.md)",
  }
  // AADSTS530035 = Microsoft's security defaults refuse the device-code sign-in: the link works there.
  if (/AADSTS530035/.test(d)) return new SignInError(err, "Microsoft's security defaults block this kind of sign-in in your firm. Run the same connect without --device-code: it gives a sign-in link instead", true)
  // AADSTS50011 = the app has no redirect for the link.
  if (/AADSTS50011/.test(d)) return new SignInError(err, `the firm's app does not allow the sign-in link yet: your IT adds the redirect ${REDIRECT} under "Mobile and desktop applications" (docs/IT-GUIDE.md)`, true)
  // AADSTS7000218 = the app is not a public client: same fix as unauthorized_client.
  const why = /AADSTS7000218/.test(d) ? say.unauthorized_client : say[err] ?? `Microsoft refused the sign-in (${err})`
  return new SignInError(err, d && !say[err] ? `${why}: ${d}` : why, DEAD.has(err) || err in say)
}

/**
 * A live access token for the mailbox. Keeps one in memory until two minutes
 * before it runs out; a new refresh token from Microsoft goes to `keep` at once
 * (it is the only one that will work from then on).
 */
export function tokenSource(o: OAuth, keep: (refreshToken: string) => void, scope = SCOPE) {
  let cur: { token: string; until: number } | null = null
  let inflight: Promise<{ token: string; until: number }> | null = null
  const refresh = async () => {
    const { body, err } = await post(o.tenant, 'token', {
      client_id: o.client_id, grant_type: 'refresh_token', refresh_token: o.refresh_token, scope,
    })
    if (err) throw scope === SCOPE ? explain(err, body, o.client_id) : filesRefused(err, body, o.client_id, scope)
    if (body.refresh_token && body.refresh_token !== o.refresh_token) {
      o.refresh_token = body.refresh_token
      keep(body.refresh_token)
    }
    return { token: String(body.access_token), until: Date.now() + (Number(body.expires_in) || 3600) * 1000 }
  }
  return {
    async get(): Promise<{ token: string; until: number }> {
      if (cur && cur.until - 120_000 > Date.now()) return cur
      inflight ??= refresh().finally(() => { inflight = null })
      cur = await inflight
      return cur
    },
    /** Forget the token in memory (the server refused it). */
    drop() { cur = null },
  }
}


/** DIVE-9474: a Graph token refused. A mail sign-in that never asked for files, or a SharePoint
 *  the company's admin has not allowed, is not a dead mailbox: never "sign in again" for mail. */
export function filesRefused(err: string, body: any, clientId: string, scope: string): SignInError {
  const d = String(body?.error_description || '').replace(/\+/g, ' ').split('\n')[0].slice(0, 300)
  const sp = scope.includes(SITES_SCOPE)
  if (/AADSTS(65001|90094|90095|90008)\b/.test(d) || err === 'consent_required' || err === 'interaction_required') {
    return new SignInError('files_consent', sp
      ? `SharePoint is not allowed yet: your company's admin has to allow this once${clientId.toLowerCase() === fivediveApp() ? ` (${adminConsentLink(clientId, 'all')})` : ''}. OneDrive keeps working.`
      : "OneDrive is not turned on for this mailbox yet: the owner turns it on in the app (the agent's Email: \"use your OneDrive and SharePoint files\")", false)
  }
  return explain(err, body, clientId)
}

export type FilesCheck = { onedrive: boolean; sharepoint: boolean; refresh_token: string; message?: string }
/** After a files sign-in: can this refresh token reach OneDrive (and SharePoint)? Sends and changes nothing. */
export async function filesCheck(o: OAuth, ask: FilesAsk): Promise<FilesCheck> {
  const graph = (process.env.EMAIL_GRAPH_BASE || 'https://graph.microsoft.com/v1.0').replace(/\/+$/, '')
  const out: FilesCheck = { onedrive: false, sharepoint: false, refresh_token: o.refresh_token }
  const keep = (rt: string) => { out.refresh_token = rt }
  // A token is the consent proven. The read after it only adds a plain note: a new Microsoft 365
  // user's OneDrive does not exist until they open it once (Microsoft answers 404 until then).
  const probe = async (scope: string, path: string): Promise<string> => {
    const t = await tokenSource(o, keep, scope).get()
    const r = await fetch(`${graph}${path}`, { headers: { authorization: `Bearer ${t.token}` }, signal: AbortSignal.timeout(20_000) }).catch(() => null)
    return !r ? 'Microsoft did not answer the first look; it may work in a minute' : r.ok ? '' : r.status === 404 && path.startsWith('/me/drive') ? 'OneDrive is not set up for this mailbox yet: sign in once at onedrive.com as this mailbox, then it works' : `Microsoft answered ${r.status} to the first look`
  }
  try { const note = await probe(graphScope(false), '/me/drive?$select=id'); out.onedrive = true; if (note) out.message = note } catch (e) { out.message = (e as Error).message; return out }
  if (ask === 'all') {
    try { const note = await probe(graphScope(true), '/sites?search=*&$top=1&$select=id'); out.sharepoint = !note || !/answered 40[13]/.test(note); if (note && !out.message) out.message = note } catch (e) { out.message = (e as Error).message }
  }
  return out
}

// ── DIVE-9120: does the mailbox let mail in and out with this sign-in? ────────
// Microsoft takes the sign-in even when IMAP or Authenticated SMTP is turned
// off for the mailbox (or, under security defaults, for the whole firm), and the
// agent would then sit connected and deaf. So connect logs in once to each with
// the new token, sends nothing, and says in plain words which switch is off.
export type Box = { host: string; port: number; secure: boolean }
export type CheckIn = { access_token: string; user: string; consumer?: boolean; imap: Box; smtp: Box }
export type CheckOut = { ok: true } | { ok: false; error: 'imap_off' | 'imap_not_ready' | 'smtp_off' | 'unreachable'; message: string }

function reader(sock: Socket) {
  let buf = '', ended = false, wake: (() => void) | null = null
  const poke = () => { const w = wake; wake = null; w?.() }
  sock.on('data', d => { buf += d.toString('latin1'); poke() })
  sock.on('close', () => { ended = true; poke() })
  sock.on('error', () => { ended = true; poke() })
  return async (done: (b: string) => boolean, ms = 15_000): Promise<string> => {
    const until = Date.now() + ms
    for (;;) {
      if (done(buf)) { const b = buf; buf = ''; return b }
      if (ended) throw new Error('the connection closed')
      if (Date.now() > until) throw new Error('no answer')
      await new Promise<void>(r => { wake = r; setTimeout(r, 250) })
    }
  }
}
// Test stand-ins speak plain TCP (EMAIL_MS_CHECK_PLAIN=1); Microsoft never does.
const plain = () => process.env.EMAIL_MS_CHECK_PLAIN === '1'
function open(b: Box): Promise<Socket> {
  return new Promise((ok, no) => {
    const s = b.secure && !plain() ? tlsConnect({ host: b.host, port: b.port, servername: b.host }) : netConnect({ host: b.host, port: b.port })
    s.setTimeout(20_000, () => s.destroy(new Error('no answer')))
    s.once(b.secure && !plain() ? 'secureConnect' : 'connect', () => ok(s))
    s.once('error', no)
  })
}
const sasl = (user: string, token: string) => Buffer.from(`user=${user}\x01auth=Bearer ${token}\x01\x01`).toString('base64')
const lastLine = (b: string) => b.trimEnd().split('\r\n').pop() ?? ''
const smtpDone = (b: string) => b.endsWith('\r\n') && /^\d{3} /.test(lastLine(b))

// DIVE-9314 (live): for up to an hour after a licence is added, Exchange takes the
// sign-in but answers "User is authenticated but not connected." The mailbox is
// not turned off, it is not ready yet.
const NOT_READY = /authenticated but not connected/i

/** IMAP: '' = logged in and the inbox opens, else the server's refusal; throws = could not ask. */
async function imapLogin(c: CheckIn): Promise<string> {
  const s = await open(c.imap)
  try {
    const read = reader(s)
    const tagged = (t: string) => (b: string) => new RegExp(`^${t} `, 'm').test(b) && b.endsWith('\r\n')
    await read(b => /^\* (OK|PREAUTH)/m.test(b))
    s.write(`c1 AUTHENTICATE XOAUTH2 ${sasl(c.user, c.access_token)}\r\n`)
    let r = await read(b => /^(c1 |\+)/m.test(b) && b.endsWith('\r\n'))
    if (/^\+/m.test(r)) { s.write('\r\n'); r = await read(tagged('c1')) } // the error challenge, answered empty
    if (!/^c1 OK/m.test(r)) return (NOT_READY.test(r) ? r.match(NOT_READY)![0] : lastLine(r)).slice(0, 200) || 'refused'
    // Exchange says "not connected" only to the first command after the sign-in.
    s.write('c2 EXAMINE INBOX\r\n'); r = await read(tagged('c2'))
    if (NOT_READY.test(r)) return r.match(NOT_READY)![0]
    if (!/^c2 OK/m.test(r)) throw new Error(`the inbox did not open: ${lastLine(r).slice(0, 100)}`)
    s.write('c3 LOGOUT\r\n')
    return ''
  } finally { setTimeout(() => s.destroy(), 200) }
}

/** SMTP: '' = logged in, else the server's refusal line; throws = could not ask. */
async function smtpLogin(c: CheckIn): Promise<string> {
  let s = await open(c.smtp)
  try {
    let read = reader(s)
    await read(smtpDone)
    s.write('EHLO 5dive\r\n'); let r = await read(smtpDone)
    if (!c.smtp.secure && !plain()) {
      s.write('STARTTLS\r\n'); r = await read(smtpDone)
      if (!/^220/.test(lastLine(r))) throw new Error(`no STARTTLS: ${lastLine(r)}`)
      s.removeAllListeners('data')
      const raw = s
      s = await new Promise<Socket>((ok, no) => { const t = tlsConnect({ socket: raw, servername: c.smtp.host }, () => ok(t)); t.once('error', no) })
      read = reader(s)
      s.write('EHLO 5dive\r\n'); await read(smtpDone)
    }
    s.write(`AUTH XOAUTH2 ${sasl(c.user, c.access_token)}\r\n`); r = await read(smtpDone)
    if (/^334/.test(lastLine(r))) { s.write('\r\n'); r = await read(smtpDone) }
    if (/^235/.test(lastLine(r))) { s.write('QUIT\r\n'); return '' }
    return lastLine(r).slice(0, 200)
  } finally { const t = s; setTimeout(() => t.destroy(), 200) }
}

export async function mailCheck(c: CheckIn): Promise<CheckOut> {
  const where = c.consumer
    ? 'in Outlook.com: Settings > Mail > Forwarding and IMAP > Let devices and apps use IMAP'
    : `in the Microsoft 365 admin center: Users > Active users > ${c.user} > Mail > Manage email apps`
  let step = 'IMAP'
  try {
    const refused = await imapLogin(c)
    if (NOT_READY.test(refused)) {
      return { ok: false, error: 'imap_not_ready', message: `Microsoft let ${c.user} sign in, but is still setting up this mailbox (common for up to an hour after a licence is added). Nothing is wrong on your side: connect again in an hour` }
    }
    if (refused) {
      return { ok: false, error: 'imap_off', message: c.consumer
        ? `Outlook.com let ${c.user} sign in, but reading mail by IMAP is turned off for it. Turn it on ${where}, then connect again`
        : `Microsoft let ${c.user} sign in, but IMAP is turned off for this mailbox. Your Microsoft admin ticks IMAP and Authenticated SMTP ${where}, then connect again` }
    }
    step = 'SMTP'
    const no = await smtpLogin(c)
    if (no) {
      return { ok: false, error: 'smtp_off', message: c.consumer
        ? `Outlook.com let ${c.user} read mail, but refused sending (${no}). Check ${where}, then connect again`
        : `Microsoft let ${c.user} read mail, but sending is turned off for this mailbox (Authenticated SMTP). Your Microsoft admin ticks Authenticated SMTP ${where} (if it is off for the whole firm: Exchange admin center > Settings > Mail flow); it can take 30 minutes to work. Then connect again` }
    }
    return { ok: true }
  } catch (e) {
    return { ok: false, error: 'unreachable', message: `could not check ${step} at ${step === 'IMAP' ? c.imap.host : c.smtp.host} (${String((e as Error)?.message ?? e).slice(0, 120)})` }
  }
}

// ── CLI: `bun msauth.ts link <tenant> <client_id> <address>` / `bun msauth.ts redeem <pending.json>` (pasted address on stdin)
//        device code: `bun msauth.ts start <tenant> <client_id> <address>` / `bun msauth.ts poll <pending.json> <wait seconds>`
//        mail check: `bun msauth.ts check` (CheckIn JSON on stdin; exit 0 ok, 1 refused, 75 could not ask)
//        files check (DIVE-9474): `bun msauth.ts files-check` ({tenant,client_id,refresh_token,ask} on stdin) ──
// One JSON line on stdout; exit 0 done/started, 75 still waiting, 1 refused.
if (import.meta.main) {
  const [verb, ...a] = process.argv.slice(2)
  const out = (o: unknown) => process.stdout.write(JSON.stringify(o) + '\n')
  try {
    if (verb === 'start') {
      const [tenant, clientId, address] = a
      if (!tenantOk(tenant) || !clientIdOk(clientId) || !address) throw new SignInError('usage', 'usage: start <tenant> <client_id> <address>', true)
      out(await deviceStart(tenant, clientId, address))
    } else if (verb === 'poll') {
      const p: Pending = JSON.parse(await Bun.file(a[0]).text())
      const d = await devicePoll(p, Math.max(0, Number(a[1]) || 0) * 1000)
      if (!d) { out({ pending: true, user_code: p.user_code, link: p.link, expires_at: p.expires_at }); process.exit(75) }
      out({ refresh_token: d.refresh_token, access_token: d.access_token, who: d.who, consumer: d.consumer })
    } else if (verb === 'link') {
      const [tenant, clientId, address, f] = a
      const files = f === '--files=all' ? 'all' : f === '--files=onedrive' ? 'onedrive' : undefined
      if (!tenantOk(tenant) || !clientIdOk(clientId) || !address || (f !== undefined && !files)) throw new SignInError('usage', 'usage: link <tenant> <client_id> <address> [--files=all|onedrive]', true)
      out(linkStart(tenant, clientId, address, files))
    } else if (verb === 'files-check') {
      // DIVE-9474: {tenant, client_id, refresh_token, ask} on stdin; the refresh token Microsoft may rotate comes back.
      const i = JSON.parse(await new Response(Bun.stdin.stream()).text())
      out(await filesCheck({ provider: 'microsoft', tenant: i.tenant, client_id: i.client_id, refresh_token: i.refresh_token }, i.ask === 'all' ? 'all' : 'onedrive'))
    } else if (verb === 'redeem') {
      // The pasted address comes on stdin, never in argv.
      const p: LinkPending = JSON.parse(await Bun.file(a[0]).text())
      const d = await linkRedeem(p, await new Response(Bun.stdin.stream()).text())
      out({ refresh_token: d.refresh_token, access_token: d.access_token, who: d.who, consumer: d.consumer })
    } else if (verb === 'check') {
      const r = await mailCheck(JSON.parse(await new Response(Bun.stdin.stream()).text()))
      out(r)
      if (!r.ok) process.exit(r.error === 'unreachable' ? 75 : 1)
    } else {
      throw new SignInError('usage', 'usage: msauth.ts start|poll|link|redeem …', true)
    }
  } catch (e) {
    const se = e instanceof SignInError ? e : new SignInError('unreachable', `Microsoft's sign-in did not answer (${String(e).slice(0, 200)})`, false)
    out({ error: se.code, message: se.message, again: se.again })
    process.exit(1)
  }
}
