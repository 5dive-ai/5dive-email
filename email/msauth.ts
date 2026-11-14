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

/** login.microsoftonline.com, or a stand-in in tests. */
import { clientIdOk, tenantOk, type OAuth } from './mail.ts'
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

/** The address Microsoft signed in, read from the id_token (shown, compared; never used for access). */
export function signedInAs(idToken: unknown): string {
  try {
    const part = String(idToken).split('.')[1]
    const claims = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'))
    return String(claims.preferred_username || claims.email || claims.upn || '').toLowerCase()
  } catch {
    return ''
  }
}

export type Pending = { tenant: string; client_id: string; address: string; device_code: string; user_code: string; link: string; interval: number; expires_at: number }

/** Step 1: Microsoft's code for a person to type at the link. */
export async function deviceStart(tenant: string, clientId: string, address: string): Promise<Pending> {
  const { body, err } = await post(tenant, 'devicecode', { client_id: clientId, scope: SCOPE })
  if (err) throw explain(err, body)
  return {
    tenant, client_id: clientId, address,
    device_code: String(body.device_code), user_code: String(body.user_code),
    link: String(body.verification_uri || 'https://microsoft.com/devicelogin'),
    interval: Math.max(1, Number(body.interval) || 5),
    expires_at: Date.now() + (Number(body.expires_in) || 900) * 1000,
  }
}

export type Done = { refresh_token: string; access_token: string; expires_at: number; who: string }

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
      return { refresh_token: body.refresh_token, access_token: body.access_token, expires_at: Date.now() + (Number(body.expires_in) || 3600) * 1000, who: signedInAs(body.id_token) }
    }
    if (err === 'slow_down') interval += 5000
    else if (err !== 'authorization_pending') throw explain(err, body)
    if (Date.now() + interval > deadline) {
      if (Date.now() + interval > p.expires_at) throw new SignInError('expired_token', 'the code expired before the sign-in was finished', true)
      return undefined
    }
    await sleep(interval)
  }
}

function explain(err: string, body: any): SignInError {
  const d = String(body?.error_description || '').split('\n')[0].slice(0, 300)
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
  // AADSTS7000218 = the app is not a public client: same fix as unauthorized_client.
  const why = /AADSTS7000218/.test(d) ? say.unauthorized_client : say[err] ?? `Microsoft refused the sign-in (${err})`
  return new SignInError(err, d && !say[err] ? `${why}: ${d}` : why, DEAD.has(err) || err in say)
}

/**
 * A live access token for the mailbox. Keeps one in memory until two minutes
 * before it runs out; a new refresh token from Microsoft goes to `keep` at once
 * (it is the only one that will work from then on).
 */
export function tokenSource(o: OAuth, keep: (refreshToken: string) => void) {
  let cur: { token: string; until: number } | null = null
  let inflight: Promise<{ token: string; until: number }> | null = null
  const refresh = async () => {
    const { body, err } = await post(o.tenant, 'token', {
      client_id: o.client_id, grant_type: 'refresh_token', refresh_token: o.refresh_token, scope: SCOPE,
    })
    if (err) throw explain(err, body)
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

// ── CLI: `bun msauth.ts start <tenant> <client_id> <address>` / `bun msauth.ts poll <pending.json> <wait seconds>` ──
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
      out({ refresh_token: d.refresh_token, who: d.who })
    } else {
      throw new SignInError('usage', 'usage: msauth.ts start|poll …', true)
    }
  } catch (e) {
    const se = e instanceof SignInError ? e : new SignInError('unreachable', `Microsoft's sign-in did not answer (${String(e).slice(0, 200)})`, false)
    out({ error: se.code, message: se.message, again: se.again })
    process.exit(1)
  }
}
