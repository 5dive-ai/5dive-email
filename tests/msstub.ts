// tests/msstub.ts — stand-ins for Microsoft 365, for the DIVE-8407 tests. No
// network beyond loopback, no dependencies (node builtins and Bun only).
//
//   identity(): Microsoft's sign-in (login.microsoftonline.com/<tenant>/oauth2/v2.0
//               devicecode + token), device-code, sign-in-link (code + PKCE) and refresh-token grants, with
//               refresh-token rotation as Microsoft does it (the old one dies).
//   imap():     Exchange Online's IMAP, the part the channel uses: AUTHENTICATE
//               XOAUTH2 (SASL-IR) with a token the identity stand-in issued,
//               SELECT, UID FETCH, UID STORE, IDLE, LOGOUT. append() delivers a mail.
//
// Run alone (`bun tests/msstub.ts <port>`) it serves only the identity part,
// for tests/cli.sh. POST /_ctl {json} changes its behaviour; GET /_log reads it.

import { createServer, type Socket } from 'node:net'

export type Ctl = {
  /** preferred_username in the id_token = who signed in. */
  who: string
  /** Each device code answers authorization_pending to this many polls, then the sign-in completes. */
  pending: number
  /** Answer every device-code poll with this error (e.g. authorization_declined). */
  error?: string
  /** Seconds an access token lives. */
  expires_in: number
  /** Every refresh token is refused (invalid_grant): the sign-in was revoked. */
  dead: boolean
  /** devicecode answers this error (e.g. unauthorized_client with AADSTS7000218). */
  start_error?: string
  /** The sign-in link (DIVE-8407): the one code Microsoft put in the page address, and the PKCE challenge from that link. */
  code?: string
  challenge?: string
  /** The code grant answers this error (e.g. invalid_grant: used or expired). */
  code_error?: string
  /** DIVE-9120: the id_token's tenant (the personal-account tenant = an Outlook.com mailbox). */
  tid?: string
  /** DIVE-9120: the mailbox has IMAP / Authenticated SMTP turned off (run-alone mail stand-ins). */
  imap_off?: boolean
  smtp_off?: boolean
  /** DIVE-9314: a freshly licensed mailbox: the sign-in is taken, the next command gets "User is authenticated but not connected." */
  imap_not_ready?: boolean
  /** DIVE-9474: refresh for the SharePoint permission is refused (the company's admin has not allowed it). */
  sites_refused?: boolean
  /** DIVE-9474: refresh for any Graph (files) permission is refused (never consented). */
  files_refused?: boolean
}

const b64u = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')

export function identity(port = 0) {
  const ctl: Ctl = { who: '', pending: 1, expires_in: 3600, dead: false }
  const log: { path: string; tenant: string; fields: Record<string, string> }[] = []
  const access = new Map<string, number>() // token -> expires (ms)
  const refresh = new Set<string>()
  let n = 0
  const devices = new Map<string, { polls: number; client: string; tenant: string }>()
  const issue = (withId: boolean) => {
    n++
    const at = `at-${n}`, rt = `rt-${n}`
    access.set(at, Date.now() + ctl.expires_in * 1000)
    refresh.add(rt)
    return {
      token_type: 'Bearer', access_token: at, refresh_token: rt, expires_in: ctl.expires_in,
      scope: 'https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send',
      ...(withId ? { id_token: `${b64u({ alg: 'none' })}.${b64u({ preferred_username: ctl.who, tid: ctl.tid || 't' })}.` } : {}),
    }
  }
  const err = (error: string, d = '') => Response.json({ error, error_description: d }, { status: 400 })
  const server = Bun.serve({
    port, hostname: '127.0.0.1',
    async fetch(req) {
      const u = new URL(req.url)
      if (u.pathname === '/_ctl') { Object.assign(ctl, await req.json()); return Response.json(ctl) }
      if (u.pathname === '/_log') return Response.json(log)
      // DIVE-9474: the two Graph reads the files check makes, with a token this stand-in issued.
      if (u.pathname.startsWith('/v1.0/')) {
        const tok = (req.headers.get('authorization') ?? '').replace(/^Bearer /, '')
        log.push({ path: `graph ${u.pathname}`, tenant: '', fields: { search: u.search } })
        if ((access.get(tok) ?? 0) <= Date.now()) return Response.json({ error: { code: 'InvalidAuthenticationToken', message: 'expired' } }, { status: 401 })
        if (u.pathname === '/v1.0/me/drive') return Response.json({ id: 'b!own' })
        if (u.pathname === '/v1.0/sites') return Response.json({ value: [{ id: 's1' }] })
        return Response.json({ error: { code: 'itemNotFound', message: 'item not found' } }, { status: 404 })
      }
      const m = u.pathname.match(/^\/([^/]+)\/oauth2\/v2\.0\/(devicecode|token)$/)
      if (!m || req.method !== 'POST') return new Response('not found', { status: 404 })
      const fields = Object.fromEntries(new URLSearchParams(await req.text()))
      const tenant = decodeURIComponent(m[1])
      log.push({ path: m[2], tenant, fields })
      if (m[2] === 'devicecode') {
        if (ctl.start_error) return err(ctl.start_error, 'AADSTS7000218: The request body must contain client_assertion or client_secret.')
        const dc = `dc-${++n}`
        devices.set(dc, { polls: 0, client: fields.client_id, tenant })
        return Response.json({ device_code: dc, user_code: 'K7QZ-4MPL', verification_uri: 'https://microsoft.com/devicelogin', expires_in: 900, interval: 1, message: '…' })
      }
      if (fields.grant_type === 'urn:ietf:params:oauth:grant-type:device_code') {
        const d = devices.get(fields.device_code)
        if (!d || d.client !== fields.client_id || d.tenant !== tenant) return err('invalid_grant')
        if (ctl.error) return err(ctl.error)
        // Read live, so a test can let the person finish signing in at any point.
        if (++d.polls <= ctl.pending) return err('authorization_pending')
        devices.delete(fields.device_code)
        return Response.json(issue(true))
      }
      if (fields.grant_type === 'authorization_code') {
        if (ctl.code_error) return err(ctl.code_error, 'AADSTS70008: The provided authorization code or refresh token has expired.')
        if (fields.redirect_uri !== 'https://login.microsoftonline.com/common/oauth2/nativeclient') return err('invalid_request', 'AADSTS50011: The redirect URI does not match.')
        if (!ctl.code || fields.code !== ctl.code) return err('invalid_grant', 'AADSTS9002313: Invalid request. Request is malformed or invalid.')
        const sum = new Bun.CryptoHasher('sha256').update(fields.code_verifier ?? '').digest('base64url')
        if (!ctl.challenge || sum !== ctl.challenge) return err('invalid_grant', 'AADSTS501481: The Code_Verifier does not match the code_challenge supplied in the authorization request.')
        ctl.code = undefined // a code works once
        return Response.json(issue(true))
      }
      if (fields.grant_type === 'refresh_token') {
        if (ctl.dead || !refresh.has(fields.refresh_token)) return err('invalid_grant', 'AADSTS50173: The provided grant has expired due to it being revoked.')
        if (ctl.files_refused && /graph\.microsoft\.com/.test(fields.scope ?? '')) return err('invalid_grant', 'AADSTS65001: The user or administrator has not consented to use the application.')
        if (ctl.sites_refused && /Sites\./.test(fields.scope ?? '')) return err('invalid_grant', 'AADSTS65001: The user or administrator has not consented to use the application.')
        refresh.delete(fields.refresh_token) // rotation: the old one is spent
        return Response.json(issue(false))
      }
      return err('unsupported_grant_type')
    },
  })
  return {
    url: `http://127.0.0.1:${server.port}`, ctl, log, server,
    /** Is this a live access token, and for whom? (the XOAUTH2 check) */
    valid: (token: string) => (access.get(token) ?? 0) > Date.now(),
    stop: () => server.stop(true),
  }
}

/** Exchange Online's IMAP, minimal. `ok(user, token)` decides the XOAUTH2 login. */
export function imap(ok: (user: string, token: string) => boolean, notReady: () => boolean = () => false) {
  const mails: { uid: number; raw: Buffer; seen: boolean }[] = []
  // Every open session and how many mails it has been told of. As a real
  // server does, a session learns of new mail at once while it IDLEs, else in
  // front of its next command's answer (or when it starts IDLE).
  const sessions = new Map<Socket, { known: number; idling: boolean }>()
  const auths: { user: string; token: string; ok: boolean }[] = []
  let nextUid = 1
  const server = createServer(sock => {
    let buf = ''
    let idleTag = ''
    let authed = false
    const w = (s: string | Buffer) => { if (!sock.destroyed) sock.write(s) }
    w('* OK [CAPABILITY IMAP4rev1 AUTH=XOAUTH2 SASL-IR IDLE UIDPLUS] Microsoft Exchange stand-in ready.\r\n')
    const me = { known: 0, idling: false }
    sessions.set(sock, me)
    const tellNew = () => { if (me.known < mails.length) { me.known = mails.length; w(`* ${mails.length} EXISTS\r\n`) } }
    sock.on('close', () => sessions.delete(sock))
    sock.on('error', () => {})
    sock.on('data', d => {
      buf += d.toString('latin1')
      let i: number
      while ((i = buf.indexOf('\r\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 2)
        if (idleTag) {
          if (line.trim().toUpperCase() === 'DONE') { w(`${idleTag} OK IDLE completed.\r\n`); idleTag = ''; me.idling = false }
          continue
        }
        const [tag, cmd0, ...rest] = line.split(' ')
        const cmd = (cmd0 || '').toUpperCase()
        const args = rest.join(' ')
        if (cmd === 'CAPABILITY') { w(`* CAPABILITY IMAP4rev1 AUTH=XOAUTH2 SASL-IR IDLE UIDPLUS\r\n${tag} OK CAPABILITY completed.\r\n`); continue }
        if (cmd === 'AUTHENTICATE') {
          const [mech, ir] = rest
          const s = Buffer.from(ir || '', 'base64').toString()
          const user = s.match(/user=([^\x01]*)/)?.[1] ?? ''
          const token = s.match(/auth=Bearer ([^\x01]*)/)?.[1] ?? ''
          const good = mech?.toUpperCase() === 'XOAUTH2' && ok(user, token)
          auths.push({ user, token, ok: good })
          if (good) { authed = true; w(`${tag} OK AUTHENTICATE completed.\r\n`) } else w(`${tag} NO AUTHENTICATE failed.\r\n`)
          continue
        }
        if (cmd === 'LOGIN') { w(`${tag} NO LOGIN failed.\r\n`); continue } // basic auth is off at Microsoft
        if (cmd === 'LOGOUT') { w(`* BYE Microsoft Exchange Server IMAP4 server signing off.\r\n${tag} OK LOGOUT completed.\r\n`); sock.end(); continue }
        if (!authed) { w(`${tag} BAD Command received in Invalid state.\r\n`); continue }
        if (notReady()) { w(`${tag} BAD User is authenticated but not connected.\r\n`); continue }
        if (cmd === 'SELECT' || cmd === 'EXAMINE') {
          me.known = mails.length
          w(`* ${mails.length} EXISTS\r\n* 0 RECENT\r\n* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n* OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)] Permanent flags\r\n* OK [UIDVALIDITY 14]\r\n* OK [UIDNEXT ${nextUid}]\r\n${tag} OK [READ-WRITE] ${cmd} completed.\r\n`)
          continue
        }
        if (cmd === 'IDLE') { idleTag = tag; me.idling = true; w('+ IDLE accepted, awaiting DONE command.\r\n'); tellNew(); continue }
        tellNew()
        if (cmd === 'UID') {
          const [sub, set] = rest
          const [lo, hi] = set.split(':')
          const from = Number(lo), to = hi === '*' ? Infinity : Number(hi ?? lo)
          // RFC 3501: n:* always includes the last message, even below n.
          let hits = mails.filter(m => m.uid >= from && m.uid <= to)
          if (!hits.length && hi === '*' && mails.length) hits = [mails[mails.length - 1]]
          if (sub.toUpperCase() === 'FETCH') {
            for (const m of hits) {
              const seq = mails.indexOf(m) + 1
              w(`* ${seq} FETCH (UID ${m.uid} FLAGS (${m.seen ? '\\Seen' : ''}) BODY[] {${m.raw.length}}\r\n`); w(m.raw); w(')\r\n')
            }
            w(`${tag} OK FETCH completed.\r\n`)
          } else if (sub.toUpperCase() === 'STORE') {
            for (const m of hits) if (/\\Seen/i.test(args)) m.seen = true
            w(`${tag} OK STORE completed.\r\n`)
          } else w(`${tag} OK ${sub} completed.\r\n`)
          continue
        }
        w(`${tag} OK ${cmd} completed.\r\n`)
      }
    })
  })
  return {
    server, mails, auths,
    listen: () => new Promise<number>(r => server.listen(0, '127.0.0.1', () => r((server.address() as any).port))),
    append(raw: string) {
      mails.push({ uid: nextUid++, raw: Buffer.from(raw.replace(/\r?\n/g, '\r\n')), seen: false })
      for (const [s, st] of sessions) if (st.idling) { st.known = mails.length; s.write(`* ${mails.length} EXISTS\r\n`) }
    },
    /** Every open session ends, as Exchange does when the token runs out. */
    kick() { for (const s of sessions.keys()) s.destroy() },
    stop: () => server.close(),
  }
}

/** DIVE-9120: Exchange Online's SMTP submission, just EHLO + AUTH XOAUTH2 + QUIT (plain TCP). */
export function smtp(ok: (user: string, token: string) => boolean, off: () => boolean) {
  const server = createServer(sock => {
    let buf = ''
    const w = (t: string) => { if (!sock.destroyed) sock.write(t) }
    sock.on('error', () => {})
    w('220 Microsoft ESMTP stand-in ready\r\n')
    sock.on('data', d => {
      buf += d.toString('latin1')
      let i: number
      while ((i = buf.indexOf('\r\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 2)
        const [cmd, mech, ir] = line.split(' ')
        const c = (cmd || '').toUpperCase()
        if (c === 'EHLO') w('250-stand-in Hello\r\n250-SIZE 157286400\r\n250 AUTH LOGIN XOAUTH2\r\n')
        else if (c === 'AUTH' && (mech || '').toUpperCase() === 'XOAUTH2') {
          const s = Buffer.from(ir || '', 'base64').toString()
          const good = ok(s.match(/user=([^\x01]*)/)?.[1] ?? '', s.match(/auth=Bearer ([^\x01]*)/)?.[1] ?? '')
          if (off()) w('535 5.7.139 Authentication unsuccessful, SmtpClientAuthentication is disabled for the Tenant.\r\n')
          else w(good ? '235 2.7.0 Authentication successful\r\n' : '535 5.7.3 Authentication unsuccessful\r\n')
        } else if (c === 'QUIT') { w('221 2.0.0 Service closing\r\n'); sock.end() }
        else w('502 5.3.3 Command not implemented\r\n')
      }
    })
  })
  return { server, listen: () => new Promise<number>(r => server.listen(0, '127.0.0.1', () => r((server.address() as any).port))) }
}

if (import.meta.main) {
  // One line: the identity URL, then (DIVE-9120) the IMAP and SMTP stand-ins' ports.
  const id = identity(Number(process.argv[2]) || 0)
  const im = imap((_u, t) => id.valid(t) && !id.ctl.imap_off, () => !!id.ctl.imap_not_ready)
  const sm = smtp((_u, t) => id.valid(t), () => !!id.ctl.smtp_off)
  console.log(`${id.url} ${await im.listen()} ${await sm.listen()}`)
}
