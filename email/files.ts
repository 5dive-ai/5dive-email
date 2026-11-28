// email/files.ts — the owner's OneDrive and SharePoint files, for the agent whose
// Microsoft mailbox is connected (DIVE-9474).
//
// Same 5dive Microsoft app and same sign-in as the Outlook mailbox: the owner
// turns it on once (`5dive email files <agent> on`, the app's switch), Microsoft
// asks for the added permission, and the mailbox's refresh token then also gets
// Microsoft Graph tokens. Read on demand only: nothing is synced or copied onto
// the box. A file the agent asks to read is fetched, turned into text here, and
// handed back; only a PDF on a box with no `pdftotext` (or a file that is not
// text at all) is written to a short-lived file for the agent's own Read tool.
//
// Loaded by server.ts only (never by mail.ts: that file is copied alone to the
// box's mail server, community wiki a-plugin-file-copied-alone-must-not-import…).

import { inflateRawSync } from 'node:zlib'
import { mkdirSync, readdirSync, rmSync, statSync, writeFileSync, readFileSync } from 'node:fs'
import { join, extname } from 'node:path'

export const MAX_READ = 25 * 1024 * 1024
export const MAX_TEXT = 200_000
const SIMPLE_PUT = 4 * 1024 * 1024
const CHUNK = 320 * 1024 * 12 // Microsoft wants upload pieces in multiples of 320 KiB

export type FilesMode = 'off' | 'onedrive' | 'onedrive_sharepoint'
export const filesMode = (v: unknown): FilesMode => (v === 'onedrive' || v === 'onedrive_sharepoint' ? v : 'off')

export class FilesError extends Error {}

/** A token for Graph: `sharepoint` asks for the SharePoint permission too. */
export type GraphToken = (sharepoint: boolean) => Promise<string>

export const graphBase = () => (process.env.EMAIL_GRAPH_BASE || 'https://graph.microsoft.com/v1.0').replace(/\/+$/, '')

const ADMIN = "SharePoint is not allowed for this agent yet: your company's admin has to allow it once (the owner turns the switch on again and sends the admin the link it gives). OneDrive keeps working."

async function call(tok: GraphToken, sharepoint: boolean, method: string, path: string, body?: unknown): Promise<any> {
  const r = await fetch(`${graphBase()}${path}`, {
    method,
    headers: { authorization: `Bearer ${await tok(sharepoint)}`, ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(60_000),
  })
  if (r.ok) return r.status === 204 ? {} : r.json()
  let msg = ''
  try { msg = String((await r.json())?.error?.message ?? '') } catch {}
  throw new FilesError(graphSays(r.status, msg, sharepoint))
}

/** Microsoft's refusal, in words an agent can pass on as they are. */
export function graphSays(status: number, msg: string, sharepoint: boolean): string {
  if ((status === 401 || status === 403) && sharepoint) return ADMIN
  if (status === 401) return 'Microsoft refused the sign-in for files: the owner turns the OneDrive switch on again in the app'
  if (status === 403) return `Microsoft says this account may not open that (${msg.slice(0, 120) || 'access denied'})`
  if (status === 404) return /mysite|not provisioned|drive/i.test(msg) && !msg.includes('item') ? 'OneDrive is not set up for this mailbox yet: sign in once at onedrive.com as this mailbox' : 'no such file or folder (list or search again for its ref)'
  if (status === 409) return 'a file with that name is already there'
  if (status === 429 || status === 503) return 'Microsoft is busy: try again in a minute'
  return `Microsoft answered ${status}${msg ? `: ${msg.slice(0, 160)}` : ''}`
}

// A file or folder is named by a ref "<driveId>:<itemId>" (from a list or a search), or in the
// owner's OneDrive by its path ("/Clients/Acme/offer.docx").
const REF_RE = /^([A-Za-z0-9!_.-]{3,200}):([A-Za-z0-9!_.-]{1,200})$/
export function itemPath(where: string): string {
  const w = where.trim()
  const m = REF_RE.exec(w)
  if (m) return m[2] === 'root' ? `/drives/${m[1]}/root` : `/drives/${m[1]}/items/${m[2]}`
  const p = w.replace(/^\/+|\/+$/g, '')
  if (!p) return '/me/drive/root'
  if (p.split('/').some(s => s === '..' || s === '.')) throw new FilesError('a path is the folder names from the top of OneDrive, like /Clients/Acme')
  return `/me/drive/root:/${p.split('/').map(encodeURIComponent).join('/')}:`
}
/** A ref is a SharePoint item when its drive is not the owner's own OneDrive. Unknown = treat as SharePoint. */
const onSharePoint = (where: string, ownDrive: string | undefined) => {
  const m = REF_RE.exec(where.trim())
  return !!m && m[1] !== ownDrive
}

export type Entry = { name: string; ref: string; folder: boolean; size?: number; modified?: string; where?: string; url?: string }
const entry = (i: any): Entry => ({
  name: String(i.name ?? ''),
  ref: `${i.parentReference?.driveId ?? i.driveId ?? ''}:${i.id}`,
  folder: !!i.folder,
  ...(i.size !== undefined && !i.folder ? { size: Number(i.size) } : {}),
  ...(i.lastModifiedDateTime ? { modified: String(i.lastModifiedDateTime) } : {}),
  ...(i.parentReference?.path ? { where: String(i.parentReference.path).replace(/^\/drives?(\/[^/]+)?\/root:?/, '') || '/' } : {}),
  ...(i.webUrl ? { url: String(i.webUrl) } : {}),
})
const SELECT = '$select=id,name,size,lastModifiedDateTime,folder,file,webUrl,parentReference'

export function makeFiles(tok: GraphToken, mode: () => FilesMode, opts: { tmpDir: string; pdftotext?: string | null }) {
  let own: string | undefined
  const ownDrive = async () => (own ??= String((await call(tok, false, 'GET', '/me/drive?$select=id')).id ?? ''))
  const need = (sp: boolean) => {
    const m = mode()
    if (m === 'off') throw new FilesError("the owner has not let you use their OneDrive and SharePoint files. They turn it on in the app: your Email > \"Let you use your OneDrive and SharePoint files\". Offer it when a file would help.")
    if (sp && m !== 'onedrive_sharepoint') throw new FilesError(ADMIN)
  }
  const spFor = async (where: string) => {
    if (!REF_RE.test(where.trim())) return false
    return onSharePoint(where, await ownDrive().catch(() => undefined))
  }

  return {
    async list(where = '/'): Promise<Entry[]> {
      const sp = await spFor(where)
      need(sp)
      const d = await call(tok, sp, 'GET', `${itemPath(where)}/children?${SELECT}&$top=200`)
      return (d.value ?? []).map(entry)
    },

    async search(q: string, everywhere: boolean): Promise<Entry[]> {
      const text = q.trim().slice(0, 200)
      if (!text) throw new FilesError('say what to look for')
      const sp = everywhere && mode() === 'onedrive_sharepoint'
      need(false)
      if (!sp) {
        const d = await call(tok, false, 'GET', `/me/drive/root/search(q='${encodeURIComponent(text.replace(/'/g, "''"))}')?${SELECT}&$top=25`)
        return (d.value ?? []).map(entry)
      }
      const d = await call(tok, true, 'POST', '/search/query', { requests: [{ entityTypes: ['driveItem'], query: { queryString: text }, from: 0, size: 25 }] })
      const hits = d.value?.[0]?.hitsContainers?.flatMap((c: any) => c.hits ?? []) ?? []
      return hits.map((h: any) => entry(h.resource ?? {}))
    },

    async sites(q: string): Promise<{ site: string; url?: string; libraries: { name: string; ref: string }[] }[]> {
      need(true)
      const s = await call(tok, true, 'GET', `/sites?search=${encodeURIComponent(q.trim() || '*')}&$top=10&$select=id,displayName,webUrl`)
      const out = []
      for (const site of (s.value ?? []).slice(0, 10)) {
        const d = await call(tok, true, 'GET', `/sites/${site.id}/drives?$select=id,name`).catch(() => ({ value: [] }))
        out.push({ site: String(site.displayName ?? site.id), ...(site.webUrl ? { url: String(site.webUrl) } : {}), libraries: (d.value ?? []).map((x: any) => ({ name: String(x.name), ref: `${x.id}:root` })) })
      }
      return out
    },

    async read(where: string): Promise<{ name: string; text?: string; path?: string; note?: string }> {
      const sp = await spFor(where)
      need(sp)
      // No $select here: Microsoft leaves the download address out of a $select answer (measured live, DIVE-9474).
      const meta = await call(tok, sp, 'GET', itemPath(where))
      if (meta.folder) throw new FilesError(`${meta.name} is a folder: list it instead`)
      if (Number(meta.size) > MAX_READ) throw new FilesError(`${meta.name} is ${Math.round(Number(meta.size) / 1048576)} MB: too big to read here (up to 25 MB)`)
      const url = meta['@microsoft.graph.downloadUrl']
      if (!url) throw new FilesError('Microsoft gave no way to download this file')
      // The download address is pre-signed: no token goes with it.
      const r = await fetch(url, { signal: AbortSignal.timeout(120_000) })
      if (!r.ok) throw new FilesError(graphSays(r.status, '', sp))
      const buf = Buffer.from(await r.arrayBuffer())
      return toText(String(meta.name), buf, opts)
    },

    async save(a: { folder?: string; name: string; text?: string; from_path?: string; overwrite?: boolean }): Promise<Entry> {
      const name = String(a.name ?? '').trim()
      if (!name || /[\/\\:*?"<>|]/.test(name) || name.length > 200) throw new FilesError('name is the file name alone, like offer-acme.docx (no folders, no / \\ : * ? " < > |)')
      const folder = String(a.folder ?? '/')
      const sp = await spFor(folder)
      need(sp)
      let body: Buffer
      if (a.from_path) {
        const st = statSync(a.from_path)
        if (!st.isFile()) throw new FilesError(`${a.from_path} is not a file`)
        if (st.size > 250 * 1024 * 1024) throw new FilesError('that file is over 250 MB')
        body = readFileSync(a.from_path)
      } else if (typeof a.text === 'string') {
        body = Buffer.from(a.text, 'utf8')
      } else throw new FilesError('give text, or from_path (a file on this server)')
      // Never write over the owner's file unless asked: Microsoft renames ours instead ("offer 1.docx").
      const conflict = a.overwrite ? 'replace' : 'rename'
      const base = itemPath(folder)
      const target = base.endsWith(':') ? `${base.slice(0, -1)}/${encodeURIComponent(name)}:` : `${base}:/${encodeURIComponent(name)}:`
      if (body.length <= SIMPLE_PUT) {
        const r = await fetch(`${graphBase()}${target}/content?@microsoft.graph.conflictBehavior=${conflict}`, {
          method: 'PUT', headers: { authorization: `Bearer ${await tok(sp)}`, 'content-type': 'application/octet-stream' }, body, signal: AbortSignal.timeout(120_000),
        })
        if (!r.ok) { let m = ''; try { m = String((await r.json())?.error?.message ?? '') } catch {} throw new FilesError(graphSays(r.status, m, sp)) }
        return entry(await r.json())
      }
      const s = await call(tok, sp, 'POST', `${target}/createUploadSession`, { item: { '@microsoft.graph.conflictBehavior': conflict } })
      let last: any = {}
      for (let at = 0; at < body.length; at += CHUNK) {
        const piece = body.subarray(at, Math.min(at + CHUNK, body.length))
        // The upload address is pre-signed: no token goes with it.
        const r = await fetch(s.uploadUrl, { method: 'PUT', headers: { 'content-range': `bytes ${at}-${at + piece.length - 1}/${body.length}` }, body: piece, signal: AbortSignal.timeout(120_000) })
        if (!r.ok) throw new FilesError(graphSays(r.status, '', sp))
        last = await r.json().catch(() => ({}))
      }
      return entry(last)
    },
  }
}

// ── turning a file into text ─────────────────────────────────────────────────

const TEXTISH = new Set(['.txt', '.md', '.csv', '.tsv', '.json', '.xml', '.html', '.htm', '.yaml', '.yml', '.log', '.eml', '.ini', '.rtf', '.ics', '.vcf'])

export async function toText(name: string, buf: Buffer, opts: { tmpDir: string; pdftotext?: string | null }): Promise<{ name: string; text?: string; path?: string; note?: string }> {
  const ext = extname(name).toLowerCase()
  const cap = (t: string) => t.length > MAX_TEXT ? { name, text: t.slice(0, MAX_TEXT), note: `cut at ${MAX_TEXT} characters of ${t.length}` } : { name, text: t }
  try {
    if (ext === '.docx' || ext === '.docm') return cap(docxText(unzip(buf, n => n === 'word/document.xml')))
    if (ext === '.xlsx' || ext === '.xlsm') return cap(xlsxText(unzip(buf, n => n === 'xl/sharedStrings.xml' || n === 'xl/workbook.xml' || /^xl\/worksheets\/sheet\d+\.xml$/.test(n))))
    if (ext === '.pptx') return cap(pptxText(unzip(buf, n => /^ppt\/slides\/slide\d+\.xml$/.test(n))))
  } catch (e) {
    throw new FilesError(`could not open ${name} (${(e as Error).message})`)
  }
  if (TEXTISH.has(ext) || (!ext && !buf.subarray(0, 4096).includes(0))) return cap(buf.toString('utf8'))
  if (ext === '.pdf' && opts.pdftotext) {
    const p = Bun.spawn([opts.pdftotext, '-layout', '-', '-'], { stdin: buf, stdout: 'pipe', stderr: 'ignore' })
    const t = await new Response(p.stdout).text()
    if ((await p.exited) === 0 && t.trim()) return cap(t)
  }
  // Not text we can make here: a short-lived file for the agent's own Read tool (it reads PDFs and images).
  mkdirSync(opts.tmpDir, { recursive: true, mode: 0o700 })
  sweep(opts.tmpDir)
  const path = join(opts.tmpDir, `${Date.now()}-${name.replace(/[^A-Za-z0-9._-]+/g, '_').slice(-80)}`)
  writeFileSync(path, buf, { mode: 0o600 })
  return { name, path, note: 'not plain text: Read this file now (it is deleted within the hour)' }
}

function sweep(dir: string, maxAge = 3600_000) {
  try {
    for (const f of readdirSync(dir)) {
      const p = join(dir, f)
      if (Date.now() - statSync(p).mtimeMs > maxAge) rmSync(p, { force: true })
    }
  } catch {}
}

/** The entries of a zip (Word, Excel and PowerPoint files are zips of XML) that `want` names. */
export function unzip(buf: Buffer, want: (name: string) => boolean): Map<string, string> {
  let eocd = -1
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65_557); i--) if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break }
  if (eocd < 0) throw new Error('not a zip file')
  const n = buf.readUInt16LE(eocd + 10)
  let at = buf.readUInt32LE(eocd + 16)
  const out = new Map<string, string>()
  for (let k = 0; k < n; k++) {
    if (buf.readUInt32LE(at) !== 0x02014b50) throw new Error('broken zip directory')
    const method = buf.readUInt16LE(at + 10), csize = buf.readUInt32LE(at + 20)
    const nlen = buf.readUInt16LE(at + 28), xlen = buf.readUInt16LE(at + 30), clen = buf.readUInt16LE(at + 32)
    const local = buf.readUInt32LE(at + 42)
    const name = buf.toString('utf8', at + 46, at + 46 + nlen)
    at += 46 + nlen + xlen + clen
    if (!want(name)) continue
    const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28)
    const raw = buf.subarray(start, start + csize)
    out.set(name, (method === 8 ? inflateRawSync(raw) : raw).toString('utf8'))
  }
  return out
}

const ENT: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" }
const unxml = (s: string) => s.replace(/<[^>]+>/g, '').replace(/&(#x?[0-9a-f]+|amp|lt|gt|quot|apos);/gi, (_, e: string) =>
  e[0] === '#' ? String.fromCodePoint(e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : Number(e.slice(1))) : ENT[e.toLowerCase()] ?? '')

export function docxText(z: Map<string, string>): string {
  const x = z.get('word/document.xml') ?? ''
  return unxml(x.replace(/<w:tab\/>/g, '\t').replace(/<w:br\/>/g, '\n').replace(/<\/w:p>/g, '\n').replace(/<\/w:tc>/g, '\t')).replace(/\n{3,}/g, '\n\n').trim()
}

export function xlsxText(z: Map<string, string>): string {
  const shared = [...(z.get('xl/sharedStrings.xml') ?? '').matchAll(/<si>([\s\S]*?)<\/si>/g)].map(m => unxml(m[1].replace(/<rPh[\s\S]*?<\/rPh>/g, '')))
  const names = [...(z.get('xl/workbook.xml') ?? '').matchAll(/<sheet [^>]*name="([^"]*)"/g)].map(m => unxml(m[1]))
  const sheets = [...z.keys()].filter(k => k.startsWith('xl/worksheets/')).sort((a, b) => Number(a.match(/\d+/)![0]) - Number(b.match(/\d+/)![0]))
  return sheets.map((k, i) => {
    const rows = [...z.get(k)!.matchAll(/<row[^>]*>([\s\S]*?)<\/row>/g)].map(r =>
      [...r[1].matchAll(/<c ([^>]*?)(?:\/>|>([\s\S]*?)<\/c>)/g)].map(c => {
        const t = /\bt="([^"]+)"/.exec(c[1])?.[1], body = c[2] ?? ''
        if (t === 's') return shared[Number(/<v>([^<]*)<\/v>/.exec(body)?.[1])] ?? ''
        if (t === 'inlineStr') return unxml(body)
        return unxml(/<v>([\s\S]*?)<\/v>/.exec(body)?.[1] ?? '')
      }).join('\t'))
    return `# ${names[i] ?? `Sheet ${i + 1}`}\n${rows.join('\n')}`
  }).join('\n\n').trim()
}

export function pptxText(z: Map<string, string>): string {
  return [...z.keys()].sort((a, b) => Number(a.match(/\d+/)![0]) - Number(b.match(/\d+/)![0])).map((k, i) =>
    `# Slide ${i + 1}\n${unxml(z.get(k)!.replace(/<\/a:p>/g, '\n')).trim()}`).join('\n\n')
}
