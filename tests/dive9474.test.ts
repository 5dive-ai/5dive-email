// DIVE-9474: the owner's OneDrive and SharePoint files through the mailbox's Microsoft sign-in.
// No network beyond loopback: a stand-in Microsoft Graph serves the calls files.ts makes.
import { test, expect, describe, afterAll } from 'bun:test'
import { deflateRawSync } from 'node:zlib'
import { mkdtempSync, writeFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { makeFiles, unzip, docxText, xlsxText, pptxText, itemPath, graphSays, toText, filesMode, type FilesMode } from '../email/files.ts'
import { linkStart, explain, filesScope, graphScope, adminConsentLink, filesRefused } from '../email/msauth.ts'
import { toolRisk, guardVerdict } from '../email/guard.ts'

/** A minimal zip (deflated entries), as Word and Excel write them. */
function zip(files: Record<string, string>): Buffer {
  const locals: Buffer[] = [], central: Buffer[] = []
  let off = 0
  for (const [name, text] of Object.entries(files)) {
    const data = deflateRawSync(Buffer.from(text)), n = Buffer.from(name)
    const l = Buffer.alloc(30); l.writeUInt32LE(0x04034b50, 0); l.writeUInt16LE(8, 8); l.writeUInt32LE(data.length, 18); l.writeUInt16LE(n.length, 26)
    const c = Buffer.alloc(46); c.writeUInt32LE(0x02014b50, 0); c.writeUInt16LE(8, 10); c.writeUInt32LE(data.length, 20); c.writeUInt16LE(n.length, 28); c.writeUInt32LE(off, 42)
    locals.push(l, n, data); central.push(c, n); off += 30 + n.length + data.length
  }
  const cd = Buffer.concat(central), e = Buffer.alloc(22)
  e.writeUInt32LE(0x06054b50, 0); e.writeUInt16LE(Object.keys(files).length, 8); e.writeUInt16LE(Object.keys(files).length, 10); e.writeUInt32LE(cd.length, 12); e.writeUInt32LE(off, 16)
  return Buffer.concat([...locals, cd, e])
}
const DOCX = zip({ '[Content_Types].xml': '<x/>', 'word/document.xml': '<w:document><w:body><w:p><w:r><w:t>Offer for Acme &amp; Co</w:t></w:r></w:p><w:p><w:r><w:t>Price:</w:t></w:r><w:r><w:tab/><w:t>4 200 EUR</w:t></w:r></w:p></w:body></w:document>' })
const XLSX = zip({
  'xl/workbook.xml': '<workbook><sheets><sheet name="Clients" sheetId="1"/></sheets></workbook>',
  'xl/sharedStrings.xml': '<sst><si><t>Name</t></si><si><t>Acme</t></si></sst>',
  'xl/worksheets/sheet1.xml': '<worksheet><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="inlineStr"><is><t>Fee</t></is></c></row><row r="2"><c r="A2" t="s"><v>1</v></c><c r="B2"><v>4200</v></c></row></sheetData></worksheet>',
})

describe('turning a file into text', () => {
  test('Word: paragraphs and tabs, entities decoded', () => {
    expect(docxText(unzip(DOCX, n => n === 'word/document.xml'))).toBe('Offer for Acme & Co\nPrice:\t4 200 EUR')
  })
  test('Excel: each sheet by name, shared and inline strings, numbers, tab-separated', () => {
    expect(xlsxText(unzip(XLSX, () => true))).toBe('# Clients\nName\tFee\nAcme\t4200')
  })
  test('PowerPoint: slide by slide', () => {
    expect(pptxText(unzip(zip({ 'ppt/slides/slide2.xml': '<a:p><a:t>Two</a:t></a:p>', 'ppt/slides/slide1.xml': '<a:p><a:t>One</a:t></a:p>' }), () => true))).toBe('# Slide 1\nOne\n\n# Slide 2\nTwo')
  })
  test('a PDF with no pdftotext on the box: a short-lived 0600 file for the Read tool, not text', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'f9474-'))
    const r = await toText('scan.pdf', Buffer.from('%PDF-1.4 \x00\x01'), { tmpDir: join(dir, 't'), pdftotext: null })
    expect(r.text).toBeUndefined()
    expect(r.note).toContain('Read this file')
    expect(existsSync(r.path!)).toBe(true)
  })
  test('a broken Word file says so in words', async () => {
    await expect(toText('x.docx', Buffer.from('not a zip'), { tmpDir: tmpdir() })).rejects.toThrow('could not open x.docx')
  })
})

describe('naming a file', () => {
  test('a ref from a list, a library root, a OneDrive path; no climbing out', () => {
    expect(itemPath('b!abc:01XYZ')).toBe('/drives/b!abc/items/01XYZ')
    expect(itemPath('b!abc:root')).toBe('/drives/b!abc/root')
    expect(itemPath('/')).toBe('/me/drive/root')
    expect(itemPath('/Clients/Acme & Co/')).toBe('/me/drive/root:/Clients/Acme%20%26%20Co:')
    expect(() => itemPath('/Clients/../../x')).toThrow()
  })
  test("Microsoft's refusals in words: SharePoint 403 names the admin, OneDrive keeps working", () => {
    expect(graphSays(403, 'Access denied', true)).toContain("company's admin has to allow it once")
    expect(graphSays(403, 'Access denied', true)).toContain('OneDrive keeps working')
    expect(graphSays(429, '', false)).toContain('try again in a minute')
  })
  test('the switch value is read strictly', () => {
    expect(filesMode('onedrive')).toBe('onedrive')
    expect(filesMode('yes')).toBe('off')
    expect(filesMode(undefined)).toBe('off')
  })
})

describe('the sign-in asks for files on top of mail, same app', () => {
  test('files on: mail + OneDrive + SharePoint in one link; OneDrive only; plain connect unchanged', () => {
    const scope = (l: string) => new URL(l).searchParams.get('scope')!
    const all = linkStart('common', '296f2516-fb76-4b8a-9930-88cdbca529d9', 'max@example.com', 'all')
    expect(scope(all.link)).toContain('IMAP.AccessAsUser.All')
    expect(scope(all.link)).toContain('https://graph.microsoft.com/Files.ReadWrite')
    expect(scope(all.link)).toContain('https://graph.microsoft.com/Sites.ReadWrite.All')
    expect(all.files).toBe('all')
    expect(scope(linkStart('common', '296f2516-fb76-4b8a-9930-88cdbca529d9', 'm@x.com', 'onedrive').link)).not.toContain('Sites.')
    const plain = linkStart('common', '296f2516-fb76-4b8a-9930-88cdbca529d9', 'm@x.com')
    expect(scope(plain.link)).not.toContain('graph.microsoft.com')
    expect('files' in plain).toBe(false)
    expect(filesScope('')).toBe('')
    expect(graphScope(true)).toContain('Sites.ReadWrite.All')
  })
  test("admin approval refusal of a files sign-in: the link asks for files too, OneDrive alone offered", () => {
    process.env.EMAIL_MS_DEFAULT_APP = '296f2516-fb76-4b8a-9930-88cdbca529d9'
    const e = explain('access_denied', { error_subcode: 'cancel' }, '296f2516-fb76-4b8a-9930-88cdbca529d9', 'all')
    expect(e.code).toBe('admin_consent')
    expect(e.message).toContain('OneDrive only')
    expect(decodeURIComponent(e.message)).toContain('Sites.ReadWrite.All')
    expect(decodeURIComponent(adminConsentLink('296f2516-fb76-4b8a-9930-88cdbca529d9'))).not.toContain('graph.microsoft.com')
  })
  test('a refused Graph token is never "sign the mailbox in again"', () => {
    const e = filesRefused('invalid_grant', { error_description: 'AADSTS65001: not consented' }, 'x', graphScope(true))
    expect(e.again).toBe(false)
    expect(e.message).toContain('OneDrive keeps working')
  })
})

describe('the guard: a stranger mail never opens the owner files', () => {
  test('files tools are held while the newest message is an outside email', () => {
    expect(toolRisk('mcp__plugin_email_email__files_read', {})?.kind).toBe('files')
    expect(toolRisk('mcp__email__files_save', {})?.kind).toBe('files')
    expect(guardVerdict('email', { check: 'on', membersMay: [] }, 'mcp__plugin_email_email__files_search', {}).ok).toBe(false)
    expect(guardVerdict('telegram', { check: 'on', membersMay: [] }, 'mcp__plugin_email_email__files_search', {}).ok).toBe(true)
    expect(toolRisk('mcp__plugin_email_email__reply', {})).toBeNull()
  })
})

describe('the file tools against a stand-in Microsoft Graph', () => {
  const calls: { method: string; path: string; auth: string; body?: string }[] = []
  const store = new Map<string, Buffer>([['offer.docx', DOCX]])
  const srv = Bun.serve({
    port: 0, hostname: '127.0.0.1',
    async fetch(req) {
      const u = new URL(req.url), path = decodeURIComponent(u.pathname) + u.search
      const body = req.method === 'PUT' ? Buffer.from(await req.arrayBuffer()) : undefined
      calls.push({ method: req.method, path, auth: req.headers.get('authorization') ?? '' })
      if (u.pathname === '/dl/offer.docx') return new Response(store.get('offer.docx'))
      if (u.pathname === '/v1.0/me/drive') return Response.json({ id: 'b!own' })
      if (u.pathname === '/v1.0/me/drive/root:/Clients:/children') return Response.json({ value: [{ id: 'i1', name: 'offer.docx', size: 900, file: {}, parentReference: { driveId: 'b!own', path: '/drive/root:/Clients' } }] })
      if (u.pathname === '/v1.0/drives/b!own/items/i1') return Response.json({ id: 'i1', name: 'offer.docx', size: 900, file: {}, '@microsoft.graph.downloadUrl': `http://127.0.0.1:${srv.port}/dl/offer.docx` })
      if (u.pathname === '/v1.0/drives/b!team/items/t1/children') return Response.json({ value: [] })
      if (u.pathname.startsWith('/v1.0/me/drive/root:/Clients/') && req.method === 'PUT') {
        const name = decodeURIComponent(/\/Clients\/([^/:]+):\/content$/.exec(u.pathname)![1])
        store.set(name, body!)
        return Response.json({ id: 'n1', name, parentReference: { driveId: 'b!own' }, webUrl: 'https://x/n1' })
      }
      return Response.json({ error: { message: 'item not found' } }, { status: 404 })
    },
  })
  afterAll(() => srv.stop(true))
  process.env.EMAIL_GRAPH_BASE = `http://127.0.0.1:${srv.port}/v1.0`
  let mode: FilesMode = 'onedrive'
  const asked: boolean[] = []
  const f = makeFiles(async sp => { asked.push(sp); return sp ? 'tok-sp' : 'tok-od' }, () => mode, { tmpDir: tmpdir() })

  test('list a OneDrive folder by path: refs come back', async () => {
    const l = await f.list('/Clients')
    expect(l).toEqual([{ name: 'offer.docx', ref: 'b!own:i1', folder: false, size: 900, where: '/Clients' }])
  })
  test('read by ref: the Word text; the pre-signed download carries no token', async () => {
    const r = await f.read('b!own:i1')
    expect(r.text).toBe('Offer for Acme & Co\nPrice:\t4 200 EUR')
    expect(calls.find(c => c.path.startsWith('/dl/'))!.auth).toBe('')
    // Microsoft leaves the download address out of a $select answer (measured live): none asked.
    expect(calls.find(c => c.path.startsWith('/v1.0/drives/b!own/items/i1'))!.path).not.toContain('$select')
  })
  test('save never replaces a same-named file unless asked', async () => {
    await f.save({ folder: '/Clients', name: 'draft.md', text: 'hello' })
    expect(calls.at(-1)!.path).toContain('conflictBehavior=rename')
    expect(store.get('draft.md')!.toString()).toBe('hello')
    await f.save({ folder: '/Clients', name: 'draft.md', text: 'v2', overwrite: true })
    expect(calls.at(-1)!.path).toContain('conflictBehavior=replace')
    await expect(f.save({ folder: '/Clients', name: '../x', text: 'a' })).rejects.toThrow('file name alone')
  })
  test('a SharePoint library with only OneDrive allowed: refused in words, no call made', async () => {
    const n = calls.length
    await expect(f.list('b!team:t1')).rejects.toThrow("company's admin has to allow it once")
    expect(calls.slice(n).some(c => c.path.includes('b!team'))).toBe(false)
    mode = 'onedrive_sharepoint'
    expect(await f.list('b!team:t1')).toEqual([])
    expect(asked.at(-1)).toBe(true)
  })
  test('switched off: every tool says how the owner turns it on', async () => {
    mode = 'off'
    await expect(f.search('acme', true)).rejects.toThrow('turn it on in the app')
  })
})
