// email/codex-adapter.ts: the entry a Codex seat's 5dive dispatcher spawns
// (DIVE-8464; the manifest's fivedive.channel.codex_adapter).
//
// Claude Code starts this plugin through package.json's `start` script, which
// installs its dependencies first. The dispatcher runs `bun <this file>` with
// the seat's work folder as cwd, so this does the same install here, then loads
// the server in adapter mode. Node builtins and ./lifecycle.ts only, so a
// missing dependency is written down instead of dying silently (start.ts).

import { existsSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { recordLifecycle } from './lifecycle.ts'

const STATE_DIR = join(homedir(), '.claude', 'channels', 'email')
process.env.CODEX_DISPATCHER_ADAPTER ||= 'email'

if (!existsSync(join(import.meta.dir, 'node_modules')) && !existsSync('/etc/5dive/local-only')) {
  const r = spawnSync(process.execPath, ['install', '--no-summary'], { cwd: import.meta.dir, stdio: ['ignore', 'ignore', 'pipe'], encoding: 'utf8', timeout: 180_000 })
  if (r.status !== 0) recordLifecycle(STATE_DIR, 'crash', 'email', `codex adapter: bun install in ${import.meta.dir} failed: ${(r.stderr || String(r.error ?? '')).trim().split('\n').pop()}`)
}

recordLifecycle(STATE_DIR, 'start', 'email', 'codex adapter: loading server.ts')
try {
  await import('./server.ts')
} catch (err) {
  recordLifecycle(STATE_DIR, 'crash', 'email', `codex adapter: server.ts failed to load: ${err}`)
  process.exit(1)
}
