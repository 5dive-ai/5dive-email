#!/usr/bin/env -S bun
// PreToolUse guard for an email-connected CODEX agent (DIVE-8464). The Claude
// Code twin is mail-guard.ts; the rule is the same (../guard.ts): while the
// running turn is an email, a risky act waits for the owner's yes.
//
// Codex has no transcript tag to read; its 5dive dispatcher persists the
// running turn's source (state.json `active.route.source`). See ../codex.ts.
//
// Failure stance (decided for DIVE-8464):
//   * no state file  -> allow: no dispatcher ever ran a turn here, so there is
//     no email turn (an interactive Codex session, the MCP fallback).
//   * a state file that cannot be read or parsed -> treat the turn AS an email:
//     only the risky classes are held (everything else still runs), and the
//     dispatcher writes that file atomically, so this is a broken seat, where
//     guessing "not an email" would let a stranger's mail run root commands.
//   * a crash in this hook -> allow, like mail-guard.ts and the Teams guard: a
//     broken hook must not stop the agent's normal work.
// Wire it in the seat's ~/.codex/config.toml (5dive-agent-start does this):
//   [[hooks.PreToolUse]]
//   [[hooks.PreToolUse.hooks]]
//   type = "command"
//   command = "bun <plugin root>/hooks/codex-mail-guard.ts"
//   timeout = 5
//   async = false

import { join } from 'node:path'
import { ASK_CODEX, guardVerdict, heldVerdict, loadRoles, type Verdict } from '../guard.ts'
import { activeSource, adapterStateDir, codexCalls } from '../codex.ts'

export function codexVerdict(statePath: string, roles: ReturnType<typeof loadRoles>, tool: string, input: Record<string, unknown> | undefined): Verdict {
  const a = activeSource(statePath)
  const source = 'unreadable' in a ? 'email' : a.source
  for (const c of codexCalls(tool, input)) {
    if (c.deletes && roles.check !== 'off' && source === 'email' && !roles.membersMay.includes('delete')) {
      return heldVerdict({ kind: 'delete', what: 'delete' }, ASK_CODEX)
    }
    const v = guardVerdict(source, roles, c.tool, c.input, ASK_CODEX)
    if (!v.ok) return v
  }
  return { ok: true }
}

if (import.meta.main) {
  try {
    const raw = await Bun.stdin.text()
    const p = raw.trim() ? JSON.parse(raw) : {}
    const v = codexVerdict(join(adapterStateDir(), 'state.json'), loadRoles(), String(p.tool_name ?? ''), p.tool_input)
    if (!v.ok) {
      process.stdout.write(
        JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: v.reason } }),
      )
    }
  } catch {}
  process.exit(0)
}
