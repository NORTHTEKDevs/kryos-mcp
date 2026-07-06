// kryos-mcp: governed code execution for any agent, backed by the Kryos compiler's
// capability system. Tools shell to the installed kryos binary: type-check, run with
// timeout, per-function capability manifest, capability verification against a grant
// list, and a full audit (capability usage + extern surface + secret patterns).
// Capability enforcement in Kryos is OPT-IN per annotated function - verify_capabilities
// therefore reports unannotated functions as UNCONSTRAINED instead of pretending
// they are safe.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { spawnSync } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { z } from 'zod';

const homeKryos = path.join(os.homedir(), '.local', 'bin', process.platform === 'win32' ? 'kryos.exe' : 'kryos');
const KRYOS = process.env.KRYOS_BIN || (fs.existsSync(homeKryos) ? homeKryos : 'kryos');
const CAPS = ['net', 'io', 'ffi', 'compute', 'crypto', 'process', 'env', 'term', 'db', 'time', 'all'];

function ok(data) {
  return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
}
function fail(msg) {
  return { content: [{ type: 'text', text: msg }], isError: true };
}
const RO = { readOnlyHint: true, openWorldHint: false };

// Each call gets its own temp project dir; extra files land as siblings so
// `use <mod>` resolution works. Cleaned up after the command runs.
function withSource(code, files, fn) {
  const dir = path.join(os.tmpdir(), 'kryos-mcp', crypto.randomBytes(6).toString('hex'));
  fs.mkdirSync(dir, { recursive: true });
  const main = path.join(dir, 'main.kry');
  try {
    fs.writeFileSync(main, code);
    for (const [name, content] of Object.entries(files || {})) {
      const safe = path.basename(name);
      if (!safe.endsWith('.kry')) throw new Error(`extra file "${name}" must end in .kry`);
      fs.writeFileSync(path.join(dir, safe), content);
    }
    return fn(main, dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function kryos(args, { timeoutMs = 30000, cwd } = {}) {
  const r = spawnSync(KRYOS, args, { encoding: 'utf8', timeout: timeoutMs, cwd, windowsHide: true });
  if (r.error && r.error.code === 'ENOENT') throw new Error(`kryos binary not found at "${KRYOS}" - set KRYOS_BIN`);
  const timedOut = r.error && r.error.code === 'ETIMEDOUT';
  return { stdout: (r.stdout || '').trim(), stderr: (r.stderr || '').trim(), status: r.status, timedOut };
}

const codeArg = z.string().min(1).describe('Kryos source for main.kry');
const filesArg = z.record(z.string()).optional().describe('Extra sibling .kry module files, name -> content (for `use <mod>`)');

const server = new McpServer({ name: 'kryos-mcp', version: '0.1.0' });

server.registerTool(
  'kryos_check',
  {
    title: 'Type-check Kryos source',
    description:
      'Compile-check without producing artifacts. Surfaces type errors and capability violations (E-CAP-BUILTIN / E0502-E0507). Fast first gate before run or verify.',
    inputSchema: { code: codeArg, files: filesArg },
    annotations: RO,
  },
  async ({ code, files }) => {
    try {
      const r = withSource(code, files, (main) => kryos(['check', main]));
      return ok({ ok: r.status === 0, exit_code: r.status, diagnostics: (r.stderr + '\n' + r.stdout).trim() || 'clean' });
    } catch (e) {
      return fail(`kryos_check failed: ${e.message}`);
    }
  }
);

server.registerTool(
  'kryos_run',
  {
    title: 'Compile and run Kryos source',
    description:
      'Compile (debug backend) and execute a Kryos program with a hard timeout, capturing stdout/stderr/exit code. Capability annotations in the code are enforced at compile time; unannotated code runs unconstrained - use verify_capabilities first when governance matters.',
    inputSchema: {
      code: codeArg,
      files: filesArg,
      timeout_ms: z.number().int().min(1000).max(120000).default(15000),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
  async ({ code, files, timeout_ms }) => {
    try {
      const r = withSource(code, files, (main, dir) => kryos(['run', main], { timeoutMs: timeout_ms, cwd: dir }));
      return ok({ ok: r.status === 0 && !r.timedOut, exit_code: r.status, timed_out: !!r.timedOut, stdout: r.stdout, stderr: r.stderr });
    } catch (e) {
      return fail(`kryos_run failed: ${e.message}`);
    }
  }
);

server.registerTool(
  'capability_manifest',
  {
    title: 'Per-function capability manifest',
    description:
      `Emit the compiler's per-function capability manifest as JSON. strict=true also lists unannotated functions (capabilities=[]). Valid capabilities: ${CAPS.join(', ')}. Gotchas: env_get and exit require "process" (not env/io); time_now needs "time".`,
    inputSchema: { code: codeArg, files: filesArg, strict: z.boolean().default(true) },
    annotations: RO,
  },
  async ({ code, files, strict }) => {
    try {
      const args = ['manifest', '--caps', '--format', 'json'];
      if (strict) args.push('--strict');
      const r = withSource(code, files, (main) => kryos([...args, main]));
      if (r.status !== 0) return fail(`manifest failed (exit ${r.status}): ${r.stderr || r.stdout}`);
      return ok(JSON.parse(r.stdout));
    } catch (e) {
      return fail(`capability_manifest failed: ${e.message}`);
    }
  }
);

server.registerTool(
  'verify_capabilities',
  {
    title: 'Verify code against a capability grant',
    description:
      `Governance verdict for a piece of Kryos code: ALLOW only if (1) it type-checks, (2) every declared capability is inside the granted set, and (3) every function is annotated (or allow_unannotated=true). Unannotated functions are reported as UNCONSTRAINED because Kryos enforcement is opt-in per function - an unannotated helper can call anything. Grantable capabilities: ${CAPS.join(', ')}.`,
    inputSchema: {
      code: codeArg,
      files: filesArg,
      granted: z.array(z.enum(CAPS)).default([]).describe('Capabilities the agent is allowed to use'),
      allow_unannotated: z.boolean().default(false),
    },
    annotations: RO,
  },
  async ({ code, files, granted, allow_unannotated }) => {
    try {
      return withSource(code, files, (main) => {
        const check = kryos(['check', main]);
        const strict = kryos(['manifest', '--caps', '--format', 'json', '--strict', main]);
        if (strict.status !== 0) {
          return fail(`manifest failed: ${(strict.stderr || strict.stdout || '').slice(0, 400)}`);
        }
        // kryos-manifest-v1: functions is an object keyed by name, each with
        // { capabilities: [], annotated: bool }.
        const fns = Object.entries(JSON.parse(strict.stdout).functions || {}).map(([name, f]) => ({
          name,
          capabilities: f.capabilities || [],
          annotated: !!f.annotated,
        }));
        const annotatedFns = fns.filter((f) => f.annotated);
        const unannotated = fns.filter((f) => !f.annotated).map((f) => f.name);
        const grantedSet = new Set(granted.includes('all') ? CAPS : granted);
        const violations = [];
        for (const f of annotatedFns) {
          for (const cap of f.capabilities) {
            if (cap !== 'all' && !grantedSet.has(cap)) violations.push({ function: f.name, capability: cap });
            if (cap === 'all' && !granted.includes('all')) violations.push({ function: f.name, capability: 'all' });
          }
        }
        const compiles = check.status === 0;
        let verdict = 'ALLOW';
        const reasons = [];
        if (!compiles) { verdict = 'DENY'; reasons.push('does not type-check'); }
        if (violations.length) { verdict = 'DENY'; reasons.push(`declares capabilities outside grant: ${violations.map((v) => `${v.function}:${v.capability}`).join(', ')}`); }
        if (unannotated.length && !allow_unannotated) { verdict = 'DENY'; reasons.push(`unannotated (UNCONSTRAINED) functions: ${unannotated.join(', ')}`); }
        return ok({
          verdict,
          reasons: reasons.length ? reasons : ['all declared capabilities within grant'],
          compiles,
          granted,
          declared: annotatedFns,
          unconstrained_functions: unannotated,
          diagnostics: compiles ? undefined : (check.stderr + '\n' + check.stdout).trim().slice(0, 800),
        });
      });
    } catch (e) {
      return fail(`verify_capabilities failed: ${e.message}`);
    }
  }
);

server.registerTool(
  'kryos_audit',
  {
    title: 'Audit Kryos source',
    description: 'Full compiler audit of the source: capability usage, extern/FFI surface, and secret-pattern scan. JSON output.',
    inputSchema: { code: codeArg, files: filesArg },
    annotations: RO,
  },
  async ({ code, files }) => {
    try {
      const r = withSource(code, files, (main, dir) => kryos(['audit', '--format', 'json', dir]));
      if (r.status !== 0 && !r.stdout) return fail(`audit failed (exit ${r.status}): ${r.stderr}`);
      let parsed;
      try { parsed = JSON.parse(r.stdout); } catch { parsed = { raw: r.stdout }; }
      return ok({ exit_code: r.status, audit: parsed });
    } catch (e) {
      return fail(`kryos_audit failed: ${e.message}`);
    }
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
