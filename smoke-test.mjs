// Smoke test for kryos-mcp: spawn over stdio, exercise every tool against the
// installed kryos binary, including a positive ALLOW and negative DENY verdict.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import path from 'path';

const HERE = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));

const HELLO = 'fn main() { println("hello from kryos-mcp") }\n';
const ANNOTATED =
  '@capabilities(net)\nfn fetch_thing() -> i64 { return 1 }\n\nfn main() { println(to_string(fetch_thing())) }\n';

const transport = new StdioClientTransport({ command: 'node', args: [path.join(HERE, 'server.mjs')] });
const client = new Client({ name: 'smoke', version: '0.0.1' });

let failures = 0;
const call = async (name, args) => JSON.parse((await client.callTool({ name, arguments: args })).content[0].text);
const check = (label, cond, detail) => {
  if (!cond) failures++;
  console.log(`  ${cond ? 'ok  ' : 'ERR '} ${label}${detail ? ': ' + detail : ''}`);
};

try {
  await client.connect(transport);
  const tools = await client.listTools();
  console.log(`=== kryos-mcp: ${tools.tools.length} tools [${tools.tools.map((t) => t.name).join(', ')}]`);
  check('tool count = 5', tools.tools.length === 5);

  const chk = await call('kryos_check', { code: HELLO });
  check('kryos_check hello', chk.ok === true, chk.diagnostics);

  const bad = await call('kryos_check', { code: 'fn main() { let x: i64 = "nope" }' });
  check('kryos_check catches type error', bad.ok === false);

  const run = await call('kryos_run', { code: HELLO });
  check('kryos_run hello', run.ok && run.stdout.includes('hello from kryos-mcp'), run.stdout || run.stderr);

  const man = await call('capability_manifest', { code: ANNOTATED });
  check('capability_manifest', man.functions?.fetch_thing?.capabilities?.includes('net'));

  const deny = await call('verify_capabilities', { code: ANNOTATED, granted: ['io'] });
  check('verify DENY (net not granted)', deny.verdict === 'DENY', deny.reasons?.join('; '));

  const allow = await call('verify_capabilities', { code: ANNOTATED, granted: ['net'], allow_unannotated: true });
  check('verify ALLOW (net granted)', allow.verdict === 'ALLOW', allow.reasons?.join('; '));

  const unc = await call('verify_capabilities', { code: ANNOTATED, granted: ['net'] });
  check('verify DENY (unannotated main)', unc.verdict === 'DENY' && unc.unconstrained_functions.includes('main'));

  const audit = await call('kryos_audit', { code: ANNOTATED });
  check('kryos_audit', audit.audit !== undefined);
} catch (e) {
  console.log(`  FATAL: ${e.message}`);
  failures++;
} finally {
  await client.close().catch(() => {});
}
console.log(`\nsmoke: ${failures === 0 ? 'PASS' : failures + ' FAILURES'}`);
process.exit(failures ? 1 : 0);
