# kryos-mcp

Governed code execution for AI agents, backed by the [Kryos](https://github.com/NORTHTEKDevs/kryos-lang) compiler's capability system. An MCP server that lets any client type-check, run, and **capability-verify** Kryos code — so an agent can only run code whose reach (network, filesystem, process, crypto, …) is declared and checked at compile time.

## Why

Most "run this code" tools give an agent an unconstrained interpreter. kryos-mcp runs code through Kryos, where every function declares its capabilities (`@capabilities(net, io)`) and the compiler rejects anything that reaches further. `verify_capabilities` turns that into a governance verdict: **ALLOW** only if the code type-checks, every declared capability is inside the grant, and every function is annotated. Because Kryos enforcement is opt-in per function, unannotated functions are reported as `UNCONSTRAINED` rather than waved through.

## Tools

| Tool | What it does |
|------|--------------|
| `kryos_check(code, files?)` | Type-check without producing artifacts; surfaces type + capability errors. |
| `kryos_run(code, files?, timeout_ms?)` | Compile and run with a hard timeout; captures stdout/stderr/exit code. |
| `capability_manifest(code, files?, strict?)` | Per-function capability manifest (JSON). |
| `verify_capabilities(code, files?, granted[], allow_unannotated?)` | ALLOW/DENY against a capability grant; reports unconstrained functions. |
| `kryos_audit(code, files?)` | Full audit: capability usage, extern/FFI surface, secret-pattern scan. |

`files` is an optional map of sibling `.kry` module files (name → content) so `use <mod>` resolves.

## Install

Requires the [Kryos toolchain](https://github.com/NORTHTEKDevs/kryos-lang) on PATH (or set `KRYOS_BIN`).

```bash
npm install
claude mcp add kryos --scope user -- node /abs/path/to/kryos-mcp/server.mjs
```

## Verify

```bash
node smoke-test.mjs   # spawns the server, exercises every tool incl. a DENY and an ALLOW verdict
```

## Capabilities reference

Valid grants (case-insensitive): `net, io, ffi, compute, crypto, process, env, term, db, time, all`. Notable gotchas the manifest reflects: `env_get`/`exit` require `process`; `time_now` requires `time`; network builtins require `net`.

MIT.
