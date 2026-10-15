# Branch Coverage Map

The Linux development report now has 100% branch coverage for both the library
and all targets. This is not a claim of cross-platform branch coverage or native
enforcement parity. Use native CI runners for Windows, macOS, FreeBSD, and
OpenBSD paths, and keep platform-specific reports separate from the Linux
report.

## Commands

Run the library unit suite with branch instrumentation:

```sh
cargo +nightly llvm-cov --lib --branch --summary-only
```

Run all targets, including the CLI integration test:

```sh
cargo +nightly llvm-cov --all-targets --branch --summary-only
```

Generate machine-readable details for mapping uncovered outcomes:

```sh
cargo +nightly llvm-cov report --json --output-path target/ai-sandbox-coverage.json
```

## Current Linux Checkpoint

Measured on 2026-10-15 after MXC policy JSON support and procfs-specific probe
coverage:

- Library-only: 488/488 branch outcomes covered (100%).
- All targets: 500/500 branch outcomes covered (100%).
- All-target tests: 211 library tests, 1 binary unit test, and 9 CLI integration
  tests passed.
- MXC policy JSON tests cover strict decoding, safe defaults, timeout bounds,
  representable read-only/workspace-write policies, explicit network-rule and
  mixed-policy rejection, host containment selection, procfs omission/mount,
  and command-argument preservation through the CLI.
- Bubblewrap tests use injected path/capability decisions for host-layout and
  kernel-independent branches and cover unsupported Proxy/Localhost policies,
  read-only root validation, workspace/system-root skips, duplicate roots and
  shared parents, sibling roots beneath the current home directory, and
  non-UTF-8 mount paths. Legacy runtime tests probe procfs support separately;
  no-proc MXC JSON execution is tested independently. Native enforcement is
  never inferred from argument-builder coverage alone.
- Execution-policy tests cover absolute executable aliases, directory bypass
  inputs, invalid path roots, network matching, and wildcard-rule fallback.
- Portable Seatbelt policy generation and Windows allow/deny path planning each
  reach 100% branch coverage in this Linux report; this does not replace native
  enforcement tests.
- OpenBSD pledge now performs the exec handoff with `execpromises` and omits the
  removed `tmppath` promise from its default policy.

Coverage can change with tests or compiler instrumentation; rerun the commands
above before updating this table. The 100% result is specific to the Linux
toolchain and source paths compiled on this host. It does not cover cfg-gated
native code on other operating systems, nor prove that the host kernel enforces
Bubblewrap or platform sandbox policies.

## Remaining Platform Work

- Linux: builder and policy coverage is expanded. Kernel-dependent Bubblewrap
  behavior still depends on host namespace support and must not be inferred
  from argument-builder tests.
- macOS: a native `sandbox-exec` test now verifies that a read-only policy
  denies file creation; it runs on the existing macOS CI runner.
- Windows: native tests exercise restricted-token process creation and verify
  unsupported ACL/network policies fail closed. Filesystem ACL and network
  enforcement are not implemented, so this does not claim those controls are
  enforced.
- FreeBSD/OpenBSD: native tests verify a real child cannot create a file under
  Capsicum/pledge. Dedicated VM jobs were added; they are the runtime checks
  because this Linux host cannot execute either kernel API.

Cross-platform runtime results must be recorded from their native CI jobs; the
Linux checkpoint above only reports locally executed tests.

Do not force coverage through fabricated error paths where a native platform
API or kernel capability is required. Prefer injectable adapters for behavior
that can be meaningfully simulated, and native CI for OS-specific enforcement.