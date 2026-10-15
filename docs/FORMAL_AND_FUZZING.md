# Formal Models and Fuzzing

This note records the adapter state-machine models and bounded fuzz campaigns
for `ai-sandbox`. The models describe the security-relevant lifecycle, not the
kernel semantics of Bubblewrap, Seatbelt, Windows tokens, Capsicum, or pledge.
The fuzz targets call pure policy and argument-building functions; none starts
a sandboxed child process or invokes an OS confinement syscall.

## Adapter Models

The TLA+ modules are in `formal/`; each `.cfg` checks `TypeOK`, a protected
execution invariant, a failure invariant, and any adapter-specific safety
property. `CommonExecutor` models the shared request boundary. Each OS model
then models adapter preparation and launch:

| Module | Modeled adapter method | Additional abstraction |
| --- | --- | --- |
| `LinuxBubblewrap` | Build Bubblewrap namespace command, then exec it | Availability, policy support, and network-policy support can each reject execution. Bubblewrap supports `NoAccess`/`FullAccess` in the active builder; `Localhost`/`Proxy` are unsupported. |
| `MacOSSeatbelt` | Compile the SBPL profile and invoke `sandbox-exec` | Unsupported network policies fail before launch; protected launch only follows profile application. |
| `WindowsRestrictedToken` | Create restricted token/process and launch with `CreateProcessAsUserW` | Unsupported network or filesystem ACL controls fail without invoking the ordinary process path. |
| `FreeBSDCapsicum` | Run `cap_enter()` from the child pre-exec hook, then exec | Adapter availability and policy support gate entry; a syscall error terminates the launch path. |
| `OpenBSDPledge` | Apply `pledge()` from the child pre-exec hook, then exec | Adapter availability and policy support gate entry; a syscall error terminates the launch path. |

All models use the lifecycle `Ready -> Prepared -> Isolated -> Executed`, with
explicit rejection paths. Each OS model treats adapter availability, policy
support, and network-policy support as explicit inputs. `RunExplicitFullAccess`
is represented separately from protected execution. The common executor model checks that the API's
`SandboxType::None` selection is rejected rather than spawned. TLC deadlock
checking is disabled because `Executed`, `Failed`, and `Rejected` are terminal
states by design.

The checked safety properties are:

- `ProtectedExecutionRequiresIsolation`: a protected request can execute only
  after its adapter established isolation.
- `FailureNeverExecutes`: failed adapter setup cannot execute the target.
- `UnsupportedProtectedPolicyNeverExecutes`: unavailable adapters or
  unsupported policy dimensions cannot reach protected execution.
- `NoUnprotectedSpawn` (common executor): execution through the common API
  requires a verified adapter selection.

Run all six finite-state checks from the crate root with a local Java runtime
and a downloaded TLC jar:

```sh
for model in CommonExecutor LinuxBubblewrap MacOSSeatbelt WindowsRestrictedToken FreeBSDCapsicum OpenBSDPledge; do
  java -cp /path/to/tla2tools.jar tlc2.TLC -nowarning \
    -config "formal/$model.cfg" "formal/$model.tla"
done
```

Checked during this change with TLC 2.19 and Java 21. All six models completed
without invariant violations. The common model explored 8 distinct states;
Each OS model explored 50 distinct states. These small counts are expected: the
models abstract away command contents, path semantics, kernel policy
interpretation, and concurrent processes.

## Fuzz Targets

The separate `fuzz/` Cargo workspace uses `cargo-fuzz`/libFuzzer and nightly
Rust. Inputs are bounded to at most 4096 bytes per campaign.

| Target | Exercised boundary | Properties checked |
| --- | --- | --- |
| `parse_policy` | Policy text parsing and command check/sanitization | Arbitrary text does not panic while parsing/matching. |
| `bwrap_policy` | Read-only/workspace Bubblewrap argv builders | Vary argv, environment keys/values, writable root and network enum; unsupported requests may return errors. |
| `seatbelt_policy` | Seatbelt policy generation | Proxy requests return errors; `NoAccess` does not emit a network allow rule. |
| `windows_policy` | Windows path computation and sandbox-level selection | Current directory is always in the allow result; only empty path lists plus enabled networking select the unrestricted process. |
| `bsd_policy` | Capsicum argument generation and pledge policy mapping/serialization | Promise output remains ASCII; NoAccess, Localhost, and Proxy do not grant `inet` or `dns`. |
| `mxc_config` | MXC JSON parsing, policy mapping, and Bubblewrap argv transformation | Accepted configs preserve workload argv; on Linux, the procfs mount matches `filesystem.mount_procfs`. The target never spawns the command. |

Build and run one target:

```sh
cargo +nightly fuzz check --fuzz-dir fuzz
cargo +nightly fuzz run parse_policy --fuzz-dir fuzz -- -max_total_time=30 -max_len=4096
cargo +nightly fuzz run mxc_config --fuzz-dir fuzz -- -max_total_time=30 -max_len=4096
```

Campaigns run for this change, on x86_64 Linux with the address sanitizer:

| Target | Bounded run | Result |
| --- | ---: | --- |
| `parse_policy` | Initial campaign stopped at crash; after fix, 214,036 executions in ~6 seconds plus a separate 20,000-run campaign | Minimized crash replay and both post-fix campaigns passed. |
| `bwrap_policy` | 50,000 executions | No crash. |
| `seatbelt_policy` | 20,000 executions | No crash. |
| `windows_policy` | 20,000 executions | No crash. |
| `bsd_policy` | 20,000 executions after adding the Localhost/Proxy properties | No crash; the new fail-closed properties passed. |
| `mxc_config` | 4,956,182 executions in 31 seconds, `-max_len=4096` | No crash; argv preservation and procfs parity properties held. |

## Findings and Fixes

The parser/matcher campaign found a panic in command sanitization. The sanitizer
truncated strings with byte-index slices at 16 bytes for program names and 1024
bytes for arguments. A lossy UTF-8 replacement character crossing either limit
made the slice end inside a code point. Truncation now backs up to the closest
valid UTF-8 boundary. The minimized input was six invalid bytes:
`ff ff ff ff 8b 8b`. A unit regression checks both string limits and the
`Policy::check` entry point.

The OpenBSD pledge mapping review found that policy conversion described
`Proxy` as `inet dns`, which does
not constrain connections to a proxy endpoint. It also granted `inet` for
`Localhost`, although pledge cannot restrict destinations to loopback. Both
policies now omit `inet` and `dns` in the pledge promises, failing closed. The
BSD fuzz target now asserts this behavior. This is intentionally restrictive; a
future adapter can support these modes only when it can enforce destination-
level controls.

The Windows policy-selection review found that a nonempty `read_allow`
list could still select the ordinary process path when `write_deny` was empty
and network access was enabled. The selector now requires both path lists to be
empty before choosing `Disabled`; a read-allow policy remains protected and
fails when its ACL enforcement is unavailable. A portable adapter regression
and the strengthened Windows fuzz property now cover this case.

Curated MXC-policy seeds are checked in under `fuzz/corpus/mxc_config/`.
Generated corpus growth and crash artifacts under `fuzz/corpus/` and
`fuzz/artifacts/` remain local working data and are not committed.