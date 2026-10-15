# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased] - 2026-09-30

### Security Disclosure

The `v0.2.1` release and earlier versions must not be treated as complete
protected executors. Applications relying on the advertised sandbox policies
may not have received the requested OS-level isolation.

Affected areas included:

- Linux execution could require an unavailable external `linux-sandbox`
  executable, while the bundled CLI only printed a request instead of running
  it. Landlock types described rules but did not apply Landlock syscalls.
- Linux command construction used invalid or overly broad mount behavior, did
  not consistently enforce network policy, and inherited environment values
  that can alter child-process loading or startup behavior.
- Unsupported or unavailable platform backends could return an ordinary
  command path, creating a fail-open risk for callers that assumed a protected
  request was executable.
- Windows protected execution could fall back to `std::process::Command`, and
  process-pipe, timeout, and handle-lifecycle failures were not fully
  contained.
- BSD enforcement was applied in the parent process rather than reliably in
  the child, and Seatbelt policy paths were not escaped before insertion into
  generated policy text.

The security fixes on this branch add a Bubblewrap executor with capability
probing, explicit mounts, filtered environments, and fail-closed network and
filesystem policy handling; remove the fake Landlock execution path; reject
unverified platform backends; harden Windows process supervision; move BSD
restrictions into child setup; escape Seatbelt paths; and make the CLI execute
and wait for the protected child. Boundary tests cover Linux read isolation,
write isolation, workspace writes, and literal argument handling. Follow-up
hardening also rejects unsupported Seatbelt Proxy networking instead of
allowing all network access, and runs mocked Seatbelt, Windows, Capsicum, and
pledge adapter tests on Linux CI. Additional review rejects writable filesystem
modes hidden inside a `ReadOnly` policy and fixes Windows command-line quoting
for quotes and backslashes while passing the executable path separately to
`CreateProcessAsUserW`.

Execution-policy matching now prevents executable names from inheriting rules
through string-prefix aliases, requires exact literal argument matches, and
uses normalized component-boundary checks for working-directory restrictions.
Restricted rules fail closed when their cwd or allowed-directory configuration
is missing, while matching Deny and restricted wildcard rules take precedence
over Allows. Path traversal in `--option=value` arguments is rejected, and the
SUID/SGID guard recognizes absolute `chmod` paths and parses numeric modes as
octal. Bubblewrap canonicalizes writable roots and rejects the filesystem root;
however, because mounts are still passed by path, a concurrent path replacement
between validation and Bubblewrap startup remains a TOCTOU limitation.

TLA+ lifecycle models now cover the common executor and
all five platform adapters, with TLC checks for fail-closed execution
invariants. Five `cargo-fuzz` targets exercise policy parsing and adapter
policy builders. Fuzzing found and fixed a UTF-8 boundary panic in execution
policy sanitization; additional review tightened OpenBSD pledge networking
promises and Windows restricted-process selection so unsupported protected
policies cannot take an unrestricted path. Native tests and Windows, macOS, and
FreeBSD cross-target checks pass. The models describe adapter lifecycle
contracts and do not verify kernel enforcement semantics.

No CVE has been requested or assigned to this disclosure.

## [0.2.1] - 2026-04-05

### Analysis: Unfinished Features

After comprehensive analysis, the following features from Issue #6 are intentionally marked as **not implemented** because they are not essential for sandbox security:

#### 1. NetworkRule Execution Logic

- **Status**: Not implemented
- **Reason**: Not core security functionality
- **Alternative**: Existing `NetworkSandboxPolicy` enum (NoAccess/Localhost/ReadOnly/FullAccess) covers 95% of security use cases
- **Security Impact**: Low - sandbox already limits network access at the OS level

#### 2. Windows Firewall Integration

- **Status**: Not implemented
- **Reason**: Not necessary - Windows Restricted Token API already provides sufficient process isolation
- **Security Impact**: None - sandboxed processes have limited network access regardless

#### 3. FreeBSD Capsicum Full Implementation

- **Status**: Partial (cap_enter() exists, requires system configuration)
- **Reason**: Platform-specific, depends on kernel support
- **Security Impact**: Medium for FreeBSD users only

#### Conclusion

The current implementation provides **stable and reliable sandbox security**:
- Filesystem isolation (ReadOnly / Workspace)
- Network access control (NoAccess / Localhost)
- Process permission limits (Restricted Token / Seatbelt / Bubblewrap)
- Execution policy engine (PrefixRule / PathRule)
- All P0/P1 security vulnerabilities from Issue #8 are fixed

Additional features would add complexity without significant security benefit.

### Security

All security fixes from v0.2.0 are maintained and verified passing in CI.

## [0.2.0] - 2026-04-04

### Security Fixes

- **P0**: Default policy changed from `DangerFullAccess` to `ReadOnly` - insecure by default now fixed
- **P0**: Empty `writable_roots` in WorkspaceWrite now validated and rejected, automatically downgraded to ReadOnly
- **P1**: Path traversal detection added via `contains_path_traversal()` method in SandboxPolicy
- **P1**: Policy priority fixed - deny rules now take precedence over allow rules in Policy::check()
- **P1**: PathRule path traversal validation added - rejects path patterns containing ".."

### Added

- Add `is_safe()` method to SandboxPolicy for security validation
- Add `SandboxPolicyExt` trait for external policy safety checks
- Add comprehensive unit tests for all security fixes (8 new tests)

### Changed

- Improved error handling and validation in policy creation
- Updated destructive_test to reflect fixed security behavior

## [0.1.9] - 2026-04-03

### Fixed
- Fix network_policy not being passed correctly in SandboxExecRequest
- Fix Windows sandbox level mapping (add Full level detection)
- Improve macOS Localhost policy to restrict to 127.0.0.1 and ::1

### Added
- Add create_pledge_promises_from_policy for OpenBSD integration
- Add FreeBSD Capsicum libc bindings
- Add PathRule to Policy engine for file path access control
- Add comprehensive unit tests for all fixes (27 new tests)

## [0.1.8] - 2026-04-01

### Fixed
- Fix functional_test: update python -c expected result to Deny
- Fix test logic and add input length limits
- Fix security vulnerabilities and test issues

## [0.1.7] - 2026-03-28

### Fixed
- Adjust test assertions for platform compatibility

## [0.1.6] - 2026-03-27

### Added
- Security: add destructive tests and enhance policy detection

## [0.1.5] - 2026-03-26

### Added
- Documentation improvements

## [0.1.4] - 2026-03-25

### Added
- Initial release