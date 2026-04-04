# Changelog

All notable changes to this project will be documented in this file.

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