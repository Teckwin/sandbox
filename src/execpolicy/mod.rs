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
            default_decision: Decision::Allow,
            whitelist_mode: false,
        }
    }

    /// Create a new policy with whitelist mode (only allow explicitly listed commands)
    pub fn new_whitelist() -> Self {
        Self {
            rules_by_program: HashMap::new(),
            network_rules: Vec::new(),
            default_decision: Decision::Deny,
            whitelist_mode: true,
        }
    }

    /// Create a new policy with blacklist mode (deny explicitly listed commands)
    pub fn new_blacklist() -> Self {
        Self {
            rules_by_program: HashMap::new(),
            network_rules: Vec::new(),
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
        _restrict_to_directories: bool,
    ) -> Result<(), String> {
        if prefix.is_empty() {
            return Err("prefix cannot be empty".to_string());
        }

        let (first, rest) = prefix.split_first().unwrap();
        let rule: Arc<dyn Rule> = Arc::new(
            PrefixRule::new(
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
            .with_allowed_directories(allowed_directories.unwrap_or_default())
            .with_directory_restriction(),
        );

        self.rules_by_program
            .entry(first.clone())
            .or_default()
            .push(rule);

        Ok(())
    }

    /// Check if a command is allowed (with working directory context)
    pub fn check(&self, command: &[String]) -> Option<RuleMatch> {
        self.check_with_cwd(command, None)
    }

    /// Check if a command is allowed with working directory context
    /// This enables detection of directory bypass attempts
    pub fn check_with_cwd(
        &self,
        command: &[String],
        working_directory: Option<&str>,
    ) -> Option<RuleMatch> {
        if command.is_empty() {
            return None;
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

        // Check program-specific rules
        if let Some(rules) = self.rules_by_program.get(program) {
            for rule in rules {
                if let Some(m) = rule.matches(args) {
                    // Check directory restrictions
                    if let Some(cwd) = working_directory {
                        let prefix_rule = rule.as_any().downcast_ref::<PrefixRule>().unwrap();
                        if prefix_rule.restrict_to_directories {
                            if let Some(ref allowed_dirs) = prefix_rule.allowed_directories {
                                if !allowed_dirs.is_empty()
                                    && !allowed_dirs.iter().any(|d| cwd.starts_with(d))
                                {
                                    return Some(RuleMatch {
                                        decision: Decision::Deny,
                                        justification: Some(
                                            "Command not allowed in current directory".to_string(),
                                        ),
                                    });
                                }
                            }
                        }
                    }
                    return Some(m);
                }
            }
        }

        // Check wildcard rules
        if let Some(rules) = self.rules_by_program.get("*") {
            for rule in rules {
                if let Some(m) = rule.matches(command) {
                    return Some(m);
                }
            }
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
        let cwd_path = Path::new(working_directory);

        for arg in args {
            // Skip options (starting with -)
            if arg.starts_with('-') {
                continue;
            }

            // Check for absolute path bypass attempts
            if arg.starts_with('/') {
                let arg_path = Path::new(arg);
                // If the absolute path is NOT within the working directory, it's a bypass
                // For example, if cwd is /tmp, then /tmp/file.txt is OK but /etc/passwd is not
                if !arg.starts_with(working_directory) && working_directory != "/" {
                    // Additional check: don't block if the path is a subdirectory of cwd
                    let is_subdir = cwd_path
                        .components()
                        .zip(arg_path.components())
                        .take(cwd_path.components().count())
                        .all(|(c1, c2)| c1 == c2);
                    if !is_subdir {
                        return true;
                    }
                }
            }

            // Check for relative path bypass attempts (..)
            if arg.contains("..") {
                return true;
            }
        }

        false
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
                    if args[i] != *s {
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

    #[test]
    fn test_policy_add_rule() {
        let mut policy = Policy::new();
        let result = policy.add_prefix_rule(&["ls".to_string()], Decision::Allow, None);
        assert!(result.is_ok());
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
    fn test_policy_check_denied() {
        let mut policy = Policy::new();
        policy
            .add_prefix_rule(&["rm".to_string()], Decision::Deny, None)
            .unwrap();

        let result = policy.check(&["rm".to_string(), "-rf".to_string()]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, Decision::Deny);
    }
}
