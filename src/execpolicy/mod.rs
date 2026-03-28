//! Execution Policy Engine
//!
//! Provides rule-based execution policy matching for commands.

use std::collections::HashMap;
use std::sync::Arc;

/// Policy decision
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    Prompt,
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

/// Prefix rule for command execution
#[derive(Clone, Debug)]
pub struct PrefixRule {
    pub pattern: PrefixPattern,
    pub decision: Decision,
    pub justification: Option<String>,
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
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Policy")
            .field(
                "rules_by_program",
                &self.rules_by_program.keys().collect::<Vec<_>>(),
            )
            .field("network_rules_count", &self.network_rules.len())
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
        }
    }

    pub fn empty() -> Self {
        Self::new()
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
        let rule: Arc<dyn Rule> = Arc::new(PrefixRule {
            pattern: PrefixPattern {
                first: Arc::from(first.as_str()),
                rest: rest
                    .iter()
                    .map(|s| PatternToken::Literal(s.clone()))
                    .collect(),
            },
            decision,
            justification,
        });

        self.rules_by_program
            .entry(first.clone())
            .or_default()
            .push(rule);

        Ok(())
    }

    /// Check if a command is allowed
    pub fn check(&self, command: &[String]) -> Option<RuleMatch> {
        if command.is_empty() {
            return None;
        }

        let program = &command[0];
        let args = &command[1..];

        // Check program-specific rules
        if let Some(rules) = self.rules_by_program.get(program) {
            for rule in rules {
                if let Some(m) = rule.matches(args) {
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
