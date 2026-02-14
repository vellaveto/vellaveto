//! ABAC (Attribute-Based Access Control) engine — Cedar-style policy evaluation.
//!
//! Compiles ABAC policies at load time into a fast in-memory representation
//! and evaluates them with forbid-overrides semantics.

use crate::matcher::PatternMatcher;
use sentinel_types::{
    AbacEffect, AbacOp, AbacPolicy, AbacEntity, Action, EvaluationContext,
    RiskScore,
};
use std::collections::HashMap;

/// Maximum transitive group membership depth to prevent cycles.
const MAX_MEMBERSHIP_DEPTH: usize = 16;

// ═══════════════════════════════════════════════════════════════════════════════
// ABAC EVALUATION RESULT
// ═══════════════════════════════════════════════════════════════════════════════

/// Result of ABAC policy evaluation.
#[derive(Debug, Clone, PartialEq)]
pub enum AbacDecision {
    /// An ABAC permit policy matched — allow the action.
    Allow { policy_id: String },
    /// An ABAC forbid policy matched — deny the action.
    Deny { policy_id: String, reason: String },
    /// No ABAC policy matched — fall through to existing verdict.
    NoMatch,
}

/// Conflict between permit and forbid policies on overlapping patterns.
#[derive(Debug, Clone)]
pub struct AbacConflict {
    pub permit_id: String,
    pub forbid_id: String,
    pub overlap_description: String,
}

// ═══════════════════════════════════════════════════════════════════════════════
// EVAL CONTEXT
// ═══════════════════════════════════════════════════════════════════════════════

/// Context for ABAC evaluation — combines EvaluationContext with resolved principal.
pub struct AbacEvalContext<'a> {
    pub eval_ctx: &'a EvaluationContext,
    pub principal_type: &'a str,
    pub principal_id: &'a str,
    pub risk_score: Option<&'a RiskScore>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPILED TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// Compiled principal constraint with pre-built matchers.
struct CompiledPrincipal {
    principal_type: Option<String>,
    id_matchers: Vec<PatternMatcher>,
    claims: Vec<(String, PatternMatcher)>,
}

/// Compiled action constraint with pre-built tool:function matchers.
struct CompiledAction {
    /// Each pattern is "tool:function" split and compiled separately.
    matchers: Vec<(PatternMatcher, PatternMatcher)>,
}

/// Compiled resource constraint with pre-built path/domain matchers.
struct CompiledResource {
    path_matchers: Vec<PatternMatcher>,
    domain_matchers: Vec<PatternMatcher>,
    tags: Vec<String>,
}

/// Compiled ABAC condition — ready for evaluation.
struct CompiledCondition {
    field: String,
    op: AbacOp,
    value: serde_json::Value,
}

/// A fully compiled ABAC policy ready for evaluation.
struct CompiledAbacPolicy {
    id: String,
    effect: AbacEffect,
    priority: i32,
    principal: CompiledPrincipal,
    action: CompiledAction,
    resource: CompiledResource,
    conditions: Vec<CompiledCondition>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENTITY STORE
// ═══════════════════════════════════════════════════════════════════════════════

/// In-memory entity store for ABAC principal/resource attributes.
pub struct EntityStore {
    /// Entities keyed by "Type::id".
    entities: HashMap<String, AbacEntity>,
    /// Group membership: entity_key → parent entity_keys.
    memberships: HashMap<String, Vec<String>>,
}

impl EntityStore {
    /// Build an entity store from config entities.
    pub fn from_config(entities: &[AbacEntity]) -> Self {
        let mut map = HashMap::new();
        let mut memberships = HashMap::new();
        for entity in entities {
            let key = format!("{}::{}", entity.entity_type, entity.id);
            memberships.insert(key.clone(), entity.parents.clone());
            map.insert(key, entity.clone());
        }
        Self {
            entities: map,
            memberships,
        }
    }

    /// Look up an entity by type and ID.
    pub fn lookup(&self, entity_type: &str, id: &str) -> Option<&AbacEntity> {
        let key = format!("{entity_type}::{id}");
        self.entities.get(&key)
    }

    /// Check if an entity is a (transitive) member of a group.
    /// Bounded to MAX_MEMBERSHIP_DEPTH to prevent infinite loops.
    pub fn is_member_of(&self, entity_key: &str, group_key: &str) -> bool {
        self.is_member_of_bounded(entity_key, group_key, 0)
    }

    fn is_member_of_bounded(&self, entity_key: &str, group_key: &str, depth: usize) -> bool {
        if depth >= MAX_MEMBERSHIP_DEPTH {
            return false;
        }
        if let Some(parents) = self.memberships.get(entity_key) {
            for parent in parents {
                if parent == group_key {
                    return true;
                }
                if self.is_member_of_bounded(parent, group_key, depth + 1) {
                    return true;
                }
            }
        }
        false
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ABAC ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

/// The ABAC policy evaluation engine.
///
/// Compiles policies at construction time and evaluates them with
/// forbid-overrides semantics (any matching forbid wins over all permits).
pub struct AbacEngine {
    compiled: Vec<CompiledAbacPolicy>,
    entity_store: EntityStore,
}

impl AbacEngine {
    /// Create an ABAC engine from policies and entities.
    ///
    /// Compiles all policies and builds the entity store. Returns an error
    /// if any policy pattern is invalid.
    pub fn new(
        policies: &[AbacPolicy],
        entities: &[AbacEntity],
    ) -> Result<Self, String> {
        let mut compiled = Vec::with_capacity(policies.len());
        for policy in policies {
            compiled.push(compile_policy(policy)?);
        }
        // Sort by priority descending (higher priority first)
        compiled.sort_by(|a, b| b.priority.cmp(&a.priority));

        let entity_store = EntityStore::from_config(entities);
        Ok(Self {
            compiled,
            entity_store,
        })
    }

    /// Evaluate an action against all ABAC policies.
    ///
    /// Uses forbid-overrides semantics:
    /// 1. Collect matching policies (principal + action + resource + conditions)
    /// 2. If any matching policy is Forbid → Deny
    /// 3. If any matching policy is Permit (and no Forbid) → Allow
    /// 4. If nothing matches → NoMatch (caller decides)
    pub fn evaluate(&self, action: &Action, ctx: &AbacEvalContext<'_>) -> AbacDecision {
        let mut best_permit: Option<&str> = None;
        let mut best_forbid: Option<(&str, String)> = None;

        for policy in &self.compiled {
            if !matches_principal(&policy.principal, ctx, &self.entity_store) {
                continue;
            }
            if !matches_action(&policy.action, action) {
                continue;
            }
            if !matches_resource(&policy.resource, action) {
                continue;
            }
            if !evaluate_conditions(&policy.conditions, ctx) {
                continue;
            }

            match policy.effect {
                AbacEffect::Forbid => {
                    if best_forbid.is_none() {
                        best_forbid = Some((
                            &policy.id,
                            format!("ABAC forbid policy '{}' matched", policy.id),
                        ));
                    }
                }
                AbacEffect::Permit => {
                    if best_permit.is_none() {
                        best_permit = Some(&policy.id);
                    }
                }
            }
        }

        // Forbid-overrides: any forbid wins
        if let Some((id, reason)) = best_forbid {
            return AbacDecision::Deny {
                policy_id: id.to_string(),
                reason,
            };
        }

        if let Some(id) = best_permit {
            return AbacDecision::Allow {
                policy_id: id.to_string(),
            };
        }

        AbacDecision::NoMatch
    }

    /// Get a reference to the entity store.
    pub fn entity_store(&self) -> &EntityStore {
        &self.entity_store
    }

    /// Detect conflicts where permit and forbid policies overlap.
    pub fn find_conflicts(&self) -> Vec<AbacConflict> {
        let mut conflicts = Vec::new();
        let permits: Vec<_> = self
            .compiled
            .iter()
            .filter(|p| p.effect == AbacEffect::Permit)
            .collect();
        let forbids: Vec<_> = self
            .compiled
            .iter()
            .filter(|p| p.effect == AbacEffect::Forbid)
            .collect();

        for permit in &permits {
            for forbid in &forbids {
                if action_patterns_overlap(&permit.action, &forbid.action) {
                    conflicts.push(AbacConflict {
                        permit_id: permit.id.clone(),
                        forbid_id: forbid.id.clone(),
                        overlap_description: format!(
                            "Permit '{}' and Forbid '{}' have overlapping action patterns",
                            permit.id, forbid.id
                        ),
                    });
                }
            }
        }
        conflicts
    }

    /// Return the number of compiled policies.
    pub fn policy_count(&self) -> usize {
        self.compiled.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPILATION
// ═══════════════════════════════════════════════════════════════════════════════

fn compile_policy(policy: &AbacPolicy) -> Result<CompiledAbacPolicy, String> {
    let principal = compile_principal(&policy.principal);
    let action = compile_action(&policy.action);
    let resource = compile_resource(&policy.resource);
    let conditions = policy
        .conditions
        .iter()
        .map(|c| CompiledCondition {
            field: c.field.clone(),
            op: c.op,
            value: c.value.clone(),
        })
        .collect();

    Ok(CompiledAbacPolicy {
        id: policy.id.clone(),
        effect: policy.effect,
        priority: policy.priority,
        principal,
        action,
        resource,
        conditions,
    })
}

fn compile_principal(pc: &sentinel_types::PrincipalConstraint) -> CompiledPrincipal {
    CompiledPrincipal {
        principal_type: pc.principal_type.clone(),
        id_matchers: pc
            .id_patterns
            .iter()
            .map(|p| PatternMatcher::compile(p))
            .collect(),
        claims: pc
            .claims
            .iter()
            .map(|(k, v)| (k.clone(), PatternMatcher::compile(v)))
            .collect(),
    }
}

fn compile_action(ac: &sentinel_types::ActionConstraint) -> CompiledAction {
    let matchers = ac
        .patterns
        .iter()
        .map(|p| {
            if let Some((tool, func)) = p.split_once(':') {
                (PatternMatcher::compile(tool), PatternMatcher::compile(func))
            } else {
                // No colon — treat as tool-only match (any function)
                (PatternMatcher::compile(p), PatternMatcher::compile("*"))
            }
        })
        .collect();
    CompiledAction { matchers }
}

fn compile_resource(rc: &sentinel_types::ResourceConstraint) -> CompiledResource {
    CompiledResource {
        path_matchers: rc
            .path_patterns
            .iter()
            .map(|p| PatternMatcher::compile(p))
            .collect(),
        domain_matchers: rc
            .domain_patterns
            .iter()
            .map(|p| PatternMatcher::compile(p))
            .collect(),
        tags: rc.tags.clone(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MATCHING
// ═══════════════════════════════════════════════════════════════════════════════

fn matches_principal(
    principal: &CompiledPrincipal,
    ctx: &AbacEvalContext<'_>,
    entity_store: &EntityStore,
) -> bool {
    // Type check
    if let Some(ref required_type) = principal.principal_type {
        if required_type != ctx.principal_type {
            // Check group membership: maybe this principal is a member of the required type
            let entity_key = format!("{}::{}", ctx.principal_type, ctx.principal_id);
            let group_key = format!("{}::{}", required_type, ctx.principal_id);
            if entity_key != group_key
                && !entity_store.is_member_of(&entity_key, &group_key)
            {
                return false;
            }
        }
    }

    // ID pattern check
    if !principal.id_matchers.is_empty()
        && !principal
            .id_matchers
            .iter()
            .any(|m| m.matches(ctx.principal_id))
    {
        return false;
    }

    // Claims check
    for (claim_key, pattern) in &principal.claims {
        let claim_value = ctx
            .eval_ctx
            .agent_identity
            .as_ref()
            .and_then(|id| id.claims.get(claim_key))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !pattern.matches(claim_value) {
            return false;
        }
    }

    true
}

fn matches_action(action_constraint: &CompiledAction, action: &Action) -> bool {
    // Empty patterns = match any action
    if action_constraint.matchers.is_empty() {
        return true;
    }
    action_constraint
        .matchers
        .iter()
        .any(|(tool_m, func_m)| tool_m.matches(&action.tool) && func_m.matches(&action.function))
}

fn matches_resource(resource: &CompiledResource, action: &Action) -> bool {
    // Path check: if patterns specified, at least one path must match
    if !resource.path_matchers.is_empty() {
        if action.target_paths.is_empty() {
            return false;
        }
        let any_path_matches = action.target_paths.iter().any(|path| {
            resource.path_matchers.iter().any(|m| m.matches(path))
        });
        if !any_path_matches {
            return false;
        }
    }

    // Domain check: if patterns specified, at least one domain must match
    if !resource.domain_matchers.is_empty() {
        if action.target_domains.is_empty() {
            return false;
        }
        let any_domain_matches = action.target_domains.iter().any(|domain| {
            resource.domain_matchers.iter().any(|m| m.matches(domain))
        });
        if !any_domain_matches {
            return false;
        }
    }

    // Tags check: all tags must be present (checked against action parameters)
    // Tags are metadata labels — for now we check if they appear as parameter keys
    if !resource.tags.is_empty() {
        if let Some(params) = action.parameters.as_object() {
            for tag in &resource.tags {
                if !params.contains_key(tag) {
                    return false;
                }
            }
        } else {
            return false;
        }
    }

    true
}

fn evaluate_conditions(conditions: &[CompiledCondition], ctx: &AbacEvalContext<'_>) -> bool {
    conditions.iter().all(|c| evaluate_single_condition(c, ctx))
}

fn evaluate_single_condition(condition: &CompiledCondition, ctx: &AbacEvalContext<'_>) -> bool {
    let field_value = resolve_field(&condition.field, ctx);
    match condition.op {
        AbacOp::Eq => field_value == condition.value,
        AbacOp::Ne => field_value != condition.value,
        AbacOp::In => {
            if let Some(arr) = condition.value.as_array() {
                arr.contains(&field_value)
            } else {
                false
            }
        }
        AbacOp::NotIn => {
            if let Some(arr) = condition.value.as_array() {
                !arr.contains(&field_value)
            } else {
                true
            }
        }
        AbacOp::Contains => {
            if let (Some(haystack), Some(needle)) =
                (field_value.as_str(), condition.value.as_str())
            {
                haystack.contains(needle)
            } else {
                false
            }
        }
        AbacOp::StartsWith => {
            if let (Some(s), Some(prefix)) =
                (field_value.as_str(), condition.value.as_str())
            {
                s.starts_with(prefix)
            } else {
                false
            }
        }
        AbacOp::Gt => compare_numbers(&field_value, &condition.value, |a, b| a > b),
        AbacOp::Lt => compare_numbers(&field_value, &condition.value, |a, b| a < b),
        AbacOp::Gte => compare_numbers(&field_value, &condition.value, |a, b| a >= b),
        AbacOp::Lte => compare_numbers(&field_value, &condition.value, |a, b| a <= b),
    }
}

fn compare_numbers(a: &serde_json::Value, b: &serde_json::Value, cmp: fn(f64, f64) -> bool) -> bool {
    match (a.as_f64(), b.as_f64()) {
        (Some(av), Some(bv)) => cmp(av, bv),
        _ => false,
    }
}

fn resolve_field(field: &str, ctx: &AbacEvalContext<'_>) -> serde_json::Value {
    match field {
        "principal.type" => serde_json::Value::String(ctx.principal_type.to_string()),
        "principal.id" => serde_json::Value::String(ctx.principal_id.to_string()),
        "risk.score" => ctx
            .risk_score
            .map(|r| serde_json::json!(r.score))
            .unwrap_or(serde_json::Value::Null),
        "context.agent_id" => ctx
            .eval_ctx
            .agent_id
            .as_ref()
            .map(|s| serde_json::Value::String(s.clone()))
            .unwrap_or(serde_json::Value::Null),
        "context.tenant_id" => ctx
            .eval_ctx
            .tenant_id
            .as_ref()
            .map(|s| serde_json::Value::String(s.clone()))
            .unwrap_or(serde_json::Value::Null),
        "context.call_chain_depth" => {
            serde_json::json!(ctx.eval_ctx.call_chain_depth())
        }
        _ => {
            // Try to resolve from agent identity claims: "claims.<key>"
            if let Some(claim_key) = field.strip_prefix("claims.") {
                ctx.eval_ctx
                    .agent_identity
                    .as_ref()
                    .and_then(|id| id.claims.get(claim_key).cloned())
                    .unwrap_or(serde_json::Value::Null)
            } else {
                serde_json::Value::Null
            }
        }
    }
}

/// Check if two action constraints could match the same action.
fn action_patterns_overlap(a: &CompiledAction, b: &CompiledAction) -> bool {
    // Empty patterns match everything, so they always overlap
    if a.matchers.is_empty() || b.matchers.is_empty() {
        return true;
    }
    // Check pairwise — conservative: if any pair could overlap, report it
    for (at, af) in &a.matchers {
        for (bt, bf) in &b.matchers {
            if patterns_could_overlap(at, bt) && patterns_could_overlap(af, bf) {
                return true;
            }
        }
    }
    false
}

/// Conservative check: could two pattern matchers match the same string?
fn patterns_could_overlap(a: &PatternMatcher, b: &PatternMatcher) -> bool {
    match (a, b) {
        (PatternMatcher::Any, _) | (_, PatternMatcher::Any) => true,
        (PatternMatcher::Exact(x), PatternMatcher::Exact(y)) => x == y,
        (PatternMatcher::Exact(e), PatternMatcher::Prefix(p))
        | (PatternMatcher::Prefix(p), PatternMatcher::Exact(e)) => e.starts_with(p.as_str()),
        (PatternMatcher::Exact(e), PatternMatcher::Suffix(s))
        | (PatternMatcher::Suffix(s), PatternMatcher::Exact(e)) => e.ends_with(s.as_str()),
        // For prefix/suffix/prefix-prefix/suffix-suffix, conservatively assume overlap
        _ => true,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_types::*;

    fn make_action(tool: &str, function: &str) -> Action {
        Action {
            tool: tool.to_string(),
            function: function.to_string(),
            parameters: serde_json::json!({}),
            target_paths: Vec::new(),
            target_domains: Vec::new(),
            resolved_ips: Vec::new(),
        }
    }

    fn make_action_with_paths(tool: &str, function: &str, paths: Vec<&str>) -> Action {
        Action {
            tool: tool.to_string(),
            function: function.to_string(),
            parameters: serde_json::json!({}),
            target_paths: paths.into_iter().map(String::from).collect(),
            target_domains: Vec::new(),
            resolved_ips: Vec::new(),
        }
    }

    fn make_action_with_domains(tool: &str, function: &str, domains: Vec<&str>) -> Action {
        Action {
            tool: tool.to_string(),
            function: function.to_string(),
            parameters: serde_json::json!({}),
            target_paths: Vec::new(),
            target_domains: domains.into_iter().map(String::from).collect(),
            resolved_ips: Vec::new(),
        }
    }

    fn make_permit_policy(id: &str, tool_pattern: &str) -> AbacPolicy {
        AbacPolicy {
            id: id.to_string(),
            description: format!("Permit {}", id),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: ActionConstraint {
                patterns: vec![tool_pattern.to_string()],
            },
            resource: Default::default(),
            conditions: vec![],
        }
    }

    fn make_forbid_policy(id: &str, tool_pattern: &str) -> AbacPolicy {
        AbacPolicy {
            id: id.to_string(),
            description: format!("Forbid {}", id),
            effect: AbacEffect::Forbid,
            priority: 0,
            principal: Default::default(),
            action: ActionConstraint {
                patterns: vec![tool_pattern.to_string()],
            },
            resource: Default::default(),
            conditions: vec![],
        }
    }

    fn make_ctx<'a>(
        eval_ctx: &'a EvaluationContext,
        principal_type: &'a str,
        principal_id: &'a str,
    ) -> AbacEvalContext<'a> {
        AbacEvalContext {
            eval_ctx,
            principal_type,
            principal_id,
            risk_score: None,
        }
    }

    fn make_engine(policies: Vec<AbacPolicy>) -> AbacEngine {
        AbacEngine::new(&policies, &[]).unwrap()
    }

    #[test]
    fn test_compile_valid_policies() {
        let engine = make_engine(vec![make_permit_policy("p1", "filesystem:read*")]);
        assert_eq!(engine.policy_count(), 1);
    }

    #[test]
    fn test_compile_empty_policies() {
        let engine = make_engine(vec![]);
        assert_eq!(engine.policy_count(), 0);
    }

    #[test]
    fn test_evaluate_permit_matches() {
        let engine = make_engine(vec![make_permit_policy("p1", "filesystem:read*")]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "test-agent");
        let action = make_action("filesystem", "read_file");

        match engine.evaluate(&action, &ctx) {
            AbacDecision::Allow { policy_id } => assert_eq!(policy_id, "p1"),
            other => panic!("Expected Allow, got {:?}", other),
        }
    }

    #[test]
    fn test_evaluate_forbid_overrides_permit() {
        let engine = make_engine(vec![
            make_permit_policy("permit-all", "*:*"),
            make_forbid_policy("forbid-bash", "bash:*"),
        ]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        let action = make_action("bash", "execute");

        match engine.evaluate(&action, &ctx) {
            AbacDecision::Deny { policy_id, .. } => assert_eq!(policy_id, "forbid-bash"),
            other => panic!("Expected Deny, got {:?}", other),
        }
    }

    #[test]
    fn test_evaluate_no_match_returns_nomatch() {
        let engine = make_engine(vec![make_permit_policy("p1", "filesystem:read*")]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        let action = make_action("network", "fetch");

        assert_eq!(engine.evaluate(&action, &ctx), AbacDecision::NoMatch);
    }

    #[test]
    fn test_evaluate_principal_type_match() {
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "Only for Agents".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: PrincipalConstraint {
                principal_type: Some("Agent".to_string()),
                id_patterns: vec![],
                claims: HashMap::new(),
            },
            action: ActionConstraint {
                patterns: vec!["*:*".to_string()],
            },
            resource: Default::default(),
            conditions: vec![],
        };
        let engine = make_engine(vec![policy]);
        let eval_ctx = EvaluationContext::default();

        // Agent matches
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        assert!(matches!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::Allow { .. }
        ));

        // Service doesn't match
        let ctx = make_ctx(&eval_ctx, "Service", "test");
        assert_eq!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::NoMatch
        );
    }

    #[test]
    fn test_evaluate_principal_id_glob() {
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "code-* agents".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: PrincipalConstraint {
                principal_type: None,
                id_patterns: vec!["code-*".to_string()],
                claims: HashMap::new(),
            },
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![],
        };
        let engine = make_engine(vec![policy]);
        let eval_ctx = EvaluationContext::default();

        let ctx = make_ctx(&eval_ctx, "Agent", "code-assistant");
        assert!(matches!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::Allow { .. }
        ));

        let ctx = make_ctx(&eval_ctx, "Agent", "data-pipeline");
        assert_eq!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::NoMatch
        );
    }

    #[test]
    fn test_evaluate_principal_claims_match() {
        let mut claims = HashMap::new();
        claims.insert("team".to_string(), "security*".to_string());

        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "security team".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: PrincipalConstraint {
                principal_type: None,
                id_patterns: vec![],
                claims,
            },
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![],
        };
        let engine = make_engine(vec![policy]);

        // Matching claim
        let mut identity_claims = HashMap::new();
        identity_claims.insert("team".to_string(), serde_json::json!("security-ops"));
        let eval_ctx = EvaluationContext {
            agent_identity: Some(AgentIdentity {
                claims: identity_claims,
                ..Default::default()
            }),
            ..Default::default()
        };
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        assert!(matches!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::Allow { .. }
        ));

        // Non-matching claim
        let mut identity_claims = HashMap::new();
        identity_claims.insert("team".to_string(), serde_json::json!("engineering"));
        let eval_ctx = EvaluationContext {
            agent_identity: Some(AgentIdentity {
                claims: identity_claims,
                ..Default::default()
            }),
            ..Default::default()
        };
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        assert_eq!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::NoMatch
        );
    }

    #[test]
    fn test_evaluate_action_tool_function_match() {
        let engine = make_engine(vec![make_permit_policy("p1", "filesystem:write_file")]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "test");

        // Exact match
        assert!(matches!(
            engine.evaluate(&make_action("filesystem", "write_file"), &ctx),
            AbacDecision::Allow { .. }
        ));
        // Different function
        assert_eq!(
            engine.evaluate(&make_action("filesystem", "read_file"), &ctx),
            AbacDecision::NoMatch
        );
    }

    #[test]
    fn test_evaluate_action_wildcard() {
        let engine = make_engine(vec![make_permit_policy("p1", "*:*")]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "test");

        assert!(matches!(
            engine.evaluate(&make_action("anything", "anything"), &ctx),
            AbacDecision::Allow { .. }
        ));
    }

    #[test]
    fn test_evaluate_resource_path_match() {
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "home dir only".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: ResourceConstraint {
                path_patterns: vec!["/home/*".to_string()],
                domain_patterns: vec![],
                tags: vec![],
            },
            conditions: vec![],
        };
        let engine = make_engine(vec![policy]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "test");

        // Matching path
        let action = make_action_with_paths("fs", "read", vec!["/home/user/file.txt"]);
        assert!(matches!(
            engine.evaluate(&action, &ctx),
            AbacDecision::Allow { .. }
        ));

        // Non-matching path
        let action = make_action_with_paths("fs", "read", vec!["/etc/passwd"]);
        assert_eq!(engine.evaluate(&action, &ctx), AbacDecision::NoMatch);

        // No paths at all → fails resource match
        let action = make_action("fs", "read");
        assert_eq!(engine.evaluate(&action, &ctx), AbacDecision::NoMatch);
    }

    #[test]
    fn test_evaluate_resource_domain_match() {
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "example.com only".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: ResourceConstraint {
                path_patterns: vec![],
                domain_patterns: vec!["*example.com".to_string()],
                tags: vec![],
            },
            conditions: vec![],
        };
        let engine = make_engine(vec![policy]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "test");

        let action = make_action_with_domains("net", "fetch", vec!["api.example.com"]);
        assert!(matches!(
            engine.evaluate(&action, &ctx),
            AbacDecision::Allow { .. }
        ));
    }

    #[test]
    fn test_evaluate_resource_tags_match() {
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "tagged resources".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: ResourceConstraint {
                path_patterns: vec![],
                domain_patterns: vec![],
                tags: vec!["sensitive".to_string()],
            },
            conditions: vec![],
        };
        let engine = make_engine(vec![policy]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "test");

        let mut action = make_action("fs", "read");
        action.parameters = serde_json::json!({"sensitive": true, "path": "/tmp"});
        assert!(matches!(
            engine.evaluate(&action, &ctx),
            AbacDecision::Allow { .. }
        ));

        // Missing tag
        let mut action = make_action("fs", "read");
        action.parameters = serde_json::json!({"path": "/tmp"});
        assert_eq!(engine.evaluate(&action, &ctx), AbacDecision::NoMatch);
    }

    #[test]
    fn test_evaluate_condition_eq() {
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "tenant check".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![AbacCondition {
                field: "context.tenant_id".to_string(),
                op: AbacOp::Eq,
                value: serde_json::json!("acme"),
            }],
        };
        let engine = make_engine(vec![policy]);

        let eval_ctx = EvaluationContext {
            tenant_id: Some("acme".to_string()),
            ..Default::default()
        };
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        assert!(matches!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::Allow { .. }
        ));

        let eval_ctx = EvaluationContext {
            tenant_id: Some("other".to_string()),
            ..Default::default()
        };
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        assert_eq!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::NoMatch
        );
    }

    #[test]
    fn test_evaluate_condition_in() {
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "tenant in list".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![AbacCondition {
                field: "context.tenant_id".to_string(),
                op: AbacOp::In,
                value: serde_json::json!(["acme", "globex"]),
            }],
        };
        let engine = make_engine(vec![policy]);

        let eval_ctx = EvaluationContext {
            tenant_id: Some("acme".to_string()),
            ..Default::default()
        };
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        assert!(matches!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::Allow { .. }
        ));
    }

    #[test]
    fn test_evaluate_condition_starts_with() {
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "agent prefix".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![AbacCondition {
                field: "context.agent_id".to_string(),
                op: AbacOp::StartsWith,
                value: serde_json::json!("prod-"),
            }],
        };
        let engine = make_engine(vec![policy]);

        let eval_ctx = EvaluationContext {
            agent_id: Some("prod-agent-1".to_string()),
            ..Default::default()
        };
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        assert!(matches!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::Allow { .. }
        ));
    }

    #[test]
    fn test_evaluate_condition_gt_lt() {
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "low risk only".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![AbacCondition {
                field: "risk.score".to_string(),
                op: AbacOp::Lt,
                value: serde_json::json!(0.5),
            }],
        };
        let engine = make_engine(vec![policy]);

        let risk = RiskScore {
            score: 0.3,
            factors: vec![],
            updated_at: "2026-02-14T00:00:00Z".to_string(),
        };
        let eval_ctx = EvaluationContext::default();
        let ctx = AbacEvalContext {
            eval_ctx: &eval_ctx,
            principal_type: "Agent",
            principal_id: "test",
            risk_score: Some(&risk),
        };
        assert!(matches!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::Allow { .. }
        ));

        let risk = RiskScore {
            score: 0.8,
            factors: vec![],
            updated_at: "2026-02-14T00:00:00Z".to_string(),
        };
        let ctx = AbacEvalContext {
            eval_ctx: &eval_ctx,
            principal_type: "Agent",
            principal_id: "test",
            risk_score: Some(&risk),
        };
        assert_eq!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::NoMatch
        );
    }

    #[test]
    fn test_evaluate_multiple_conditions_all_must_pass() {
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "both conditions".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![
                AbacCondition {
                    field: "context.tenant_id".to_string(),
                    op: AbacOp::Eq,
                    value: serde_json::json!("acme"),
                },
                AbacCondition {
                    field: "context.agent_id".to_string(),
                    op: AbacOp::Eq,
                    value: serde_json::json!("agent-1"),
                },
            ],
        };
        let engine = make_engine(vec![policy]);

        // Both match
        let eval_ctx = EvaluationContext {
            tenant_id: Some("acme".to_string()),
            agent_id: Some("agent-1".to_string()),
            ..Default::default()
        };
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        assert!(matches!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::Allow { .. }
        ));

        // Only one matches
        let eval_ctx = EvaluationContext {
            tenant_id: Some("acme".to_string()),
            agent_id: Some("agent-2".to_string()),
            ..Default::default()
        };
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        assert_eq!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::NoMatch
        );
    }

    #[test]
    fn test_evaluate_priority_ordering() {
        // Higher priority permit should be reported even if lower priority forbid exists
        // But forbid-overrides means forbid always wins regardless of priority
        let engine = make_engine(vec![
            AbacPolicy {
                id: "high-permit".to_string(),
                description: "high priority permit".to_string(),
                effect: AbacEffect::Permit,
                priority: 100,
                principal: Default::default(),
                action: ActionConstraint {
                    patterns: vec!["*:*".to_string()],
                },
                resource: Default::default(),
                conditions: vec![],
            },
            AbacPolicy {
                id: "low-forbid".to_string(),
                description: "low priority forbid".to_string(),
                effect: AbacEffect::Forbid,
                priority: 1,
                principal: Default::default(),
                action: ActionConstraint {
                    patterns: vec!["*:*".to_string()],
                },
                resource: Default::default(),
                conditions: vec![],
            },
        ]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "test");

        // Forbid wins even with lower priority
        match engine.evaluate(&make_action("any", "any"), &ctx) {
            AbacDecision::Deny { policy_id, .. } => assert_eq!(policy_id, "low-forbid"),
            other => panic!("Expected Deny, got {:?}", other),
        }
    }

    #[test]
    fn test_evaluate_fail_closed_missing_principal() {
        // Policy requires specific principal type, context has different type
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "admins only".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: PrincipalConstraint {
                principal_type: Some("Admin".to_string()),
                id_patterns: vec![],
                claims: HashMap::new(),
            },
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![],
        };
        let engine = make_engine(vec![policy]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "anonymous");

        // No match → fail-closed at the caller
        assert_eq!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::NoMatch
        );
    }

    #[test]
    fn test_entity_store_lookup() {
        let entities = vec![AbacEntity {
            entity_type: "Agent".to_string(),
            id: "agent-1".to_string(),
            attributes: HashMap::new(),
            parents: vec![],
        }];
        let store = EntityStore::from_config(&entities);
        assert!(store.lookup("Agent", "agent-1").is_some());
        assert!(store.lookup("Agent", "nonexistent").is_none());
    }

    #[test]
    fn test_entity_store_group_membership() {
        let entities = vec![
            AbacEntity {
                entity_type: "Group".to_string(),
                id: "admins".to_string(),
                attributes: HashMap::new(),
                parents: vec![],
            },
            AbacEntity {
                entity_type: "Agent".to_string(),
                id: "agent-1".to_string(),
                attributes: HashMap::new(),
                parents: vec!["Group::admins".to_string()],
            },
        ];
        let store = EntityStore::from_config(&entities);
        assert!(store.is_member_of("Agent::agent-1", "Group::admins"));
        assert!(!store.is_member_of("Agent::agent-1", "Group::operators"));
    }

    #[test]
    fn test_entity_store_transitive_membership_bounded() {
        // Chain: a → b → c → d (transitive)
        let entities = vec![
            AbacEntity {
                entity_type: "G".to_string(),
                id: "d".to_string(),
                attributes: HashMap::new(),
                parents: vec![],
            },
            AbacEntity {
                entity_type: "G".to_string(),
                id: "c".to_string(),
                attributes: HashMap::new(),
                parents: vec!["G::d".to_string()],
            },
            AbacEntity {
                entity_type: "G".to_string(),
                id: "b".to_string(),
                attributes: HashMap::new(),
                parents: vec!["G::c".to_string()],
            },
            AbacEntity {
                entity_type: "A".to_string(),
                id: "a".to_string(),
                attributes: HashMap::new(),
                parents: vec!["G::b".to_string()],
            },
        ];
        let store = EntityStore::from_config(&entities);
        assert!(store.is_member_of("A::a", "G::d"));
        assert!(store.is_member_of("A::a", "G::b"));
    }

    #[test]
    fn test_find_conflicts_none() {
        let engine = make_engine(vec![
            make_permit_policy("p1", "filesystem:*"),
            make_forbid_policy("f1", "bash:*"),
        ]);
        assert!(engine.find_conflicts().is_empty());
    }

    #[test]
    fn test_find_conflicts_detected() {
        let engine = make_engine(vec![
            make_permit_policy("p1", "*:*"),
            make_forbid_policy("f1", "bash:*"),
        ]);
        let conflicts = engine.find_conflicts();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].permit_id, "p1");
        assert_eq!(conflicts[0].forbid_id, "f1");
    }

    #[test]
    fn test_evaluate_with_risk_score_threshold() {
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "low risk".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![AbacCondition {
                field: "risk.score".to_string(),
                op: AbacOp::Lte,
                value: serde_json::json!(0.5),
            }],
        };
        let engine = make_engine(vec![policy]);

        let risk = RiskScore {
            score: 0.5,
            factors: vec![],
            updated_at: "2026-02-14T00:00:00Z".to_string(),
        };
        let eval_ctx = EvaluationContext::default();
        let ctx = AbacEvalContext {
            eval_ctx: &eval_ctx,
            principal_type: "Agent",
            principal_id: "test",
            risk_score: Some(&risk),
        };
        assert!(matches!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::Allow { .. }
        ));
    }

    #[test]
    fn test_evaluate_condition_ne_not_in() {
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "not in blocklist".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![
                AbacCondition {
                    field: "context.tenant_id".to_string(),
                    op: AbacOp::Ne,
                    value: serde_json::json!("blocked"),
                },
                AbacCondition {
                    field: "context.agent_id".to_string(),
                    op: AbacOp::NotIn,
                    value: serde_json::json!(["evil-agent", "bad-agent"]),
                },
            ],
        };
        let engine = make_engine(vec![policy]);

        let eval_ctx = EvaluationContext {
            tenant_id: Some("acme".to_string()),
            agent_id: Some("good-agent".to_string()),
            ..Default::default()
        };
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        assert!(matches!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::Allow { .. }
        ));

        let eval_ctx = EvaluationContext {
            tenant_id: Some("blocked".to_string()),
            agent_id: Some("good-agent".to_string()),
            ..Default::default()
        };
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        assert_eq!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::NoMatch
        );
    }
}
