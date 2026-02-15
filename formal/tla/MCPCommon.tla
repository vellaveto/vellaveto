--------------------------- MODULE MCPCommon ---------------------------
(**************************************************************************)
(* Shared operators for Vellaveto formal specifications.                  *)
(*                                                                        *)
(* Maps to:                                                               *)
(*   - PatternMatcher in vellaveto-engine/src/matcher.rs                  *)
(*   - sort_policies() in vellaveto-engine/src/lib.rs:209-224            *)
(*                                                                        *)
(* Design decision: Pattern matching is abstracted to wildcard ("*") and  *)
(* exact matching only. Full glob/regex correctness is already covered    *)
(* by 22 fuzz targets. The security properties we verify here are about   *)
(* evaluation ordering and fail-closed semantics, not pattern compilation.*)
(**************************************************************************)
EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    Tools,          \* Set of tool identifiers (e.g., {"fs", "net", "exec"})
    Functions,      \* Set of function identifiers (e.g., {"read", "write", "list"})
    Paths,          \* Set of path identifiers (e.g., {"/home", "/etc", "/tmp"})
    Domains,        \* Set of domain identifiers (e.g., {"a.com", "b.com", "c.com"})
    Wildcard        \* Distinguished element representing "*" (matches everything)

(**************************************************************************)
(* PatternMatch: Abstract glob/regex matching                             *)
(*                                                                        *)
(* Models the glob_match() function at capability_token.rs:433-462 and    *)
(* the pattern matching in matcher.rs. Abstracted to two cases:           *)
(*   1. Wildcard matches everything                                       *)
(*   2. Exact value matches only itself                                   *)
(*                                                                        *)
(* This is sound for the properties we verify: if a property holds with   *)
(* abstract matching, it holds with any refinement (concrete glob/regex). *)
(**************************************************************************)
PatternMatch(pattern, value) ==
    \/ pattern = Wildcard       \* Wildcard matches everything
    \/ pattern = value          \* Exact match

(**************************************************************************)
(* PathMatch / DomainMatch: Specialized matching for paths and domains    *)
(*                                                                        *)
(* In the implementation, path matching involves normalization (removing   *)
(* "..", null bytes, etc.) and domain matching involves case folding.      *)
(* At the abstraction level of this spec, both reduce to PatternMatch.    *)
(**************************************************************************)
PathMatch(path, pattern) == PatternMatch(pattern, path)
DomainMatch(domain, pattern) == PatternMatch(pattern, domain)

(**************************************************************************)
(* PolicyType: The three policy types in the engine                       *)
(*                                                                        *)
(* Maps to PolicyType enum in vellaveto-types/src/core.rs                 *)
(**************************************************************************)
PolicyTypes == {"Allow", "Deny", "Conditional"}

(**************************************************************************)
(* PolicyRecord: A single policy entry                                    *)
(*                                                                        *)
(* Fields:                                                                *)
(*   .id        - Unique policy identifier (string)                       *)
(*   .priority  - Integer priority (higher = evaluated first)             *)
(*   .type      - "Allow" | "Deny" | "Conditional"                       *)
(*   .tool      - Tool pattern (Wildcard or specific tool)                *)
(*   .function  - Function pattern (Wildcard or specific function)        *)
(*   .blocked_paths   - Set of blocked path patterns                      *)
(*   .allowed_paths   - Set of allowed path patterns                      *)
(*   .blocked_domains - Set of blocked domain patterns                    *)
(*   .allowed_domains - Set of allowed domain patterns                    *)
(*   .on_no_match     - "deny" | "continue" (for Conditional only)        *)
(*   .requires_context - BOOLEAN (does this policy need eval context?)    *)
(**************************************************************************)

(**************************************************************************)
(* IsDenyType: Helper to check if a policy type is Deny                   *)
(*                                                                        *)
(* Used in sort tiebreaker: at equal priority, deny policies come first.  *)
(* Maps to sort_policies() deny-first logic at lib.rs:213-216.           *)
(**************************************************************************)
IsDenyType(ptype) == IF ptype = "Deny" THEN 1 ELSE 0

(**************************************************************************)
(* SortedByPriority: Predicate asserting a sequence of policies is        *)
(* correctly sorted according to the engine's evaluation order.           *)
(*                                                                        *)
(* Maps to sort_policies() at vellaveto-engine/src/lib.rs:209-224:       *)
(*   1. Priority descending (higher priority evaluated first)             *)
(*   2. At equal priority: deny-first (deny before allow/conditional)     *)
(*   3. At equal priority and type: lexicographic by policy ID            *)
(*                                                                        *)
(* The implementation uses Rust's sort_by with a three-level comparator.  *)
(* This predicate checks that every adjacent pair satisfies the ordering. *)
(**************************************************************************)
SortedByPriority(pols) ==
    \A i \in 1..(Len(pols) - 1) :
        LET a == pols[i]
            b == pols[i + 1]
        IN
            \/ a.priority > b.priority
            \/ /\ a.priority = b.priority
               /\ IsDenyType(a.type) > IsDenyType(b.type)
            \/ /\ a.priority = b.priority
               /\ IsDenyType(a.type) = IsDenyType(b.type)
               /\ a.id < b.id  \* TLC uses lexicographic ordering on strings

(**************************************************************************)
(* MatchesAction: Does a policy match a given action?                     *)
(*                                                                        *)
(* An action matches a policy if both the tool pattern and function       *)
(* pattern match. This is the first filter before path/network/context    *)
(* rules are checked.                                                     *)
(*                                                                        *)
(* Maps to matches_action() in vellaveto-engine/src/lib.rs               *)
(**************************************************************************)
MatchesAction(policy, action) ==
    /\ PatternMatch(policy.tool, action.tool)
    /\ PatternMatch(policy.function, action.function)

(**************************************************************************)
(* CheckPathRules: Evaluate path rules for an action against a policy     *)
(*                                                                        *)
(* Invariant: blocked paths ALWAYS override allowed paths.                *)
(* Maps to check_path_rules() in vellaveto-engine/src/rule_check.rs:50-59*)
(*                                                                        *)
(* Returns: "deny" if any target path matches a blocked pattern           *)
(*          "allow" if all target paths match an allowed pattern           *)
(*          "skip" if no path rules apply (empty sets)                    *)
(**************************************************************************)
CheckPathRules(policy, action) ==
    LET blocked == policy.blocked_paths
        allowed == policy.allowed_paths
        targets == action.target_paths
    IN
        IF targets = {} THEN "skip"
        ELSE IF \E p \in targets : \E bp \in blocked : PathMatch(p, bp)
             THEN "deny"     \* Blocked overrides allowed (S3)
        ELSE IF allowed # {} /\ \A p \in targets : \E ap \in allowed : PathMatch(p, ap)
             THEN "allow"
        ELSE IF allowed # {}
             THEN "deny"     \* Path not in allow list → deny
        ELSE "skip"          \* No path rules configured

(**************************************************************************)
(* CheckDomainRules: Evaluate domain rules for an action against a policy *)
(*                                                                        *)
(* Invariant: blocked domains ALWAYS override allowed domains.            *)
(* Maps to check_network_rules() in vellaveto-engine/src/rule_check.rs   *)
(*   :124-133                                                             *)
(*                                                                        *)
(* Returns: "deny" if any target domain matches a blocked pattern         *)
(*          "allow" if all target domains match an allowed pattern         *)
(*          "skip" if no domain rules apply                               *)
(**************************************************************************)
CheckDomainRules(policy, action) ==
    LET blocked == policy.blocked_domains
        allowed == policy.allowed_domains
        targets == action.target_domains
    IN
        IF targets = {} THEN "skip"
        ELSE IF \E d \in targets : \E bd \in blocked : DomainMatch(d, bd)
             THEN "deny"     \* Blocked overrides allowed (S4)
        ELSE IF allowed # {} /\ \A d \in targets : \E ad \in allowed : DomainMatch(d, ad)
             THEN "allow"
        ELSE IF allowed # {}
             THEN "deny"     \* Domain not in allow list → deny
        ELSE "skip"          \* No domain rules configured

=========================================================================
