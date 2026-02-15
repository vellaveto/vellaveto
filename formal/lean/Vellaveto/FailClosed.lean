/-!
# Fail-Closed Property

Proves that when no policy matches an action, the verdict is Deny.
This is the S1 safety invariant from the TLA+ model
(`formal/tla/MCPPolicyEngine.tla`, InvariantS1_FailClosed).

Models `PolicyEngine::evaluate_action` from
`vellaveto-engine/src/lib.rs:234-296`, specifically lines 293-295:

```rust
Ok(Verdict::Deny {
    reason: "No matching policy".to_string(),
})
```

## Invariant statement

For all actions `a` and policy sets `P`:
if no policy in `P` matches `a`, then `evaluate(P, a) = Deny`.
-/

-- Policy types mirroring vellaveto-types.
-- Defined locally (not imported) so each proof file is self-contained.
inductive Verdict where
  | allow : Verdict
  | deny (reason : String) : Verdict
  | requireApproval (reason : String) : Verdict
  deriving DecidableEq, Repr

inductive PolicyType where
  | allow : PolicyType
  | deny : PolicyType
  | conditional : PolicyType
  deriving DecidableEq, Repr

structure Policy where
  id : String
  priority : Nat
  policyType : PolicyType
  deriving DecidableEq, Repr

structure Action where
  tool : String
  function : String
  deriving DecidableEq, Repr

/-- Abstract matching predicate. -/
variable (matchesAction : Policy → Action → Bool)

/-- Abstract policy application. -/
variable (applyPolicy : Policy → Action → Option Verdict)

/-- First-match evaluation with parameterized matching. -/
def evaluateFirstMatch' (action : Action) : List Policy → Verdict
  | [] => Verdict.deny "No matching policy"
  | p :: ps =>
    if matchesAction p action then
      match applyPolicy p action with
      | some v => v
      | none => evaluateFirstMatch' action ps
    else
      evaluateFirstMatch' action ps

/-! ## S1: Fail-closed on empty policy set -/

/-- With an empty policy list, the verdict is always Deny. -/
theorem s1_empty_policies_deny (action : Action) :
    evaluateFirstMatch' matchesAction applyPolicy action [] =
    Verdict.deny "No matching policy" := by
  rfl

/-! ## S1: Fail-closed when no policy matches -/

/-- When no policy in the list matches the action, the verdict is Deny.
    This is the core fail-closed invariant. -/
theorem s1_no_match_implies_deny
    (action : Action) (policies : List Policy)
    (h_none_match : ∀ p ∈ policies, matchesAction p action = false) :
    evaluateFirstMatch' matchesAction applyPolicy action policies =
    Verdict.deny "No matching policy" := by
  induction policies with
  | nil => rfl
  | cons p ps ih =>
    simp [evaluateFirstMatch']
    have hp := h_none_match p (List.mem_cons_self p ps)
    rw [hp]
    simp
    exact ih (fun q hq => h_none_match q (List.mem_cons_of_mem p hq))

/-! ## S1: Fail-closed when all matching policies return `none` (on_no_match=continue) -/

/-- When every matching policy returns `none` from `applyPolicy`
    (i.e., all are Conditional with unmet conditions), the verdict is still Deny. -/
theorem s1_all_continue_implies_deny
    (action : Action) (policies : List Policy)
    (h_all_none : ∀ p ∈ policies, matchesAction p action = true →
                   applyPolicy p action = none) :
    evaluateFirstMatch' matchesAction applyPolicy action policies =
    Verdict.deny "No matching policy" := by
  induction policies with
  | nil => rfl
  | cons p ps ih =>
    simp [evaluateFirstMatch']
    by_cases hm : matchesAction p action = true
    · rw [hm]; simp
      have := h_all_none p (List.mem_cons_self p ps) hm
      rw [this]
      exact ih (fun q hq hq_match => h_all_none q (List.mem_cons_of_mem p hq) hq_match)
    · simp [Bool.eq_false_iff.mpr (by simp_all : ¬matchesAction p action = true)] at hm ⊢
      rw [hm]; simp
      exact ih (fun q hq hq_match => h_all_none q (List.mem_cons_of_mem p hq) hq_match)

/-! ## Corollary: Allow requires a matching Allow policy (S5) -/

/-- If `evaluate` returns Allow, then there exists a matching policy
    whose application produces Allow. Contrapositive of S1. -/
theorem s5_allow_requires_match
    (action : Action) (policies : List Policy)
    (h_result : evaluateFirstMatch' matchesAction applyPolicy action policies = Verdict.allow)
    : ∃ p ∈ policies, matchesAction p action = true ∧
                       applyPolicy p action = some Verdict.allow := by
  induction policies with
  | nil => simp [evaluateFirstMatch'] at h_result
  | cons p ps ih =>
    simp [evaluateFirstMatch'] at h_result
    by_cases hm : matchesAction p action = true
    · rw [hm] at h_result; simp at h_result
      cases ha : applyPolicy p action with
      | none =>
        rw [ha] at h_result
        obtain ⟨q, hq_mem, hq_match, hq_apply⟩ := ih h_result
        exact ⟨q, List.mem_cons_of_mem p hq_mem, hq_match, hq_apply⟩
      | some v =>
        rw [ha] at h_result
        simp at h_result
        exact ⟨p, List.mem_cons_self p ps, hm, by rw [ha]; exact congrArg some h_result⟩
    · simp [Bool.eq_false_iff.mpr (by simp_all : ¬matchesAction p action = true)] at hm
      rw [hm] at h_result; simp at h_result
      obtain ⟨q, hq_mem, hq_match, hq_apply⟩ := ih h_result
      exact ⟨q, List.mem_cons_of_mem p hq_mem, hq_match, hq_apply⟩
