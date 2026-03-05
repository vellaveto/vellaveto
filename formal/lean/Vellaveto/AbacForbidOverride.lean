/-!
# ABAC Forbid-Override Properties (S7-S10)

Proves the ABAC combining algorithm's forbid-override semantics:
- S7:  Forbid dominance — any matching forbid -> Deny
- S8:  Forbid ignores priority — forbid at any position beats permit
- S9:  Permit requires no forbid — Allow -> no matching forbid exists
- S10: No match -> NoMatch

Models `vellaveto-engine/src/abac.rs:322-364`.

The core algorithm: scan sorted policies; the first forbid match
wins immediately (Deny), accumulating the best permit along the way.

## Correspondence

- Coq: `formal/coq/Vellaveto/AbacForbidOverride.v` (4 theorems)
- TLA+: `formal/tla/AbacForbidOverrides.tla` (S7-S10, L3)
- Alloy: `formal/alloy/AbacForbidOverride.als` (S7-S10)
-/

-- ABAC types mirroring vellaveto-engine/src/abac.rs.
-- Defined locally so each proof file is self-contained.

inductive AbacEffect where
  | permit : AbacEffect
  | forbid : AbacEffect
  deriving DecidableEq, Repr

structure AbacPolicy where
  id : String
  effect : AbacEffect
  priority : Nat
  deriving DecidableEq, Repr

inductive AbacDecision where
  | deny (policyId : String) : AbacDecision
  | allow (policyId : String) : AbacDecision
  | noMatch : AbacDecision
  deriving DecidableEq, Repr

section AbacEval

variable (policyMatches : AbacPolicy -> Bool)

/-- Core ABAC combining algorithm: scan policies in order.
    First forbid match -> Deny (immediate exit).
    Accumulate best permit (first-match).
    Maps to `abac.rs:322-364`. -/
def abacEval (policies : List AbacPolicy) (bestPermit : Option String) : AbacDecision :=
  match policies with
  | [] =>
    match bestPermit with
    | some pid => AbacDecision.allow pid
    | none => AbacDecision.noMatch
  | p :: ps =>
    if policyMatches p then
      match p.effect with
      | .forbid => AbacDecision.deny p.id  -- S7: immediate exit
      | .permit =>
        abacEval ps
          (match bestPermit with
           | some _ => bestPermit  -- keep first permit
           | none => some p.id)
    else
      abacEval ps bestPermit

/-! ## S7: Forbid Dominance -/

/-- Helper: if the head is a matching forbid, result is Deny. -/
theorem abacEval_head_forbid (p : AbacPolicy) (ps : List AbacPolicy)
    (bp : Option String) (hm : policyMatches p = true) (he : p.effect = AbacEffect.forbid) :
    abacEval policyMatches (p :: ps) bp = AbacDecision.deny p.id := by
  simp [abacEval, hm, he]

/-- If a matching forbid exists anywhere in the policy list,
    `abacEval` returns `Deny` (for some forbid policy's ID).
    This is the core ABAC invariant: forbid dominance. -/
theorem s7_forbid_dominance
    (policies : List AbacPolicy) (bp : Option String)
    (h : ∃ p ∈ policies, policyMatches p = true ∧ p.effect = AbacEffect.forbid) :
    ∃ pid, abacEval policyMatches policies bp = AbacDecision.deny pid := by
  induction policies with
  | nil =>
    obtain ⟨p, hp, _⟩ := h
    exact absurd hp (List.not_mem_nil p)
  | cons q qs ih =>
    obtain ⟨p, hp_mem, hp_match, hp_eff⟩ := h
    simp [abacEval]
    cases hq : policyMatches q
    · -- q does not match
      simp [hq]
      cases hp_mem with
      | head => rw [hp_match] at hq; exact absurd hq (by simp)
      | tail _ h_in => exact ih bp ⟨p, h_in, hp_match, hp_eff⟩
    · -- q matches
      simp [hq]
      cases hqe : q.effect
      · -- q is permit: forbid must be in tail
        simp [hqe]
        cases hp_mem with
        | head =>
          -- p = q, but q is permit and p is forbid: contradiction
          rw [hp_eff] at hqe; exact absurd hqe (by simp)
        | tail _ h_in =>
          exact ih _ ⟨p, h_in, hp_match, hp_eff⟩
      · -- q is forbid: immediate deny
        exact ⟨q.id, by simp [hqe]⟩

/-! ## S8: Forbid Ignores Priority -/

/-- Forbid at any position beats permit at any position.
    Corollary of S7: if a forbid matches, the result is always Deny
    regardless of where permits appear. -/
theorem s8_forbid_ignores_priority
    (policies : List AbacPolicy) (bp : Option String)
    (pf pp : AbacPolicy)
    (hf_in : pf ∈ policies) (hp_in : pp ∈ policies)
    (hf_match : policyMatches pf = true) (hf_eff : pf.effect = AbacEffect.forbid)
    (_hp_match : policyMatches pp = true) (_hp_eff : pp.effect = AbacEffect.permit) :
    ∃ pid, abacEval policyMatches policies bp = AbacDecision.deny pid :=
  s7_forbid_dominance policyMatches policies bp ⟨pf, hf_in, hf_match, hf_eff⟩

/-! ## S9: Permit Requires No Forbid -/

/-- If `abacEval` returns `Allow`, then no matching forbid exists
    in the policy list. Contrapositive of S7. -/
theorem s9_permit_requires_no_forbid
    (policies : List AbacPolicy) (bp : Option String) (pid : String)
    (hresult : abacEval policyMatches policies bp = AbacDecision.allow pid) :
    ¬ ∃ p ∈ policies, policyMatches p = true ∧ p.effect = AbacEffect.forbid := by
  intro hcontra
  obtain ⟨fid, hfid⟩ := s7_forbid_dominance policyMatches policies bp hcontra
  rw [hfid] at hresult
  exact absurd hresult (by simp [AbacDecision.deny, AbacDecision.allow])

/-! ## S10: No Match -> NoMatch -/

/-- If no policy matches, `abacEval` returns whatever `bestPermit`
    dictates. Starting with `None`, it returns `NoMatch`. -/
theorem s10_no_match_noMatch
    (policies : List AbacPolicy)
    (h_none : ∀ p ∈ policies, policyMatches p = false) :
    abacEval policyMatches policies none = AbacDecision.noMatch := by
  induction policies with
  | nil => rfl
  | cons q qs ih =>
    simp [abacEval]
    have hq := h_none q (List.mem_cons_self q qs)
    rw [hq]; simp
    exact ih (fun p hp => h_none p (List.mem_cons_of_mem q hp))

end AbacEval
