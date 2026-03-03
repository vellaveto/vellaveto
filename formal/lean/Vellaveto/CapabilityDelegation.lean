/-!
# Capability Delegation Attenuation (S11-S16)

Proves the capability token delegation chain's security properties:
- S11: Monotonic attenuation — child grants subset of parent grants
- S12: Transitive attenuation — holds across entire chains
- S13: Depth bounded — chain length <= root depth
- S14: Temporal monotonicity — child.expires <= parent.expires
- S15: Terminal cannot delegate — depth=0 -> no children
- S16: Issuer chain integrity — child.issuer = parent.holder

Models `vellaveto-mcp/src/capability_token.rs`.

## Correspondence

- Coq: `formal/coq/Vellaveto/CapabilityDelegation.v` (6 theorems)
- Alloy: `formal/alloy/CapabilityDelegation.als` (S11-S16)
-/

-- Capability delegation types mirroring vellaveto-types/src/capability.rs.
-- Defined locally so each proof file is self-contained.

structure Grant where
  toolPattern : String
  funcPattern : String
  depthAllowed : Nat
  deriving DecidableEq, Repr

structure CapToken where
  id : String
  parentId : Option String
  issuer : String
  holder : String
  grants : List Grant
  remainingDepth : Nat
  expires : Nat
  deriving DecidableEq, Repr

/-! ## Grant Subset Relation -/

/-- Abstract grant subset: every permission in `g` is covered by `pg`.
    Axiomatized because the concrete coverage check involves glob matching. -/
axiom grantSubset : Grant -> Grant -> Prop

/-- `grantSubset` is reflexive. -/
axiom grantSubset_refl : ∀ g, grantSubset g g

/-- `grantSubset` is transitive. -/
axiom grantSubset_trans :
  ∀ g1 g2 g3, grantSubset g1 g2 -> grantSubset g2 g3 -> grantSubset g1 g3

/-! ## Attenuation -/

/-- Attenuated: every child grant is covered by some parent grant. -/
def attenuated (child parent : CapToken) : Prop :=
  ∀ g ∈ child.grants, ∃ pg ∈ parent.grants, grantSubset g pg

/-! ## Well-Formed Delegation -/

/-- Structural invariants for a single delegation step.
    Maps to `attenuate_capability_token()`. -/
structure WellFormedDelegation (child parent : CapToken) : Prop where
  parentLink : child.parentId = some parent.id
  issuerChain : child.issuer = parent.holder
  depthPositive : parent.remainingDepth > 0
  depthDecrement : child.remainingDepth = parent.remainingDepth - 1
  expiryBound : child.expires ≤ parent.expires
  grantAttenuation : attenuated child parent

/-! ## Ancestor Chain -/

/-- An ancestor chain is a sequence of well-formed delegations. -/
inductive AncestorChain : CapToken -> List CapToken -> Prop where
  | root : ∀ t, AncestorChain t []
  | step : ∀ child parent rest,
      WellFormedDelegation child parent ->
      AncestorChain parent rest ->
      AncestorChain child (parent :: rest)

/-! ## S11: Monotonic Attenuation -/

/-- Well-formed delegation implies attenuation. -/
theorem s11_monotonic_attenuation (child parent : CapToken)
    (h : WellFormedDelegation child parent) :
    attenuated child parent :=
  h.grantAttenuation

/-! ## S12: Transitive Attenuation -/

/-- Attenuation is transitive. -/
theorem attenuated_trans (t1 t2 t3 : CapToken)
    (h12 : attenuated t1 t2) (h23 : attenuated t2 t3) :
    attenuated t1 t3 := by
  intro g hg
  obtain ⟨pg, hpg_in, hpg_sub⟩ := h12 g hg
  obtain ⟨gpg, hgpg_in, hgpg_sub⟩ := h23 pg hpg_in
  exact ⟨gpg, hgpg_in, grantSubset_trans g pg gpg hpg_sub hgpg_sub⟩

/-- Attenuation holds across entire ancestor chains.
    For any token `t` with ancestor chain, `t` is attenuated
    w.r.t. every ancestor in the chain. -/
theorem s12_transitive_attenuation (t : CapToken) (chain : List CapToken)
    (hchain : AncestorChain t chain)
    (ancestor : CapToken) (h_in : ancestor ∈ chain) :
    attenuated t ancestor := by
  induction hchain with
  | root => exact absurd h_in (List.not_mem_nil ancestor)
  | step child parent rest hwf _hparent ih =>
    cases h_in with
    | head =>
      exact s11_monotonic_attenuation child parent hwf
    | tail _ h_rest =>
      exact attenuated_trans child parent ancestor
        (s11_monotonic_attenuation child parent hwf)
        (ih h_rest)

/-! ## S13: Depth Bounded -/

/-- Well-formed delegation strictly decreases remaining depth. -/
theorem depth_step (child parent : CapToken)
    (hwf : WellFormedDelegation child parent) :
    child.remainingDepth < parent.remainingDepth := by
  have h1 := hwf.depthPositive
  have h2 := hwf.depthDecrement
  omega

/-- Any ancestor in the chain has strictly greater remaining depth
    than the leaf token. Since remaining depth is a natural number,
    this bounds the maximum chain length to the root's remaining depth. -/
theorem s13_depth_bounded (t : CapToken) (chain : List CapToken)
    (hchain : AncestorChain t chain)
    (ancestor : CapToken) (h_in : ancestor ∈ chain) :
    t.remainingDepth < ancestor.remainingDepth := by
  induction hchain with
  | root => exact absurd h_in (List.not_mem_nil ancestor)
  | step child parent rest hwf _hparent ih =>
    cases h_in with
    | head =>
      exact depth_step child parent hwf
    | tail _ h_rest =>
      exact Nat.lt_trans (depth_step child parent hwf) (ih h_rest)

/-! ## S14: Temporal Monotonicity -/

/-- Well-formed delegation implies child.expires <= parent.expires. -/
theorem s14_temporal_monotonicity (child parent : CapToken)
    (hwf : WellFormedDelegation child parent) :
    child.expires ≤ parent.expires :=
  hwf.expiryBound

/-! ## S15: Terminal Cannot Delegate -/

/-- If a token has depth 0, it cannot be a parent in a well-formed
    delegation (no children allowed). -/
theorem s15_terminal_no_children (child parent : CapToken)
    (hzero : parent.remainingDepth = 0) :
    ¬ WellFormedDelegation child parent := by
  intro hwf
  have := hwf.depthPositive
  omega

/-! ## S16: Issuer Chain Integrity -/

/-- Well-formed delegation implies child.issuer = parent.holder. -/
theorem s16_issuer_chain_integrity (child parent : CapToken)
    (hwf : WellFormedDelegation child parent) :
    child.issuer = parent.holder :=
  hwf.issuerChain
