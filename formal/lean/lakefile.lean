import Lake
open Lake DSL

package vellaveto where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib Vellaveto where
  srcDir := "."
  roots := #[`Vellaveto.Determinism, `Vellaveto.FailClosed, `Vellaveto.PathNormalization]
