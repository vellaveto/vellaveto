# MCPSEC Scoring Rubric

## Tier Definitions

| Tier | Score | Name | Meaning |
|------|-------|------|---------|
| 0 | 0-19% | Unsafe | No meaningful security controls. Gateway provides tool routing only. |
| 1 | 20-39% | Basic | Allowlist-based access control. No parameter inspection, injection detection, or audit integrity. |
| 2 | 40-59% | Moderate | Some parameter inspection or injection detection, but significant gaps in coverage. |
| 3 | 60-79% | Strong | Injection detection + DLP + audit, but missing Unicode normalization, schema integrity, or delegation controls. |
| 4 | 80-94% | Comprehensive | Full threat coverage with minor gaps. All major attack classes addressed. |
| 5 | 95-100% | Hardened | All 10 security properties verified. Production-grade security for AI agent deployments. |

## Property Weights

The overall score is a weighted average of the 10 property scores:

| Property | Weight | Rationale |
|----------|--------|-----------|
| **P1** Tool-Level Access Control | 15% | Foundation property. Without deny-by-default, nothing else matters. |
| **P2** Parameter Constraint Enforcement | 12% | Deep inspection is what separates real security from allowlist theater. |
| **P3** Priority Monotonicity | 5% | Policy correctness. Important but lower attack surface. |
| **P4** Injection Resistance | 15% | Primary threat vector. Prompt injection is the #1 AI agent risk. |
| **P5** Schema Integrity | 10% | Supply chain defense. Rug-pulls are unique to MCP. |
| **P6** Response Confidentiality | 12% | Data exfiltration prevention. Multi-layer encoding is the differentiator. |
| **P7** Audit Immutability | 10% | Forensic and compliance. Required for EU AI Act, SOC 2. |
| **P8** Delegation Monotonicity | 8% | Privilege escalation prevention. Critical for multi-agent systems. |
| **P9** Unicode Normalization | 8% | Evasion resistance. Without this, P4 and P5 are bypassable. |
| **P10** Temporal Consistency | 5% | Operational correctness. Rate limiting and time windows. |
| **Total** | **100%** | |

## Score Calculation

### Per-Property Score

Each property's score is the percentage of associated test cases that pass:

```
property_score(Pi) = tests_passed(Pi) / tests_total(Pi) * 100
```

Tests map to properties as defined in [ATTACKS.md](ATTACKS.md).

### Overall Score

```
overall_score = Σ (property_score(Pi) * weight(Pi)) for i in 1..10
```

### Tier Assignment

The tier is determined by the overall score using the thresholds defined above.

## Test-to-Property Mapping

| Test | Properties |
|------|------------|
| A1.1-A1.15 | P4, P9 |
| A2.1-A2.7 | P5 |
| A3.1-A3.6 | P1, P2 |
| A4.1-A4.9 | P6 |
| A5.1-A5.5 | P1, P2, P3, P8 |
| A6.1-A6.5 | P4, P6 |
| A7.1-A7.5 | P5, P9 |
| A8.1-A8.4 | P7 |
| A9.1-A9.8 | P2 |
| A10.1-A10.4 | P10 |
| A11.1-A11.3 | P2, P6 |
| A12.1-A12.3 | P1, P4 |
| A13.1-A13.4 | P6 |
| A14.1-A14.4 | P5 |

When a test maps to multiple properties, a pass counts toward all mapped properties.

## Expected Results (Reference)

Based on documented capabilities of known MCP gateways:

| Gateway | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 | P9 | P10 | Overall | Tier |
|---------|----|----|----|----|----|----|----|----|----|----|---------|------|
| **Vellaveto v6.0** | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | **100** | **5** |
| MintMCP | 60 | 0 | ? | 0 | 0 | 0 | 20 | 0 | 0 | ? | ~10 | 0 |
| Lasso | 60 | 0 | ? | 10 | 0 | 20 | 20 | 0 | 0 | ? | ~12 | 0 |
| Docker MCP GW | 50 | 0 | ? | 10 | 0 | 30 | 30 | 0 | 0 | ? | ~14 | 0 |
| AWS AgentCore | 70 | 20 | ? | 15 | 0 | 0 | 40 | 0 | 0 | ? | ~18 | 0 |
| Palo Alto | 60 | 10 | ? | 30 | 20 | 20 | 30 | 0 | 0 | ? | ~20 | 1 |
| Gopher | 60 | ? | ? | 30 | ? | ? | ? | ? | ? | ? | ~15 | 0 |

**Note:** Scores marked with `?` indicate capabilities that could not be verified from public documentation. These gateways should be benchmarked directly for accurate results.
