# VELLAVETO → FOUNDATION: STRICT DEPLOYMENT PLAN
## Italy-First Market Entry | Q2 2026 – Q1 2028

---

## PREMISE

**Vellaveto** (6,293 tests, 52 audit rounds, v4.0.0-dev) is commercially ready. **Foundation** (v0.1.0 alpha, 2,252 tests) needs 12–18 more months of development. The plan: Vellaveto generates revenue under Italy's regime forfettario (~3.35% effective tax year 1), funding Foundation to maturity.

**Hard constraints:**
- EU AI Act full enforcement — **August 2, 2026**
- NIS2 implementation (D.Lgs. 138/2024) — **18-month compliance window** from entity notification
- DORA — **applicable since January 2025** for financial entities
- Only **6% of large Italian companies** consider themselves AI Act compliant
- **Zero competitors** in MCP security exist in Italy

---

## MARKET REALITY

### Italy: total whitespace

Italy's cybersecurity market reached **€2.48 billion** in 2024 (+15% YoY). The AI market reached **€1.8 billion** in 2025 (+50% YoY), with **71% of large enterprises** running AI projects. Agentic AI represents **4%** of the market — at the inflection point between experimentation and production.

**No Italian company works on MCP security, AI agent governance, or tool-call security.** No international MCP security vendor has Italian presence. Vellaveto would be:
- The only Italian MCP security product in existence
- The only European open-source MCP runtime security engine
- The only AI agent firewall with native EU AI Act compliance (Art 50, Art 10, Art 12, Art 14, Art 43)
- The only solution combining OWASP Agentic Top 10, CoSAI 38/38, Adversa 25/25, and formal verification

### Positioning

**Control plane di sicurezza e compliance per tool-calls** with three verifiable promises:
1. **Policy enforcement** — every tool call evaluated against configurable rules
2. **Tamper-evident audit trail** — SHA-256 hash chain + Ed25519 checkpoints + Merkle proofs
3. **Compliance evidence factory** — NIS2, EU AI Act, DORA, SOC 2, ISO 42001 reporting

### Key buying signals

- **Banking leads AI agent deployment**: Intesa Sanpaolo (150+ AI apps), UniCredit (10-year Google Cloud deal), Generali (~50 AI agents)
- **Banking cybersecurity spend**: €483M/year. Manufacturing: €454.9M/year
- **Shadow AI**: 80% of Italian workers use non-company AI tools
- **PA**: 100%+ growth in AI spending, 120 AI projects across 45 public entities
- **MCP adoption**: Liquid Reply (AAIF member) using MCP in client projects; Openapi SpA launched 400+ Italian business data APIs via MCP

### Competitive landscape

| Competitor | Type | MCP-Native | Audit Trail | EU AI Act | Italian Presence |
|-----------|------|-----------|------------|----------|-----------------|
| Prompt Security | AI gateway | Partial | No | No | No |
| Lakera Guard | AI firewall | No | No | No | No |
| Traefik Labs | MCP gateway | Yes | Partial | No | No |
| Cloudflare | Zero Trust MCP | Partial | No | No | Yes (CDN) |
| Kong | API→MCP gateway | Partial | No | No | No |
| IBM MCP Context Forge | MCP gateway | Yes | No | No | Yes (IBM Italy) |
| OPA/Styra | Policy engine | No | No | No | No |
| **Vellaveto** | **MCP firewall** | **Full (3 transports)** | **Tamper-evident** | **Art 5–50** | **Built in Italy** |

---

## PRICING (Dual-Track)

### Track 1: International Self-Serve (Paddle)

| Tier | Price | Limits |
|------|-------|--------|
| Community (AGPL) | Free | 5 servers, 3 users, single-node |
| Pro | $149/month (≤10 servers, $29/server above) | 25 servers, 20 users |
| Enterprise | Custom | Unlimited |

### Track 2: Italian Enterprise (Stripe Direct Invoicing)

| Tier | Target | Price (€/year) | Metric |
|------|--------|----------------|--------|
| Pro | PMI / enterprise pilot | €18,000–€36,000 | up to X tool-call/s |
| Business | Regulated mid-market | €60,000–€120,000 | per environment + volume |
| Enterprise | PA / energy / finance | €150,000–€300,000+ | per entity + HA |
| Compliance-as-a-Service | Audit / compliance | €25,000–€80,000 | per audit cycle |

### Feature Gating

| Feature | Community | Pro | Business | Enterprise |
|---------|-----------|-----|----------|-----------|
| Core policy engine | Yes | Yes | Yes | Yes |
| Ed25519 audit trail | Yes | Yes | Yes | Yes |
| CLI management | Yes | Yes | Yes | Yes |
| Web dashboard | No | Yes | Yes | Yes |
| OIDC SSO | No | Yes | Yes | Yes |
| SAML SSO + SCIM | No | No | Yes | Yes |
| Team RBAC | No | Yes | Yes | Yes |
| Fine-grained RBAC | No | No | No | Yes |
| Audit export (JSON/webhook) | No | Yes | Yes | Yes |
| SIEM connectors (Splunk/Elastic) | No | No | Yes | Yes |
| NIS2 evidence pack | No | No | Yes | Yes |
| AI Act evidence factory | No | No | Yes | Yes |
| Incident reporting workflow | No | No | Yes | Yes |
| Compliance dashboards | No | No | Yes | Yes |
| Multi-tenancy (MSP) | No | No | No | Yes |
| HA clustering | No | No | No | Yes |
| Dedicated support (30min P1 SLA) | No | No | No | Yes |
| Air-gapped deployment | No | No | No | Yes |

---

## PHASE 0: LEGAL & FISCAL FOUNDATION (March–April 2026)
**Duration:** 6 weeks | **Cost:** ~€500–€1,500

| # | Action | Deadline | Blocker |
|---|--------|----------|---------|
| 0.1 | Open Partita IVA — ATECO 62.01.00, regime forfettario | Mar 15 | None |
| 0.2 | Register PEC (certified email) + digital signature | Mar 15 | 0.1 |
| 0.3 | Open business bank account (Qonto or Finom) | Mar 20 | 0.1 |
| 0.4 | Configure Paddle as MoR for self-serve sales (handles global VAT) | Mar 31 | 0.3 |
| 0.5 | Configure Stripe for B2B enterprise invoicing | Mar 31 | 0.3 |
| 0.6 | Draft CLA (Contributor License Agreement) — block external PRs until signed | Mar 31 | None |
| 0.7 | Register `vellaveto.com` domain + transactional email (Resend/Postmark) | Mar 20 | None |
| 0.8 | Set up INPS gestione separata (50% reduction first 3 years) | Apr 15 | 0.1 |
| 0.9 | Register as **startup innovativa** in Registro Imprese | Mar 31 | 0.1 |
| 0.10 | Register trademark "Vellaveto" at UIBM | Apr 30 | 0.1 |

**Tax structure:**
- Revenue × 67% = taxable base
- 5% sostitutiva tax (first 5 years)
- INPS ~24% on taxable base (50% reduction years 1–3)
- **Effective rate: ~11.4% on €85K ceiling**

**Startup innovativa benefits:** 65% IRPEF investor tax deduction, simplified access to Fondo di Garanzia, equity crowdfunding rights, favorable stock option treatment.

**Exit criterion:** Partita IVA active, payment rails live, CLA drafted, startup innovativa registered.

---

## PHASE 1: VELLAVETO AGPL LAUNCH + NIS2 POSITIONING (April–May 2026)
**Duration:** 6 weeks | **Revenue target:** €0 (adoption phase)

| # | Action | Deadline | Depends on |
|---|--------|----------|------------|
| 1.1 | Complete Phase 24 (EU AI Act Art 50(2) + Art 10) | Apr 15 | None |
| 1.2 | Complete Phase 25 (MCP June 2026 spec) | Apr 30 | Spec publication |
| 1.3 | Publish `vellaveto` crate to crates.io | May 1 | 1.1 |
| 1.4 | Publish Python SDK to PyPI | May 1 | 1.3 |
| 1.5 | Publish Docker image to GHCR + Docker Hub | May 1 | 1.3 |
| 1.6 | Ship landing page at vellaveto.com (pricing, compliance, docs) | May 5 | 0.7 |
| 1.7 | Launch Discord community | May 5 | None |
| 1.8 | Execute "Show HN" post (Tue–Thu, 14:00–15:00 UTC) | May 6–8 | 1.6 |
| 1.9 | Publish on **Developers Italia** (developers.italia.it) | May 15 | 1.3 |
| 1.10 | Begin **ACN cloud qualification** process | May 15 | 0.1 |
| 1.11 | NIS2 evidence mapping (D.Lgs. 138/2024 controls → Vellaveto features) | May 15 | None |
| 1.12 | Submit CFP to **Security Summit Milan** (Clusit) | May 15 | None |

**Targets:** 1,000+ GitHub stars, 100+ Discord members, 50+ Docker pulls, Developers Italia listing live.

**Exit criterion:** AGPL edition live on all registries, NIS2 mapping published, community seeded.

---

## PHASE 2: COMPLIANCE MARKETING + FIRST PARTNERS (May–July 2026)
**Duration:** 8 weeks | **Revenue target:** €0–€5K MRR

| # | Action | Deadline | Depends on |
|---|--------|----------|------------|
| 2.1 | Publish "EU AI Act compliance for AI agent deployments" guide (IT + EN) | May 15 | 1.1 |
| 2.2 | Publish "NIS2 evidence generation with Vellaveto" guide | May 30 | 1.11 |
| 2.3 | Procurement kit v1 (capitolato tecnico, SLA/penali, exit strategy) | Jun 1 | None |
| 2.4 | Approach **Liquid Reply** for technology partnership (already uses MCP) | Jun 1 | 1.3 |
| 2.5 | Approach **Spike Reply** for security channel partnership | Jun 15 | 2.4 |
| 2.6 | Submit to TIM Enterprise **Cybersecurity Made in Italy Challenge** | Jun 15 | None |
| 2.7 | Apply to **CyberXcelerator** (CDP VC/Leonardo accelerator, Cosenza) | Jun 15 | 0.9 |
| 2.8 | Apply to **Smart&Start Italia** via Invitalia (up to €1.5M zero-interest) | Jun 30 | 0.9 |
| 2.9 | Offer 3–5 free design partner deployments to Italian enterprises | Jun 1 | 1.3 |
| 2.10 | Contact ACN for Cyber Innovation Network inclusion | Jun 15 | 1.10 |
| 2.11 | Incident reporting builder (pre-notifica 24h / notifica 72h / relazione 1M) | Jun 15 | None |
| 2.12 | Engage **United Ventures** and **Neva SGR** for seed conversations | Jun 30 | 0.9 |

**Target organizations (in priority order):**

1. **Liquid Reply** — already using MCP, AAIF member, natural technology partner
2. **Spike Reply** — security arm of Reply, vendor-agnostic, AI capabilities
3. **TIM Enterprise / Telsy** — Made in Italy cybersecurity program, massive distribution
4. **Intesa Sanpaolo** (via Innovation Center / AI Lab) — largest bank, 150+ AI apps
5. **CDP Venture Capital** — AI Fund + CyberXcelerator for funding + acceleration
6. **Engineering / Cybertech** — largest Italian SI, PA and banking dominance
7. **ACN** — regulatory relationship + Cyber Innovation Network
8. **UniCredit** — Google Cloud AI partnership, active agent deployment
9. **CY4GATE** — potential OEM/integration partner
10. **Consip** — pre-position for Q3 2026 AI mega-tender

**Exit criterion:** 3+ design partners deployed, 2+ compliance guides published, 1+ SI partnership initiated.

---

## PHASE 3: COMMERCIAL LAUNCH (July–September 2026)
**Duration:** 12 weeks | **Revenue target:** €5K–€15K MRR

| # | Action | Deadline | Depends on |
|---|--------|----------|------------|
| 3.1 | Build Pro tier web dashboard (policy management, real-time monitoring) | Jul 15 | None |
| 3.2 | Implement OIDC SSO (Okta, Google Workspace, Azure Entra ID) | Jul 30 | None |
| 3.3 | Implement team RBAC with predefined roles | Jul 30 | None |
| 3.4 | Implement audit log export (JSON + webhooks) + SIEM connectors (Splunk/Elastic) | Aug 1 | None |
| 3.5 | AI Act evidence factory (Art 11–12 logging + istruzioni d'uso package) | Aug 1 | None |
| 3.6 | NIS2 evidence pack (mapping controls + evidence + CDA checklist) | Aug 1 | 1.11 |
| 3.7 | Launch Pro tier via Paddle ($149/month) + Italian enterprise via Stripe (€18K+/year) | Aug 2 | 3.1–3.6 |
| 3.8 | **EU AI Act enforcement date — August 2, 2026** | Aug 2 | — |
| 3.9 | Convert design partners to paid subscriptions | Aug 15 | 3.7 |
| 3.10 | Policy library: regulated sector presets (PA, finance, health, energy) | Sep 1 | None |
| 3.11 | Reference architecture on qualified cloud (blueprint for PA deploy) | Sep 1 | None |
| 3.12 | Present at **RomHack** (September, English, travel covered) | Sep | None |
| 3.13 | Partner program v1 for MSP/SI (onboarding kit + playbook) | Sep 15 | None |

**Exit criterion:** Commercial product live (both tracks), 5+ paying customers, first Italian enterprise contract signed.

---

## PHASE 4: ENTERPRISE + PA READINESS (October–December 2026)
**Duration:** 12 weeks | **Revenue target:** €15K–€25K MRR

| # | Action | Deadline | Depends on |
|---|--------|----------|------------|
| 4.1 | Implement SAML SSO + SCIM auto-provisioning | Oct 15 | None |
| 4.2 | Implement multi-tenancy (MSP mode) | Nov 15 | None |
| 4.3 | Complete ACN cloud qualification | Nov 1 | 1.10 |
| 4.4 | Launch Enterprise tier (€150K+/year) | Nov 1 | 4.1–4.2 |
| 4.5 | Present at **Cybertech Europe Rome** (premier B2B cybersecurity event) | Oct | None |
| 4.6 | Present at **No Hat** (Bergamo, October) | Oct | None |
| 4.7 | Submit response to Consip AI tender pre-commercial engagement | Nov 1 | 4.3 |
| 4.8 | Formalize Reply/Spike Reply channel partnership | Nov 15 | 2.5 |
| 4.9 | First dual-license sales ($10K–$50K/year by company size) | Dec 1 | 0.6 |
| 4.10 | Launch Compliance-as-a-Service (€25K–€80K per audit cycle) | Dec 1 | 3.5, 3.6 |
| 4.11 | Pursue SOC 2 Type I compliance for Vellaveto itself | Dec 31 | None |
| 4.12 | Secure SDLC + supply chain controls documentation | Dec 31 | None |

**Revenue mix target:**
- 40% Italian enterprise contracts (€6K–€10K MRR)
- 25% International Pro subscriptions (€3.75K–€6.25K MRR)
- 20% Compliance-as-a-Service (€3K–€5K MRR)
- 15% Dual-license + consulting (€2.25K–€3.75K MRR)

**Exit criterion:** Enterprise tier live, ACN qualified, 10+ paying customers, first PA pipeline.

---

## PHASE 5: FOUNDATION FUNDING UNLOCKED (January–June 2027)
**Duration:** 24 weeks | **Revenue target:** €25K+ MRR

At €25K MRR with ~80% margin:
- **Gross:** €300K/year
- **Tax:** transition to SRL required (exceeds €85K forfettario ceiling)
- **Net (post-SRL):** ~€180K–€200K → funds Foundation + first hire

| # | Action | Deadline | Depends on |
|---|--------|----------|------------|
| 5.1 | Transition to SRL + activate Patent Box (110% R&D super-deduction) | Jan 15 | Revenue > €85K |
| 5.2 | Allocate 40% development time to Foundation | Jan 1 | Revenue ≥ €15K MRR |
| 5.3 | Complete Foundation CLI Phase 2 (wire LLM providers, Ollama + OpenAI) | Feb 28 | 5.2 |
| 5.4 | Complete Foundation web Phase 2 (Meilisearch, Hocuspocus, MinIO) | Apr 30 | 5.2 |
| 5.5 | Launch Vellaveto Cloud beta (managed service) | Mar 31 | None |
| 5.6 | Close seed funding round (if applicable — CyberXcelerator/CDP VC) | Mar 31 | 2.7, 2.12 |
| 5.7 | Hire first developer (when MRR > €20K) | Q1 2027 | Revenue |
| 5.8 | Foundation CLI v0.2.0 release | Jun 30 | 5.3 |
| 5.9 | Foundation web alpha launch (invite-only, Italian user base first) | Jun 30 | 5.4 |
| 5.10 | Target 5 paying enterprise customers | Jun 30 | 4.4 |

---

## PHASE 6: SCALING (July 2027 – March 2028)
**Duration:** 36 weeks | **Revenue target:** €50K+ MRR

| # | Action | Deadline | Depends on |
|---|--------|----------|------------|
| 6.1 | Vellaveto Cloud GA | Jul 2027 | 5.5 |
| 6.2 | SOC 2 Type II certification | Sep 2027 | 4.11 |
| 6.3 | Foundation web public launch (open registration) | Sep 2027 | 5.9 |
| 6.4 | AWS + Azure Marketplace listings | Oct 2027 | 6.1 |
| 6.5 | EUCC readiness assessment (Common Criteria gap analysis) | Nov 2027 | None |
| 6.6 | Complete Phases 41 (Post-Quantum Crypto) + 42 (Benchmark Paper) | Dec 2027 | None |
| 6.7 | Foundation CLI v1.0.0 (stable release) | Mar 2028 | 5.8 |
| 6.8 | Establish advisory board (Clusit members, former ACN officials) | Q1 2028 | Network |

---

## 30/60/90/180-DAY ITALIAN MARKET ENTRY

### Days 1–30: Foundation and positioning
- Register Partita IVA + startup innovativa
- Publish AGPL edition on GitHub + Developers Italia
- Submit CFP to Security Summit Milan (Clusit)
- Apply to CyberXcelerator (CDP VC/Leonardo, Cosenza)
- Begin ACN cloud qualification
- Write Italian-language MCP security brief for Cybersecurity360.it / AI4Business.it

### Days 31–60: First partnerships and funding
- Approach Liquid Reply for technical partnership
- Submit to TIM Enterprise Cybersecurity Made in Italy Challenge
- Apply to Smart&Start Italia via Invitalia (up to €1.5M zero-interest)
- Schedule meetings with CDP VC AI Fund team
- Submit CFP to RomHack (September) and No Hat (October)
- Engage United Ventures and Neva SGR for seed conversations

### Days 61–90: Customer pipeline and community
- Italian-language compliance documentation
- Run proof-of-concept with one banking customer (Intesa Sanpaolo or UniCredit)
- Present at HackInBo
- Engage I3P (Politecnico di Torino) for incubation + academic credibility
- Begin V-Valley/Esprinet distributor conversations
- Publish Clusit Report-style MCP security risk analysis

### Days 91–180: Scale and institutional positioning
- Present at Cybertech Europe Rome (October)
- Complete ACN cloud qualification
- Formalize Reply/Spike Reply channel partnership
- Submit to Consip pre-commercial engagement for AI tender
- Close seed funding round
- Target 5 paying enterprise customers
- Apply for SERICS (€116M PNRR cybersecurity partnership) research collaboration

---

## CRITICAL PATH TIMELINE

```
2026
 Mar ─── Phase 0: Partita IVA + startup innovativa + payment rails
 Apr ─── Phase 1: AGPL launch + Developers Italia + NIS2 mapping
 May ─── Phase 1: HN launch + ACN qualification started
 Jun ─── Phase 2: Reply partnership + CyberXcelerator + design partners
 Jul ─── Phase 3: Build Pro + Business tiers + compliance packs
 Aug ─── Phase 3: COMMERCIAL LAUNCH + EU AI Act enforcement ← BIGGEST TRIGGER
 Sep ─── Phase 3: RomHack + partner program + convert design partners
 Oct ─── Phase 4: Cybertech Rome + No Hat + enterprise tier
 Nov ─── Phase 4: ACN qualified + Consip tender + enterprise launch
 Dec ─── Phase 4: €15K–€25K MRR target + Compliance-as-a-Service

2027
 Jan ─── Phase 5: SRL transition + Foundation dev begins (40% time)
 Mar ─── Phase 5: Vellaveto Cloud beta + first hire
 Jun ─── Phase 5: Foundation CLI v0.2.0 + web alpha
 Sep ─── Phase 6: Foundation public launch + SOC 2 Type II
 Dec ─── Phase 6: €50K+ MRR

2028
 Mar ─── Phase 6: Foundation v1.0.0 stable
```

---

## REVENUE MILESTONES & DECISION GATES

| Gate | Trigger | Decision |
|------|---------|----------|
| G1 | First Italian enterprise contract | Validate enterprise pricing model |
| G2 | €5K MRR | Begin Business/Enterprise tier development |
| G3 | €15K MRR | Allocate 40% time to Foundation |
| G4 | €85K annual revenue | Transition to SRL (mandatory — forfettario ceiling) |
| G5 | €20K MRR | Hire first developer |
| G6 | €25K MRR | Foundation is sustainable — increase to 50% time |
| G7 | €50K MRR | Second hire + Vellaveto Cloud GA |

---

## REGULATORY FRAMEWORK

### NIS2 (D.Lgs. 138/2024)
- **Governance shift**: board-level accountability for cybersecurity measures
- **37 measures / 87 requirements** for important entities; **43 measures / 116 requirements** for essential entities
- **Incident notification**: pre-notification 24h, notification 72h, final report 1 month
- **Sanctions**: up to €10M or 2% worldwide turnover (essential entities)
- **Vellaveto angle**: "evidence machine" — policy enforcement + logging + incident workflow + export

### EU AI Act (L. 132/2025 + Reg. 2024/1689)
- **High-risk AI**: automatic event logging, documentation, human oversight mechanisms
- **PA requirements**: transparency and traceability of AI use, AI as support tool only
- **Vellaveto angle**: tool-call ledger for tracciabilita, accountability, and control evidence

### DORA (Reg. 2022/2554)
- **Applicable since January 2025** for financial entities
- **Vellaveto angle**: control plane producing evidence of control and logging

### PA Cloud Qualification (ACN)
- Strategic data → sovereign Italian infrastructure
- Critical data → encrypted EU-hosted solutions
- Cloud services must be in ACN catalog for valid PA contracts

### CAD Articles 68–69
- PA must evaluate open-source before purchasing proprietary
- AgID guidelines mandate publicly funded software released as open source
- AGPL-3.0 explicitly covered in AgID licensing guide
- **73% of Italian enterprises** use open-source software

---

## IP STRATEGY

1. **Trademark**: Register "Vellaveto" at UIBM (Phase 0.10)
2. **Trade secrets**: Policy library, scoring heuristics, adversarial test datasets, compliance report templates — protected under D.Lgs. 63/2018 (trade secrets directive)
3. **CLA**: Apache ICLA-style for contributor code relicensing rights
4. **Patent Box**: 110% super-deduction on R&D costs when transitioning to SRL (Phase 5.1)
5. **AI training opt-out**: Reserved under EU CDSM Directive Article 4 and EU AI Act Article 53

---

## RISK REGISTER

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| EU AI Act interpretation ambiguity | Over/under-engineering | High | Ship configurable verbosity; track EU AI Office guidance |
| Zero Italian conversions by month 6 | Cash flow crisis | Medium | Pivot to consulting (€150/hr); Compliance-as-a-Service as bridge |
| Microsoft MCP GW goes free | Price pressure | Low | Vellaveto's security depth (ABAC, ZK, formal verification, NIS2 evidence) unreplicable |
| Revenue exceeds €85K before SRL ready | Tax penalty | Medium | Monitor monthly; engage commercialista at €70K |
| SI partner delays | Slower pipeline | Medium | Maintain direct sales channel; don't depend on single partner |
| PA procurement cycles (6–18 months) | Delayed revenue | High | Parallel international self-serve revenue; PA as long-term pipeline |
| Styra trap (free edition too complete) | No conversions | High | **SSO, RBAC, SIEM, NIS2 evidence, compliance dashboards = paid** |
| Burnout (solo developer) | Everything stops | Medium | Strict 40hr/week cap; hire at G5 (€20K MRR) |

---

## STRICT RULES

1. **Never spend money before revenue.** Infrastructure runs on free tiers until G1.
2. **Italy first, EU second, US third.** Build case studies locally before going global.
3. **Vellaveto funds Foundation, never the reverse.** Foundation gets zero investment until G3.
4. **Ship weekly.** Every Monday: one release, one blog post, or one integration.
5. **Feature-gate ruthlessly.** Individual developer features = free. Team/compliance features = paid.
6. **No hiring before €20K MRR.** Solo until proven sustainable.
7. **Monitor the €85K ceiling monthly.** SRL transition must be planned, not reactive.
8. **Dual-track pricing.** International self-serve (Paddle) + Italian enterprise (Stripe direct). Never conflate.
9. **Compliance is the product.** NIS2 evidence, AI Act logging, DORA reporting = highest-margin features.
10. **Made in Italy.** Sovereignty narrative is the most powerful weapon in regulated Italian sectors.
