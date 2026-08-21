# PromptGuard Enterprise: AI-Powered Content Threat Detection and Prevention Platform

**Document type:** Product requirements, architecture, security, implementation, and delivery blueprint  
**Version:** 1.0  
**Status:** Proposed target state  
**Audience:** Executive sponsors, product managers, enterprise/security architects, developers, AI/ML engineers, SRE, privacy, compliance, and security operations  
**Planning horizon:** 18–24 months  

> This is a reference architecture, not a certification or legal conclusion. Each deployment must complete jurisdiction-, sector-, and use-case-specific privacy, safety, records, labor, and AI impact assessments with qualified counsel and auditors.

---

## 1. Executive summary

PromptGuard Enterprise is a tenant-isolated, cloud-native control plane and data plane for inspecting content before it enters an AI system, enterprise repository, collaboration channel, or outbound response. It analyzes text, documents, images, video, audio, email, web pages, social content, RAG sources, prompts, tool inputs, model outputs, and attachments; correlates findings; calculates contextual risk; and executes an explicit policy decision: **allow, allow with transformation, warn, hold for review, quarantine, or block**.

The platform is not a single classifier. It is a defense-in-depth pipeline combining:

- deterministic signatures, parsers, allow/deny lists, data classification, and malware scanning;
- specialized ML models for language, vision, audio, deepfake, manipulation, toxicity, and anomaly detection;
- LLM-assisted semantic analysis constrained to structured findings and isolated from enforcement;
- contextual signals such as user, application, data classification, destination, model/tool privileges, and threat intelligence;
- a versioned policy engine that produces reproducible, explainable decisions;
- human review and incident workflows for uncertain or high-impact cases.

The recommended deployment provides a synchronous gateway for latency-sensitive text and API traffic, an asynchronous event pipeline for large or multimodal content, regional storage and processing for residency, and a management plane for policy, model, evidence, analytics, and integrations.

### 1.1 Business outcomes

- Reduce successful prompt injection, data exfiltration, phishing, unsafe content, and malicious-file exposure.
- Enforce consistent AI, privacy, DLP, acceptable-use, and records policies across channels.
- Give SOC, privacy, and AI governance teams one evidence-backed operating picture.
- Safely accelerate AI adoption through reusable guardrails and integration SDKs.
- Produce auditable decisions with policy/model/rule versions, evidence lineage, and reviewer actions.

### 1.2 Product principles

1. **Content is untrusted by default.** Retrieved documents, OCR, transcripts, metadata, URLs, and model output are data—not instructions.
2. **Deterministic enforcement.** Models emit findings; a versioned policy engine decides actions.
3. **Least privilege and minimum retention.** Scan with only required access and avoid storing raw content unless policy requires it.
4. **Explainability with evidence.** Every decision includes reason codes, contributing findings, confidence, and applied policy version.
5. **Fail safely by context.** High-risk privileged AI/tool flows fail closed; lower-risk workflows may fail open with alerting when explicitly approved.
6. **Human authority for consequential ambiguity.** Reviewers can release, redact, escalate, or override with a reason; no silent autonomous learning from overrides.
7. **Provider independence.** Detection and enforcement contracts remain stable while models, clouds, and security products can change.
8. **Continuous evaluation.** Model/rule releases pass regression, adversarial, bias, privacy, and operational gates.

---

## 2. Scope, assumptions, and success measures

### 2.1 In scope

- Inbound and outbound content scanning at upload, API, email, chat, web, collaboration, RAG ingestion/retrieval, and AI prompt/output boundaries.
- Files: PDF, DOCX, PPTX, XLSX, TXT, CSV, common archive types, images, audio, and video.
- Detection, classification, scoring, policy enforcement, transformation, quarantine, investigation, reporting, and threat-intelligence lifecycle.
- SaaS, dedicated single-tenant, private cloud, and hybrid data-plane patterns.
- Connectors for AI providers/frameworks, Microsoft 365, SIEM/SOAR, DLP, identity, ticketing, and object stores.

### 2.2 Explicit non-goals for MVP

- Replacing endpoint antivirus/EDR, secure email gateways, CASB/SSE, enterprise DLP, or SIEM.
- Guaranteeing that all deepfakes, hallucinations, or novel prompt attacks are detected.
- Automatically deleting source-system content.
- Training foundation models on tenant content by default.
- Claiming compliance solely because the product is deployed.

### 2.3 Service-level objectives

| Measure | MVP target | Enterprise target |
|---|---:|---:|
| Synchronous text scan availability | 99.9% | 99.95% regional |
| Management plane availability | 99.5% | 99.9% |
| Text p95 latency, payload ≤32 KB | <500 ms | <250 ms excluding external providers |
| Small document p95, ≤10 MB | <30 s | <15 s |
| Event acceptance durability | 99.99% | 99.999% |
| RPO / RTO | 15 min / 4 h | 5 min / 1 h |
| Policy-decision reproducibility | 100% | 100% |
| Critical-event alert delivery | <2 min | <60 s |

### 2.4 Security and product KPIs

- Precision, recall, F1, false-positive rate, and false-negative rate by detector/category/language/modality.
- Attack success rate against the protected system before and after controls.
- Mean time to detect, acknowledge, contain, and resolve; quarantine release time.
- Percentage of decisions with complete provenance and evidence lineage.
- Scanner bypass/failure rate, policy drift, model drift, queue age, and connector health.
- Percentage of privileged AI flows protected by input, retrieval, tool, and output controls.
- Reviewer agreement rate and override rate by policy.
- Sensitive-data exposure prevented, bytes/tokens redacted, and repeat offenders/campaigns correlated.

---

## 3. Users, personas, and journeys

| Persona | Goal | Primary capabilities |
|---|---|---|
| SOC analyst | Triage credible threats quickly | Alert queue, evidence, timeline, search, case actions, SIEM/SOAR |
| AI security engineer | Prevent model and agent abuse | Prompt/output policies, attack library, adversarial tests, tool-call controls |
| Data privacy officer | Reduce unlawful disclosure | Data-classification policies, redaction, residency, retention, reports |
| Compliance/auditor | Verify control operation | Immutable audit trail, mappings, samples, approvals, evidence export |
| Platform engineer | Integrate safely at scale | Gateway/API/SDK, webhooks, connectors, quotas, observability |
| ML engineer | Improve detectors safely | Registry, evaluation sets, shadow/canary deployment, drift monitoring |
| Content moderator | Review ambiguous harm | Safe preview, queues, rationale, decision taxonomy, wellness controls |
| Business owner | Set risk appetite | Policy templates, exceptions, dashboards, impact and cost metrics |
| End user | Receive safe, understandable outcomes | Warnings, redacted content, appeals, remediation guidance |

### 3.1 Critical journeys

1. **Inline AI request:** application sends prompt and context → gateway normalizes and scans → policy allows/transforms/blocks → permitted request reaches model → output is scanned and validated → safe response returns.
2. **RAG ingestion:** connector fetches source → sandboxed parser extracts visible/hidden content → chunks retain provenance and trust labels → malicious instructions are excluded or marked as data → approved chunks enter vector index.
3. **Large video:** upload receives a pre-signed URL → content is quarantined → frames/audio/transcript are analyzed asynchronously → aggregate decision releases, redacts/transcodes, or retains quarantine.
4. **Incident:** correlated high-risk events create a case → analyst reviews immutable evidence → containment playbook disables connector/token or quarantines objects → decisions and notifications are audited.

---

## 4. Product requirements

### 4.1 Functional requirements

#### Ingestion and orchestration

- Upload, REST/gRPC API, webhook, message bus, batch manifest, streaming, SDK, reverse proxy, ICAP-compatible adapter, and external connector ingestion.
- Idempotency keys, content hashes, chunked/resumable upload, MIME verification, archive recursion and size limits, decompression-bomb protection, rate limits, and backpressure.
- Connector checkpoints, incremental scans, delta tokens, retries with jitter, dead-letter queues, and least-privilege credentials.
- Sync scan for bounded text/small objects; async job for large files and media; callback, webhook, polling, and event result delivery.
- Correlation identifiers across source, content, scan, finding, decision, action, case, and audit records.

#### Detection coverage

| Domain | Required techniques and signals |
|---|---|
| Prompt attacks | hierarchy override, jailbreak, system-prompt extraction, role manipulation, delimiter abuse, indirect injection, tool misuse, encoded payloads, multilingual and typoglycemic variants |
| Social engineering/phishing | impersonation, urgency, credential/payment request, lookalike URLs/domains, QR extraction, brand/logo mismatch, reply-chain anomalies |
| Malware/embedded threats | AV/YARA, file magic, hashes, macros, scripts, OLE/OOXML relationships, PDFs actions/JavaScript, archives, URLs, sandbox verdict integration |
| Sensitive data | PII/PHI/payment/secrets/source code/confidential labels using regex, checksum, NER, fingerprinting, exact-data matching, dictionaries, entropy, and contextual classifiers |
| Safety/content | toxicity, abuse, self-harm, sexual content, violence, extremism, illegal activity, child-safety escalation, configurable jurisdiction and age policies |
| Media authenticity | provenance/metadata, perceptual hashes, manipulation artifacts, face/voice spoof models, temporal inconsistency, lip-sync, watermark/C2PA verification where present |
| Compliance | data residency, retention, consent/purpose, records, sector policy, model/use-case restrictions, content licensing and source trust |
| AI output quality | grounding/attribution checks, schema validation, unsafe code/URL, unsupported claim indicators, policy and leakage checks |

#### Multimodal processing

- **Text:** language detection, Unicode normalization, de-obfuscation with original preservation, tokenization, NER, entity linking, classification, sentiment/intent as risk signals—not sole enforcement grounds.
- **Documents:** sandboxed parsing, OCR, structure/table extraction, metadata/comments/notes/revisions/hidden sheets/hidden text, links, macros, attachments, digital signatures, embedded object analysis.
- **Images:** OCR, object/logo/face detection where lawful, safety classification, QR/barcode/URL extraction, EXIF and provenance, manipulation/deepfake signals.
- **Video:** container/codec inspection, scene/keyframe sampling, frame analysis, OCR, audio extraction, transcript, temporal/deepfake/anomaly aggregation.
- **Audio:** malware/container inspection, speech-to-text, keyword/entity analysis, speaker/voice-spoof signals with consent controls, acoustic anomaly analysis.
- Findings retain modality, source coordinates (page, cell, slide, timestamp, frame, bounding box, character range), detector and model version.

#### Prevention and response

- Actions: allow, transform, warn, step-up approval, hold, quarantine, block, revoke, isolate connector, or notify.
- Transformations: redact/mask/tokenize entities; neutralize active links/macros; strip metadata; flatten/re-render documents; omit unsafe RAG chunks; remove/quarantine attachments.
- Preserve originals in a restricted evidence vault only when policy permits. Never overwrite source content without a separate authorized workflow.
- Policy simulation, dry run, shadow mode, canary, scheduled activation, dual approval for high-impact policies, rollback, and exception expiry.
- User-facing responses expose safe reason codes and remediation; detailed detection logic remains analyst-only.

### 4.2 Non-functional requirements

- Horizontal scale, stateless workers, queue-based load leveling, tenant quotas, priority lanes, and admission control.
- Regional processing/residency; customer-managed keys option; private networking and private endpoints.
- WCAG 2.2 AA target for management UI; localization and multilingual detection metrics.
- OpenTelemetry traces/metrics/logs; tamper-evident audit; cost and carbon telemetry by modality/model.
- Portable deployment on Kubernetes with managed-cloud service adapters.
- No tenant content used for shared-model training without explicit, revocable agreement and separate controls.

---

## 5. High-level architecture

```text
 Sources / Protected Systems
 ┌──────────┬──────────┬─────────┬──────────┬───────────┬─────────────┐
 │ Apps/API │ M365/mail│ Web/chat│ File/RAG │ AI/agents │ Streams/batch│
 └────┬─────┴────┬─────┴────┬────┴────┬─────┴─────┬─────┴──────┬──────┘
      │          │          │         │           │            │
 TB-1▼───────────▼──────────▼─────────▼───────────▼────────────▼────────
 Edge & Ingestion: WAF/API gateway │ auth │ quota │ upload │ connectors
      │                     │
      │ sync                │ async + object reference
      ▼                     ▼
 ┌──────────────┐    ┌───────────────┐       ┌─────────────────────────┐
 │ Scan Gateway │───▶│ Event Backbone│──────▶│ Sandboxed Preprocessors │
 └──────┬───────┘    └──────┬────────┘       │ parse/OCR/AV/media/STT  │
        │                    │                └────────────┬────────────┘
 TB-2───┼────────────────────┼─────────────────────────────┼─────────────
        │                    ▼                             ▼
        │       ┌──────────────────────────────────────────────────────┐
        │       │ Detection Fabric                                    │
        │       │ rules │ DLP/NER │ ML │ LLM judge │ media │ TI       │
        │       └───────────────────────────┬──────────────────────────┘
        │                                   ▼
        │                         ┌──────────────────┐
        └────────────────────────▶│ Risk Aggregator  │
                                  └────────┬─────────┘
                                           ▼
                                  ┌──────────────────┐
                                  │ Policy Decision  │◀── policy/context
                                  │ Point (PDP)      │
                                  └────────┬─────────┘
                                decision  │  evidence
                    ┌─────────────────────┼─────────────────────┐
                    ▼                     ▼                     ▼
             ┌────────────┐       ┌─────────────┐       ┌─────────────┐
             │Enforcement │       │Quarantine & │       │Evidence /   │
             │Points/SDKs │       │Transformation│      │Audit Stores │
             └─────┬──────┘       └─────────────┘       └──────┬──────┘
 TB-3──────────────┼────────────────────────────────────────────┼────────
                   ▼                                            ▼
         Protected destination                         Management Plane
                                                 policy/model/rules/cases/
                                                 analytics/admin/integrations
```

### 5.1 Planes and trust boundaries

- **TB-1 External/untrusted:** all source payloads, filenames, headers, URLs, retrieved documents, metadata, and callbacks. Controls: strong authentication, WAF, schema validation, malware precheck, MIME verification, rate/size limits, SSRF-safe fetcher.
- **TB-2 Processing data plane:** ephemeral content processing and model inference. Controls: tenant/workload identity, network policy, read-only images, sandboxing, no ambient internet, egress allowlist, per-job temporary volumes, memory/CPU limits.
- **TB-3 Restricted management/evidence:** policies, secrets, audit, evidence, cases, and admin actions. Controls: phishing-resistant MFA, RBAC+ABAC, privileged access management, immutable audit, dual control, customer/regional keys.
- Separate production from development/evaluation; sanitized or synthetic data only in lower environments.

### 5.2 Core components

| Component | Responsibility | Scale/state |
|---|---|---|
| API gateway/WAF | TLS, auth, quotas, routing, request limits | Stateless, multi-AZ |
| Ingestion service | Validate envelope, hash, dedupe, choose sync/async path | Stateless + idempotency store |
| Connector manager | OAuth/workload credentials, checkpoints, incremental sync | Partitioned by tenant/connector |
| Orchestrator | Build modality DAG, deadlines, retries, partial results | Durable workflow engine |
| Content normalizer | Unicode/de-obfuscation, MIME and structural normalization | Sandboxed stateless workers |
| Extractors | PDF/OOXML/archive/media parsing, OCR, STT | Sandboxed CPU/GPU pools |
| Detection fabric | Run detectors in parallel and emit common findings | CPU/GPU pools; model cache |
| Threat-intel service | IOC/signature/pattern ingestion, validation, distribution | Versioned low-latency cache |
| Risk aggregator | Combine evidence, context, uncertainty, impact | Stateless; versioned config |
| Policy decision point | Evaluate policy-as-code and obligations | HA; strongly consistent policy |
| Enforcement/transformation | Block, redact, sanitize, quarantine, notify | Idempotent actions |
| Evidence vault | Encrypted restricted artifacts and legal holds | Object store + KMS + WORM option |
| Metadata/incident store | Tenants, scans, findings, decisions, cases | HA relational DB |
| Search/analytics | Investigation search and aggregates | Tenant-filtered search/lakehouse |
| Control plane | Policies, models, evaluation, admin, reports | Separate network/account |

---

## 6. Data flows and sequence designs

### 6.1 Synchronous AI gateway

```text
Client → PEP/Gateway: prompt + trusted context + user/app/model/tool metadata
PEP → AuthZ: authenticate workload/user and authorize scan/use case
PEP → Detectors: bounded parallel scan under deadline
Detectors → Risk/PDP: normalized findings + uncertainty + context
PDP → PEP: ALLOW | TRANSFORM | WARN | REVIEW | BLOCK + obligations
PEP → Model: only allowed/transformed prompt; untrusted context delimited/tagged
Model → PEP: response/tool call
PEP → Detectors/PDP: output, grounding, URL/code, leakage, tool policy
PEP → Client/Tool: permitted response or safe denial; async audit event
```

Tool execution is a separate authorization event. Model text never directly invokes a privileged tool. The tool gateway validates identity, intent, arguments, destination, data sensitivity, transaction value, and user confirmation.

### 6.2 Asynchronous document/media scan

```text
Producer → Upload API → quarantine object store
                    └→ ScanAccepted(content_id, scan_id)
Workflow → AV/parser/OCR/media/STT workers → extracted artifacts
Workflow → detector fan-out → finding events → risk aggregate → PDP
PDP → action worker → release/sanitize/retain quarantine/block callback
All stages → append-only audit; failures → retry then DLQ/manual operations queue
```

### 6.3 RAG security flow

1. Authorize connector and record source ACLs, owner, classification, and lineage.
2. Scan source and embedded objects before extraction; quarantine active/malicious content.
3. Extract and chunk with source/page/span provenance and trust score.
4. Detect indirect prompt injection per chunk. Store unsafe chunks outside the production index or label them non-instructional and non-retrievable for privileged flows.
5. Enforce source ACLs at query time before retrieval, not only at ingestion.
6. Scan query, retrieved context, constructed prompt, output, citations, and proposed tool calls.
7. Treat retrieved content as quoted data; system/developer policy is immutable from retrieved text.

### 6.4 Failure semantics

| Failure | Privileged/regulated flow | Standard low-risk flow |
|---|---|---|
| PDP unavailable | Fail closed; cached signed policy only if valid | Configurable cached decision; alert |
| Optional detector timeout | Apply degraded-policy threshold; hold if uncertainty too high | Continue with `partial=true`; log |
| Mandatory AV/parser failure | Quarantine | Quarantine |
| Audit sink unavailable | Buffer durably; block if buffer cannot guarantee record | Buffer; alert before capacity breach |
| Transformer failure | Do not release original when transform was required | Hold/retry |

---

## 7. Detection and risk architecture

### 7.1 Common finding contract

Every detector returns a signed/versioned structure:

```json
{
  "finding_id": "fnd_...",
  "scan_id": "scn_...",
  "detector": {"id": "prompt-injection-ensemble", "version": "3.4.1"},
  "category": "AI.PROMPT_INJECTION.INDIRECT",
  "severity": "HIGH",
  "confidence": 0.94,
  "evidence": [{"artifact_id": "art_...", "page": 4, "start": 928, "end": 1011}],
  "reason_codes": ["INSTRUCTION_OVERRIDE", "EXTERNAL_EXFIL_DESTINATION"],
  "indicators": [{"type": "url", "value_hash": "sha256:..."}],
  "recommended_actions": ["EXCLUDE_RAG_CHUNK", "CREATE_ALERT"],
  "explanation": "Untrusted document text attempts to alter instruction hierarchy.",
  "created_at": "2026-08-21T00:00:00Z"
}
```

Raw sensitive evidence is referenced, not duplicated. User responses receive generalized reason codes; authorized analysts can retrieve redacted evidence and, with elevated permission, originals.

### 7.2 Ensemble strategy

- **Tier 0:** size/type validation, hashes, known-bad IOCs, AV, exact DLP, hard policy. Fast and deterministic.
- **Tier 1:** regex/YARA, linguistic heuristics, NER, lightweight classifiers, URL reputation, perceptual hash.
- **Tier 2:** transformer/vision/audio models and cross-modal correlation.
- **Tier 3:** constrained LLM semantic judge for ambiguous content, returning JSON schema with citations; never receives secrets not required for the task.
- **Tier 4:** sandbox/detonation or specialist human review for high-risk unknowns.

Escalate selectively based on risk and uncertainty. Cache only safe-to-cache outputs keyed by tenant, policy/model version, normalized content hash, and data-classification constraints.

### 7.3 Risk-scoring model

Maintain both category-level risk and an overall decision score. A reference formulation is:

```text
evidence_i = severity_i × calibrated_confidence_i × detector_reliability_i
likelihood  = noisy_or(evidence_i) adjusted for corroboration and campaign context
impact      = max(data_sensitivity, user_privilege, destination_exposure,
                  tool_capability, regulatory_impact, business_criticality)
base_risk   = 100 × likelihood × impact
final_risk  = clamp(base_risk × exposure_modifier × recurrence_modifier
                    - compensating_controls, 0, 100)
```

Suggested bands: 0–19 informational, 20–39 low, 40–59 medium, 60–79 high, 80–100 critical. Policies may override bands: a verified malware signature or prohibited child-safety material is not averaged down by benign classifiers. Confidence describes evidence uncertainty, not business impact.

### 7.4 Calibration and learning

- Calibrate per detector, language, modality, and tenant domain using held-out labeled sets.
- Track precision-recall curves and choose thresholds by business cost, not accuracy alone.
- Reviewer feedback enters a labeled queue; privacy review, de-identification, QA, and approval precede training.
- Detect feature/input drift, performance drift, label drift, and subgroup disparities.
- Champion/challenger, shadow, canary, and instant rollback; pin model version on every scan.
- Prevent poisoning with provenance, signed datasets, access separation, anomaly checks, and reproducible training manifests.

---

## 8. Policy and prevention model

### 8.1 Policy inputs and outputs

Inputs include tenant, subject/workload, role, device/session risk, source/destination, use case, model, agent/tool capability, content/data class, geography, consent/purpose, findings, score, uncertainty, business hours, and exception state.

Output:

```json
{
  "decision": "TRANSFORM",
  "risk": {"score": 78, "band": "HIGH", "confidence": 0.92},
  "policy": {"id": "customer-support-egress", "version": 17},
  "reason_codes": ["PII.GOV_ID", "DESTINATION.EXTERNAL_MODEL"],
  "obligations": [
    {"type": "REDACT", "entity_types": ["GOV_ID"]},
    {"type": "LOG", "retention_class": "SECURITY_1Y"}
  ],
  "expires_at": "2026-08-21T00:05:00Z"
}
```

### 8.2 Policy precedence

1. Legal hold and mandatory legal/safety controls.
2. Organization global deny/mandatory controls.
3. Data-domain and regulated-use controls.
4. Application/use-case controls.
5. Team/project controls.
6. Time-bound exception approved by designated owner.

More restrictive action wins unless an explicit, authorized override policy names the control. Policy bundles are signed, versioned, tested, and promoted through environments.

### 8.3 Safe transformation

- Redaction returns a new derivative with a manifest mapping transformations to finding IDs.
- Prefer irreversible removal for external release; reversible tokenization requires a separate vault and access policy.
- For documents, remove content from the underlying structure—not merely cover it visually—and verify via re-extraction/OCR.
- Strip active content and risky metadata; optionally flatten to a safe format. Preserve fidelity and signatures only when compatible with policy.
- Never attempt to “rewrite away” malware. Quarantine and refer to specialist controls.

---

## 9. Low-level service design

### 9.1 Suggested microservices

| Service | Key endpoints/events | Dependencies |
|---|---|---|
| Identity/tenant | tenant config, service principals, roles | Enterprise IdP, relational DB |
| Scan API | `POST /v1/scans`, status, cancel | gateway, orchestrator |
| Upload | pre-sign, finalize, hash/type check | quarantine object store |
| Workflow | `ScanAccepted`, task DAG, timeout/retry | event bus, state store |
| Extraction | `ArtifactReady`, coordinates, lineage | sandbox pools, object store |
| Detection router | detector selection, budgets, fan-out | registry, feature/model services |
| Detector services | common finding contract | rules/models/TI |
| Risk | aggregate and explain | context, calibration registry |
| Policy | evaluate/simulate/version | policy store/cache |
| Transformation | redaction/sanitization derivatives | KMS, sandbox workers |
| Quarantine | custody, release, retention/legal hold | object store, case service |
| Incidents | alert/case/timeline/tasks | relational/search, SOAR |
| Notification | webhooks/email/chat/SIEM | queue, signing keys |
| Audit | append event, verification/export | WORM-capable store |
| Analytics | aggregates, dashboards, reporting | lakehouse/search |
| Model/rule registry | metadata, signatures, rollout | artifact registry, eval service |

### 9.2 Event envelope

Use CloudEvents-compatible metadata and schema registry:

```json
{
  "specversion": "1.0",
  "type": "com.promptguard.scan.finding.v1",
  "source": "detector/prompt-injection",
  "id": "evt_...",
  "time": "2026-08-21T00:00:00Z",
  "subject": "tenants/tnt_.../scans/scn_...",
  "datacontenttype": "application/json",
  "dataschema": "urn:promptguard:schema:finding:1",
  "traceparent": "00-...",
  "data": {"finding_id": "fnd_...", "artifact_ref": "art_..."}
}
```

Partition by tenant plus content/scan key to preserve per-scan ordering. Consumers are idempotent; use transactional outbox/inbox patterns, retry budgets, poison-message isolation, and DLQs. Do not place raw content on the bus—only encrypted object references with short-lived scoped access.

### 9.3 API specification (abridged OpenAPI semantics)

#### `POST /v1/scans`

- Auth: OAuth 2.0 client credentials or workload identity; `scan:create` scope.
- Headers: `Idempotency-Key`, `X-Tenant-Id` derived/validated by gateway, optional `Prefer: respond-async`.
- Body: one of inline text (bounded) or uploaded `content_id`; `direction`, `channel`, `use_case`, `source`, `destination`, `subject`, `policy_set`, and optional customer metadata allowlist.
- Response: `200` completed sync decision or `202` with `scan_id`, `status_url`, and expiry.
- Errors: RFC 9457 problem details; never echo sensitive input.

#### Other principal endpoints

```text
POST   /v1/uploads                         create scoped upload
POST   /v1/uploads/{id}:finalize           verify/hash and enqueue
GET    /v1/scans/{scan_id}                 status and authorized result
POST   /v1/scans/{scan_id}:cancel          best-effort cancellation
POST   /v1/policies:simulate               side-effect-free evaluation
POST   /v1/quarantine/{id}:release         dual-control where configured
POST   /v1/quarantine/{id}:delete          retention/legal-hold guarded
POST   /v1/cases                           create case
PATCH  /v1/cases/{id}                      transition with optimistic lock
POST   /v1/webhook-endpoints               register and verify destination
GET    /v1/audit-events                    privileged filtered export
```

Webhooks use timestamped HMAC or asymmetric signatures, nonce/event ID, replay window, endpoint verification, exponential retry, and a customer-visible delivery log.

### 9.4 State machines

```text
Scan: RECEIVED → VALIDATING → QUEUED → PROCESSING → DECIDING
      → COMPLETED | PARTIAL | FAILED | CANCELED

Content custody: QUARANTINED → RELEASED | SANITIZED_RELEASED | RETAINED
                 → EXPIRED → DELETED

Case: NEW → TRIAGED → INVESTIGATING → CONTAINED → REMEDIATED
      → CLOSED → REOPENED
```

Transitions require authorization, valid prior state, reason, actor, timestamp, and optimistic version; each emits an audit event.

---

## 10. Data model and storage

### 10.1 Logical schema

| Entity | Essential fields |
|---|---|
| `tenant` | id, name, region, key_ref, status, config_version |
| `subject` | id, tenant_id, external_ref_hash, type, risk_attributes |
| `content` | id, tenant_id, sha256, size, verified_mime, source, classification, custody_state, object_ref, retention_class |
| `artifact` | id, content_id, parent_id, modality, coordinates, sha256, lineage, trust_label |
| `scan` | id, tenant_id, content_id, direction, channel, use_case, status, started/completed, policy_version, trace_id |
| `detector_run` | id, scan_id, detector/version, status, latency, input_hash, error_code |
| `finding` | id, run_id, category, severity, confidence, reason_codes, evidence_ref, disposition |
| `risk_assessment` | id, scan_id, model_version, category_scores, impact, overall_score, band, explanation |
| `decision` | id, scan_id, policy/version, action, obligations, reason_codes, expiry |
| `action_execution` | id, decision_id, type, status, target_ref, idempotency_key, result_ref |
| `policy` / `policy_version` | id, scope, source, compiled_hash, signer, status, effective/expiry |
| `rule` / `rule_version` | id, category, expression/artifact_ref, provenance, tests, status |
| `threat_indicator` | id, type, value_hash/value_ref, confidence, source, TLP, first/last_seen, expiry |
| `incident` | id, tenant_id, severity, owner, status, summary, SLA timestamps |
| `case_event` | id, incident_id, actor, action, reason, evidence_refs, timestamp |
| `exception` | id, scope, control, justification, approvers, effective, expiry, status |
| `model_version` | id, artifact_digest, SBOM, dataset_manifest, metrics, approval, rollout |
| `audit_event` | id, tenant_id, actor, action, resource, outcome, timestamp, prev_hash, signature |

All tenant-owned tables include `tenant_id`; database row-level security is defense in depth, not a substitute for service authorization. Use opaque IDs, uniqueness on `(tenant_id, idempotency_key)`, and immutable version rows.

### 10.2 Storage assignment

- Relational database: operational metadata, policies, decisions, cases, approvals.
- Object storage: quarantined originals, extracted artifacts, derivatives, model artifacts; per-region encryption and lifecycle.
- Search engine: redacted findings, cases, IOCs, operational search; tenant filter enforced server-side.
- Lakehouse: pseudonymized analytics/evaluation with governed access and deletion propagation.
- Cache: policy bundles, tenant config, rate limits; never authoritative for audit/custody.
- Vector store: approved knowledge chunks with source ACL, provenance, classification, and trust fields.

### 10.3 Retention and privacy

- Configure retention by record class, tenant, region, and legal hold. Example defaults: raw low-risk content 0–24 hours, quarantined evidence 30 days, findings/decisions 1 year, security audit 1–7 years according to policy.
- Support access, export, correction where applicable, deletion, legal hold, and cryptographic erasure workflows.
- Hash or tokenize identity fields used for correlation; separate identity resolution from analyst search.
- Log access to evidence. Watermark safe previews and prevent browser execution of active content.

---

## 11. Security architecture and controls

### 11.1 Identity and authorization

- Workforce SSO through OIDC/SAML; phishing-resistant MFA for administrators and analysts.
- Workload identity through SPIFFE/SPIRE or cloud-native federation; short-lived tokens, no static service keys.
- OAuth 2.0/OIDC for APIs/connectors with narrow scopes; mTLS for sensitive service and partner paths.
- RBAC roles: viewer, analyst, incident commander, policy author, policy approver, model operator, auditor, tenant admin, platform admin.
- Add ABAC conditions for tenant, region, data class, case assignment, purpose, device/session risk, and time-bound elevation.
- Separation of duties: authors cannot solely approve production policy/model releases; quarantine release and bulk evidence export can require dual control.

### 11.2 Data and platform protection

- TLS 1.2+ externally and TLS 1.3 where supported; mTLS east-west for sensitive services.
- AES-256-equivalent encryption at rest using envelope encryption; per-tenant or customer-managed key options; rotation and revocation.
- Secrets in managed vault/HSM; automatic rotation; secret scanning; no secrets in images, code, logs, or events.
- Private clusters/subnets, default-deny network policies, egress proxy/allowlists, DNS controls, WAF/API threat protection.
- Signed images and artifacts, SBOM, provenance attestations, admission policy, vulnerability scanning, minimal distroless images, non-root/read-only containers.
- Sandboxed parsing/detonation with gVisor/Kata/microVM equivalent, seccomp, no credentials, no metadata endpoint, disposable storage, resource/time limits.
- SSRF-safe fetch service: scheme/port allowlist, DNS pinning defenses, private/link-local IP blocking, redirect revalidation, download caps.
- Immutable/tamper-evident audit using hash chaining/signatures plus WORM-capable retention for required records.

### 11.3 AI/LLM-specific controls

- Immutable instruction hierarchy; clearly label and delimit untrusted data.
- Scan direct prompts, indirect context, retrieved chunks, outputs, citations, code, URLs, and tool calls.
- Give models no ambient credentials; broker all tools through a separately authenticated/authorized gateway.
- Parameter schemas, destination allowlists, transaction ceilings, read-before-write, user confirmation, and postcondition validation.
- Context minimization and secret brokering; never place credentials in model context.
- Grounding and citation checks for high-impact responses; deterministic schema/format validation.
- Rate/use anomaly detection, session risk, memory isolation, conversation length and recursion limits.
- Provider configuration inventory, data-use/retention settings, regional endpoints, model/version allowlist, and kill switch.
- Treat LLM-as-judge output as untrusted evidence; require structured output, cited spans, calibration, and rule/policy mediation.

### 11.4 Security controls matrix

| Control objective | Implementation | Evidence | Owner |
|---|---|---|---|
| Tenant isolation | tenant-scoped auth, RLS, keys, queues/partitions, tests | isolation test results, access logs | Platform security |
| Strong access control | SSO, MFA, RBAC+ABAC, JIT elevation | IdP config, access reviews | IAM |
| Data confidentiality | minimization, encryption, private networking | KMS logs, config snapshots | Security engineering |
| Data integrity | hashes, signatures, immutable versions, lineage | artifact digest, audit chain | Platform engineering |
| Availability | multi-AZ, autoscale, load shedding, DR | SLOs, restore/failover tests | SRE |
| Secure ingestion | WAF, schema/type/size validation, sandbox | gateway and sandbox tests | AppSec |
| Malware prevention | AV/YARA, active-content extraction, quarantine | scan verdicts, rule versions | Detection engineering |
| Prompt-injection defense | layered detectors, context labels, policy, tool broker | adversarial suite, decisions | AI security |
| Sensitive-data protection | DLP/NER/EDM, redaction validation | redaction tests, reports | Privacy/DLP |
| Model governance | signed registry, eval gates, canary/rollback | model cards, approvals | ML platform |
| Policy governance | versioning, simulation, approval, expiry | policy history, test suite | GRC/product |
| Incident response | alerts, cases, playbooks, chain of custody | exercises, case timelines | SOC |
| Auditability | append-only events, time sync, WORM option | verification report | Compliance |
| Supply-chain security | SBOM, provenance, signed builds, dependency policy | attestations, scan results | DevSecOps |
| Privacy rights/retention | purpose, region, retention, deletion/hold | DPIA, deletion and hold logs | Privacy |

### 11.5 Threat model highlights

| Threat | Attack path | Principal mitigations |
|---|---|---|
| Direct/indirect prompt injection | user or retrieved content changes behavior | hierarchy isolation, detectors, chunk trust, tool authorization, output checks |
| Parser exploit | crafted PDF/OOXML/media targets libraries | sandbox/microVM, patching, type check, resource limits, no network/secrets |
| Archive bomb | nested/compressed payload exhausts resources | recursion, ratio, member, size, CPU/time limits |
| Cross-tenant access | IDOR/cache/search/filter defect | tenant-bound identity, RLS, key namespace, negative isolation tests |
| Model extraction/evasion | repeated probes reveal boundaries | rate/anomaly limits, generalized user reasons, rule confidentiality |
| Training/feedback poisoning | malicious labels or samples | provenance, reviewer separation, dataset signing, anomaly and holdout gates |
| Malicious connector | overbroad token or hostile callback | scoped OAuth, vault, egress limits, signature/replay validation |
| Evidence tampering | attacker alters case or logs | append-only signed audit, WORM, separated custody roles |
| Deepfake false assurance | detector misses or overstates authenticity | ensemble/provenance, uncertainty, human review, never claim proof from one model |
| Compromised dependency/model | malicious artifact in pipeline | signed provenance, SBOM/model manifest, allowlist, admission checks |

---

## 12. Compliance and governance

The control catalog should map to applicable obligations without claiming automatic compliance:

- **GDPR:** lawful basis/purpose, minimization, transparency, data-subject workflows, processor controls, transfer/residency, retention, security, DPIA where required.
- **HIPAA:** administrative, physical, and technical safeguards; minimum necessary; access/audit/integrity/transmission controls; BAA and breach processes where the service handles PHI.
- **SOC 2:** security common criteria plus availability, confidentiality, processing integrity, and privacy criteria selected for the service scope.
- **ISO/IEC 27001:2022:** ISMS risk treatment, access, cryptography, operations, supplier, incident, continuity, and audit controls.
- **AI governance:** NIST AI RMF functions Govern, Map, Measure, Manage; the NIST Generative AI Profile; ISO/IEC 42001:2023 AIMS; organization model/use-case inventory and impact assessment.
- **EU AI Act:** role and system classification, prohibited-practice screening, literacy, transparency, documentation, human oversight, risk and post-market obligations as applicable to the organization’s provider/deployer/importer role.

Current primary references: [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework), [NIST AI 600-1 Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence), [ISO/IEC 42001:2023](https://www.iso.org/standard/42001), and [Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj?locale=en).

### 12.1 Governance operating model

- Executive AI/security risk committee sets appetite and accepts material residual risk.
- Product owner owns outcomes and backlog; CISO owns security policy; privacy/legal interpret obligations; data owners classify sources; model risk committee approves high-impact models.
- Maintain inventories for tenants, systems, models, prompts/templates, agents/tools, datasets, connectors, policies, subprocessors, and exceptions.
- Perform threat model, privacy/DPIA, AI impact assessment, data-flow review, and abuse-case review before launch and material changes.
- Quarterly access/policy/exception reviews; annual independent penetration test and control audit; continuous evidence collection.

---

## 13. Security operations dashboard

### 13.1 Views

- **SOC live:** critical alerts, attack category, tenant/app, campaign correlation, queue age, SLA, containment state.
- **Investigation:** safe content preview, extracted entities/IOCs, decision explanation, detector disagreement, provenance, related scans/users/sources, timeline.
- **AI security:** attack success rate, prompt-injection vectors, agent/tool denials, model/provider/version, grounding and output failures.
- **Privacy/compliance:** data categories, flows/destinations, redaction volume, residency/retention exceptions, evidence coverage, scheduled reports.
- **Executive:** risk trend, blocked exposure, business services protected, material incidents, control effectiveness, SLO/cost, residual risk.
- **Platform:** throughput/latency/error, detector health, GPU utilization, queue/DLQ, connector freshness, drift, policy cache age.

### 13.2 Incident workflow

Alert deduplication and correlation create a case from related findings. Playbooks can quarantine content, disable connector credentials, block indicators, restrict an AI application, preserve evidence, notify owners, and open SIEM/SOAR/ticket records. Destructive or business-impacting actions require configured approval. Chain of custody records hashes, actors, access, transformations, and timestamps.

---

## 14. Integrations

### 14.1 Integration patterns

- **AI providers:** OpenAI/Azure OpenAI, Anthropic, and Gemini through gateway adapters that normalize requests/responses while retaining provider-specific capabilities.
- **Frameworks:** LangChain callbacks/middleware and Semantic Kernel filters for prompt, retrieval, tool, and output enforcement.
- **Microsoft ecosystem:** SharePoint/OneDrive delta ingestion, Teams bot/message and webhook patterns, Microsoft Graph mail, Copilot extension/agent boundary where supported.
- **Email:** journaling/API/secure gateway adapter, MIME recursion, URL/attachment scanning, verdict headers, quarantine integration.
- **SIEM/SOAR:** CEF/LEEF/syslog, OpenTelemetry, webhooks, STIX/TAXII where appropriate; Microsoft Sentinel, Splunk, QRadar-compatible mappings.
- **DLP/security:** ICAP/API, label/classification exchange, EDR/sandbox verdict, threat-intel feeds, ticketing and pager integrations.

Connector contracts must document permissions, data accessed, direction, polling/webhook behavior, throttling, deletion propagation, residency, failure semantics, and revocation. Provider-specific capabilities must be verified during implementation because APIs and product names change.

---

## 15. Technology and deployment recommendation

### 15.1 Reference technology stack

| Layer | Recommended options |
|---|---|
| Edge/API | Envoy/Kong/cloud API gateway, WAF, OAuth/OIDC, gRPC/REST |
| Services | Go or Java/Kotlin for high-throughput control services; Python for ML workers; TypeScript/React for console |
| Workflow/events | Temporal for durable workflows; Kafka/Pulsar or managed equivalent; schema registry |
| Policy | Open Policy Agent/Rego or Cedar with signed bundles and custom obligation service |
| Data | PostgreSQL-compatible HA DB; S3-compatible object store; OpenSearch; Redis; lakehouse; governed vector store |
| ML | PyTorch/ONNX Runtime/Triton; MLflow-compatible registry; Ray/Kubernetes jobs where useful |
| Extraction | Apache Tika plus format-specific hardened parsers; OCR/STT provider abstraction; FFmpeg in sandbox |
| Malware | ClamAV/YARA baseline plus enterprise sandbox/AV integrations |
| Platform | Kubernetes, service mesh selectively, KEDA/HPA, Argo CD/Flux, Helm/Kustomize |
| Observability | OpenTelemetry, Prometheus, Grafana, centralized logs/traces, SIEM export |
| Supply chain | OIDC CI, SLSA-style provenance, Sigstore/Cosign, SBOM, artifact registry, admission policies |

Managed services should replace self-hosted components when they meet residency, security, portability, and cost requirements.

### 15.2 Kubernetes model

- Separate namespaces and preferably accounts/subscriptions/projects for edge, control plane, processing, evidence, and observability.
- Regional clusters across at least three availability zones; active-active stateless services and regional data authority.
- Dedicated tainted node pools for parsers, CPU inference, GPU inference, and trusted management workloads.
- Default-deny network policies; Pod Security restricted baseline; workload identity; secrets CSI; read-only root FS; ephemeral volumes.
- KEDA/HPA scales on request rate, queue lag, token/frame duration, GPU utilization, and deadlines; cluster autoscaler provisions pools.
- Pod disruption budgets, topology spread, anti-affinity, priority classes, quotas, and graceful draining.
- GitOps promotion with signed artifacts, policy checks, progressive delivery, automated rollback, and audited break-glass.

### 15.3 Scalability and HA

- Content-addressed artifacts avoid repeat extraction within allowed trust/retention boundaries.
- Split large media into scenes/chunks and aggregate hierarchically; bounded fan-out prevents tenant starvation.
- Bulkheads per tenant/modality/provider, circuit breakers, adaptive concurrency, and cost budgets.
- Regional active-active edge with tenant home region. Metadata replication must respect residency; avoid cross-region raw content by default.
- Back up metadata with point-in-time recovery; object versioning/replication as policy permits; quarterly restore and annual regional failover tests.

---

## 16. Testing and assurance strategy

| Test layer | Minimum scope | Release gate |
|---|---|---|
| Unit/contract | parsers, scoring, policy, schemas, idempotency | required on every change |
| Integration | object/event/DB/connectors/provider adapters | no critical failures |
| End-to-end | sync, async, RAG, quarantine, redaction, case | golden journeys pass |
| Security | SAST/SCA/IaC/container/secret/DAST/API fuzz | no unaccepted critical/high |
| Parser robustness | malformed files, polyglots, bombs, fuzzing | sandbox contained; no escape/exhaustion |
| Adversarial AI | direct/indirect injection, jailbreak, encoding, multilingual, multimodal, tool abuse | attack success below approved threshold |
| Model | precision/recall/calibration, subgroup/language, robustness, privacy | model card and risk owner approval |
| Redaction | re-extract/OCR derivative, metadata/hidden layers | zero retained target entities in test corpus |
| Performance | latency, throughput, soak, spike, queue recovery | SLO and cost envelope met |
| Resilience | dependency failure, AZ loss, DLQ, restore, chaos | documented recovery within RTO/RPO |
| Red team | cross-tenant, control plane, supply chain, model/agent abuse | material findings remediated or accepted |

Maintain a versioned attack/evaluation corpus with benign near-neighbors to measure false positives. Include multiple languages, OCR noise, split payloads, hidden layers, images containing text, audio instructions, adversarial suffixes, poisoned RAG documents, data exfiltration, and tool-call manipulation. Protect the corpus to prevent benchmark overfitting.

---

## 17. PRD, epics, stories, and acceptance criteria

### 17.1 PRD summary

**Problem:** Enterprises lack a consistent, auditable control point for malicious and sensitive content moving across AI, collaboration, repositories, and multimodal workflows. Point classifiers do not preserve provenance, understand business context, or enforce policies consistently.

**Vision:** Make every enterprise content and AI boundary observable, explainable, and enforceable without making safe business workflows unusably slow.

**MVP users:** AI platform engineer, AI security engineer, SOC analyst, tenant administrator.

**MVP hypothesis:** A text/document gateway with prompt-injection, malware, secrets/PII, policy enforcement, quarantine, and investigation will materially reduce unsafe AI/RAG exposure while meeting agreed latency and false-positive targets.

### 17.2 Epics and representative stories

| Epic | User story | Acceptance criteria |
|---|---|---|
| E1 Ingestion | As a platform engineer, I submit text or a file synchronously/asynchronously | Auth and tenant enforced; idempotent; MIME/hash captured; size/ratio limits; status/result available; audit linked |
| E2 Extraction | As an analyst, I see visible and hidden document evidence | PDF/DOCX/PPTX/XLSX/TXT supported; page/slide/cell/span provenance; macros/links/metadata surfaced; malformed files safely fail |
| E3 Detection | As AI security, I detect direct and indirect prompt attacks | versioned findings with category/severity/confidence/evidence; baseline corpus threshold met; multilingual metrics reported |
| E4 DLP/malware | As privacy/SOC, I prevent sensitive or malicious files | AV/YARA and selected PII/secrets; exact/checksum tests; quarantine; redaction verified through re-extraction |
| E5 Risk/policy | As a policy owner, I convert findings and context to action | signed/versioned policy; simulation; deterministic replay; allow/transform/review/block; safe reason codes |
| E6 Quarantine | As an analyst, I review and release held content | safe preview; chain of custody; RBAC; reason required; dual control optional; source is not silently overwritten |
| E7 Incidents | As SOC, I triage correlated high-risk activity | dedup/correlation; timeline; owner/SLA; containment actions; SIEM/webhook integration |
| E8 AI gateway | As an app owner, I protect prompt, retrieval, output, and tool calls | each boundary separately logged/decided; tool schema/auth; context treated as untrusted; provider timeout policy tested |
| E9 Governance | As an auditor, I prove control operation | filtered immutable export; policy/model/rule versions; access/override history; retention and legal hold |
| E10 Operations | As SRE, I run the service reliably | dashboards/alerts; queue/DLQ; SLOs; autoscale; backup restore; runbooks |

### 17.3 Definition of done

- Threat model and privacy review complete; data classification and retention assigned.
- Code, API, schema, unit/contract/integration tests, telemetry, runbook, and rollback included.
- Model/rule change includes evaluation report, model/rule card, signed artifact, reviewer approval, and drift monitors.
- Accessibility and localization checks for user-visible behavior.
- No unresolved critical/high vulnerability unless formally accepted with owner and expiry.
- Operational and control evidence automatically collected.

---

## 18. MVP definition and sprint backlog

### 18.1 MVP scope (approximately 16 weeks, two-week sprints)

- Multi-tenant identity, REST scan API, inline text, and async upload up to an approved bounded size.
- TXT, PDF, and DOCX extraction with sandbox, AV, hidden text/metadata/link inspection.
- Prompt injection/jailbreak, secrets, selected PII, phishing URLs, and malware indicators.
- Risk aggregation and policy actions: allow, redact, quarantine, block.
- Management UI: live events, scan detail, quarantine review, policies, cases, basic executive metrics.
- Signed webhooks and one SIEM integration; OpenAI/Azure OpenAI gateway adapter; one RAG ingestion SDK example.
- PostgreSQL, object store, event backbone, Kubernetes, KMS/vault, audit trail, dashboards, backup/restore.

Excluded: full video/audio, production deepfake claims, autonomous remediation, broad connector catalog, global active-active, custom model training UI.

### 18.2 Sprint plan

| Sprint | Deliverable | Exit evidence |
|---:|---|---|
| 0 | Architecture runway, threat model, data classification, SLOs, CI/CD/IaC | approved ADRs and threat/privacy reviews |
| 1 | Tenant/IAM, API gateway, scan envelope, audit skeleton | auth/tenant negative tests, API contract |
| 2 | Upload/quarantine, object hashing, event/workflow, idempotency | retry/DLQ and custody tests |
| 3 | Sandboxed TXT/PDF/DOCX extraction, AV | malformed/bomb/escape tests, provenance |
| 4 | Prompt/secrets/PII/URL detectors and common findings | evaluation baseline and model/rule cards |
| 5 | Risk aggregator, policy PDP, simulation, allow/block | deterministic replay and policy tests |
| 6 | Redaction, safe preview, quarantine release | re-extraction validation, RBAC/dual-control tests |
| 7 | AI gateway input/output, webhooks, SIEM, cases | end-to-end protected AI journey |
| 8 | performance, chaos/restore, red team, accessibility, launch | SLO report, remediation, go-live approval |

### 18.3 MVP release gates

- No cross-tenant access in automated/manual tests.
- Mandatory detector/parser failure never releases quarantined content.
- Policy decisions reproduce from recorded input versions.
- Redaction verification passes target corpus.
- Detection thresholds approved using representative benign and malicious data.
- Backup restore and incident tabletop completed; on-call and rollback ready.

---

## 19. Release roadmap

| Phase | Window | Product outcome | Major capabilities |
|---|---|---|---|
| 1. MVP | 0–4 months | Protect priority AI/text/document flow | gateway/API, PDF/DOCX/TXT, prompt attacks, AV, PII/secrets, risk/policy, quarantine, cases, SIEM |
| 2. Enterprise | 5–9 months | Operate across departments/regions | PPTX/XLSX/email/chat/M365, HA/DR, residency/CMK, policy packs, advanced DLP, SSO/PAM, analytics, connector SDK |
| 3. Advanced AI Security | 10–15 months | Protect multimodal and agentic AI | image/audio/video pipelines, deepfake/manipulation signals, RAG graph, tool broker, campaign correlation, advanced red team/evals |
| 4. Autonomous Prevention | 16–24 months | Closed-loop response with governed autonomy | adaptive policies, behavioral baselines, SOAR playbooks, proposed rule generation, safe automated containment, causal/control-effectiveness analytics |

Phase 4 autonomy remains bounded: the system may automatically execute pre-approved reversible actions within policy; destructive, legal, employee-impacting, or high-blast-radius actions require human authorization.

---

## 20. Delivery organization and development workstreams

| Workstream | Responsibilities | Initial staffing indication |
|---|---|---:|
| Product/design | discovery, PRD, workflows, accessibility, adoption | 2–3 |
| Platform/API | gateway, tenancy, workflow, policy, integrations | 5–7 |
| Content processing | parsers, sandbox, transformations, media | 4–6 |
| AI/detection | models, rules, evaluation, drift, threat research | 5–7 |
| Data/analytics | schema, lakehouse, search, dashboards | 3–4 |
| Security/GRC | threat model, AppSec, IAM, controls/evidence | 3–4 |
| SRE/DevSecOps | Kubernetes, CI/CD, observability, HA/DR | 3–4 |
| QA/red team | automation, performance, adversarial validation | 3–5 |

Indicative only; staffing depends on managed services, existing SOC/DLP platforms, target regions, and connector breadth.

### 20.1 Key ADRs to decide early

1. SaaS multi-tenant versus dedicated/private data planes.
2. Home-region and cross-region metadata strategy.
3. Authoritative policy language and decision semantics.
4. Raw-content retention defaults and customer-managed keys.
5. Build versus buy for AV/sandbox, OCR/STT, deepfake, DLP, and threat intelligence.
6. Event backbone and workflow engine.
7. Model/provider hosting and customer opt-out/private inference.
8. Safe preview and document sanitization approach.
9. Regulated-sector boundaries and certification scope.

---

## 21. Operational readiness

### 21.1 Required runbooks

- Elevated false positives/false negatives; detector rollback; policy rollback.
- Parser zero-day or sandbox escape; disable affected format and quarantine backlog.
- Queue backlog, poison message, provider outage, GPU exhaustion, regional failure.
- Cross-tenant suspicion, evidence access anomaly, key compromise, connector-token compromise.
- Malware/child-safety/legal escalation with restricted handling and jurisdiction-specific process.
- Data deletion, legal hold, customer offboarding, CMK revocation, and disaster restore.

### 21.2 Observability

- RED metrics per API/service and USE metrics per resource pool.
- Trace one scan across ingestion, artifact DAG, detectors, decision, enforcement, callback, and audit.
- Security telemetry excludes raw content by default; structured reason codes and hashed indicators support correlation.
- Alerts: SLO burn, mandatory-detector failure, policy-cache expiry, audit buffer risk, isolation test failure, unusual evidence export, drift, connector staleness, DLQ growth.

---

## 22. Current repository gap assessment

The current PromptGuard repository is a useful browser-side demonstration: it contains regex-based text detection and DOCX XML extraction. It is **not** yet the enterprise platform described here. Principal gaps include server-side identity and tenant isolation, durable ingestion/workflows, sandboxed parsing, malware scanning, policy/risk services, evidence custody, persistence, model governance, multimodal processing, integrations, HA/DR, operations, and compliance evidence.

Recommended next repository steps:

1. Preserve the current UI as a demonstrator and label local-only processing clearly.
2. Define the common finding, scan, decision, and event schemas as versioned packages.
3. Add a server-side vertical slice: authenticated scan API → durable audit → prompt detector → policy decision → UI result.
4. Move document parsing out of the browser into a sandboxed worker before accepting untrusted enterprise files.
5. Implement Sprint 0 ADRs, threat model, data classification, and evaluation corpus before adding more detector breadth.

---

## 23. Go-live checklist

- [ ] Business owner, data owner, CISO, privacy/legal, and SRE approve scope and residual risk.
- [ ] Architecture, threat model, DPIA/AI impact assessment, subprocessors, and data flows are current.
- [ ] Tenant isolation, authorization, encryption, secret rotation, sandbox, and audit controls pass tests.
- [ ] Detection/model cards and representative evaluation results are approved.
- [ ] Policy simulation completed; exceptions have owners and expiries.
- [ ] SLO/load/soak/chaos/restore/regional failover results meet release gates.
- [ ] Red-team findings are closed or formally accepted.
- [ ] SOC playbooks, on-call, escalation, safe handling, and customer communications are rehearsed.
- [ ] Retention, deletion, legal hold, evidence export, and offboarding work end to end.
- [ ] Rollback/kill switches are tested for policies, models, formats, connectors, and providers.

---

## 24. Final recommendation

Build PromptGuard as an enforcement platform, not a collection of classifiers. Begin with one protected AI/RAG workflow and a complete vertical control loop—ingest, extract, detect, score, decide, enforce, audit, investigate—then add modalities and connectors behind the same contracts. Make the policy decision deterministic and reproducible, keep untrusted content isolated from privileged tools, preserve precise provenance, measure both security efficacy and operational cost, and introduce autonomy only through pre-approved, reversible playbooks.
