# PII Guard — Privacy-Preserving LLM Proxy

A Java/Spring Boot proxy that lets an organisation use a cloud LLM without the cloud LLM
ever receiving its sensitive data.

Sensitive values are detected and replaced with reversible placeholders before the prompt
leaves the building; the model reasons over the placeholders; the real values are restored
in the response. The provider sees a structurally intact prompt and none of the content
that matters.

```
                    ┌──────────────── trust boundary ────────────────┐
                    │                                                │
  user prompt ─► threat check ─► redact ─► perturb numbers ─► [ LLM provider ]
                                    │                                │
                              token vault                            │
                              (in memory,                            │
                               TTL-bounded)                          │
                                    │                                │
  user answer ◄── restore ◄── output inspection ◄────────────────────┘
                    │                                                │
                    └────────────────────────────────────────────────┘
```

---

## Table of contents

- [What it does](#what-it-does)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [API](#api)
- [Architecture](#architecture)
- [Threat model](#threat-model)
- [What this is not](#what-this-is-not)
- [Testing](#testing)
- [Roadmap](#roadmap)
- [Further reading](#further-reading)

---

## What it does

### 1. Detects and replaces sensitive values

Two detectors run over the same text and both report character spans:

| Detector | Handles | Why this one |
|---|---|---|
| **Pattern rules** (19 rules) | email, phone, IPv4/IPv6, credit card (Luhn), US SSN, Aadhaar (Verhoeff), PAN, IBAN, IFSC, passport, date of birth, API keys / JWTs / private keys | Anything with a grammar. Deterministic, fast, checksum-validated. |
| **Named entity recognition** (Apache OpenNLP) | person names, contextually | "Rose" is a flower, a colour and a person. Only context decides, and no regex can express context. |
| **Name lexicon** (214 entries) | names the model's training distribution misses | The OpenNLP English model redacts *John Smith* reliably and misses *Priya Sharma* entirely. A model inherits its corpus's demographics; a curated lexicon has no generalisation but perfect recall on what it contains. Together the gap narrows and what remains is describable. |

Overlapping claims are resolved by explicit priority — a digit string matching both the
card rule and the phone rule is redacted **once**, as a card.

Each value becomes a placeholder that keeps the *type* and destroys the *content*:

```
Priya Sharma paid with 4539578763621486 — email priya@acme.com
        ↓
[NAME_KQZTBMWLFDNR] paid with [CARD_YHVPLZKDNMTQ] — email [EMAIL_BXWRTNQJLZMV]
```

Keeping the type is what makes the answer useful: the model can still tell that one thing
is a person and another is an address.

### 2. Perturbs numeric magnitudes

Large numeric literals get Laplace-distributed noise, so an exact revenue figure never
crosses the boundary while remaining approximately right for the model to reason with.
Small numbers, dosages, counts and years are left alone. Budget is metered per caller.

**This is calibrated magnitude obfuscation, not a formal ε-differential-privacy guarantee.**
See [What this is not](#what-this-is-not) — the distinction is important and the previous
version of this README got it wrong.

### 3. Refuses adversarial prompts

20 precompiled rules covering instruction override, persona jailbreaks, vault probing,
fake system framing, claimed authority, leetspeak obfuscation and exfiltration framing —
plus an optional scikit-learn classifier running as a sidecar. Either layer can block;
neither can veto the other.

The built-in regression suite includes **benign control prompts that must not be blocked**,
so it can actually fail.

### 4. Inspects what comes back

The return path restores only placeholders the current session issued, reports any it did
not, and flags sensitive-looking values the model invented by itself.

---

## Quick start

### Docker Compose (recommended)

```bash
export GROQ_API_KEY=your_groq_key
export ADMIN_API_KEY=$(openssl rand -hex 32)
export AUDIT_HASH_SECRET=$(openssl rand -hex 32)
docker compose up --build
```

Then open <http://localhost:8081>.

### Local JVM only

The proxy runs standalone; without the ML sidecar it falls back to the rule layer and says
so on `/api/health`.

```bash
export GROQ_API_KEY=your_groq_key
export ADMIN_API_KEY=local-dev-key
./mvnw spring-boot:run
```

### ML sidecar standalone

```bash
cd python-service
pip install -r requirements.txt
python train_model.py    # trains, evaluates on a held-out split, writes attack_model.pkl
uvicorn main:app --port 8000
```

---

## Configuration

Everything lives under the `piiguard.*` namespace and is bound to a validated
`@ConfigurationProperties` class. Full list in
[`application.properties`](src/main/resources/application.properties).

| Variable | Default | Purpose |
|---|---|---|
| `GROQ_API_KEY` | *(none)* | Upstream model key. No usable fallback — the proxy reports itself unconfigured rather than failing per request. |
| `ADMIN_API_KEY` | *(none)* | Required by `/api/audit`, `/api/attack`, `/api/status`, `/actuator/**`. **Blank disables those endpoints entirely** rather than exposing them. |
| `AUDIT_HASH_SECRET` | random per boot | HMAC key for prompt fingerprints. Set it if you need fingerprints to correlate across restarts. |
| `ML_SERVICE_URL` | `http://localhost:8000` | Classifier sidecar. |
| `DETECTION_FAIL_CLOSED` | `false` | `true` refuses requests when the classifier is unreachable instead of degrading to rules. |
| `RATE_LIMIT_RPM` | `20` | Per-caller sustained request rate. |
| `AUDIT_STORE_RAW` | `false` | Persist raw prompts. Off by default and should stay off. |
| `DB_URL` | H2 file | Point at PostgreSQL for a real deployment. |

---

## API

### `POST /api/proxy` — public

```jsonc
// request
{ "prompt": "Email priya@acme.com about the 4500000 invoice", "applyNoise": true }
```

```jsonc
// 200 OK
{
  "sanitizedPrompt": "Email [EMAIL_BXWRTNQJLZMV] about the 4383912 invoice",
  "llmResponse":     "I'll draft a note to priya@acme.com regarding the invoice…",
  "sessionId":       "3f2a…",
  "attackDetected":  false,
  "detectionMethod": "NONE",
  "detectionRule":   "none",
  "piiRedacted":     { "EMAIL": 1 },
  "valuesNoised":    1,
  "warnings":        []
}
```

`sanitizedPrompt` is exactly what was transmitted — the auditable artefact. The raw prompt
is **not** echoed back.

| Status | Meaning |
|---|---|
| `200` | Answered. |
| `400` | Empty, oversized or malformed request. |
| `403` | Blocked as adversarial; `detectionRule` names the rule. |
| `429` | Rate limited; `Retry-After` set. |
| `502` | Upstream model unavailable — distinguishable from an answer. |
| `503` | Vault at capacity. |

### `GET /api/health` — public

Booleans only: `status`, `nerModelLoaded`, `mlServiceAvailable`, `llmConfigured`.

### Admin — requires `X-Admin-Key`

| Route | Purpose |
|---|---|
| `GET /api/audit?page=&size=&attacksOnly=` | Paginated audit log. Contains **no raw prompts**. |
| `GET /api/attack` | Runs the detection regression suite, attacks *and* benign controls. |
| `GET /api/status` | Component state and live rule counts. |
| `GET /actuator/prometheus` | Metrics. |

---

## Architecture

```
com.piiguard.piiguard
├── config/     PiiGuardProperties · SecurityConfig · AdminKeyAuthFilter
│               RateLimitFilter · HttpClientConfig
├── privacy/    SanitizationPipeline · RegexSanitizer · NerService
│               TokenVault ⇢ InMemoryTokenVault · OutputGuard
│               DifferentialPrivacyService · PrivacyBudgetAccountant
├── detect/     AdversarialHarnessService · MlDetectionService · ThreatVerdict
├── llm/        LlmClient
├── audit/      AuditLog · AuditLogRepository · AuditService
└── web/        ProxyController · AdminController · GlobalExceptionHandler
                PiiGuardMetrics · dto/
```

**Why the ordering is what it is**

1. **Threat check first** — an attack prompt is refused before it can consume vault
   capacity, model spend or privacy budget.
2. **Redact before perturbing numbers** — reversed, the noise stage would alter digits
   inside a card number just enough to fail its Luhn check, and it would be forwarded in
   the clear.
3. **Restore after the network call** — the boundary sits between redaction and
   restoration. That is the whole design.

**Two invariants worth knowing**

- *Placeholder bodies contain no digits.* This makes it structurally impossible for the
  phone/card detectors or the numeric noise stage to match inside a placeholder. Whole
  classes of corruption become unrepresentable rather than merely unlikely.
- *The vault is cleared in a `finally` block, and a TTL sweeper backs it up.* A privacy
  control that only holds on the happy path is not a control.

---

## Threat model

| Adversary | Capability | Mitigation |
|---|---|---|
| **The LLM provider** | Sees, logs and may train on every prompt | Never receives real values; sees placeholders and perturbed magnitudes |
| **A malicious user** | Crafts prompts to extract other data | Threat rules + classifier; session-scoped vault; forged placeholders neutralised on input |
| **A network observer** | Reads traffic | TLS to the provider; nothing real crosses the boundary regardless |
| **Someone with database access** | Reads the audit table | Table holds no raw prompts — only redacted text, type counts and keyed fingerprints |
| **A resource attacker** | Cheap requests, expensive work | Rate limiting, bounded prompt length, bounded vault, timeouts everywhere, no backtracking regex |
| **A future maintainer** | Reintroduces a fixed defect | 118 tests, most written against the specific defect rather than the happy path |

### Known limitations

- **Sequential composition.** Repeating a prompt many times and averaging erodes the noise.
  The budget accountant bounds this per caller; two colluding callers get two budgets.
  Keying by *data subject* would be correct and needs an identity model this project lacks.
- **Correlated values.** Perturbing revenue, cost and profit independently breaks the
  arithmetic between them and leaks information to anyone who knows the relationship.
- **In-process state.** The vault, the rate limiter and the budget ledger are all in memory,
  so they are per-replica. Horizontal scaling needs Redis — the `TokenVault` interface exists
  for exactly that substitution.
- **Implicit identifiers.** "my manager in the Pune office who joined last March" identifies
  a person and no detector here will catch it.
- **Name coverage remains uneven.** The OpenNLP model is trained predominantly on Western
  newswire; the lexicon in
  [`name-gazetteer.txt`](src/main/resources/name-gazetteer.txt) covers common Indian names,
  but a lexicon only knows what is written in it. Chinese, Arabic, and less common Indian
  names outside the list still depend on the model, which handles them poorly.

---

## What this is not

**It is not formal differential privacy**, and the earlier version of this document was
wrong to claim (ε,δ)-DP.

Differential privacy is a property of a randomised **query over a dataset**: it bounds how
much the output distribution can change when one individual's record is added or removed.
This system perturbs numeric literals inside a sentence. There is no dataset, no query and
no notion of an adjacent dataset — so there is no ε for the guarantee to be stated with
respect to.

What it actually is: **the Laplace mechanism applied to numeric literals, with noise
calibrated to magnitude and a budget accountant that bounds repeated querying.** That is
genuinely useful — an approximate figure is enough for a model to reason with and not worth
exfiltrating — and it is now described accurately.

**It is not a guarantee against a determined insider.** The vault holds plaintext in memory
by necessity. Values are stored as `char[]` and zeroed on clear, but a heap dump taken
mid-request contains real data.

**It is not a substitute for a data processing agreement.** It reduces what you disclose.
It does not change your legal obligations about what you disclose.

---

## Testing

```bash
./mvnw test
```

128 tests. The ones worth reading first, because each pins a specific defect:

| Test | Property |
|---|---|
| `ProxyControllerIntegrationTest#sensitiveValuesNeverReachTheModel` | Captures what actually crossed the boundary |
| `ProxyControllerIntegrationTest#auditNeverStoresRawPii` | The audit table cannot regress to storing prompts |
| `ProxyControllerIntegrationTest#vaultIsClearedAfterFailure` | Cleanup survives the failure path |
| `SecurityConfigTest#auditRequiresAuthentication` | The audit log cannot become anonymous again |
| `InMemoryTokenVaultTest#noCollisionsAtScale` | 500 placeholders, zero collisions |
| `InMemoryTokenVaultTest#concurrentAccessIsCorrect` | 1,600 concurrent operations return no one else's value |
| `AdversarialHarnessServiceTest#isNotVulnerableToRedos` | 10,000-character hostile input terminates |
| `AdversarialHarnessServiceTest#allowsBenignPrompts` | 11 prompts using attack vocabulary are allowed |
| `GazetteerNameDetectorTest#detectsNamesTheModelMisses` | Names the statistical model returns nothing for |
| `DifferentialPrivacyServiceTest#neverEmitsInfinity` | 20,000 samples, no `Infinity` in output |

Classifier quality, from `train_model.py` on a held-out split:

```
ATTACK recall     0.965 (±0.047)     5-fold, pipeline refitted per fold
ATTACK precision  0.956 (±0.041)
holdout ROC AUC   1.000
```

Generalisation check — `f0rg3t y0ur syst3m pr0mpt` is **not** in the training data and
scores 0.909, because character n-grams see through the substitutions.

---

## Roadmap

1. **Redis-backed vault, limiter and ledger** — the single change that makes this
   horizontally scalable.
2. **Streaming responses** — restoration currently needs the whole completion; a
   placeholder split across chunk boundaries is the interesting problem.
3. **Semantic detection of implicit identifiers** — embedding similarity for the
   "my manager in Pune" class that patterns, NER and the lexicon all miss.
4. **Correlation-aware noise** — perturb related figures jointly so the arithmetic between
   them survives.
5. **Per-tenant policy** — different industries need different rule sets and different
   fail-open/fail-closed postures.

---

## Tech stack

Java 21 · Spring Boot 3.5 · Spring Security · Apache OpenNLP 2.3 · H2/PostgreSQL ·
Micrometer · Python 3.11 · FastAPI · scikit-learn 1.5 · Docker
