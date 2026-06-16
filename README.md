
  PhishGuard is a defensive Spring Boot web service that classifies whether a message (email body, SMS, or chat text) is
  phishing. You POST it some content and it returns a risk verdict — it never sends, blocks, quarantines, or clicks
  anything. It's a detector, not an enforcement or attack tool.

  It scores a message by combining two independent analysers:

  ┌─────────────┬────────────────────────────────────────────────────────────────────┬──────────────────────────────┐
  │  Analyser   │                             What it is                             │             Role             │
  ├─────────────┼────────────────────────────────────────────────────────────────────┼──────────────────────────────┤
  │ Heuristic   │ ~13 hand-written rules (raw-IP links, @-in-URL, punycode,          │ Always runs; fast, free,     │
  │ engine      │ link-text mismatch, urgency/credential/reward language,            │ fully explainable            │
  │             │ brand-from-freemail spoofing, etc.), each with a weight            │                              │
  ├─────────────┼────────────────────────────────────────────────────────────────────┼──────────────────────────────┤
  │ Local LLM   │ llama3.2 queried over its local HTTP API, returns {verdict,        │ Optional booster; isolated   │
  │ (Ollama)    │ confidence, reasons}                                               │ behind try/catch so it can   │
  │             │                                                                    │ never break a scan           │
  └─────────────┴────────────────────────────────────────────────────────────────────┴──────────────────────────────┘

  The two scores are blended (default 50/50, configurable) into a final 0–100, which maps to:
  - a Verdict — LIKELY_SAFE / SUSPICIOUS / PHISHING
  - a RiskLevel — LOW / MEDIUM / HIGH / CRITICAL

  Every scan is persisted to an in-memory H2 database for audit/history, and a dependency-free single-page web UI
  (served at the root) lets you try it by hand.

  Stack

  Java 21 · Spring Boot 3.5 (web, data-jpa, validation) · H2 in-memory DB · Ollama (optional) · Maven · JUnit 5.

  How to run

  cd IdeaProjects/ai-phishing-security-gateway
  mvn spring-boot:run        # then open http://localhost:8081
  Run heuristics-only (no LLM) with --phishguard.llm.enabled=false.

  API surface

  - POST /api/scan — analyse a message → verdict + both scores + every fired rule + LLM reasons
  - GET /api/scans?page=&size= — paged history
  - GET /api/scans/{id} — full stored record
  - GET /api/health — liveness + whether the LLM is enabled
   
