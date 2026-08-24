# BRAMA Assurance Boundary

A clean-boundary integrity and transition-assurance prototype for Ukraine's BRAMA / Cyber Brama public service surface.

This project is deliberately **not** a propaganda collector, classifier, reporting bot or hostile-content archive. It is designed to help verify BRAMA's own public-facing integrity while preserving a strict separation between a clean Ukrainian/English assurance environment and hostile material that BRAMA may need to process operationally.

## Purpose

BRAMA's mission requires contact with hostile and manipulative information. That makes direct corpus integration inappropriate for systems with a zero-Russian operating-corpus rule. The assurance boundary therefore works on public service state, metadata, provenance and sanitized transition events rather than importing hostile text.

The core distinction is:

> detection != evidence != attribution != authority != permission to act

Automated observations may create a reviewable finding. They do not create authority to report, block, accuse, classify or otherwise act against a person, account or resource.

## Components

### Public Integrity Monitor

Read-only checks against an explicit HTTPS allowlist for BRAMA's own public pages. Current checks include:

- UA/EN locale integrity;
- freshness and translation drift;
- canonical-domain drift;
- privacy-policy consistency indicators;
- testing-state exposure;
- response provenance and SHA-256 evidence digests.

Raw page bodies are processed transiently and are not retained by the monitor.

### Governed Transition Model

The governance module models a constrained workflow:

```text
RECEIVED
  -> QUARANTINED
  -> HUMAN_REVIEW_PENDING
  -> VERIFIED | REJECTED | INSUFFICIENT_EVIDENCE
  -> AUTHORIZED_FOR_ACTION
  -> ACTION_ACTIVE
  -> EXTERNAL_ACTION_OBSERVED
  -> CLOSED
```

`AUTHORIZED_FOR_ACTION` requires an explicit human approval record. Automated detector output cannot jump directly into an action-authorized state.

### Sanitized Event Boundary

The event sanitizer rejects content-bearing fields before metadata can cross from a hostile-analysis environment into a clean assurance environment.

Allowed examples include:

- submission identifier;
- platform class;
- timestamps;
- evidence digest;
- source class;
- moderator state;
- decision;
- approval identifier;
- transition history;
- report status.

Raw message bodies, transcripts, post text, prompts and equivalent content fields are not allowed through the boundary.

### Clean-Corpus Audit

The audit checks repository invariants, including absence of Russian-language locale surfaces and Russian-specific Cyrillic characters in project text.

## Public observations motivating the prototype

Verified against the live public portal on 2026-08-23:

1. `https://stopfraud.gov.ua/` states that the portal is in testing/filling mode.
2. The Ukrainian homepage exposes August 2026 news while `/en` exposes February 2024 news and Ukrainian-language headlines, indicating translation/freshness drift.
3. The live privacy policy is hosted on `.gov.ua` while its text still identifies `https://stopfraud.com.ua`.
4. The privacy policy declares automatic collection of a MAC address. Ordinary web browsers do not normally expose a client's network-interface MAC address to a remote website, so this declaration merits implementation/policy verification.

These are public-surface assurance findings, not allegations of wrongdoing.

## Non-goals

- no hostile-content collection;
- no Russian-language corpus;
- no automated propaganda classification;
- no automated reporting of accounts or resources;
- no bypassing moderation or platform controls;
- no attribution or corruption allegations;
- no privileged or non-public BRAMA access.

## Author / contact

**Valentyn Rukhaylo**  
Altru.dev  
Email: altrudevelop@gmail.com  
Contact: https://altru.dev/contact  
GitHub: https://github.com/altrudev  
LinkedIn: https://www.linkedin.com/in/val-rukhaylo-437a1b3b6

## Status

Research prototype / contribution package. Not affiliated with or endorsed by the Department of Cyber Police of the National Police of Ukraine, EUAM Ukraine, or BRAMA unless they explicitly adopt it.
