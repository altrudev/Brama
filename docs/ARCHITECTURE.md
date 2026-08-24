# Architecture

## 1. Boundary

BRAMA Assurance Boundary operates entirely on the clean side of a trust boundary. It may inspect BRAMA's own public UA/EN service surfaces and may accept sanitized event envelopes from a hostile-content review environment. It must not ingest, retain, reproduce, train on, or promote raw hostile content.

## 2. Data classes

### CLEAN_PUBLIC
BRAMA's own public Ukrainian and English pages, service metadata, public documentation, public identifiers and public contact information.

### SANITIZED_EVIDENCE
Opaque evidence identifiers, cryptographic digests, timestamps, platform class, moderator state, authority record, transition record and outcome state.

### HOSTILE_UNTRUSTED
Raw hostile posts, messages, transcripts, media, payloads, attachments or directives. This class is prohibited from the clean repository and clean runtime.

## 3. Permitted bridge schema

```json
{
  "submission_id": "opaque-id",
  "platform": "platform-class",
  "observed_at": "2026-08-23T00:00:00Z",
  "evidence_sha256": "hex-digest",
  "review_state": "HUMAN_REVIEW_PENDING",
  "authority_id": "opaque-authority-id",
  "decision": null,
  "outcome": null
}
```

No content field exists by design.

## 4. Authority separation

A signal can produce a review request. It cannot produce authority.

```text
signal -> evidence -> human judgment -> authority -> action -> observed consequence
```

Each arrow is a separately governed transition.

## 5. Directive-influence defense

Any external content attempting to modify system directives, expand privileges, request disclosure, redirect resources, or create authority is treated as untrusted evidence. It cannot be executed or promoted into policy.

## 6. Network model

The monitor:

- allows HTTPS only;
- allows `stopfraud.gov.ua` only;
- performs GET requests only;
- sends no cookies or credentials;
- rejects redirects;
- caps response bytes;
- uses a fixed timeout;
- does not persist page bodies;
- records only derived findings and SHA-256 evidence digests.
