import unittest

from brama_assurance.evidence import EvidenceCapsule, EvidenceCapsuleRejected
from brama_assurance.bundle import build_proof_bundle, verify_bundle
from brama_assurance.governance import State
from brama_assurance.ledger import LedgerRejected, append_transition, verify_chain
from brama_assurance.outcome import OutcomeMetrics, assess_outcome
from brama_assurance.platform_export import ExportDenied, ReviewRequestType, build_platform_review_package
from brama_assurance.response import ResponseType, SimulationInput, simulate
from brama_assurance.review import ReviewAttestation, ReviewDecision, evaluate_consensus
from brama_assurance.merkle import merkle_proof, merkle_root, verify_merkle_proof
from brama_assurance.safeguards import ReconsiderationRecord
from brama_assurance.transparency import summarize
from brama_assurance.verifier import verify_proof


DIGEST = "a" * 64
POLICY_DIGEST = "c" * 64


class ProoflineTests(unittest.TestCase):
    def capsule(self):
        return EvidenceCapsule(
            case_id="BR-20481",
            evidence_sha256=DIGEST,
            observed_at="2026-08-24T04:00:00Z",
            platform="platform-class",
            source_type="account",
            review_state="HUMAN_REVIEW_PENDING",
            finding_confidence=0.81,
            attribution_confidence=0.34,
            policy_version="P-1", policy_sha256=POLICY_DIGEST,
        )

    def authorized_ledger(self):
        entries = []
        append_transition(
            entries, case_id="BR-20481", from_state=State.RECEIVED,
            to_state=State.QUARANTINED, actor_id="system", actor_type="system",
            occurred_at="2026-08-24T04:01:00Z", evidence_sha256=DIGEST,
        )
        append_transition(
            entries, case_id="BR-20481", from_state=State.QUARANTINED,
            to_state=State.HUMAN_REVIEW_PENDING, actor_id="moderation-queue",
            actor_type="system", occurred_at="2026-08-24T04:02:00Z",
            evidence_sha256=DIGEST,
        )
        append_transition(
            entries, case_id="BR-20481", from_state=State.HUMAN_REVIEW_PENDING,
            to_state=State.VERIFIED, actor_id="reviewer-1", actor_type="human",
            occurred_at="2026-08-24T04:03:00Z", evidence_sha256=DIGEST,
        )
        append_transition(
            entries, case_id="BR-20481", from_state=State.VERIFIED,
            to_state=State.AUTHORIZED_FOR_ACTION, actor_id="reviewer-2",
            actor_type="human", occurred_at="2026-08-24T04:04:00Z",
            evidence_sha256=DIGEST, authority_id="AUTH-7", policy_version="P-1",
            policy_sha256=POLICY_DIGEST, human_approval=True,
        )
        return entries

    def test_capsule_is_deterministically_hashed(self):
        capsule = self.capsule()
        self.assertEqual(capsule.capsule_hash(), capsule.capsule_hash())
        self.assertEqual(len(capsule.capsule_hash()), 64)

    def test_capsule_rejects_invalid_confidence(self):
        capsule = EvidenceCapsule(
            case_id="x", evidence_sha256=DIGEST, observed_at="2026-08-24T04:00:00Z",
            platform="p", source_type="a", review_state="RECEIVED",
            finding_confidence=1.5,
        )
        with self.assertRaises(EvidenceCapsuleRejected):
            capsule.validate()

    def test_ledger_chain_verifies(self):
        entries = self.authorized_ledger()
        self.assertEqual(verify_chain(entries), [])

    def test_ledger_requires_human_authority(self):
        entries = []
        append_transition(entries, case_id="BR-1", from_state=State.RECEIVED, to_state=State.QUARANTINED, actor_id="s", actor_type="system", occurred_at="2026-08-24T04:01:00Z", evidence_sha256=DIGEST)
        append_transition(entries, case_id="BR-1", from_state=State.QUARANTINED, to_state=State.HUMAN_REVIEW_PENDING, actor_id="s", actor_type="system", occurred_at="2026-08-24T04:02:00Z", evidence_sha256=DIGEST)
        append_transition(entries, case_id="BR-1", from_state=State.HUMAN_REVIEW_PENDING, to_state=State.VERIFIED, actor_id="r", actor_type="human", occurred_at="2026-08-24T04:03:00Z", evidence_sha256=DIGEST)
        with self.assertRaises(ValueError):
            append_transition(entries, case_id="BR-1", from_state=State.VERIFIED, to_state=State.AUTHORIZED_FOR_ACTION, actor_id="detector", actor_type="system", occurred_at="2026-08-24T04:04:00Z", evidence_sha256=DIGEST, authority_id="A-1")

    def test_ledger_rejects_wrong_current_state(self):
        entries = self.authorized_ledger()
        with self.assertRaises(LedgerRejected):
            append_transition(entries, case_id="BR-20481", from_state=State.VERIFIED, to_state=State.AUTHORIZED_FOR_ACTION, actor_id="r", actor_type="human", occurred_at="2026-08-24T04:05:00Z", evidence_sha256=DIGEST, authority_id="A-2", policy_sha256=POLICY_DIGEST, human_approval=True)

    def test_platform_package_denied_before_authority(self):
        entries = []
        append_transition(entries, case_id="BR-20481", from_state=State.RECEIVED, to_state=State.QUARANTINED, actor_id="s", actor_type="system", occurred_at="2026-08-24T04:01:00Z", evidence_sha256=DIGEST)
        with self.assertRaises(ExportDenied):
            build_platform_review_package(self.capsule(), entries, requested_review=ReviewRequestType.POLICY_COMPLIANCE_REVIEW)

    def test_platform_package_has_no_raw_content(self):
        package = build_platform_review_package(self.capsule(), self.authorized_ledger(), requested_review=ReviewRequestType.POLICY_COMPLIANCE_REVIEW)
        forbidden = {"content", "text", "body", "payload", "message", "transcript", "media"}
        self.assertTrue(forbidden.isdisjoint(package))
        self.assertEqual(package["authority_id"], "AUTH-7")

    def test_response_simulator_is_advisory_only(self):
        result = simulate(SimulationInput(response=ResponseType.PUBLIC_CORRECTION, evidence_confidence=0.7, attribution_confidence=0.3, amplification_risk=0.8, rights_risk=0.4, current_reach=0.1))
        self.assertTrue(result.advisory_only)
        self.assertIn(result.recommendation, {"HUMAN_REVIEW_REQUIRED", "PREFER_LOWER_IMPACT_RESPONSE"})

    def test_response_simulator_flags_low_reach_amplification(self):
        result = simulate(SimulationInput(response=ResponseType.PUBLIC_WARNING, evidence_confidence=0.8, attribution_confidence=0.7, amplification_risk=0.9, rights_risk=0.2, current_reach=0.1))
        self.assertTrue(any("amplify" in reason for reason in result.reasons))

    def test_outcome_improvement(self):
        before = OutcomeMetrics(0.8, 0.7, 0.6, 0.1)
        after = OutcomeMetrics(0.3, 0.2, 0.3, 0.1)
        result = assess_outcome(before, after, counterfactual_reach_index=0.9, confidence="moderate")
        self.assertEqual(result.classification, "IMPROVEMENT_OBSERVED")
        self.assertGreater(result.counterfactual_gap, 0)

    def test_outcome_adverse_effect(self):
        before = OutcomeMetrics(0.2, 0.2, 0.1, 0.1)
        after = OutcomeMetrics(0.7, 0.7, 0.6, 0.6)
        result = assess_outcome(before, after)
        self.assertEqual(result.classification, "ADVERSE_EFFECT_OBSERVED")

    def test_transparency_summary(self):
        summary = summarize(self.authorized_ledger())
        self.assertEqual(summary["cases_seen"], 1)
        self.assertEqual(summary["actions_authorized"], 1)

    def test_reconsideration_requires_independent_review(self):
        record = ReconsiderationRecord(case_id="BR-20481", requested_at="2026-08-24T05:00:00Z", requester_role="reviewer", reason_code="NEW_EVIDENCE")
        self.assertTrue(record.independent_review_required)
        self.assertEqual(len(record.record_hash()), 64)

    def test_independent_verifier_does_not_assert_correctness(self):
        capsule = self.capsule()
        report = verify_proof(capsule, capsule.capsule_hash(), self.authorized_ledger())
        self.assertTrue(report.integrity_verified)
        self.assertTrue(report.authority_chain_verified)
        self.assertFalse(report.contents_disclosed)
        self.assertFalse(report.decision_correctness_asserted)

    def test_merkle_evidence_set_proof(self):
        digests = ["1" * 64, "2" * 64, "3" * 64]
        root = merkle_root(digests)
        proof = merkle_proof(digests, 1)
        self.assertTrue(verify_merkle_proof(digests[1], proof, root))
        self.assertFalse(verify_merkle_proof("4" * 64, proof, root))

    def test_reviewer_consensus_requires_independent_reviewers(self):
        attestations = [
            ReviewAttestation(case_id="BR-20481", reviewer_id="r1", reviewer_group="g1", evidence_sha256=DIGEST, decision=ReviewDecision.VERIFIED, confidence=0.8, occurred_at="2026-08-24T04:10:00Z"),
            ReviewAttestation(case_id="BR-20481", reviewer_id="r2", reviewer_group="g2", evidence_sha256=DIGEST, decision=ReviewDecision.VERIFIED, confidence=0.9, occurred_at="2026-08-24T04:11:00Z"),
        ]
        result = evaluate_consensus(attestations, min_reviewers=2, min_groups=2)
        self.assertTrue(result.reached)
        self.assertEqual(result.decision, "VERIFIED")

    def test_verifier_detects_tampered_chain(self):
        from dataclasses import replace
        entries = self.authorized_ledger()
        entries[1] = replace(entries[1], actor_id="tampered")
        capsule = self.capsule()
        report = verify_proof(capsule, capsule.capsule_hash(), entries)
        self.assertFalse(report.integrity_verified)
        self.assertTrue(any("hash mismatch" in item for item in report.failures))

    def test_proof_without_authority_is_not_action_proof(self):
        entries = []
        append_transition(entries, case_id="BR-20481", from_state=State.RECEIVED, to_state=State.QUARANTINED, actor_id="s", actor_type="system", occurred_at="2026-08-24T04:01:00Z", evidence_sha256=DIGEST)
        capsule = self.capsule()
        report = verify_proof(capsule, capsule.capsule_hash(), entries)
        self.assertFalse(report.integrity_verified)
        self.assertFalse(report.authority_chain_verified)

    def test_offline_proof_bundle_verifies_without_raw_content(self):
        capsule = self.capsule()
        bundle = build_proof_bundle(capsule, self.authorized_ledger())
        self.assertFalse(bundle["raw_content_included"])
        self.assertNotIn("content", bundle)
        report = verify_bundle(bundle)
        self.assertTrue(report.integrity_verified)

    def test_offline_proof_bundle_rejects_head_tampering(self):
        capsule = self.capsule()
        bundle = build_proof_bundle(capsule, self.authorized_ledger())
        bundle["ledger_head_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            verify_bundle(bundle)

    def test_proof_bundle_rejects_attestation_tampering(self):
        capsule = self.capsule()
        attestation = ReviewAttestation(case_id="BR-20481", reviewer_id="r1", reviewer_group="g1", evidence_sha256=DIGEST, decision=ReviewDecision.VERIFIED, confidence=0.8, occurred_at="2026-08-24T04:10:00Z")
        bundle = build_proof_bundle(capsule, self.authorized_ledger(), reviewer_attestations=[attestation])
        bundle["reviewer_attestations"][0]["confidence"] = 0.1
        report = verify_bundle(bundle)
        self.assertFalse(report.integrity_verified)
        self.assertTrue(any("attestation hash mismatch" in item for item in report.failures))

    def test_proof_bundle_filters_unrelated_cases(self):
        capsule = self.capsule()
        entries = self.authorized_ledger()
        append_transition(entries, case_id="OTHER", from_state=State.RECEIVED, to_state=State.QUARANTINED, actor_id="s", actor_type="system", occurred_at="2026-08-24T04:06:00Z", evidence_sha256=DIGEST)
        bundle = build_proof_bundle(capsule, entries)
        self.assertTrue(all(item["case_id"] == capsule.case_id for item in bundle["ledger"]))


if __name__ == "__main__":
    unittest.main()
