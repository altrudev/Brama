import unittest

from brama_assurance.governance import State, TransitionDenied, TransitionRequest, validate_transition

DIGEST = "a" * 64


class GovernanceTests(unittest.TestCase):
    def test_normal_review_transition(self):
        validate_transition(TransitionRequest(
            State.QUARANTINED,
            State.HUMAN_REVIEW_PENDING,
            "system",
            DIGEST,
        ))

    def test_detector_cannot_create_action_authority(self):
        with self.assertRaises(TransitionDenied):
            validate_transition(TransitionRequest(
                State.VERIFIED,
                State.AUTHORIZED_FOR_ACTION,
                "system",
                DIGEST,
                human_approval=False,
            ))

    def test_human_can_authorize_after_verification(self):
        validate_transition(TransitionRequest(
            State.VERIFIED,
            State.AUTHORIZED_FOR_ACTION,
            "human",
            DIGEST,
            human_approval=True,
        ))

    def test_invalid_state_jump_denied(self):
        with self.assertRaises(TransitionDenied):
            validate_transition(TransitionRequest(
                State.RECEIVED,
                State.ACTION_ACTIVE,
                "human",
                DIGEST,
                human_approval=True,
            ))
