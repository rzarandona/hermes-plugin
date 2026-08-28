from datetime import datetime, timedelta, timezone
import unittest

from hermes_kanban_workflow.activation import ActivationChain, ActivationDecision, ActivationEvidence
from hermes_kanban_workflow.release_gate import AuditVerdict, evaluate_release_readiness


class ActivationAndReleaseTests(unittest.TestCase):
    def test_activation_chain_has_ten_ordered_non_skippable_gates(self) -> None:
        chain = ActivationChain(package_digest="pkg", policy_digest="pol", host_digest="host")
        stage1 = chain.advance(
            ActivationEvidence(stage=1, predecessor_digest=None, passed=True),
            ActivationDecision(stage=1, owner_id="owner", package_digest="pkg", policy_digest="pol", host_digest="host"),
        )
        self.assertEqual(stage1.stage, 1)
        with self.assertRaisesRegex(PermissionError, "ACTIVATION_STAGE_SKIP_DENIED"):
            chain.advance(
                ActivationEvidence(stage=3, predecessor_digest=stage1.receipt_digest, passed=True),
                ActivationDecision(stage=3, owner_id="owner", package_digest="pkg", policy_digest="pol", host_digest="host"),
            )

    def test_release_gate_rejects_stale_or_open_high_findings(self) -> None:
        now = datetime.now(timezone.utc)
        verdict = AuditVerdict(
            reviewer_id="reviewer-a", scope_digest="scope", evidence_digest="evidence", verdict="PASS",
            open_p0=0, open_p1=0, p2_disposition="accepted", issued_at=now,
            expires_at=now + timedelta(days=1), gatekeeper_ack=True,
        )
        self.assertTrue(evaluate_release_readiness(verdict, now).ready)
        self.assertFalse(evaluate_release_readiness(verdict.model_copy(update={"open_p1": 1}), now).ready)
        self.assertFalse(evaluate_release_readiness(verdict, now + timedelta(days=2)).ready)


if __name__ == "__main__":
    unittest.main()
