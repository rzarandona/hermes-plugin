import unittest

from hermes_kanban_workflow.flows.lifecycle import Flow, LifecycleEngine
from hermes_kanban_workflow.recovery.controls import HoldRegistry, RecoveryClass, RecoveryPolicy
from hermes_kanban_workflow.reporting.owner_brief import ArtifactLocator, OwnerBrief
from hermes_kanban_workflow.review.classifier import DeliveryClassifier, DeliveryProfile, IntakeFacts
from hermes_kanban_workflow.review.verdicts import ReviewIdentity, ReviewPacket, ReviewVerdict, seal_reviews


class FlowAndControlTests(unittest.TestCase):
    def test_classifier_fails_closed_and_implementation_keeps_two_reviews(self) -> None:
        classifier = DeliveryClassifier()
        small = classifier.classify(IntakeFacts(mutates_product=True, modules=1, protected=False, external_effect=False, design_unknown=False, dependencies=()))
        self.assertEqual(small.profile, DeliveryProfile.BOUNDED_IMPLEMENTATION)
        self.assertEqual(small.required_reviews, 2)
        uncertain = classifier.classify(IntakeFacts(mutates_product=True, modules=1, protected=False, external_effect=False, design_unknown=True, dependencies=()))
        self.assertEqual(uncertain.profile, DeliveryProfile.DESIGN_REQUIRED)

    def test_two_reviews_require_independent_controllers_and_credentials(self) -> None:
        a = ReviewIdentity("subject-a", "controller-a", "family-a")
        b = ReviewIdentity("subject-b", "controller-b", "family-b")
        packet_a = ReviewPacket("r1", a, ReviewVerdict.PASS, ("correctness",), "digest")
        packet_b = ReviewPacket("r2", b, ReviewVerdict.PASS, ("risk",), "digest")
        self.assertEqual(seal_reviews(packet_a, packet_b).candidate_digest, "digest")
        alias = ReviewIdentity("subject-b", "controller-a", "family-b")
        with self.assertRaisesRegex(PermissionError, "REVIEWER_INDEPENDENCE_DENIED"):
            seal_reviews(packet_a, ReviewPacket("r3", alias, ReviewVerdict.PASS, ("risk",), "digest"))

    def test_four_flow_boundaries_reject_skips(self) -> None:
        engine = LifecycleEngine()
        request = engine.start("work-1")
        execution = engine.advance(request, Flow.EXECUTION, evidence="owner-approved")
        release = engine.advance(execution, Flow.RELEASE, evidence="gatekeeper-pass")
        operations = engine.advance(release, Flow.OPERATIONS, evidence="handoff-accepted")
        self.assertEqual(operations.flow, Flow.OPERATIONS)
        with self.assertRaisesRegex(ValueError, "FLOW_TRANSITION_DENIED"):
            engine.advance(request, Flow.RELEASE, evidence="shortcut")

    def test_recovery_and_hold_are_bounded(self) -> None:
        policy = RecoveryPolicy(allowlisted_r1=frozenset({"restart-worker"}))
        self.assertTrue(policy.can_automate(RecoveryClass.R0, "requeue"))
        self.assertTrue(policy.can_automate(RecoveryClass.R1, "restart-worker"))
        self.assertFalse(policy.can_automate(RecoveryClass.R2, "rollback"))
        holds = HoldRegistry()
        record = holds.create("project-a", ("card-1", "card-2"), "owner priority")
        self.assertEqual(holds.resume_candidates(record.hold_id, ("card-1", "card-3")), ("card-1",))

    def test_owner_brief_keeps_substance_and_artifact_locator(self) -> None:
        brief = OwnerBrief(
            requested_outcome="Create the plan", accomplishment="Plan verified", impact="Ready for review",
            verification="All checks passed", remaining_risk="Not installed", next_action="Owner review",
            artifact=ArtifactLocator("Implementation plan", "C:/safe/plan.html", supported=False),
        )
        payload = brief.to_dict()
        self.assertEqual(len({k for k in payload if k != "artifact"}), 6)
        self.assertEqual(payload["artifact"]["outcome"], "ARTIFACT_LOCATOR_UNSUPPORTED")


if __name__ == "__main__":
    unittest.main()
