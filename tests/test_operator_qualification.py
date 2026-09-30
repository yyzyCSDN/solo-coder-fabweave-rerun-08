from fabweave.core.versioning import RevisionHistory
from fabweave.training.qualification import (
    OperatorCertificate,
    TrainingRule,
    operator_qualification_decision,
)


def rule(version: int, effective_at: int = 0, grace_until: int | None = None) -> TrainingRule:
    return TrainingRule(version, effective_at, "ETCH", "PLASMA", version, grace_until)


def certificate(
    training_version: int,
    effective_at: int = 0,
    expires_at: int = 100,
    revoked_at: int | None = None,
    operator_id: str = "OP-1",
) -> OperatorCertificate:
    return OperatorCertificate(
        operator_id, "ETCH", "PLASMA", training_version, effective_at, expires_at, revoked_at
    )


def test_decision_requires_operation_equipment_family_and_operator_match():
    rules = [rule(3)]
    certificates = [
        certificate(3, operator_id="OP-2"),
        OperatorCertificate("OP-1", "CLEAN", "PLASMA", 3, 0, 100),
        OperatorCertificate("OP-1", "ETCH", "IMPLANT", 3, 0, 100),
    ]

    decision = operator_qualification_decision("OP-1", "ETCH", "PLASMA", 50, rules, certificates)

    assert decision.reasons == ("training_certificate_missing",)
    assert decision.evidence == {
        "operator_id": "OP-1",
        "operation_id": "ETCH",
        "equipment_family": "PLASMA",
        "evaluated_at": 50,
        "matching_certificate_count": 0,
        "rule_revision": 3,
        "rule_effective_at": 0,
        "required_version": 3,
        "grace_period": None,
        "grace_until": None,
    }


def test_missing_rule_and_certificate_are_reported_together():
    decision = operator_qualification_decision("OP-1", "ETCH", "PLASMA", 10, [], [])

    assert decision.reasons == ("training_rule_missing", "training_certificate_missing")
    assert "rule_revision" not in decision.evidence


def test_certificate_effective_expiry_and_revocation_boundaries_are_inclusive_or_exclusive():
    rules = [rule(2)]
    certificates = [certificate(2, effective_at=10, expires_at=90, revoked_at=50)]

    assert operator_qualification_decision("OP-1", "ETCH", "PLASMA", 9, rules, certificates).reasons == (
        "training_certificate_not_effective",
    )
    assert operator_qualification_decision("OP-1", "ETCH", "PLASMA", 10, rules, certificates).allowed
    assert operator_qualification_decision("OP-1", "ETCH", "PLASMA", 49, rules, certificates).allowed
    assert operator_qualification_decision("OP-1", "ETCH", "PLASMA", 50, rules, certificates).reasons == (
        "training_certificate_revoked",
    )
    assert operator_qualification_decision("OP-1", "ETCH", "PLASMA", 100, rules, certificates).reasons == (
        "training_certificate_expired",
        "training_certificate_revoked",
    )


def test_same_effective_time_uses_latest_revision_and_rejects_all_certificate_states():
    rules = [
        TrainingRule(1, 20, "ETCH", "PLASMA", 1),
        TrainingRule(3, 30, "ETCH", "PLASMA", 3),
        TrainingRule(2, 30, "ETCH", "PLASMA", 2),
    ]
    certificates = [
        certificate(3, effective_at=40, expires_at=100),
        certificate(2, effective_at=0, expires_at=20),
        certificate(1, effective_at=0, expires_at=100, revoked_at=25),
    ]

    decision = operator_qualification_decision("OP-1", "ETCH", "PLASMA", 35, rules, certificates)

    assert decision.evidence["rule_revision"] == 3
    assert decision.evidence["required_version"] == 3
    assert decision.reasons == (
        "training_certificate_not_effective",
        "training_certificate_expired",
        "training_certificate_revoked",
        "training_version_mismatch",
    )


def test_old_training_version_is_accepted_during_grace_but_rejected_after_it():
    rules = [TrainingRule(2, 20, "ETCH", "PLASMA", 2, grace_until=40)]
    certificates = [certificate(1)]

    during_grace = operator_qualification_decision("OP-1", "ETCH", "PLASMA", 40, rules, certificates)
    assert during_grace.allowed
    assert during_grace.evidence["training_version"] == 1
    assert during_grace.evidence["grace_used"] is True

    after_grace = operator_qualification_decision("OP-1", "ETCH", "PLASMA", 41, rules, certificates)
    assert after_grace.reasons == ("training_version_grace_expired",)


def test_current_version_is_preferred_over_an_otherwise_eligible_old_version():
    rules = [TrainingRule(2, 20, "ETCH", "PLASMA", 2, grace_until=40)]
    certificates = [certificate(1, expires_at=200), certificate(2, expires_at=100)]

    decision = operator_qualification_decision("OP-1", "ETCH", "PLASMA", 30, rules, certificates)

    assert decision.allowed
    assert decision.evidence["training_version"] == 2
    assert decision.evidence["certificate_expires_at"] == 100
    assert decision.evidence["grace_used"] is False


def test_grace_may_be_supplied_as_a_period_from_the_revision_effective_time():
    decision = operator_qualification_decision(
        "OP-1",
        "ETCH",
        "PLASMA",
        39,
        [TrainingRule(2, 20, "ETCH", "PLASMA", 2, None, 20)],
        [certificate(1)],
    )

    assert decision.allowed
    assert decision.evidence["grace_period"] == 20
    assert decision.evidence["grace_until"] == 40


def test_reproducing_a_past_decision_ignores_later_rules_revocations_and_expiry():
    policy: RevisionHistory[tuple[TrainingRule, ...]] = RevisionHistory()
    policy.publish(1, 0, (TrainingRule(1, 0, "ETCH", "PLASMA", 1, grace_until=30),))
    policy.publish(2, 40, (TrainingRule(2, 40, "ETCH", "PLASMA", 2, grace_until=45),))
    certificates = [certificate(1, expires_at=40, revoked_at=25)]

    past = operator_qualification_decision(
        "OP-1", "ETCH", "PLASMA", 20, policy, certificates
    )
    now = operator_qualification_decision(
        "OP-1", "ETCH", "PLASMA", 50, policy, certificates
    )

    assert past.allowed
    assert past.evidence["rule_revision"] == 1
    assert past.evidence["grace_used"] is False
    assert now.reasons == (
        "training_certificate_expired",
        "training_certificate_revoked",
        "training_version_grace_expired",
    )
