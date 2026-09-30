from __future__ import annotations

import pytest

from fabweave.core.decision import Decision
from fabweave.operator.qualification import (
    OperatorCertificate,
    TrainingPolicy,
    TrainingRule,
    operator_allowed,
    operator_qualification_decision,
)


def policies_with_grace() -> list[TrainingPolicy]:
    return [
        TrainingPolicy(1, 0, "ETCH", "ETCHER-A", required_version=1),
        TrainingPolicy(2, 10, "ETCH", "ETCHER-A", required_version=2, grace_period=5),
    ]


def test_qualification_requires_operator_operation_equipment_family_and_version():
    policies = [
        TrainingPolicy(1, 0, "ETCH", "ETCHER-A", required_version=2),
        TrainingPolicy(1, 0, "DEPOSIT", "ETCHER-A", required_version=2),
        TrainingPolicy(1, 0, "ETCH", "ETCHER-C", required_version=2),
    ]
    certificates = [
        OperatorCertificate("OP-1", "ETCH", "ETCHER-A", 2, 0, 100),
        OperatorCertificate("OP-2", "ETCH", "ETCHER-A", 2, 0, 100),
        OperatorCertificate("OP-1", "CLEAN", "ETCHER-A", 2, 0, 100),
        OperatorCertificate("OP-1", "ETCH", "ETCHER-B", 2, 0, 100),
        OperatorCertificate("OP-1", "ETCH", "ETCHER-A", 1, 0, 100),
    ]
    decision = operator_qualification_decision(
        "OP-1", "ETCH", "ETCHER-A", 20, policies, certificates
    )

    assert decision.allowed
    assert decision.evidence["training_version"] == 2
    for operator_id, operation_id, family in [
        ("OP-3", "ETCH", "ETCHER-A"),
        ("OP-1", "DEPOSIT", "ETCHER-A"),
        ("OP-1", "ETCH", "ETCHER-C"),
    ]:
        rejected = operator_qualification_decision(
            operator_id, operation_id, family, 20, policies, certificates
        )
        assert rejected.reasons == ("operator_certificate_missing",)


def test_certificate_boundaries_include_effective_and_expiry_but_not_revocation():
    policies = [TrainingPolicy(1, 0, "ETCH", "F", required_version=1)]
    certificate = OperatorCertificate("OP", "ETCH", "F", 1, 10, 20, revoked_at=18)

    assert not operator_allowed("OP", "ETCH", "F", 9, policies, [certificate])
    assert operator_allowed("OP", "ETCH", "F", 10, policies, [certificate])
    assert operator_allowed("OP", "ETCH", "F", 17, policies, [certificate])
    revoked = operator_qualification_decision(
        "OP", "ETCH", "F", 18, policies, [certificate]
    )
    assert revoked.reasons == ("certificate_revoked",)

    unrevoked = OperatorCertificate("OP", "ETCH", "F", 1, 10, 20)
    assert operator_allowed("OP", "ETCH", "F", 20, policies, [unrevoked])
    expired = operator_qualification_decision(
        "OP", "ETCH", "F", 21, policies, [unrevoked]
    )
    assert expired.reasons == ("certificate_expired",)


def test_same_effective_time_is_adjudicated_by_highest_revision():
    policies = [
        TrainingPolicy(1, 10, "ETCH", "F", required_version=1),
        TrainingPolicy(3, 10, "ETCH", "F", required_version=3),
        TrainingPolicy(2, 10, "ETCH", "F", required_version=2),
    ]
    certificates = [OperatorCertificate("OP", "ETCH", "F", 3, 0, 100)]

    decision = operator_qualification_decision(
        "OP", "ETCH", "F", 10, policies, certificates
    )

    assert decision.allowed
    assert decision.evidence["policy_revision"] == 3


def test_same_time_superseded_revision_is_not_used_as_grace_predecessor():
    policies = [
        TrainingPolicy(1, 10, "ETCH", "F", required_version=1),
        TrainingPolicy(3, 10, "ETCH", "F", required_version=3),
    ]
    certificate = OperatorCertificate("OP", "ETCH", "F", 1, 0, 100)

    decision = operator_qualification_decision(
        "OP", "ETCH", "F", 10, policies, [certificate]
    )

    assert decision.reasons == ("operator_certificate_missing",)
    assert decision.evidence["previous_training_version"] is None


def test_immediately_previous_training_version_is_accepted_during_half_open_grace():
    policies = [
        *policies_with_grace(),
        TrainingPolicy(3, 20, "ETCH", "ETCHER-A", required_version=3, grace_period=5),
    ]
    certificates = [
        OperatorCertificate("OP", "ETCH", "ETCHER-A", 1, 10, 100),
        OperatorCertificate("OP", "ETCH", "ETCHER-A", 2, 15, 19),
    ]

    decision_at_9 = operator_qualification_decision(
        "OP", "ETCH", "ETCHER-A", 9, policies, certificates
    )
    assert decision_at_9.reasons == ("certificate_not_yet_effective",)
    assert operator_allowed("OP", "ETCH", "ETCHER-A", 10, policies, certificates)
    assert operator_allowed("OP", "ETCH", "ETCHER-A", 14, policies, certificates)

    at_boundary = operator_qualification_decision(
        "OP", "ETCH", "ETCHER-A", 25, policies, certificates
    )
    assert at_boundary.reasons == (
        "operator_certificate_missing",
        "old_version_grace_expired",
        "certificate_expired",
    )

    # Version 1 is two revisions behind at time 20 and is no longer the
    # immediately previous requirement.
    at_20 = operator_qualification_decision(
        "OP", "ETCH", "ETCHER-A", 20, policies, certificates
    )
    assert at_20.reasons == (
        "operator_certificate_missing",
        "certificate_expired",
    )


def test_rejection_lists_all_certificate_and_grace_reasons():
    policies = policies_with_grace()
    certificates = [
        OperatorCertificate("OP", "ETCH", "ETCHER-A", 2, 0, 5, revoked_at=4),
        OperatorCertificate("OP", "ETCH", "ETCHER-A", 1, 0, 100, revoked_at=15),
    ]

    decision = operator_qualification_decision(
        "OP", "ETCH", "ETCHER-A", 15, policies, certificates
    )

    assert decision.reasons == (
        "certificate_expired",
        "certificate_revoked",
        "old_version_grace_expired",
    )
    assert decision.evidence["required_training_version"] == 2
    assert decision.evidence["previous_training_version"] == 1


def test_decision_can_be_reproduced_at_a_past_point():
    policies = [
        TrainingPolicy(1, 0, "ETCH", "F", required_version=1),
        TrainingPolicy(2, 15, "ETCH", "F", required_version=2),
    ]
    certificates = [OperatorCertificate("OP", "ETCH", "F", 1, 0, 100, revoked_at=20)]

    historical = operator_qualification_decision(
        "OP", "ETCH", "F", 10, policies, certificates
    )
    current = operator_qualification_decision(
        "OP", "ETCH", "F", 20, policies, certificates
    )

    assert historical.allowed
    assert historical.evidence["policy_revision"] == 1
    assert current.reasons == (
        "operator_certificate_missing",
        "old_version_grace_expired",
        "certificate_revoked",
    )


def test_missing_policy_and_future_policy_are_fail_closed():
    certificates = [OperatorCertificate("OP", "ETCH", "F", 1, 0, 100)]

    assert operator_qualification_decision(
        "OP", "ETCH", "F", 0, [], certificates
    ).reasons == ("training_policy_missing",)

    future_policy = [TrainingPolicy(1, 10, "ETCH", "F", required_version=1)]
    assert operator_qualification_decision(
        "OP", "ETCH", "F", 5, future_policy, certificates
    ).reasons == ("training_policy_missing",)


def test_training_rule_constructor_accepts_training_version_name():
    rule = TrainingRule(2, 10, "ETCH", "F", training_version=3, grace_period=2)
    certificate = OperatorCertificate("OP", "ETCH", "F", 3, 0, 100)

    assert isinstance(rule, TrainingPolicy)
    assert rule.required_version == rule.training_version == 3
    decision = operator_qualification_decision(
        "OP", "ETCH", "F", 11, [rule], [certificate]
    )
    assert isinstance(decision, Decision)
    assert decision.allowed


def test_invalid_policy_and_certificate_ranges_are_rejected():
    with pytest.raises(ValueError):
        TrainingPolicy(0, 0, "ETCH", "F", required_version=1)
    with pytest.raises(ValueError):
        TrainingPolicy(1, 0, "ETCH", "F", required_version=1, grace_period=-1)
    with pytest.raises(ValueError):
        OperatorCertificate("OP", "ETCH", "F", 1, 20, 10)
    with pytest.raises(ValueError):
        OperatorCertificate("OP", "ETCH", "F", 1, 10, 20, revoked_at=5)
