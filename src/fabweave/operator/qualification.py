from __future__ import annotations

from dataclasses import dataclass

from fabweave.core.decision import Decision, allow, deny


@dataclass(frozen=True, slots=True)
class OperatorCertificate:
    operator_id: str
    operation_id: str
    equipment_family: str
    training_version: int
    effective_at: int
    expires_at: int
    revoked_at: int | None = None

    def __post_init__(self) -> None:
        if self.training_version <= 0:
            raise ValueError("training version must be positive")
        if self.expires_at < self.effective_at:
            raise ValueError("certificate cannot expire before it becomes effective")
        if self.revoked_at is not None and self.revoked_at < self.effective_at:
            raise ValueError(
                "certificate cannot be revoked before it becomes effective"
            )

    def active_at(self, instant: int) -> bool:
        return not self.inactive_reasons_at(instant)

    def inactive_reasons_at(self, instant: int) -> tuple[str, ...]:
        reasons: list[str] = []
        if instant < self.effective_at:
            reasons.append("certificate_not_yet_effective")
        if instant > self.expires_at:
            reasons.append("certificate_expired")
        if self.revoked_at is not None and instant >= self.revoked_at:
            reasons.append("certificate_revoked")
        return tuple(reasons)


@dataclass(frozen=True, slots=True)
class TrainingPolicy:
    revision: int
    effective_at: int
    operation_id: str
    equipment_family: str
    required_version: int
    grace_period: int = 0

    def __post_init__(self) -> None:
        if self.revision <= 0:
            raise ValueError("policy revision must be positive")
        if self.required_version <= 0:
            raise ValueError("required training version must be positive")
        if self.grace_period < 0:
            raise ValueError("grace period cannot be negative")

    @property
    def training_version(self) -> int:
        return self.required_version


class TrainingRule(TrainingPolicy):
    """Alias constructor for callers that name the field ``training_version``."""

    def __init__(
        self,
        revision: int,
        effective_at: int,
        operation_id: str,
        equipment_family: str,
        training_version: int,
        grace_period: int = 0,
    ) -> None:
        super().__init__(
            revision,
            effective_at,
            operation_id,
            equipment_family,
            training_version,
            grace_period,
        )


TrainingRequirement = TrainingPolicy
TrainingVersionPolicy = TrainingPolicy
TrainingVersionRule = TrainingRule
OperatorQualification = OperatorCertificate
Certificate = OperatorCertificate


def _matching_policy(
    operation_id: str,
    equipment_family: str,
    at: int,
    policies: list[TrainingPolicy],
) -> TrainingPolicy | None:
    active = [
        policy
        for policy in policies
        if policy.operation_id == operation_id
        and policy.equipment_family == equipment_family
        and policy.effective_at <= at
    ]
    if not active:
        return None
    return max(active, key=lambda policy: (policy.effective_at, policy.revision))


def _previous_policy(
    current: TrainingPolicy,
    policies: list[TrainingPolicy],
) -> TrainingPolicy | None:
    previous = [
        policy
        for policy in policies
        if policy.operation_id == current.operation_id
        and policy.equipment_family == current.equipment_family
        and policy.effective_at < current.effective_at
    ]
    if not previous:
        return None
    return max(previous, key=lambda policy: (policy.effective_at, policy.revision))


def _certificates_for_version(
    operator_id: str,
    operation_id: str,
    equipment_family: str,
    training_version: int,
    certificates: list[OperatorCertificate],
) -> list[OperatorCertificate]:
    return [
        certificate
        for certificate in certificates
        if certificate.operator_id == operator_id
        and certificate.operation_id == operation_id
        and certificate.equipment_family == equipment_family
        and certificate.training_version == training_version
    ]


def operator_qualification_decision(
    operator_id: str,
    operation_id: str,
    equipment_family: str,
    at: int,
    policies: list[TrainingPolicy],
    certificates: list[OperatorCertificate],
) -> Decision:
    """Decide whether an operator may run an operation on an equipment family.

    The policy history is evaluated by event time, so passing a past ``at``
    reproduces the decision made then.  When several policy revisions became
    effective at the same instant, the highest revision number adjudicates.
    The immediately previous required training version remains acceptable for
    the half-open interval ``[effective_at, effective_at + grace_period)``.
    """

    policy = _matching_policy(operation_id, equipment_family, at, policies)
    if policy is None:
        return deny(
            "training_policy_missing",
            operator_id=operator_id,
            operation_id=operation_id,
            equipment_family=equipment_family,
            evaluated_at=at,
        )

    previous = _previous_policy(policy, policies)
    grace_until = policy.effective_at + policy.grace_period
    previous_required_version = (
        previous.required_version if previous is not None else None
    )
    grace_version = (
        previous_required_version
        if previous_required_version is not None
        and previous_required_version != policy.required_version
        and at < grace_until
        else None
    )

    evidence = {
        "operator_id": operator_id,
        "operation_id": operation_id,
        "equipment_family": equipment_family,
        "evaluated_at": at,
        "policy_revision": policy.revision,
        "policy_effective_at": policy.effective_at,
        "required_training_version": policy.required_version,
        "grace_period": policy.grace_period,
        "grace_until": grace_until,
        "previous_training_version": previous_required_version,
    }

    current_certificates = _certificates_for_version(
        operator_id,
        operation_id,
        equipment_family,
        policy.required_version,
        certificates,
    )
    old_version_certificates = (
        _certificates_for_version(
            operator_id,
            operation_id,
            equipment_family,
            previous_required_version,
            certificates,
        )
        if previous_required_version is not None
        else []
    )
    grace_certificates = old_version_certificates if grace_version is not None else []

    active_current = [
        certificate for certificate in current_certificates if certificate.active_at(at)
    ]
    active_grace = [
        certificate for certificate in grace_certificates if certificate.active_at(at)
    ]

    if active_current:
        chosen = max(
            active_current,
            key=lambda certificate: (certificate.effective_at, certificate.expires_at),
        )
        return allow(
            **evidence,
            training_version=chosen.training_version,
            certificate_effective_at=chosen.effective_at,
            certificate_expires_at=chosen.expires_at,
            using_grace=False,
        )
    if active_grace:
        chosen = max(
            active_grace,
            key=lambda certificate: (certificate.effective_at, certificate.expires_at),
        )
        return allow(
            **evidence,
            training_version=chosen.training_version,
            certificate_effective_at=chosen.effective_at,
            certificate_expires_at=chosen.expires_at,
            using_grace=True,
        )

    reasons: list[str] = []
    if current_certificates:
        for certificate in current_certificates:
            reasons.extend(certificate.inactive_reasons_at(at))
    else:
        reasons.append("operator_certificate_missing")

    if grace_version is not None:
        for certificate in grace_certificates:
            reasons.extend(certificate.inactive_reasons_at(at))
    elif (
        grace_version is None
        and previous_required_version is not None
        and old_version_certificates
    ):
        reasons.append("old_version_grace_expired")
        for certificate in old_version_certificates:
            reasons.extend(certificate.inactive_reasons_at(at))

    return deny(*reasons, **evidence)


def operator_allowed(
    operator_id: str,
    operation_id: str,
    equipment_family: str,
    at: int,
    policies: list[TrainingPolicy],
    certificates: list[OperatorCertificate],
) -> bool:
    return operator_qualification_decision(
        operator_id,
        operation_id,
        equipment_family,
        at,
        policies,
        certificates,
    ).allowed


operator_decision = operator_qualification_decision
operator_training_decision = operator_qualification_decision
operator_certification_decision = operator_qualification_decision
training_qualification_decision = operator_qualification_decision
