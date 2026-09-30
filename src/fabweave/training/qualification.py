from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import TypeAlias

from fabweave.core.decision import Decision, allow, deny
from fabweave.core.versioning import RevisionHistory


_REASON_ORDER = (
    "training_rule_missing",
    "training_certificate_missing",
    "training_certificate_not_effective",
    "training_certificate_expired",
    "training_certificate_revoked",
    "training_version_mismatch",
    "training_version_grace_expired",
)


@dataclass(frozen=True, slots=True)
class TrainingRule:
    """Effective-dated required training for one operation/equipment-family pair."""

    revision: int
    effective_at: int
    operation_id: str
    equipment_family: str
    required_version: int
    grace_until: int | None = None
    grace_period: int | None = None

    def __post_init__(self) -> None:
        if self.revision <= 0 or self.required_version <= 0:
            raise ValueError("revision and training version must be positive")
        if self.grace_period is not None and self.grace_period < 0:
            raise ValueError("grace period cannot be negative")
        if self.grace_period is not None and self.grace_until is not None:
            if self.grace_until != self.effective_at + self.grace_period:
                raise ValueError("grace period and grace end disagree")
            grace_until = self.grace_until
        elif self.grace_period is not None:
            grace_until = self.effective_at + self.grace_period
            object.__setattr__(self, "grace_until", grace_until)
        else:
            grace_until = self.grace_until
            if grace_until is not None:
                object.__setattr__(self, "grace_period", grace_until - self.effective_at)

        if grace_until is not None and grace_until < self.effective_at:
            raise ValueError("grace cannot end before the rule becomes effective")

    @property
    def required_training_version(self) -> int:
        return self.required_version


@dataclass(frozen=True, slots=True)
class OperatorCertificate:
    """A certificate tying an operator's training version to one work scope."""

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
        if self.expires_at <= self.effective_at:
            raise ValueError("certificate must expire after it becomes effective")

    @property
    def version(self) -> int:
        return self.training_version

    @property
    def tool_family(self) -> str:
        return self.equipment_family

    def active_at(self, instant: int) -> bool:
        return (
            self.effective_at <= instant <= self.expires_at
            and (self.revoked_at is None or instant < self.revoked_at)
        )


TrainingRequirement = TrainingRule
TrainingPolicy = TrainingRule
TrainingCertificate = OperatorCertificate
OperatorTrainingCertificate = OperatorCertificate

RuleSource: TypeAlias = (
    Iterable[TrainingRule]
    | RevisionHistory[TrainingRule]
    | RevisionHistory[tuple[TrainingRule, ...]]
    | RevisionHistory[frozenset[TrainingRule]]
)


def _rules_at(source: RuleSource, at: int) -> tuple[TrainingRule, ...]:
    if isinstance(source, RevisionHistory):
        value = source.at(at).value
        if isinstance(value, TrainingRule):
            return (value,)
        return tuple(value)
    return tuple(source)


def _ordered_reasons(reasons: Iterable[str]) -> tuple[str, ...]:
    present = set(reasons)
    return tuple(reason for reason in _REASON_ORDER if reason in present)


def _current_rule(
    operation_id: str,
    equipment_family: str,
    at: int,
    rules: RuleSource,
) -> TrainingRule | None:
    effective = [
        rule
        for rule in rules
        if rule.operation_id == operation_id
        and rule.equipment_family == equipment_family
        and rule.effective_at <= at
    ]
    if not effective:
        return None
    return max(effective, key=lambda rule: (rule.effective_at, rule.revision))


def training_qualification_decision(
    operator_id: str,
    operation_id: str,
    equipment_family: str,
    at: int,
    requirements: RuleSource,
    certificates: Iterable[OperatorCertificate],
) -> Decision:
    """Evaluate operator access at ``at`` from complete effective-dated records.

    Later revisions are ignored when replaying a past instant. Likewise, a
    later expiration or revocation does not invalidate a certificate at that
    instant. All independently applicable rejection reasons are returned.
    """

    rules = _rules_at(requirements, at)
    certificate_records = tuple(certificates)
    rule = _current_rule(operation_id, equipment_family, at, rules)
    candidates = tuple(
        certificate
        for certificate in certificate_records
        if certificate.operator_id == operator_id
        and certificate.operation_id == operation_id
        and certificate.equipment_family == equipment_family
    )

    evidence: dict[str, object] = {
        "operator_id": operator_id,
        "operation_id": operation_id,
        "equipment_family": equipment_family,
        "evaluated_at": at,
        "matching_certificate_count": len(candidates),
    }
    if rule is not None:
        evidence.update(
            rule_revision=rule.revision,
            rule_effective_at=rule.effective_at,
            required_version=rule.required_version,
            grace_period=rule.grace_period,
            grace_until=rule.grace_until,
        )

    reasons: list[str] = []
    if rule is None:
        reasons.append("training_rule_missing")
    if not candidates:
        reasons.append("training_certificate_missing")

    eligible: list[OperatorCertificate] = []
    for certificate in candidates:
        certificate_reasons: list[str] = []
        if at < certificate.effective_at:
            certificate_reasons.append("training_certificate_not_effective")
        if at > certificate.expires_at:
            certificate_reasons.append("training_certificate_expired")
        if certificate.revoked_at is not None and at >= certificate.revoked_at:
            certificate_reasons.append("training_certificate_revoked")
        reasons.extend(certificate_reasons)

        if rule is None:
            continue

        if certificate.training_version == rule.required_version:
            version_allowed = True
        elif certificate.training_version < rule.required_version and rule.grace_until is not None:
            version_allowed = at <= rule.grace_until
            if not version_allowed:
                reasons.append("training_version_grace_expired")
        else:
            version_allowed = False
            reasons.append("training_version_mismatch")

        if not certificate_reasons and version_allowed:
            eligible.append(certificate)

    if reasons:
        return deny(*_ordered_reasons(reasons), **evidence)

    chosen = max(
        eligible,
        key=lambda certificate: (
            certificate.training_version == rule.required_version,
            certificate.training_version,
            certificate.expires_at,
        ),
    )
    return allow(
        **evidence,
        training_version=chosen.training_version,
        certificate_effective_at=chosen.effective_at,
        certificate_expires_at=chosen.expires_at,
        grace_used=chosen.training_version != rule.required_version,
    )


def operator_qualification_decision(
    operator_id: str,
    operation_id: str,
    equipment_family: str,
    at: int,
    rules: RuleSource,
    certificates: Iterable[OperatorCertificate],
) -> Decision:
    return training_qualification_decision(
        operator_id, operation_id, equipment_family, at, rules, certificates
    )


def operator_training_decision(
    operator_id: str,
    operation_id: str,
    equipment_family: str,
    at: int,
    rules: RuleSource,
    certificates: Iterable[OperatorCertificate],
) -> Decision:
    return training_qualification_decision(
        operator_id, operation_id, equipment_family, at, rules, certificates
    )


def operator_allowed(
    operator_id: str,
    operation_id: str,
    equipment_family: str,
    at: int,
    rules: RuleSource,
    certificates: Iterable[OperatorCertificate],
) -> bool:
    return operator_qualification_decision(
        operator_id, operation_id, equipment_family, at, rules, certificates
    ).allowed
