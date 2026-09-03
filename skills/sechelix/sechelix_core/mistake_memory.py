"""De-identified mistake-class memory for SecHelix training/evaluation.

The memory stores *classes of reasoning mistakes*, never target source code,
credentials, repository paths, user identifiers, or raw findings. It is meant
to improve the next verification question without turning historical refutation
into an auto-dismiss rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

_ALLOWED_OUTCOMES = {"MISSED", "FALSE_POSITIVE", "OVERCLAIMED", "UNDERCLAIMED", "UNKNOWN_HANDLED_POORLY"}


@dataclass(frozen=True)
class MistakeObservation:
    mistake_class: str
    outcome: str
    lesson: str
    verification_question: str
    domains: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.outcome not in _ALLOWED_OUTCOMES:
            raise ValueError(f"unsupported outcome: {self.outcome}")
        for value, name in (
            (self.mistake_class, "mistake_class"),
            (self.lesson, "lesson"),
            (self.verification_question, "verification_question"),
        ):
            if not value.strip():
                raise ValueError(f"{name} must not be empty")
        forbidden = ("/home/", "c:\\users\\", "github.com/", "token=", "authorization:", "password=")
        serialized = " ".join((self.mistake_class, self.lesson, self.verification_question, *self.domains)).lower()
        if any(marker in serialized for marker in forbidden):
            raise ValueError("mistake memory must be de-identified and secret-free")

    def to_dict(self) -> dict[str, object]:
        return {
            "mistake_class": self.mistake_class,
            "outcome": self.outcome,
            "lesson": self.lesson,
            "verification_question": self.verification_question,
            "domains": list(self.domains),
            "auto_dismiss": False,
        }


@dataclass
class MistakeMemory:
    observations: list[MistakeObservation] = field(default_factory=list)

    def add(self, observation: MistakeObservation) -> None:
        if observation.to_dict() not in [item.to_dict() for item in self.observations]:
            self.observations.append(observation)

    def questions_for(self, domains: Iterable[str]) -> list[str]:
        wanted = {item.strip().lower() for item in domains if item.strip()}
        questions = {
            item.verification_question
            for item in self.observations
            if not wanted or wanted.intersection(domain.lower() for domain in item.domains)
        }
        return sorted(questions)

    def export(self) -> dict[str, object]:
        ordered = sorted(
            self.observations,
            key=lambda item: (item.mistake_class, item.outcome, item.verification_question),
        )
        return {
            "schema_version": "1.0",
            "policy": "De-identified reasoning mistakes only; entries ask future verification questions and never auto-dismiss findings.",
            "observations": [item.to_dict() for item in ordered],
        }
