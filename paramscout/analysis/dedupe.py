"""Candidate de-duplication with provenance preservation.

De-duplication key is ``(endpoint, parameter name)``.  Names are **not**
case-folded: ``?ID=1`` and ``?id=1`` are recorded as two candidates, because
plenty of real applications (ASP.NET, some Java frameworks) treat them
differently.  The report shows both; the operator decides.
"""

from __future__ import annotations

from collections import OrderedDict

from paramscout.models import Candidate, Evidence


class CandidateSet:
    """An order-preserving, provenance-preserving candidate collection."""

    def __init__(self) -> None:
        self._items: OrderedDict[tuple[str, str], Candidate] = OrderedDict()
        self._order = 0

    def add(self, endpoint: str, name: str, evidence: Evidence, *, observed_value: str | None = None) -> Candidate:
        """Add or merge one observation."""

        key = (endpoint, name)
        candidate = self._items.get(key)
        if candidate is None:
            self._order += 1
            candidate = Candidate(endpoint=endpoint, name=name, first_seen_order=self._order)
            self._items[key] = candidate
        candidate.add_evidence(evidence)
        if observed_value is not None and observed_value not in candidate.observed_values:
            candidate.observed_values.append(observed_value)
        return candidate

    def extend(
        self,
        endpoint: str,
        pairs: list[tuple[str, Evidence]],
        values: dict[str, str] | None = None,
    ) -> None:
        """Add many ``(name, evidence)`` observations for one endpoint."""

        for name, evidence in pairs:
            observed = (values or {}).get(name)
            self.add(endpoint, name, evidence, observed_value=observed)

    def get(self, endpoint: str, name: str) -> Candidate | None:
        return self._items.get((endpoint, name))

    def names_for(self, endpoint: str) -> list[Candidate]:
        return [item for item in self._items.values() if item.endpoint == endpoint]

    def endpoints(self) -> list[str]:
        seen: list[str] = []
        for candidate in self._items.values():
            if candidate.endpoint not in seen:
                seen.append(candidate.endpoint)
        return seen

    def parameter_frequency(self) -> dict[str, int]:
        """How many distinct endpoints each parameter name appears on."""

        counts: dict[str, int] = {}
        for candidate in self._items.values():
            counts[candidate.name] = counts.get(candidate.name, 0) + 1
        return counts

    def __iter__(self):
        return iter(self._items.values())

    def __len__(self) -> int:
        return len(self._items)

    def to_list(self) -> list[Candidate]:
        return list(self._items.values())
