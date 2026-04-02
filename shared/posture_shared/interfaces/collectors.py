from abc import ABC, abstractmethod
from typing import Any

from posture_shared.models.telemetry import EndpointTelemetry


class CollectorModule(ABC):
    name: str

    @abstractmethod
    def collect(self) -> dict[str, Any]:
        """Return partial telemetry data for this collector."""

    def merge(self, telemetry: EndpointTelemetry, data: dict[str, Any]) -> None:
        """Optional hook to merge data into a full telemetry model."""
        for key, value in data.items():
            setattr(telemetry, key, value)
