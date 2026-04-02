from abc import ABC, abstractmethod
from typing import Any


class CollectorModule(ABC):
    name: str

    @abstractmethod
    def collect(self) -> dict[str, Any]:
        """Return a partial telemetry payload."""
