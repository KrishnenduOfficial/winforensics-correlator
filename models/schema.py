from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, Optional

@dataclass
class TimelineEntry:
    timestamp: datetime
    source: str
    artifact_type: str
    path: str
    hash_val: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)