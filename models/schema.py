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
    user_sid: Optional[str] = None  # Added for BAM/DAM attribution
    details: Dict[str, Any] = field(default_factory=dict)