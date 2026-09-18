from datetime import datetime, timedelta, timezone
from typing import Optional

def filetime_to_datetime(filetime: int) -> Optional[datetime]:
    """
    Converts a Windows FILETIME (100-nanosecond intervals since 1601-01-01)
    to a UTC datetime object.
    """
    if not filetime or filetime < 0:
        return None
        
    try:
        # Windows FILETIME epoch starts on Jan 1, 1601
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        # Convert 100-nanosecond intervals to microseconds (divide by 10)
        delta = timedelta(microseconds=filetime / 10)
        return epoch + delta
    except OverflowError:
        return None