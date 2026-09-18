from datetime import datetime, timezone
from utils.time_utils import filetime_to_datetime
from models.schema import TimelineEntry

def test_filetime_converter_valid():
    """Test that a valid Windows FILETIME converts to the correct UTC datetime."""
    # 10,000,000 intervals (100-nanoseconds) = exactly 1 second after the 1601 Epoch
    one_second_filetime = 10000000 
    expected_time = datetime(1601, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
    
    result = filetime_to_datetime(one_second_filetime)
    assert result == expected_time, f"Expected {expected_time}, but got {result}"

def test_filetime_converter_invalid():
    """Test that invalid, empty, or negative filetimes are handled safely."""
    assert filetime_to_datetime(-500) is None
    assert filetime_to_datetime(None) is None
    assert filetime_to_datetime(0) is None

def test_timeline_entry_schema():
    """Test that the TimelineEntry dataclass initializes correctly."""
    entry = TimelineEntry(
        timestamp=datetime(2026, 9, 18, tzinfo=timezone.utc),
        source="Amcache",
        artifact_type="Execution",
        path="C:\\Windows\\System32\\malware.exe",
        hash_val="deadbeef"
    )
    
    # Verify the fields populated correctly
    assert entry.source == "Amcache"
    assert entry.path == "C:\\Windows\\System32\\malware.exe"
    assert entry.hash_val == "deadbeef"
    
    # Verify that 'details' defaulted to an empty dictionary
    assert isinstance(entry.details, dict)
    assert len(entry.details) == 0