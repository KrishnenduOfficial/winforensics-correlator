from datetime import datetime
from pathlib import Path
from typing import Generator, Optional
from Registry import Registry

from models.schema import TimelineEntry
from utils.time_utils import filetime_to_datetime

def parse_amcache(hive_path: str | Path) -> Generator[TimelineEntry, None, None]:
    """
    Parses an Amcache.hve registry hive to extract file execution and 
    artifact metadata, yielding standardized TimelineEntry objects.
    """
    hive_path = Path(hive_path)
    if not hive_path.exists():
        raise FileNotFoundError(f"Amcache hive not found at: {hive_path}")

    reg = Registry.Registry(str(hive_path))
    
    try:
        # Amcache entries for executed/tracked files are typically located under Root\File
        root_file_key = reg.open("Root\\File")
    except Registry.RegistryKeyNotFoundException:
        # Fallback or alternative path handling if structure differs
        try:
            root_file_key = reg.open("Root")
        except Registry.RegistryKeyNotFoundException as e:
            raise ValueError(f"Invalid Amcache hive structure: {e}")

    for subkey in root_file_key.subkeys():
        file_path = _get_value_data(subkey, "Path") or _get_value_data(subkey, "Name")
        sha1 = _get_value_data(subkey, "FileId") or _get_value_data(subkey, "SHA1")
        
        # Amcache uses Windows FILETIME timestamps for file creation or modification
        raw_timestamp = subkey.timestamp() # Hive key last write time
        timestamp = filetime_to_datetime(raw_timestamp) if raw_timestamp else None

        if not timestamp:
            continue

        # Build the unified timeline entry
        yield TimelineEntry(
            timestamp=timestamp,
            source="Amcache",
            artifact_type="File Execution / Metadata",
            path=file_path or "Unknown Path",
            hash_val=sha1,
            details={
                "subkey_name": subkey.name(),
                "raw_filetime": raw_timestamp
            }
        )

def _get_value_data(subkey: Registry.RegistryKey, value_name: str) -> Optional[str]:
    """Helper method to safely extract a registry value string."""
    try:
        val = subkey.value(value_name)
        return str(val.value()) if val else None
    except Registry.RegistryValueNotFoundException:
        return None