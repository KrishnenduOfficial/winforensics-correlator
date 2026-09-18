import struct
from pathlib import Path
from typing import Generator
from Registry import Registry

from models.schema import TimelineEntry
from utils.time_utils import filetime_to_datetime

def parse_bam_dam(system_hive_path: str | Path) -> Generator[TimelineEntry, None, None]:
    """
    Parses a SYSTEM registry hive to extract Background Activity Moderator (BAM) 
    and Desktop Activity Moderator (DAM) execution entries, including user SID attribution.
    """
    system_hive_path = Path(system_hive_path)
    if not system_hive_path.exists():
        raise FileNotFoundError(f"SYSTEM hive not found at: {system_hive_path}")

    reg = Registry.Registry(str(system_hive_path))
    
    try:
        select_key = reg.open("Select")
        current_control_set = select_key.value("Current").value()
        ccs_name = f"ControlSet{current_control_set:03d}"
    except Registry.RegistryKeyNotFoundException:
        raise ValueError("Invalid SYSTEM hive: 'Select' key not found.")
        
    # Define all possible locations for BAM and DAM across different Windows builds
    targets = [
        (f"{ccs_name}\\Services\\bam\\State\\UserSettings", "BAM"), # Win 10 1809+ / Win 11
        (f"{ccs_name}\\Services\\bam\\UserSettings", "BAM"),        # Win 10 pre-1809
        (f"{ccs_name}\\Services\\dam\\UserSettings", "DAM")         # DAM 
    ]

    for target_path, source_name in targets:
        try:
            user_settings_key = reg.open(target_path)
        except Registry.RegistryKeyNotFoundException:
            continue # If this specific path doesn't exist on this OS, skip to the next one

        for sid_key in user_settings_key.subkeys():
            user_sid = sid_key.name()
            
            for val in sid_key.values():
                path = val.name()
                
                # BAM/DAM execution paths start with \Device\. 
                # This check safely skips registry metadata values like 'Version' or 'SequenceNumber'
                if not path.startswith("\\Device\\"):
                    continue
                    
                raw_data = val.value()
                
                # The binary blob contains the FILETIME in the first 8 bytes
                if isinstance(raw_data, bytes) and len(raw_data) >= 8:
                    try:
                        filetime_raw = struct.unpack("<Q", raw_data[:8])[0]
                        timestamp = filetime_to_datetime(filetime_raw)
                        
                        if timestamp:
                            yield TimelineEntry(
                                timestamp=timestamp,
                                source=source_name,
                                artifact_type="Background Execution",
                                path=path,
                                user_sid=user_sid,
                                details={
                                    "control_set": ccs_name,
                                    "raw_filetime": filetime_raw
                                }
                            )
                    except struct.error:
                        pass # Fail gracefully if binary chunk is malformed