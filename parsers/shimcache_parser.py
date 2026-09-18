import struct
from pathlib import Path
from typing import Generator
from Registry import Registry

from models.schema import TimelineEntry
from utils.time_utils import filetime_to_datetime

def parse_shimcache(system_hive_path: str | Path) -> Generator[TimelineEntry, None, None]:
    """
    Parses a SYSTEM registry hive to locate and extract the AppCompatCache (Shimcache).
    Utilizes a structure-agnostic byte-carving approach to safely extract 
    Windows 10/11 ('10ts') binary entries without relying on volatile header offsets.
    """
    system_hive_path = Path(system_hive_path)
    if not system_hive_path.exists():
        raise FileNotFoundError(f"SYSTEM hive not found at: {system_hive_path}")

    reg = Registry.Registry(str(system_hive_path))
    
    try:
        # Dynamically determine the active ControlSet
        select_key = reg.open("Select")
        current_control_set = select_key.value("Current").value()
        ccs_name = f"ControlSet{current_control_set:03d}"
        
        # Navigate to the AppCompatCache key
        shimcache_path = f"{ccs_name}\\Control\\Session Manager\\AppCompatCache"
        shimcache_key = reg.open(shimcache_path)
        
        # Extract the raw binary cache data
        appcompat_value = shimcache_key.value("AppCompatCache")
        raw_data = appcompat_value.value()
        
        # Verify modern Windows 10/11 Signature ('10ts' -> 0x31307473)
        if raw_data[:4] != b'10ts':
            raise ValueError("Unsupported Shimcache format. Only Windows 10/11 ('10ts') is supported.")
            
        # Start searching for entries after the main cache header
        offset = 4 
        
        while offset < len(raw_data):
            # Hunt for the next '10ts' signature which marks the start of an entry
            next_entry = raw_data.find(b'10ts', offset)
            if next_entry == -1:
                break
                
            entry_offset = next_entry
            
            try:
                # Win 10/11 Entry Header: Magic (4) + Unknown (4) + FILETIME (8) + Path Length (2) = 18 bytes
                entry_header = raw_data[entry_offset:entry_offset + 18]
                if len(entry_header) < 18:
                    break
                    
                sig, unk, filetime_raw, path_len = struct.unpack("<4sIQH", entry_header)
                
                # Extract the UTF-16-LE Path
                path_offset = entry_offset + 18
                path_bytes = raw_data[path_offset:path_offset + path_len]
                path_str = path_bytes.decode('utf-16-le', errors='replace')
                
                # Convert the raw Windows FILETIME
                timestamp = filetime_to_datetime(filetime_raw)
                
                # Validate the path (Shimcache paths typically start with \??\)
                if path_str and timestamp and "\\??\\" in path_str:
                    clean_path = path_str.replace("\\??\\", "")
                    
                    yield TimelineEntry(
                        timestamp=timestamp,
                        source="Shimcache",
                        artifact_type="System Execution Cache",
                        path=clean_path,
                        details={
                            "raw_filetime": filetime_raw,
                            "control_set": ccs_name
                        }
                    )
            except (struct.error, UnicodeDecodeError):
                pass # If a chunk is malformed, fail gracefully and keep hunting
                
            # Move offset forward to prevent infinite loops and continue carving
            offset = entry_offset + 4 
            
    except Registry.RegistryKeyNotFoundException as e:
        raise ValueError(f"Could not locate Shimcache in SYSTEM hive: {e}")
    except Registry.RegistryValueNotFoundException:
        pass # Key exists, but cache value is empty/missing