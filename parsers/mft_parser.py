from pathlib import Path
from typing import Generator
from dissect.ntfs.mft import Mft

from models.schema import TimelineEntry
from utils.time_utils import filetime_to_datetime

def parse_mft(mft_path: str | Path) -> Generator[TimelineEntry, None, None]:
    """
    Parses a raw Windows $MFT file. Extracts both $STANDARD_INFORMATION ($SI)
    and $FILE_NAME ($FN) timestamps to detect potential timestomping anomalies.
    """
    mft_path = Path(mft_path)
    if not mft_path.exists():
        raise FileNotFoundError(f"$MFT file not found at: {mft_path}")
        
    with open(mft_path, "rb") as f:
        mft = Mft(f)
        
        # We do a sequential read of the MFT for speed and low RAM overhead.
        for record in mft.segments():
            try:
                # Skip unallocated/deleted records for baseline timeline
                if not record.in_use():
                    continue
                    
                # 1. Grab $STANDARD_INFORMATION (Type 0x10)
                si_attr = next(record.attributes(0x10), None)
                if not si_attr:
                    continue
                si = si_attr.value
                
                # 2. Grab all $FILE_NAME attributes (Type 0x30)
                fn_attrs = [attr.value for attr in record.attributes(0x30)]
                if not fn_attrs:
                    continue
                    
                # Files often have multiple $FN entries (DOS 8.3 name vs Win32 Long Name)
                longest_fn = max(fn_attrs, key=lambda fn: len(fn.Name))
                
                # Secure string decoding
                file_name = longest_fn.Name
                if isinstance(file_name, bytes):
                    file_name = file_name.decode("utf-16-le", errors="replace").rstrip('\x00')
                
                # Safely extract raw FILETIMEs from dissect.ntfs structs
                si_mod = getattr(si, 'LastModificationTime', 0)
                fn_mod = getattr(longest_fn, 'LastModificationTime', 0)
                
                timestamp = filetime_to_datetime(si_mod)
                if not timestamp:
                    continue

                # --- ANOMALY DETECTION ENGINE ---
                is_timestomped = False
                anomaly_flags = []
                
                # Flag 1: $FN is newer than $SI. 
                # (Attackers backdate $SI to hide the file, but OS keeps $FN accurate)
                if fn_mod > 0 and si_mod > 0 and (fn_mod - si_mod) > 10000000:
                    is_timestomped = True
                    anomaly_flags.append("FN_NEWER_THAN_SI")
                    
                # Flag 2: Millisecond zeroing.
                # (Many stomping tools use standard APIs that truncate sub-second precision)
                if si_mod > 0 and (si_mod % 10000000) == 0:
                    is_timestomped = True
                    anomaly_flags.append("SI_SUBSECONDS_ZEROED")

                # Extract Parent reference so correlator can rebuild full path later
                parent_ref = getattr(longest_fn, 'ParentDirectory', None)
                parent_seg = parent_ref.segment_number if parent_ref else None

                yield TimelineEntry(
                    timestamp=timestamp,
                    source="MFT",
                    artifact_type="File System Record",
                    path=file_name, # Note: Flat MFT parse yields filename only
                    details={
                        "mft_record_number": record.segment_number,
                        "parent_segment": parent_seg,
                        "si_modification_time": si_mod,
                        "fn_modification_time": fn_mod,
                        "timestomp_detected": is_timestomped,
                        "timestomp_flags": anomaly_flags
                    }
                )
            except Exception:
                # If a specific MFT record is corrupt, fail gracefully and parse the next one
                continue