from pathlib import Path
from typing import Generator

from models.schema import TimelineEntry
from utils.time_utils import filetime_to_datetime

try:
    import pyesedb
    HAS_ESEDB = True
except ImportError:
    HAS_ESEDB = False

def parse_srum_network(srudb_path: str | Path) -> Generator[TimelineEntry, None, None]:
    """
    Parses a Windows SRUM (System Resource Usage Monitor) ESE database.
    Dynamically maps columns to extract Network Data Usage (Bytes Sent/Recv)
    and resolves Application Paths and User SIDs via the SruDbIdMapTable.
    """
    if not HAS_ESEDB:
        # Graceful fallback for cloud CI/CD runners where pyesedb binaries are missing
        return

    srudb_path = Path(srudb_path)
    if not srudb_path.exists():
        raise FileNotFoundError(f"SRUDB.dat not found at: {srudb_path}")

    # SRUM GUID for Network Data Usage
    NETWORK_TABLE_GUID = "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
    
    try:
        db = pyesedb.open(str(srudb_path))
    except Exception as e:
        raise ValueError(f"Failed to open ESE database (Is it locked by a live OS?): {e}")

    try:
        # --- 1. Build the ID Mapping Table (Maps integers to App Paths & User SIDs) ---
        id_map = {}
        map_table = db.get_table_by_name("SruDbIdMapTable")
        
        if map_table:
            # Dynamically resolve map columns to survive Windows Updates
            col_id_index = None
            col_id_blob = None
            for i in range(map_table.get_number_of_columns()):
                name = map_table.get_column(i).get_name()
                if name == "IdIndex": col_id_index = i
                elif name == "IdBlob": col_id_blob = i
                
            if col_id_index is not None and col_id_blob is not None:
                for record in map_table.records:
                    try:
                        id_idx = record.get_value_data_as_integer(col_id_index)
                        raw_blob = record.get_value_data(col_id_blob)
                        
                        if not raw_blob: 
                            continue
                            
                        # Safely decode ESE binary blobs into readable strings
                        if isinstance(raw_blob, bytes):
                            val = raw_blob.decode('utf-16-le', errors='ignore').rstrip('\x00')
                        else:
                            val = str(raw_blob).rstrip('\x00')
                            
                        id_map[id_idx] = val
                    except Exception:
                        continue # Skip malformed mapping rows

        # --- 2. Parse the Network Data Usage Table ---
        net_table = db.get_table_by_name(NETWORK_TABLE_GUID)
        if not net_table:
            return 
            
        # Dynamically resolve network columns
        cols = {}
        for i in range(net_table.get_number_of_columns()):
            cols[net_table.get_column(i).get_name()] = i
            
        req_cols = ["TimeStamp", "AppId", "UserId", "BytesSent", "BytesRecvd"]
        if not all(k in cols for k in req_cols):
            # Fallback to standard indices if column names are stripped
            cols = {"TimeStamp": 1, "AppId": 2, "UserId": 3, "BytesSent": 7, "BytesRecvd": 8}

        for record in net_table.records:
            try:
                ts_raw = record.get_value_data_as_integer(cols["TimeStamp"])
                app_id = record.get_value_data_as_integer(cols["AppId"])
                user_id = record.get_value_data_as_integer(cols["UserId"])
                b_sent = record.get_value_data_as_integer(cols["BytesSent"]) or 0
                b_recv = record.get_value_data_as_integer(cols["BytesRecvd"]) or 0
                
                # Filter out empty telemetry
                if b_sent == 0 and b_recv == 0:
                    continue
                    
                timestamp = filetime_to_datetime(ts_raw)
                if not timestamp:
                    continue
                    
                app_path = id_map.get(app_id, f"Unknown_AppId_{app_id}")
                user_sid = id_map.get(user_id, None) # Get User SID attribution!
                
                yield TimelineEntry(
                    timestamp=timestamp,
                    source="SRUM",
                    artifact_type="Network Usage",
                    path=app_path,
                    user_sid=user_sid,
                    details={
                        "bytes_sent": b_sent,
                        "bytes_received": b_recv,
                        "total_bytes": b_sent + b_recv,
                        "srum_caveat": "Timestamp is an hourly flush interval, not exact execution time"
                    }
                )
            except Exception:
                continue # Skip malformed network rows

    finally:
        db.close() # Ensure file handle is released even if it crashes