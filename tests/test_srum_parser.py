import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

from parsers.srum_parser import parse_srum_network

def create_mock_table(name, columns_list, records_data):
    """Generates a highly realistic ESE table mock with dynamic column mapping."""
    table = MagicMock()
    table.get_name.return_value = name
    table.get_number_of_columns.return_value = len(columns_list)
    
    # Mock dynamic column discovery
    def get_column(i):
        col = MagicMock()
        col.get_name.return_value = columns_list[i]
        return col
    table.get_column.side_effect = get_column
    
    # Mock records
    records = []
    for data in records_data:
        rec = MagicMock()
        # FIX: Added 'd=data' to prevent Python's late binding loop bug
        rec.get_value_data_as_integer.side_effect = lambda idx, d=data: d.get(idx)
        # Handle the IdBlob extraction specifically
        rec.get_value_data.side_effect = lambda idx, d=data: d.get(idx)
        records.append(rec)
        
    table.records = records
    return table

@patch('parsers.srum_parser.Path.exists')
@patch('parsers.srum_parser.pyesedb')
def test_parse_srum_network(mock_pyesedb, mock_exists):
    """Test that SRUM parser dynamically maps schemas, AppIDs, and User SIDs."""
    mock_exists.return_value = True
    mock_db = MagicMock()
    mock_pyesedb.open.return_value = mock_db
    
    # --- 1. Setup Mock Map Table (Col 0: IdIndex, Col 1: IdBlob) ---
    map_cols = ["IdIndex", "IdBlob"]
    # We simulate UTF-16LE encoded bytes as they exist in real ESE blobs
    map_records = [
        {0: 405, 1: "C:\\Windows\\System32\\svchost.exe\x00".encode('utf-16-le')},
        {0: 406, 1: "C:\\Temp\\malware.exe\x00".encode('utf-16-le')},
        {0: 999, 1: "S-1-5-21-123456-1001\x00".encode('utf-16-le')} # Mock User SID
    ]
    mock_map_table = create_mock_table("SruDbIdMapTable", map_cols, map_records)
    
    # --- 2. Setup Mock Network Table ---
    net_cols = ["TimeStamp", "AppId", "UserId", "BytesSent", "BytesRecvd"]
    base_time = 10000000 # 1601-01-01 00:00:01
    
    net_records = [
        # Normal Traffic: svchost (App 405) under SYSTEM (No SID)
        {0: base_time, 1: 405, 2: 0, 3: 500, 4: 1500},
        
        # Malicious Exfil: malware (App 406) under User SID (App 999)
        {0: base_time, 1: 406, 2: 999, 3: 9000000, 4: 0},
        
        # Noise: Zero byte traffic should be ignored
        {0: base_time, 1: 405, 2: 0, 3: 0, 4: 0}
    ]
    mock_net_table = create_mock_table("{973F5D5C-1D90-4944-BE8E-24B94231A174}", net_cols, net_records)
    
    # Route tables
    mock_db.get_table_by_name.side_effect = lambda name: mock_map_table if name == "SruDbIdMapTable" else mock_net_table
    
    # Run the parser
    entries = list(parse_srum_network("dummy_SRUDB.dat"))
    
    # Assertions
    assert len(entries) == 2, "Zero-byte noise was not properly filtered out"
    
    # Verify malware exfiltration and User SID attribution!
    assert entries[1].path == "C:\\Temp\\malware.exe"
    assert entries[1].user_sid == "S-1-5-21-123456-1001"
    assert entries[1].details["bytes_sent"] == 9000000
    assert entries[1].details["total_bytes"] == 9000000
    assert "srum_caveat" in entries[1].details