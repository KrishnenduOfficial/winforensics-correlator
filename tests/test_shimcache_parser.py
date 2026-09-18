import struct
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

from parsers.shimcache_parser import parse_shimcache

def create_mock_shimcache_data() -> bytes:
    """Generates a valid fake Windows 10/11 '10ts' Shimcache binary blob."""
    path_str = "\\??\\C:\\Windows\\System32\\cmd.exe"
    path_bytes = path_str.encode('utf-16-le')
    path_len = len(path_bytes)
    
    # Windows FILETIME for 1601-01-01 00:00:01 UTC
    filetime_raw = 10000000 
    
    # 18-byte entry header: Magic(4s) + Unknown(I) + Filetime(Q) + PathLen(H)
    entry_header = struct.pack("<4sIQH", b'10ts', 0, filetime_raw, path_len)
    
    # Combine main cache header ('10ts' + 4 random bytes) + our injected entry
    return b'10ts\x00\x00\x00\x00' + entry_header + path_bytes

@patch('parsers.shimcache_parser.Registry.Registry')
@patch('parsers.shimcache_parser.Path.exists')
def test_parse_shimcache_valid(mock_exists, mock_registry):
    """Test that the byte carver accurately extracts paths and timestamps."""
    mock_exists.return_value = True
    
    # 1. Mock the registry engine
    mock_reg_instance = MagicMock()
    mock_registry.return_value = mock_reg_instance
    
    # 2. Mock the ControlSet key
    mock_select_key = MagicMock()
    mock_select_key.value.return_value.value.return_value = 1
    
    # 3. Mock the AppCompatCache key with our fake binary blob
    mock_shimcache_key = MagicMock()
    mock_shimcache_key.value.return_value.value.return_value = create_mock_shimcache_data()
    
    # 4. Route the mocked registry paths
    def side_effect_open(path):
        if path == "Select":
            return mock_select_key
        if path == "ControlSet001\\Control\\Session Manager\\AppCompatCache":
            return mock_shimcache_key
        raise ValueError(f"Unexpected path: {path}")
        
    mock_reg_instance.open.side_effect = side_effect_open
    
    # Run the parser
    entries = list(parse_shimcache("dummy_SYSTEM_hive"))
    
    assert len(entries) == 1
    assert entries[0].path == "C:\\Windows\\System32\\cmd.exe" # The \??\ prefix should be stripped
    assert entries[0].source == "Shimcache"
    assert entries[0].timestamp == datetime(1601, 1, 1, 0, 0, 1, tzinfo=timezone.utc)

@patch('parsers.shimcache_parser.Path.exists')
def test_parse_shimcache_invalid_header(mock_exists):
    """Ensure the parser safely rejects older or corrupted Shimcache formats."""
    mock_exists.return_value = True
    with patch('parsers.shimcache_parser.Registry.Registry') as mock_registry:
        mock_reg_instance = MagicMock()
        mock_registry.return_value = mock_reg_instance
        
        mock_select_key = MagicMock()
        mock_select_key.value.return_value.value.return_value = 1
        
        mock_shimcache_key = MagicMock()
        mock_shimcache_key.value.return_value.value.return_value = b'bad_signature_data'
        
        mock_reg_instance.open.side_effect = lambda p: mock_select_key if p == "Select" else mock_shimcache_key
        
        with pytest.raises(ValueError, match="Unsupported Shimcache format"):
            list(parse_shimcache("dummy_SYSTEM_hive"))