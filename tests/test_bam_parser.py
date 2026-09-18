import struct
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone
from Registry import Registry  # <--- Add this line here

from parsers.bam_parser import parse_bam_dam

def test_parse_bam_dam_valid():
    """Test that BAM/DAM parser successfully extracts execution paths and User SIDs."""
    
    with patch('parsers.bam_parser.Path.exists') as mock_exists, \
         patch('parsers.bam_parser.Registry.Registry') as mock_registry:
         
        mock_exists.return_value = True
        
        # 1. Mock the registry engine
        mock_reg_instance = MagicMock()
        mock_registry.return_value = mock_reg_instance
        
        # 2. Mock the ControlSet selection
        mock_select_key = MagicMock()
        mock_select_key.value.return_value.value.return_value = 1
        
        # 3. Mock the UserSettings key and subkeys (representing a User SID)
        mock_user_settings = MagicMock()
        mock_sid_key = MagicMock()
        mock_sid_key.name.return_value = "S-1-5-21-123456789-123456789-123456789-1001"
        
        # Windows FILETIME for 1601-01-01 00:00:01 UTC packed as 8 bytes (little-endian unsigned long long)
        valid_filetime_bytes = struct.pack("<Q", 10000000)
        
        # Create a mock registry value for an execution path
        mock_val_exec = MagicMock()
        mock_val_exec.name.return_value = "\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe"
        mock_val_exec.value.return_value = valid_filetime_bytes
        
        # Create a mock registry value for non-execution metadata (should be filtered out)
        mock_val_meta = MagicMock()
        mock_val_meta.name.return_value = "SequenceNumber"
        mock_val_meta.value.return_value = valid_filetime_bytes
        
        mock_sid_key.values.return_value = [mock_val_meta, mock_val_exec]
        mock_user_settings.subkeys.return_value = [mock_sid_key]
        
        # 4. Route the mocked registry paths
        def side_effect_open(path):
            if path == "Select":
                return mock_select_key
            if "Services\\bam\\State\\UserSettings" in path:
                return mock_user_settings
            raise Registry.RegistryKeyNotFoundException("Not found")
            
        mock_reg_instance.open.side_effect = side_effect_open
        
        # Run the parser
        entries = list(parse_bam_dam("dummy_SYSTEM_hive"))
        
        # Assertions
        assert len(entries) == 1, "Should only extract the execution path starting with \\Device\\"
        assert entries[0].source == "BAM"
        assert entries[0].artifact_type == "Background Execution"
        assert entries[0].path == "\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe"
        assert entries[0].user_sid == "S-1-5-21-123456789-123456789-123456789-1001"
        assert entries[0].timestamp == datetime(1601, 1, 1, 0, 0, 1, tzinfo=timezone.utc)