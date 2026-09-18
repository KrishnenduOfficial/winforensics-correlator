import pytest
from unittest.mock import MagicMock, patch, mock_open
from datetime import datetime, timezone

from parsers.mft_parser import parse_mft

def create_mock_mft_record(segment_number, name, si_time, fn_time):
    """Helper to generate simulated MFT records with controlled timestamps."""
    record = MagicMock()
    record.in_use.return_value = True
    record.segment_number = segment_number
    
    # 1. Mock $STANDARD_INFORMATION
    si_val = MagicMock()
    si_val.LastModificationTime = si_time
    si_attr = MagicMock()
    si_attr.value = si_val
    
    # 2. Mock $FILE_NAME
    fn_val = MagicMock()
    fn_val.Name = name
    fn_val.LastModificationTime = fn_time
    
    parent_ref = MagicMock()
    parent_ref.segment_number = 5  # Arbitrary parent folder segment
    fn_val.ParentDirectory = parent_ref
    
    fn_attr = MagicMock()
    fn_attr.value = fn_val
    
    # 3. Route the attributes based on their hex type
    def attributes_side_effect(attr_type):
        if attr_type == 0x10:
            return iter([si_attr])
        elif attr_type == 0x30:
            return iter([fn_attr])
        return iter([])
        
    record.attributes.side_effect = attributes_side_effect
    return record


@patch('parsers.mft_parser.Path.exists')
@patch('builtins.open', new_callable=mock_open)
@patch('parsers.mft_parser.Mft')
def test_parse_mft_anomalies(mock_mft_class, mock_file, mock_exists):
    """Test that the MFT parser accurately flags normal files and timestomped anomalies."""
    mock_exists.return_value = True
    
    # Setup our mock MFT instance
    mock_mft_instance = MagicMock()
    mock_mft_class.return_value = mock_mft_instance
    
    # Base Windows FILETIME (e.g., 1601-01-01 00:00:01 + some subseconds)
    base_time = 1000000005  
    
    # Generate 3 Simulated Records
    record_normal = create_mock_mft_record(
        segment_number=100, 
        name="legit_file.txt", 
        si_time=base_time, 
        fn_time=base_time
    )
    
    # Attacker backdates SI by 5 seconds (50,000,000 intervals)
    record_backdated = create_mock_mft_record(
        segment_number=101, 
        name="malware_backdated.exe", 
        si_time=base_time - 50000000, 
        fn_time=base_time
    )
    
    # Attacker uses a tool that zeroes out sub-seconds (divisible by 10,000,000)
    record_zeroed = create_mock_mft_record(
        segment_number=102, 
        name="malware_zeroed.exe", 
        si_time=20000000, 
        fn_time=20000000
    )
    
    # Load the records into the mock MFT
    mock_mft_instance.segments.return_value = [record_normal, record_backdated, record_zeroed]
    
    # Run the parser
    entries = list(parse_mft("dummy_MFT_path"))
    
    assert len(entries) == 3, "Parser should successfully extract all 3 valid records"
    
    # 1. Verify Normal File
    assert entries[0].path == "legit_file.txt"
    assert entries[0].details["timestomp_detected"] is False
    assert len(entries[0].details["timestomp_flags"]) == 0
    
    # 2. Verify Backdated File ($FN newer than $SI)
    assert entries[1].path == "malware_backdated.exe"
    assert entries[1].details["timestomp_detected"] is True
    assert "FN_NEWER_THAN_SI" in entries[1].details["timestomp_flags"]
    
    # 3. Verify Sub-second Zeroing
    assert entries[2].path == "malware_zeroed.exe"
    assert entries[2].details["timestomp_detected"] is True
    assert "SI_SUBSECONDS_ZEROED" in entries[2].details["timestomp_flags"]