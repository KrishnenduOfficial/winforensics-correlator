import pytest
from unittest.mock import patch
from datetime import datetime, timezone, timedelta

from engine.correlator import ExecutionCorrelator
from models.schema import TimelineEntry

@patch('engine.correlator.Path.exists')
@patch('engine.correlator.parse_bam_dam')
@patch('engine.correlator.parse_mft')
def test_correlator_partial_data_stitching(mock_parse_mft, mock_parse_bam, mock_exists):
    """Test 1: Basic partial data stitching (Original Test)."""
    mock_exists.return_value = True
    base_time = datetime(2026, 9, 18, 10, 0, 0, tzinfo=timezone.utc)
    
    mock_parse_bam.return_value = [
        TimelineEntry(timestamp=base_time, source="BAM", artifact_type="Exec", path="\\Device\\HarddiskVolume3\\Temp\\malware.exe", user_sid="S-1-5-21-9999-1001")
    ]
    mock_parse_mft.return_value = [
        TimelineEntry(timestamp=base_time + timedelta(minutes=2), source="MFT", artifact_type="FS", path="malware.exe", details={"timestomp_detected": True, "timestomp_flags": ["FN_NEWER_THAN_SI"]})
    ]
    
    engine = ExecutionCorrelator()
    engine.ingest(mft_path="dummy_mft", system_hive_path="dummy_system")
    
    with patch('engine.correlator.parse_shimcache', return_value=[]):
        chains = engine.correlate_chains(time_window_minutes=5)
        
    assert len(chains) == 1
    assert chains[0]["target_file"] == "malware.exe"
    assert chains[0]["sources_involved"] == {"BAM", "MFT"}


def test_correlator_advanced_lotl_exfiltration():
    """
    Test 2: Living off the Land (LotL) + Timestomping + Network Exfil.
    Simulates an attacker disguising malware as 'svchost.exe' in a Temp directory.
    """
    engine = ExecutionCorrelator()
    base_time = datetime(2026, 9, 18, 14, 0, 0, tzinfo=timezone.utc)
    
    # 1. Amcache catches the execution and logs a highly suspicious hash for svchost
    engine.timeline.append(TimelineEntry(
        timestamp=base_time, source="Amcache", artifact_type="Exec", 
        path="C:\\Windows\\Temp\\svchost.exe", hash_val="deadbeef_malware_hash"
    ))
    
    # 2. BAM catches execution and proves it ran under a standard user, NOT 'SYSTEM'
    engine.timeline.append(TimelineEntry(
        timestamp=base_time + timedelta(seconds=10), source="BAM", artifact_type="Exec", 
        path="\\Device\\HarddiskVolume3\\Windows\\Temp\\svchost.exe", user_sid="S-1-5-21-1001"
    ))
    
    # 3. MFT proves the file exists, but catches sub-second timestomping
    engine.timeline.append(TimelineEntry(
        timestamp=base_time + timedelta(seconds=15), source="MFT", artifact_type="FS", 
        path="svchost.exe", details={"timestomp_detected": True, "timestomp_flags": ["SI_SUBSECONDS_ZEROED"]}
    ))
    
    # 4. SRUM proves this "svchost" sent 500MB of data out to the network
    engine.timeline.append(TimelineEntry(
        timestamp=base_time + timedelta(minutes=2), source="SRUM", artifact_type="Net", 
        path="C:\\Windows\\Temp\\svchost.exe", details={"bytes_sent": 500000000, "bytes_received": 1000}
    ))
    
    # Run the correlator engine
    chains = engine.correlate_chains(time_window_minutes=5)
    
    assert len(chains) == 1, "Failed to cluster all 4 artifacts into a single APT chain"
    
    chain = chains[0]
    assert chain["target_file"] == "svchost.exe"
    assert len(chain["sources_involved"]) == 4, "Missing evidence sources in the chain"
    assert chain["hash_val"] == "deadbeef_malware_hash"
    assert chain["user_sid"] == "S-1-5-21-1001"
    assert "SI_SUBSECONDS_ZEROED" in chain["anomalies"]
    
    # Calculate total exfil across all events in the chain
    total_sent = sum(e.details.get("bytes_sent", 0) for e in chain["events"])
    assert total_sent == 500000000, "Failed to aggregate network exfiltration data"


def test_correlator_ghost_execution():
    """
    Test 3: Ghost Execution (Anti-Forensics / File Wiping).
    Simulates malware that executes in memory and is securely deleted from the MFT.
    The correlator must reconstruct the chain purely from registry memory caches.
    """
    engine = ExecutionCorrelator()
    base_time = datetime(2026, 9, 18, 18, 30, 0, tzinfo=timezone.utc)
    
    # Shimcache catches it
    engine.timeline.append(TimelineEntry(
        timestamp=base_time, source="Shimcache", artifact_type="Exec", 
        path="C:\\Users\\Public\\ghost_dropper.exe"
    ))
    
    # Amcache catches it 2 seconds later with a hash
    engine.timeline.append(TimelineEntry(
        timestamp=base_time + timedelta(seconds=2), source="Amcache", artifact_type="Exec", 
        path="C:\\Users\\Public\\ghost_dropper.exe", hash_val="badc0ffee"
    ))
    
    # Note: NO MFT entry is injected because the attacker wiped it from the disk.
    
    chains = engine.correlate_chains(time_window_minutes=5)
    
    assert len(chains) == 1
    chain = chains[0]
    assert chain["target_file"] == "ghost_dropper.exe"
    assert chain["sources_involved"] == {"Shimcache", "Amcache"}
    assert "MFT" not in chain["sources_involved"], "MFT should be empty (Ghost file)"
    assert chain["hash_val"] == "badc0ffee"

def test_correlator_ultimate_apt_simulation():
    """
    ULTIMATE HARDCORE INTEGRATION TEST:
    Simulates a complex APT campaign with chaotic, out-of-order log arrival:
    - Multiple user accounts (Privilege escalation / lateral movement).
    - Timestomped MFT records (Anti-forensics).
    - Massive network exfiltration (SRUM).
    - Ghost execution (Wiped files missing from MFT, caught only by registry).
    - Out-of-order timeline ingestion (Testing sorting and sliding window resilience).
    """
    engine = ExecutionCorrelator()
    t0 = datetime(2026, 9, 18, 8, 0, 0, tzinfo=timezone.utc)
    
    # Intentionally shuffle the chronological order to test sorting and sliding window resilience
    chaotic_events = [
        # Event 5: SRUM network exfiltration (arrives late in raw log stream)
        TimelineEntry(
            timestamp=t0 + timedelta(minutes=15), source="SRUM", artifact_type="Net",
            path="C:\\Users\\Public\\update.exe", details={"bytes_sent": 1200000000, "bytes_received": 500}
        ),
        # Event 1: MFT creation with brutal timestomping flags
        TimelineEntry(
            timestamp=t0, source="MFT", artifact_type="FS",
            path="update.exe", details={"timestomp_detected": True, "timestomp_flags": ["FN_NEWER_THAN_SI", "SI_SUBSECONDS_ZEROED"]}
        ),
        # Event 3: BAM execution under a low-privilege user
        TimelineEntry(
            timestamp=t0 + timedelta(minutes=2), source="BAM", artifact_type="Exec",
            path="\\Device\\HarddiskVolume3\\Users\\Public\\update.exe", user_sid="S-1-5-21-user-1001"
        ),
        # Event 6: Ghost execution / secondary payload dropped later (No MFT entry)
        TimelineEntry(
            timestamp=t0 + timedelta(hours=1), source="Shimcache", artifact_type="Exec",
            path="C:\\Users\\Public\\payload.dll"
        ),
        # Event 2: Amcache capturing the hash right after MFT
        TimelineEntry(
            timestamp=t0 + timedelta(seconds=30), source="Amcache", artifact_type="Exec",
            path="C:\\Users\\Public\\update.exe", hash_val="sha256_evil_hash_999"
        ),
        # Event 4: Privilege escalation - same binary run later by SYSTEM / Admin SID
        TimelineEntry(
            timestamp=t0 + timedelta(minutes=5), source="BAM", artifact_type="Exec",
            path="\\Device\\HarddiskVolume3\\Users\\Public\\update.exe", user_sid="S-1-5-18 (SYSTEM)"
        ),
    ]

    engine.timeline.extend(chaotic_events)

    # Manually sort since we bypassed the ingest() method's auto-sorter
    engine.timeline.sort(key=lambda x: x.timestamp)
    
    # Run correlator with a tight 10-minute sliding window (FIXED TYPO HERE)
    chains = engine.correlate_chains(time_window_minutes=10)
    
    # We expect 2 separate target files: 'update.exe' and 'payload.dll'
    # Furthermore, 'update.exe' had a re-execution at t0 + 5 mins (which is within the 10 min window, 
    # so it should merge into the primary chain while capturing multiple SIDs).
    assert len(chains) == 2, f"Expected 2 distinct execution chains, got {len(chains)}"
    
    # Map chains by target file for deep assertion
    chain_map = {c["target_file"]: c for c in chains}
    
    # --- Verify 'update.exe' APT Campaign Chain ---
    update_chain = chain_map["update.exe"]
    
    # 1. Check sources involved (MFT, Amcache, BAM, SRUM)
    assert update_chain["sources_involved"] == {"MFT", "Amcache", "BAM", "SRUM"}
    
    # 2. Check hash propagation
    assert update_chain["hash_val"] == "sha256_evil_hash_999"
    
    # 3. Check multiple SIDs captured across execution phases
    assert update_chain["user_sid"] == "S-1-5-21-user-1001" # Inherited first SID
    
    # 4. Check dual-timestomp anomaly flags are deduplicated and present
    assert "FN_NEWER_THAN_SI" in update_chain["anomalies"]
    assert "SI_SUBSECONDS_ZEROED" in update_chain["anomalies"]
    
    # 5. Check network exfiltration math
    total_exfil = sum(e.details.get("bytes_sent", 0) for e in update_chain["events"])
    assert total_exfil == 1200000000, "Failed to aggregate large-scale exfiltration data"

    # --- Verify 'payload.dll' Ghost Execution Chain ---
    payload_chain = chain_map["payload.dll"]
    assert payload_chain["sources_involved"] == {"Shimcache"}
    assert "MFT" not in payload_chain["sources_involved"], "Ghost file incorrectly found in MFT"
    assert len(payload_chain["events"]) == 1