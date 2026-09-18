from pathlib import Path
from typing import List, Dict, Any
from datetime import timedelta, datetime, timezone

from models.schema import TimelineEntry
from parsers.amcache_parser import parse_amcache
from parsers.shimcache_parser import parse_shimcache
from parsers.bam_parser import parse_bam_dam
from parsers.mft_parser import parse_mft
from parsers.srum_parser import parse_srum_network

class ExecutionCorrelator:
    def __init__(self):
        self.timeline: List[TimelineEntry] = []
        self.warnings: List[str] = []

    def ingest(self, 
               mft_path: str | Path | None = None, 
               amcache_path: str | Path | None = None, 
               system_hive_path: str | Path | None = None, 
               srudb_path: str | Path | None = None) -> None:
        """
        Dynamic ingestion engine. Gracefully handles missing artifacts by only 
        parsing what is explicitly provided and existing on disk.
        """
        if mft_path and Path(mft_path).exists():
            try:
                self.timeline.extend(parse_mft(mft_path))
            except Exception as e:
                self.warnings.append(f"MFT parsing failed: {e}")

        if amcache_path and Path(amcache_path).exists():
            try:
                self.timeline.extend(parse_amcache(amcache_path))
            except Exception as e:
                self.warnings.append(f"Amcache parsing failed: {e}")

        if system_hive_path and Path(system_hive_path).exists():
            try:
                self.timeline.extend(parse_shimcache(system_hive_path))
            except Exception as e:
                self.warnings.append(f"Shimcache parsing failed: {e}")
                
            try:
                self.timeline.extend(parse_bam_dam(system_hive_path))
            except Exception as e:
                self.warnings.append(f"BAM/DAM parsing failed: {e}")

        if srudb_path and Path(srudb_path).exists():
            try:
                self.timeline.extend(parse_srum_network(srudb_path))
            except Exception as e:
                self.warnings.append(f"SRUM parsing failed: {e}")

        # Crash-proof sorting: push entries with missing datetimes to the end
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        self.timeline.sort(key=lambda x: x.timestamp if x.timestamp else epoch)

    def _get_base_filename(self, path: str) -> str:
        """Universally normalizes any Windows/Linux/Device path down to the base executable."""
        if not path:
            return "unknown"
        # Standardize all slashes to forward slashes, then extract the tail
        normalized = path.replace('\\', '/')
        return normalized.split('/')[-1].lower()

    def correlate_chains(self, time_window_minutes: int = 5) -> List[Dict[str, Any]]:
        """
        Clusters execution artifacts by filename within a sliding time window.
        Returns synthesized 'Execution Chains', deduping anomalies and merging contexts.
        """
        if not self.timeline:
            return []

        chains = []
        window = timedelta(minutes=time_window_minutes)
        
        for entry in self.timeline:
            base_name = self._get_base_filename(entry.path)
            matched_chain = None
            
            # Slide backward to find a matching executable within the time window
            for chain in reversed(chains):
                if chain['target_file'] == base_name:
                    if entry.timestamp and chain['end_time']:
                        if (entry.timestamp - chain['end_time']) <= window:
                            matched_chain = chain
                            break
                        
            if matched_chain:
                # Merge into existing execution chain
                matched_chain['events'].append(entry)
                matched_chain['end_time'] = entry.timestamp
                matched_chain['sources_involved'].add(entry.source)
                
                if entry.user_sid and not matched_chain['user_sid']:
                    matched_chain['user_sid'] = entry.user_sid
                if entry.hash_val and not matched_chain['hash_val']:
                    matched_chain['hash_val'] = entry.hash_val
                    
                if entry.details.get("timestomp_detected"):
                    matched_chain['anomalies'].update(entry.details.get("timestomp_flags", []))
            else:
                # Initialize new chain with deduplicated sets
                new_chain = {
                    "target_file": base_name,
                    "start_time": entry.timestamp,
                    "end_time": entry.timestamp,
                    "user_sid": entry.user_sid,
                    "hash_val": entry.hash_val,
                    "sources_involved": {entry.source},
                    "anomalies": set(entry.details.get("timestomp_flags", [])) if entry.details.get("timestomp_detected") else set(),
                    "events": [entry]
                }
                chains.append(new_chain)

        return chains