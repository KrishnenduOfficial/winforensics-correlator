import sys
import click
from pathlib import Path
from datetime import datetime, timezone, timedelta
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from engine.correlator import ExecutionCorrelator
from engine.reporter import export_json, export_csv
from models.schema import TimelineEntry

console = Console()

def load_demo_data(correlator: ExecutionCorrelator):
    """Populates the timeline with a simulated multi-artifact APT attack scenario and clean baselines."""
    t0 = datetime(2026, 9, 18, 10, 0, 0, tzinfo=timezone.utc)
    
    correlator.timeline.extend([
        # 1. Timestomped MFT record (Anomaly)
        TimelineEntry(
            timestamp=t0,
            source="MFT",
            artifact_type="File System Record",
            path="powershell_stealth.exe",
            details={
                "timestomp_detected": True,
                "timestomp_flags": ["FN_NEWER_THAN_SI", "SI_SUBSECONDS_ZEROED"]
            }
        ),
        # 2. Amcache execution + hash
        TimelineEntry(
            timestamp=t0 + timedelta(seconds=15),
            source="Amcache",
            artifact_type="Execution Cache",
            path="C:\\Users\\Public\\powershell_stealth.exe",
            hash_val="a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
        ),
        # 3. BAM user SID attribution
        TimelineEntry(
            timestamp=t0 + timedelta(minutes=1),
            source="BAM",
            artifact_type="Background Execution",
            path="\\Device\\HarddiskVolume3\\Users\\Public\\powershell_stealth.exe",
            user_sid="S-1-5-21-382914-1002"
        ),
        # 4. SRUM Network Exfiltration
        TimelineEntry(
            timestamp=t0 + timedelta(minutes=4),
            source="SRUM",
            artifact_type="Network Usage",
            path="C:\\Users\\Public\\powershell_stealth.exe",
            details={"bytes_sent": 845000000, "bytes_received": 12000}
        ),
        # 5. Clean baseline process running concurrently (Clean / No Anomalies)
        TimelineEntry(
            timestamp=t0 + timedelta(minutes=10),
            source="BAM",
            artifact_type="Background Execution",
            path="C:\\Program Files\\Google\\Chrome\\chrome.exe",
            user_sid="S-1-5-21-382914-1002"
        ),
        # 6. Another clean utility running in background
        TimelineEntry(
            timestamp=t0 + timedelta(minutes=15),
            source="BAM",
            artifact_type="Background Execution",
            path="C:\\Windows\\System32\\notepad.exe",
            user_sid="S-1-5-21-382914-1002"
        ),
        # 7. Ghost file wiping (caught in Shimcache, deleted from MFT)
        TimelineEntry(
            timestamp=t0 + timedelta(minutes=30),
            source="Shimcache",
            artifact_type="Execution Cache",
            path="C:\\Windows\\Temp\\mimikatz_dump.exe"
        )
    ])
    correlator.timeline.sort(key=lambda x: x.timestamp)


EPILOG = """
Note: --shimcache and --bam can point to the same SYSTEM hive file.
      MFT is required for timestomping detection. Without it, only
      execution-without-presence and cross-artifact anomalies are reported.

Examples:
  # Full analysis with all artifacts
  wfcr --amcache Amcache.hve --shimcache SYSTEM --bam SYSTEM --mft $MFT --srum SRUDB.dat

  # MFT unavailable — execution cross-correlation only
  wfcr --amcache Amcache.hve --shimcache SYSTEM --bam SYSTEM --srum SRUDB.dat --min-confidence low --verbose

  # Export to CSV for further analysis
  wfcr --amcache Amcache.hve --mft $MFT --output csv --outfile results.csv

  # High confidence findings only, IST timezone
  wfcr --amcache Amcache.hve --shimcache SYSTEM --bam SYSTEM --mft $MFT --srum SRUDB.dat --min-confidence high --timezone Asia/Kolkata

Confidence levels:
  high    Anomaly confirmed by 3+ independent artifact sources
  medium  Anomaly confirmed by 1-2 sources; corroborating source unavailable
  low     Pattern is suspicious but ambiguous or single-source only

Exit codes:
  0   Completed successfully, no anomalies found
  1   Completed successfully, anomalies detected
  2   Input error (invalid path, no artifact provided)
  3   Parse error (artifact found but could not be read)
"""

@click.command(
    context_settings={"help_option_names": ["-h", "--help"], "max_content_width": 100},
    epilog=EPILOG,
    help="""Windows Forensic Timeline Correlator\n
Correlates Amcache, Shimcache, BAM/DAM, SRUM execution evidence with MFT
timestamps to detect timestomping and execution-without-file-presence anomalies."""
)
@click.version_option(version="1.0", prog_name="Windows Forensic Timeline Correlator")
@click.option('--amcache', type=click.Path(exists=True), help='Path to Amcache.hve (C:\\Windows\\AppCompat\\Programs\\Amcache.hve)')
@click.option('--shimcache', type=click.Path(exists=True), help='Path to SYSTEM hive containing AppCompatCache')
@click.option('--bam', type=click.Path(exists=True), help='Path to SYSTEM hive containing BAM/DAM entries')
@click.option('--mft', type=click.Path(exists=True), help='Path to extracted $MFT file')
@click.option('--srum', type=click.Path(exists=True), help='Path to SRUDB.dat (C:\\Windows\\System32\\sru\\SRUDB.dat)')
@click.option('--output', type=click.Choice(['cli', 'csv', 'json']), default='cli', help='Report format (default: cli)')
@click.option('--outfile', type=click.Path(), help='Write output to file instead of stdout')
@click.option('--min-confidence', type=click.Choice(['low', 'medium', 'high']), default='low', help='Filter anomalies by confidence level (default: low)')
@click.option('--timezone', metavar="TZ", default='UTC', help='Normalize all timestamps to this timezone (default: UTC)')
@click.option('--verbose', is_flag=True, help='Show per-artifact parsing status, skipped entries, and source availability summary')
@click.option('--demo', is_flag=True, hidden=True, help='Run with simulated APT telemetry.')
def main(amcache, shimcache, bam, mft, srum, output, outfile, min_confidence, timezone, verbose, demo):
    
    # If using CLI output, show the rich header
    if output == 'cli':
        console.print(Panel.fit(
            "[bold cyan]Windows Forensic Timeline Correlator[/bold cyan]\n"
            "[dim]Production-Grade Incident Response Engine[/dim]",
            border_style="cyan"
        ))

    if not demo and not any([mft, amcache, shimcache, bam, srum]):
        console.print("[bold red][!] Error: You must provide at least one forensic artifact path.[/bold red]")
        console.print("Run [bold]wfcr -h[/bold] for usage options.")
        sys.exit(2)

    correlator = ExecutionCorrelator()

    if demo:
        if verbose:
            console.print("[bold yellow][*] Running in DEMO mode with simulated APT telemetry...[/bold yellow]")
        load_demo_data(correlator)
    else:
        with console.status("[bold green]Ingesting artifacts...", spinner="dots") if output == 'cli' else console.status(""):
            # Map shimcache and bam to the engine's system_hive_path
            system_hive = shimcache if shimcache else bam
            correlator.ingest(mft_path=mft, amcache_path=amcache, system_hive_path=system_hive, srudb_path=srum)

    chains = correlator.correlate_chains(time_window_minutes=5)

    # ---------------------------------------------------------
    # OUTPUT ROUTING (CLI vs JSON vs CSV)
    # ---------------------------------------------------------
    if output == 'json':
        if not outfile:
            console.print("[red][!] Error: --outfile is required when using --output json[/red]")
            sys.exit(2)
        export_json(chains, outfile)
        if verbose:
            console.print(f"[green][+] JSON report written to {outfile}[/green]")
            
    elif output == 'csv':
        if not outfile:
            console.print("[red][!] Error: --outfile is required when using --output csv[/red]")
            sys.exit(2)
        export_csv(chains, outfile)
        if verbose:
            console.print(f"[green][+] CSV report written to {outfile}[/green]")
            
    else:
        # CLI Output Mode
        table = Table(title=f"Correlated Execution Chains (Confidence: {min_confidence.upper()})", show_lines=True, header_style="bold magenta")
        table.add_column("Target Executable", style="bold white", width=24)
        table.add_column(f"Time Window ({timezone})", style="cyan", width=22)
        table.add_column("Corroborating Sources", style="yellow", width=20)
        table.add_column("User SID Attribution", style="blue", width=26)
        table.add_column("Threat Indicators & Flags", style="bold red", width=30)

        for chain in chains:
            sources_str = ", ".join(sorted(chain["sources_involved"]))
            start_str = chain["start_time"].strftime('%Y-%m-%d %H:%M:%S') if chain["start_time"] else "N/A"
            end_str = chain["end_time"].strftime('%H:%M:%S') if chain["end_time"] else "N/A"
            time_str = f"{start_str}\n-> {end_str}"
            sid_str = chain["user_sid"] if chain["user_sid"] else "[dim]SYSTEM / Unknown[/dim]"
            anomalies_str = "\n".join([f"⚠️  {anomaly}" for anomaly in chain["anomalies"]]) if chain["anomalies"] else "[green]✓ Clean[/green]"
            
            table.add_row(chain["target_file"], time_str, sources_str, sid_str, anomalies_str)

        console.print(table)
        
    # Set proper exit codes based on anomaly presence
    has_anomalies = any(chain.get("anomalies") for chain in chains)
    sys.exit(1 if has_anomalies else 0)


if __name__ == '__main__':
    main()