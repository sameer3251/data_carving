#!/usr/bin/env python3
"""
ForensicCarver CLI - Professional Data Carving Tool

A high-performance forensic file carving tool for Kali Linux.
"""

import argparse
import sys
import os
import signal
from typing import Optional

# Rich for beautiful CLI output
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from .carver_engine import CarverEngine
from .hasher import HashAlgorithm
from .reporter import ReportGenerator
from .scanner import ScanProgress, format_progress
from .utils import format_size, parse_size, validate_source, validate_output_dir, check_root
from . import __version__


# Global for signal handling
_engine: Optional[CarverEngine] = None


def signal_handler(sig, frame):
    """Handle interrupt signal."""
    if _engine:
        print("\n[!] Cancelling... Please wait for current operations to complete.")
        _engine.cancel()
    else:
        sys.exit(1)


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        prog='forensic-carver',
        description='ForensicCarver - Professional Data Carving & Recovery Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Scan raw disk (requires root)
  sudo forensic-carver -i /dev/sdb -o ./recovered/

  # Scan disk image
  forensic-carver -i forensic.dd -o ./output/

  # Specific file types only
  forensic-carver -i image.img -o ./output/ -t jpg,png,pdf

  # Advanced options
  forensic-carver -i /dev/nvme0n1 -o ./output/ \\
    --block-size 4096 --threads 8 --report json,html

  # Quick scan to estimate files
  forensic-carver -i disk.dd -o ./output/ --quick-scan
'''
    )
    
    # Required arguments
    parser.add_argument(
        '-i', '--input',
        required=True,
        help='Input device or image file (e.g., /dev/sdb, forensic.dd)'
    )
    parser.add_argument(
        '-o', '--output',
        required=True,
        help='Output directory for recovered files'
    )
    
    # File type options
    parser.add_argument(
        '-t', '--types',
        type=str,
        default=None,
        help='File types to recover (comma-separated, e.g., jpg,png,pdf)'
    )
    parser.add_argument(
        '--list-types',
        action='store_true',
        help='List all supported file types and exit'
    )
    
    # Scanning options
    parser.add_argument(
        '--block-size',
        type=int,
        default=512,
        help='Block size in bytes (default: 512)'
    )
    parser.add_argument(
        '--threads',
        type=int,
        default=None,
        help='Number of threads (default: CPU count)'
    )
    parser.add_argument(
        '--start-offset',
        type=str,
        default='0',
        help='Starting offset (e.g., 0, 1GB, 0x1000)'
    )
    parser.add_argument(
        '--end-offset',
        type=str,
        default=None,
        help='Ending offset (default: end of source)'
    )
    parser.add_argument(
        '--quick-scan',
        action='store_true',
        help='Quick scan to estimate recoverable files'
    )
    
    # File size options
    parser.add_argument(
        '--min-size',
        type=str,
        default='100',
        help='Minimum file size (default: 100B)'
    )
    parser.add_argument(
        '--max-size',
        type=str,
        default=None,
        help='Maximum file size (default: from signature)'
    )
    
    # Output options
    parser.add_argument(
        '--report',
        type=str,
        default='json,html',
        help='Report formats: json, csv, html, txt (comma-separated)'
    )
    parser.add_argument(
        '--hash',
        type=str,
        default='md5,sha256',
        help='Hash algorithms: md5, sha1, sha256, sha512 (comma-separated)'
    )
    parser.add_argument(
        '--no-dedup',
        action='store_true',
        help='Do not skip duplicate files'
    )
    
    # Verbosity
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Quiet mode (minimal output)'
    )
    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {__version__}'
    )
    
    return parser


def parse_offset(offset_str: str) -> int:
    """Parse offset string (supports hex and size units)."""
    offset_str = offset_str.strip()
    
    # Handle hex
    if offset_str.lower().startswith('0x'):
        return int(offset_str, 16)
    
    # Handle size units
    return parse_size(offset_str)


def list_types():
    """List supported file types."""
    from .signatures import SignatureDB, FileCategory
    
    db = SignatureDB()
    
    if RICH_AVAILABLE:
        console = Console()
        
        for category in FileCategory:
            sigs = db.get_by_category(category)
            if not sigs:
                continue
            
            table = Table(
                title=f"📁 {category.name}",
                box=box.ROUNDED,
                header_style="bold cyan"
            )
            table.add_column("Name", style="green")
            table.add_column("Extension")
            table.add_column("Description")
            table.add_column("Max Size")
            
            for sig in sigs:
                table.add_row(
                    sig.name,
                    f".{sig.extension}",
                    sig.description,
                    format_size(sig.max_size)
                )
            
            console.print(table)
            console.print()
    else:
        print("\nSupported File Types:")
        print("=" * 60)
        
        for category in FileCategory:
            sigs = db.get_by_category(category)
            if not sigs:
                continue
            
            print(f"\n{category.name}:")
            print("-" * 40)
            for sig in sigs:
                print(f"  {sig.name:12} .{sig.extension:6} {sig.description}")


def parse_hash_algorithms(hash_str: str) -> list:
    """Parse hash algorithm string."""
    algorithms = []
    for name in hash_str.split(','):
        name = name.strip().lower()
        if name == 'md5':
            algorithms.append(HashAlgorithm.MD5)
        elif name == 'sha1':
            algorithms.append(HashAlgorithm.SHA1)
        elif name == 'sha256':
            algorithms.append(HashAlgorithm.SHA256)
        elif name == 'sha512':
            algorithms.append(HashAlgorithm.SHA512)
    return algorithms or [HashAlgorithm.MD5, HashAlgorithm.SHA256]


def main():
    """Main entry point."""
    global _engine
    
    parser = create_parser()
    args = parser.parse_args()
    
    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Handle list-types
    if args.list_types:
        list_types()
        return 0
    
    # Setup console
    if RICH_AVAILABLE:
        console = Console()
    else:
        console = None
    
    def print_msg(msg, style=None):
        if args.quiet:
            return
        if console:
            console.print(msg, style=style)
        else:
            print(msg)
    
    def print_error(msg):
        if console:
            console.print(f"[bold red]Error:[/] {msg}")
        else:
            print(f"Error: {msg}", file=sys.stderr)
    
    # Banner
    if not args.quiet and RICH_AVAILABLE:
        banner = Text()
        banner.append("🔍 ForensicCarver ", style="bold blue")
        banner.append(f"v{__version__}", style="dim")
        console.print(Panel(banner, title="Data Recovery Tool", border_style="blue"))
    elif not args.quiet:
        print(f"\n=== ForensicCarver v{__version__} ===\n")
    
    # Validate input
    valid, msg = validate_source(args.input)
    if not valid:
        print_error(msg)
        return 1
    
    # Check root for devices
    from .utils import is_block_device
    if is_block_device(args.input) and not check_root():
        print_error("Root privileges required for raw device access. Run with sudo.")
        return 1
    
    # Validate output
    valid, msg = validate_output_dir(args.output)
    if not valid:
        print_error(msg)
        return 1
    
    # Parse options
    file_types = None
    if args.types:
        file_types = [t.strip().lower() for t in args.types.split(',')]
    
    start_offset = parse_offset(args.start_offset)
    end_offset = parse_offset(args.end_offset) if args.end_offset else None
    min_size = parse_size(args.min_size)
    max_size = parse_size(args.max_size) if args.max_size else None
    hash_algorithms = parse_hash_algorithms(args.hash)
    report_formats = [f.strip().lower() for f in args.report.split(',')]
    
    # Progress callback
    if RICH_AVAILABLE and not args.quiet:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("•"),
            TextColumn("{task.fields[files]} files"),
            TextColumn("•"),
            TextColumn("{task.fields[speed]}"),
            TimeRemainingColumn(),
            console=console
        )
        task_id = None
        
        def progress_callback(p: ScanProgress):
            nonlocal task_id
            if task_id is None:
                return
            speed = f"{p.bytes_per_second / (1024*1024):.1f} MB/s"
            progress.update(
                task_id,
                completed=p.scanned_bytes,
                files=p.files_found,
                speed=speed
            )
    else:
        progress = None
        last_percent = -1
        
        def progress_callback(p: ScanProgress):
            nonlocal last_percent
            percent = int(p.percent_complete)
            if percent != last_percent and percent % 10 == 0:
                print(format_progress(p))
                last_percent = percent
    
    # Create engine
    print_msg(f"[dim]Source:[/] {args.input}")
    print_msg(f"[dim]Output:[/] {args.output}")
    if file_types:
        print_msg(f"[dim]Types:[/]  {', '.join(file_types)}")
    print_msg("")
    
    try:
        _engine = CarverEngine(
            output_dir=args.output,
            file_types=file_types,
            block_size=args.block_size,
            num_threads=args.threads,
            min_file_size=min_size,
            max_file_size=max_size,
            hash_algorithms=hash_algorithms,
            skip_duplicates=not args.no_dedup,
            validate_content=True,
            progress_callback=progress_callback
        )
        
        # Quick scan mode
        if args.quick_scan:
            print_msg("[bold]Running quick scan...[/]")
            estimates = _engine.quick_scan(args.input)
            
            print_msg(f"\n[green]Quick Scan Results:[/]")
            print_msg(f"  Source size:       {format_size(estimates['source_size'])}")
            print_msg(f"  Sampled:           {format_size(estimates['sampled_bytes'])}")
            print_msg(f"  Headers found:     {estimates['headers_found']}")
            print_msg(f"  Estimated total:   ~{estimates['estimated_total']} files")
            
            if estimates['by_type']:
                print_msg(f"\n[green]By Type (estimated):[/]")
                for ftype, count in sorted(estimates['by_type'].items(), key=lambda x: -x[1]):
                    print_msg(f"    {ftype}: ~{count}")
            
            return 0
        
        # Full scan
        from .block_reader import BlockReader
        reader = BlockReader(args.input)
        total_size = reader.size
        reader.close()
        
        if progress:
            with progress:
                task_id = progress.add_task(
                    "Scanning...",
                    total=total_size,
                    files=0,
                    speed="0 MB/s"
                )
                session = _engine.carve(args.input, start_offset, end_offset)
        else:
            print_msg("[bold]Starting scan...[/]")
            session = _engine.carve(args.input, start_offset, end_offset)
        
        # Results
        print_msg("")
        print_msg("[bold green]✓ Scan Complete![/]")
        print_msg(f"  Files recovered:  {len(session.files_recovered)}")
        print_msg(f"  Unique files:     {session.unique_files}")
        print_msg(f"  Duplicates:       {session.duplicates_skipped}")
        print_msg(f"  Data recovered:   {format_size(session.total_bytes_carved)}")
        print_msg(f"  Duration:         {session.duration:.1f}s")
        
        if session.errors:
            print_msg(f"  [yellow]Errors: {len(session.errors)}[/]")
        
        # Generate reports
        if report_formats:
            print_msg("\n[dim]Generating reports...[/]")
            reporter = ReportGenerator(args.output)
            paths = reporter.generate_all(session, report_formats)
            
            for fmt, path in paths.items():
                print_msg(f"  {fmt.upper()}: {path}")
        
        print_msg(f"\n[bold]Recovered files saved to:[/] {args.output}")
        
        return 0
        
    except KeyboardInterrupt:
        print_msg("\n[yellow]Cancelled by user[/]")
        return 130
    except Exception as e:
        print_error(str(e))
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
