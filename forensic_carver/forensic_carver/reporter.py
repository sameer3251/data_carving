"""
Report Generator Module for ForensicCarver

Generates forensic reports in various formats.
"""

import json
import csv
import os
from typing import Optional, List, Dict, Any
from dataclasses import asdict
from pathlib import Path
from datetime import datetime
from html import escape

from .carver_engine import CarveSession, RecoveredFile
from .file_carver import CarveStatus


class ReportGenerator:
    """
    Generates forensic recovery reports.
    
    Supports:
    - JSON (machine-readable)
    - CSV (spreadsheet-compatible)
    - HTML (human-readable with styling)
    - TXT (plain text summary)
    """
    
    def __init__(self, output_dir: str):
        """
        Initialize report generator.
        
        Args:
            output_dir: Directory for report files
        """
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    def generate_all(
        self,
        session: CarveSession,
        formats: Optional[List[str]] = None
    ) -> Dict[str, str]:
        """
        Generate reports in multiple formats.
        
        Args:
            session: Carve session data
            formats: List of formats ('json', 'csv', 'html', 'txt')
            
        Returns:
            Dictionary of format -> file path
        """
        if formats is None:
            formats = ['json', 'html']
        
        paths = {}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        for fmt in formats:
            fmt = fmt.lower()
            if fmt == 'json':
                path = self.generate_json(session, f"report_{timestamp}.json")
                paths['json'] = path
            elif fmt == 'csv':
                path = self.generate_csv(session, f"report_{timestamp}.csv")
                paths['csv'] = path
            elif fmt == 'html':
                path = self.generate_html(session, f"report_{timestamp}.html")
                paths['html'] = path
            elif fmt == 'txt':
                path = self.generate_txt(session, f"report_{timestamp}.txt")
                paths['txt'] = path
        
        return paths
    
    def generate_json(
        self,
        session: CarveSession,
        filename: str = "report.json"
    ) -> str:
        """Generate JSON report."""
        filepath = Path(self.output_dir) / filename
        
        # Build report data
        report = {
            'metadata': {
                'tool': 'ForensicCarver',
                'version': '1.0.0',
                'generated_at': datetime.now().isoformat(),
            },
            'source': {
                'path': session.source_path,
                'size': session.source_size,
                'size_human': self._format_size(session.source_size),
            },
            'settings': {
                'file_types': session.file_types,
                'block_size': session.block_size,
                'threads': session.num_threads,
            },
            'results': {
                'total_files': len(session.files_recovered),
                'unique_files': session.unique_files,
                'duplicates': session.duplicates_skipped,
                'bytes_carved': session.total_bytes_carved,
                'bytes_carved_human': self._format_size(session.total_bytes_carved),
                'duration_seconds': session.duration,
                'errors': len(session.errors),
            },
            'files': [],
            'errors': session.errors,
        }
        
        # Add file details
        for rf in session.files_recovered:
            if rf.output_path:  # Skip duplicates that weren't saved
                file_info = {
                    'filename': rf.filename,
                    'type': rf.file_type,
                    'extension': rf.carved.extension,
                    'size': rf.size,
                    'size_human': self._format_size(rf.size),
                    'source_offset': rf.carved.start_offset,
                    'source_offset_hex': hex(rf.carved.start_offset),
                    'status': rf.carved.status.name,
                    'entropy': round(rf.carved.entropy, 4),
                    'hashes': rf.file_hash.as_dict(),
                    'output_path': rf.output_path,
                    'is_duplicate': rf.is_duplicate,
                }
                report['files'].append(file_info)
        
        # Write JSON
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return str(filepath)
    
    def generate_csv(
        self,
        session: CarveSession,
        filename: str = "report.csv"
    ) -> str:
        """Generate CSV report."""
        filepath = Path(self.output_dir) / filename
        
        # Define columns
        columns = [
            'Filename', 'Type', 'Extension', 'Size', 'Size (Human)',
            'Offset', 'Offset (Hex)', 'Status', 'Entropy',
            'MD5', 'SHA256', 'Path', 'Duplicate'
        ]
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(columns)
            
            for rf in session.files_recovered:
                if rf.output_path:
                    row = [
                        rf.filename,
                        rf.file_type,
                        rf.carved.extension,
                        rf.size,
                        self._format_size(rf.size),
                        rf.carved.start_offset,
                        hex(rf.carved.start_offset),
                        rf.carved.status.name,
                        round(rf.carved.entropy, 4),
                        rf.file_hash.md5 or '',
                        rf.file_hash.sha256 or '',
                        rf.output_path,
                        'Yes' if rf.is_duplicate else 'No',
                    ]
                    writer.writerow(row)
        
        return str(filepath)
    
    def generate_html(
        self,
        session: CarveSession,
        filename: str = "report.html"
    ) -> str:
        """Generate HTML report with styling."""
        filepath = Path(self.output_dir) / filename
        
        # Group files by type
        by_type: Dict[str, List[RecoveredFile]] = {}
        for rf in session.files_recovered:
            if rf.output_path:
                ftype = rf.file_type
                if ftype not in by_type:
                    by_type[ftype] = []
                by_type[ftype].append(rf)
        
        # Generate HTML
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ForensicCarver Recovery Report</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent: #3b82f6;
            --success: #22c55e;
            --warning: #f59e0b;
            --error: #ef4444;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        h1 {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, var(--accent), #8b5cf6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .subtitle {{ color: var(--text-secondary); margin-bottom: 2rem; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: var(--bg-secondary);
            padding: 1.5rem;
            border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.1);
        }}
        .stat-value {{ font-size: 2rem; font-weight: 700; color: var(--accent); }}
        .stat-label {{ color: var(--text-secondary); font-size: 0.9rem; }}
        .section {{ margin-bottom: 2rem; }}
        .section-title {{
            font-size: 1.5rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--accent);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-secondary);
            border-radius: 12px;
            overflow: hidden;
        }}
        th, td {{
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }}
        th {{
            background: rgba(59, 130, 246, 0.1);
            font-weight: 600;
            color: var(--accent);
        }}
        tr:hover {{ background: rgba(255,255,255,0.02); }}
        .status-complete {{ color: var(--success); }}
        .status-truncated {{ color: var(--warning); }}
        .status-corrupted {{ color: var(--error); }}
        .hash {{ font-family: monospace; font-size: 0.85rem; color: var(--text-secondary); }}
        .type-badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            background: var(--accent);
            border-radius: 999px;
            font-size: 0.85rem;
            font-weight: 600;
        }}
        .meta-info {{
            background: var(--bg-secondary);
            padding: 1.5rem;
            border-radius: 12px;
            margin-bottom: 2rem;
        }}
        .meta-row {{ display: flex; margin-bottom: 0.5rem; }}
        .meta-label {{ width: 150px; color: var(--text-secondary); }}
        .meta-value {{ font-weight: 500; }}
        code {{
            background: rgba(0,0,0,0.3);
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-family: monospace;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 ForensicCarver Report</h1>
        <p class="subtitle">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        
        <div class="meta-info">
            <div class="meta-row">
                <span class="meta-label">Source:</span>
                <span class="meta-value"><code>{escape(session.source_path)}</code></span>
            </div>
            <div class="meta-row">
                <span class="meta-label">Source Size:</span>
                <span class="meta-value">{self._format_size(session.source_size)}</span>
            </div>
            <div class="meta-row">
                <span class="meta-label">Scan Duration:</span>
                <span class="meta-value">{self._format_duration(session.duration)}</span>
            </div>
            <div class="meta-row">
                <span class="meta-label">Threads Used:</span>
                <span class="meta-value">{session.num_threads}</span>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{len(session.files_recovered)}</div>
                <div class="stat-label">Files Recovered</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{self._format_size(session.total_bytes_carved)}</div>
                <div class="stat-label">Data Recovered</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len(by_type)}</div>
                <div class="stat-label">File Types Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{session.duplicates_skipped}</div>
                <div class="stat-label">Duplicates Skipped</div>
            </div>
        </div>
'''
        
        # Add files by type
        for ftype, files in sorted(by_type.items()):
            html += f'''
        <div class="section">
            <h2 class="section-title"><span class="type-badge">{escape(ftype)}</span> ({len(files)} files)</h2>
            <table>
                <thead>
                    <tr>
                        <th>Filename</th>
                        <th>Size</th>
                        <th>Offset</th>
                        <th>Status</th>
                        <th>Entropy</th>
                        <th>SHA256</th>
                    </tr>
                </thead>
                <tbody>
'''
            for rf in files:
                status_class = f"status-{rf.carved.status.name.lower()}"
                sha256_short = (rf.file_hash.sha256 or '')[:16] + '...' if rf.file_hash.sha256 else 'N/A'
                
                html += f'''                    <tr>
                        <td>{escape(rf.filename)}</td>
                        <td>{self._format_size(rf.size)}</td>
                        <td><code>{hex(rf.carved.start_offset)}</code></td>
                        <td class="{status_class}">{rf.carved.status.name}</td>
                        <td>{rf.carved.entropy:.2f}</td>
                        <td class="hash" title="{rf.file_hash.sha256 or ''}">{sha256_short}</td>
                    </tr>
'''
            html += '''                </tbody>
            </table>
        </div>
'''
        
        # Close HTML
        html += '''
    </div>
</body>
</html>'''
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return str(filepath)
    
    def generate_txt(
        self,
        session: CarveSession,
        filename: str = "report.txt"
    ) -> str:
        """Generate plain text report."""
        filepath = Path(self.output_dir) / filename
        
        lines = [
            "=" * 70,
            "FORENSICCARVER RECOVERY REPORT",
            "=" * 70,
            "",
            "METADATA",
            "-" * 40,
            f"Generated:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Source:        {session.source_path}",
            f"Source Size:   {self._format_size(session.source_size)}",
            f"Duration:      {self._format_duration(session.duration)}",
            "",
            "RESULTS SUMMARY",
            "-" * 40,
            f"Files Recovered:    {len(session.files_recovered)}",
            f"Unique Files:       {session.unique_files}",
            f"Duplicates:         {session.duplicates_skipped}",
            f"Data Recovered:     {self._format_size(session.total_bytes_carved)}",
            f"Errors:             {len(session.errors)}",
            "",
            "RECOVERED FILES",
            "-" * 40,
        ]
        
        for i, rf in enumerate(session.files_recovered, 1):
            if rf.output_path:
                lines.extend([
                    f"{i}. {rf.filename}",
                    f"   Type:    {rf.file_type}",
                    f"   Size:    {self._format_size(rf.size)}",
                    f"   Offset:  {hex(rf.carved.start_offset)}",
                    f"   Status:  {rf.carved.status.name}",
                    f"   MD5:     {rf.file_hash.md5 or 'N/A'}",
                    f"   SHA256:  {rf.file_hash.sha256 or 'N/A'}",
                    "",
                ])
        
        if session.errors:
            lines.extend([
                "",
                "ERRORS",
                "-" * 40,
            ])
            for error in session.errors:
                lines.append(f"  - {error}")
        
        lines.extend([
            "",
            "=" * 70,
            "END OF REPORT",
            "=" * 70,
        ])
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        
        return str(filepath)
    
    @staticmethod
    def _format_size(size: int) -> str:
        """Format size in human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f} {unit}" if unit != 'B' else f"{size} {unit}"
            size /= 1024
        return f"{size:.2f} PB"
    
    @staticmethod
    def _format_duration(seconds: float) -> str:
        """Format duration in human-readable format."""
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            mins = seconds / 60
            return f"{mins:.1f} minutes"
        else:
            hours = seconds / 3600
            return f"{hours:.1f} hours"
