"""
Utility Functions for ForensicCarver
"""

import os
import stat
from typing import Optional, Tuple


def format_size(size: int) -> str:
    """Format size in human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.2f} {unit}" if unit != 'B' else f"{size} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def parse_size(size_str: str) -> int:
    """
    Parse size string to bytes.
    
    Examples: "100", "10KB", "5MB", "1GB"
    """
    size_str = size_str.strip().upper()
    
    units = {
        'B': 1,
        'K': 1024,
        'KB': 1024,
        'M': 1024 * 1024,
        'MB': 1024 * 1024,
        'G': 1024 * 1024 * 1024,
        'GB': 1024 * 1024 * 1024,
        'T': 1024 * 1024 * 1024 * 1024,
        'TB': 1024 * 1024 * 1024 * 1024,
    }
    
    for unit, multiplier in sorted(units.items(), key=lambda x: -len(x[0])):
        if size_str.endswith(unit):
            number = size_str[:-len(unit)].strip()
            return int(float(number) * multiplier)
    
    return int(size_str)


def format_duration(seconds: float) -> str:
    """Format duration in human-readable format."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        mins = int(seconds / 60)
        secs = int(seconds % 60)
        return f"{mins}m {secs}s"
    else:
        hours = int(seconds / 3600)
        mins = int((seconds % 3600) / 60)
        return f"{hours}h {mins}m"


def is_block_device(path: str) -> bool:
    """Check if path is a block device."""
    try:
        mode = os.stat(path).st_mode
        return stat.S_ISBLK(mode)
    except OSError:
        return False


def get_device_size(path: str) -> int:
    """Get size of a block device."""
    try:
        with open(path, 'rb') as f:
            f.seek(0, 2)  # Seek to end
            return f.tell()
    except (IOError, OSError):
        return 0


def validate_source(path: str) -> Tuple[bool, str]:
    """
    Validate source path.
    
    Returns:
        Tuple of (is_valid, message)
    """
    if not os.path.exists(path):
        return False, f"Path does not exist: {path}"
    
    # Check if block device
    if is_block_device(path):
        # Check read permission
        if not os.access(path, os.R_OK):
            return False, f"No read permission on device: {path}. Try running with sudo."
        return True, "Block device"
    
    # Check if regular file
    if os.path.isfile(path):
        if not os.access(path, os.R_OK):
            return False, f"No read permission on file: {path}"
        return True, "File"
    
    return False, f"Not a valid source (must be file or block device): {path}"


def validate_output_dir(path: str) -> Tuple[bool, str]:
    """
    Validate output directory.
    
    Returns:
        Tuple of (is_valid, message)
    """
    if os.path.exists(path):
        if not os.path.isdir(path):
            return False, f"Output path exists but is not a directory: {path}"
        if not os.access(path, os.W_OK):
            return False, f"No write permission on directory: {path}"
        return True, "Existing directory"
    
    # Try to create parent directories
    try:
        parent = os.path.dirname(os.path.abspath(path))
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
        return True, "Will create directory"
    except OSError as e:
        return False, f"Cannot create directory: {e}"


def hex_dump(data: bytes, offset: int = 0, length: int = 256) -> str:
    """
    Create hex dump of data.
    
    Args:
        data: Bytes to dump
        offset: Starting offset for display
        length: Number of bytes to show
        
    Returns:
        Formatted hex dump string
    """
    lines = []
    data = data[:length]
    
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        hex_part = hex_part.ljust(48)
        
        # ASCII representation
        ascii_part = ''.join(
            chr(b) if 32 <= b < 127 else '.'
            for b in chunk
        )
        
        addr = offset + i
        lines.append(f'{addr:08x}  {hex_part} |{ascii_part}|')
    
    return '\n'.join(lines)


def check_root() -> bool:
    """Check if running as root."""
    return os.geteuid() == 0


def safe_filename(name: str, max_length: int = 200) -> str:
    """Create safe filename from string."""
    # Replace unsafe characters
    unsafe = '<>:"/\\|?*'
    for char in unsafe:
        name = name.replace(char, '_')
    
    # Truncate
    if len(name) > max_length:
        name = name[:max_length]
    
    return name
