"""
Block Reader Module for ForensicCarver

Provides read-only access to raw disks, partitions, and disk images.
Supports .dd, .img, and .E01 (with pyewf) formats.
"""

import os
import stat
import mmap
from typing import Optional, Iterator, BinaryIO, Tuple
from pathlib import Path
from dataclasses import dataclass


@dataclass
class SourceInfo:
    """Information about the source being read."""
    path: str
    size: int
    is_device: bool
    is_e01: bool
    block_size: int
    sector_size: int = 512


class BlockReader:
    """
    Read-only block reader for forensic data sources.
    
    Supports:
    - Raw block devices (/dev/sdX, /dev/nvmeX)
    - Disk images (.dd, .img)
    - E01 forensic images (requires pyewf)
    
    All access is read-only to maintain forensic integrity.
    """
    
    def __init__(
        self,
        source_path: str,
        block_size: int = 512,
        use_mmap: bool = True,
        buffer_size: int = 100 * 1024 * 1024  # 100MB buffer
    ):
        """
        Initialize the block reader.
        
        Args:
            source_path: Path to device or image file
            block_size: Block size for reading (default 512 bytes)
            use_mmap: Use memory-mapped I/O when possible
            buffer_size: Read buffer size for chunked operations
        """
        self.source_path = source_path
        self.block_size = block_size
        self.use_mmap = use_mmap
        self.buffer_size = buffer_size
        
        self._handle: Optional[BinaryIO] = None
        self._mmap: Optional[mmap.mmap] = None
        self._e01_handle = None
        self._source_info: Optional[SourceInfo] = None
        
        self._open()
    
    def _open(self):
        """Open the source in read-only mode."""
        path = Path(self.source_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Source not found: {self.source_path}")
        
        # Check if it's a block device
        is_device = False
        try:
            mode = os.stat(self.source_path).st_mode
            is_device = stat.S_ISBLK(mode)
        except OSError:
            pass
        
        # Check for E01 format
        is_e01 = self.source_path.lower().endswith(('.e01', '.ex01', '.s01'))
        
        if is_e01:
            self._open_e01()
        else:
            self._open_regular(is_device)
        
        # Get source size
        size = self._get_size()
        
        self._source_info = SourceInfo(
            path=self.source_path,
            size=size,
            is_device=is_device,
            is_e01=is_e01,
            block_size=self.block_size
        )
    
    def _open_regular(self, is_device: bool):
        """Open a regular file or block device."""
        flags = os.O_RDONLY
        
        # Add direct I/O for devices if available
        if is_device and hasattr(os, 'O_DIRECT'):
            # Note: O_DIRECT requires aligned buffers, skip for simplicity
            pass
        
        # Use low-level open for devices
        if is_device:
            fd = os.open(self.source_path, flags)
            self._handle = os.fdopen(fd, 'rb', buffering=0)
        else:
            self._handle = open(self.source_path, 'rb')
        
        # Try to use mmap for regular files
        if self.use_mmap and not is_device:
            try:
                self._mmap = mmap.mmap(
                    self._handle.fileno(),
                    0,  # Map entire file
                    access=mmap.ACCESS_READ
                )
            except (OSError, ValueError):
                # mmap might fail for very large files or special cases
                self._mmap = None
    
    def _open_e01(self):
        """Open an E01 forensic image using pyewf."""
        try:
            import pyewf
        except ImportError:
            raise ImportError(
                "E01 support requires pyewf library. "
                "Install with: sudo apt install libewf-dev && pip install pyewf"
            )
        
        # Find all segments (E01, E02, ..., EAA, etc.)
        glob_pattern = self.source_path[:-3] + "E*"
        base_path = Path(self.source_path)
        segment_dir = base_path.parent
        base_name = base_path.stem
        
        # Collect all segment files
        segments = []
        for ext_num in range(1, 100):  # E01 to E99
            seg_path = segment_dir / f"{base_name}.E{ext_num:02d}"
            if seg_path.exists():
                segments.append(str(seg_path))
            else:
                break
        
        if not segments:
            segments = [self.source_path]
        
        self._e01_handle = pyewf.handle()
        self._e01_handle.open(segments)
    
    def _get_size(self) -> int:
        """Get the total size of the source."""
        if self._e01_handle is not None:
            return self._e01_handle.get_media_size()
        
        if self._mmap is not None:
            return len(self._mmap)
        
        if self._handle is not None:
            # Seek to end to get size
            current = self._handle.tell()
            self._handle.seek(0, 2)  # Seek to end
            size = self._handle.tell()
            self._handle.seek(current)  # Restore position
            return size
        
        return 0
    
    @property
    def info(self) -> SourceInfo:
        """Get source information."""
        if self._source_info is None:
            raise RuntimeError("Block reader not initialized")
        return self._source_info
    
    @property
    def size(self) -> int:
        """Get total size in bytes."""
        return self.info.size
    
    @property
    def total_blocks(self) -> int:
        """Get total number of blocks."""
        return (self.size + self.block_size - 1) // self.block_size
    
    def read_at(self, offset: int, size: int) -> bytes:
        """
        Read bytes at a specific offset.
        
        Args:
            offset: Byte offset to start reading from
            size: Number of bytes to read
            
        Returns:
            Bytes read (may be less than requested at end of source)
        """
        if offset < 0:
            raise ValueError("Offset cannot be negative")
        
        if offset >= self.size:
            return b""
        
        # Clamp size to available data
        available = self.size - offset
        size = min(size, available)
        
        if self._e01_handle is not None:
            self._e01_handle.seek(offset)
            return self._e01_handle.read(size)
        
        if self._mmap is not None:
            return self._mmap[offset:offset + size]
        
        if self._handle is not None:
            self._handle.seek(offset)
            return self._handle.read(size)
        
        return b""
    
    def read_block(self, block_index: int) -> bytes:
        """
        Read a single block by index.
        
        Args:
            block_index: Zero-based block index
            
        Returns:
            Block data (may be less than block_size at end)
        """
        offset = block_index * self.block_size
        return self.read_at(offset, self.block_size)
    
    def read_blocks(self, start_block: int, count: int) -> bytes:
        """
        Read multiple consecutive blocks.
        
        Args:
            start_block: Starting block index
            count: Number of blocks to read
            
        Returns:
            Concatenated block data
        """
        offset = start_block * self.block_size
        size = count * self.block_size
        return self.read_at(offset, size)
    
    def iter_blocks(
        self,
        start_offset: int = 0,
        end_offset: Optional[int] = None,
        step: int = 1
    ) -> Iterator[Tuple[int, bytes]]:
        """
        Iterate over blocks in the source.
        
        Args:
            start_offset: Starting byte offset (aligned to block_size)
            end_offset: Ending byte offset (None = end of source)
            step: Number of blocks to read at once
            
        Yields:
            Tuple of (offset, data) for each chunk
        """
        if end_offset is None:
            end_offset = self.size
        
        # Align start to block boundary
        start_offset = (start_offset // self.block_size) * self.block_size
        
        chunk_size = step * self.block_size
        offset = start_offset
        
        while offset < end_offset:
            read_size = min(chunk_size, end_offset - offset)
            data = self.read_at(offset, read_size)
            if not data:
                break
            yield offset, data
            offset += len(data)
    
    def iter_chunks(
        self,
        chunk_size: Optional[int] = None,
        start_offset: int = 0,
        end_offset: Optional[int] = None
    ) -> Iterator[Tuple[int, bytes]]:
        """
        Iterate over the source in large chunks.
        
        Args:
            chunk_size: Size of each chunk (default: buffer_size)
            start_offset: Starting byte offset
            end_offset: Ending byte offset (None = end of source)
            
        Yields:
            Tuple of (offset, data) for each chunk
        """
        if chunk_size is None:
            chunk_size = self.buffer_size
        
        if end_offset is None:
            end_offset = self.size
        
        offset = start_offset
        
        while offset < end_offset:
            read_size = min(chunk_size, end_offset - offset)
            data = self.read_at(offset, read_size)
            if not data:
                break
            yield offset, data
            offset += len(data)
    
    def search_bytes(
        self,
        pattern: bytes,
        start_offset: int = 0,
        end_offset: Optional[int] = None,
        limit: int = 0
    ) -> Iterator[int]:
        """
        Search for a byte pattern in the source.
        
        Args:
            pattern: Bytes to search for
            start_offset: Starting offset
            end_offset: Ending offset (None = end of source)
            limit: Maximum matches to find (0 = unlimited)
            
        Yields:
            Offsets where pattern was found
        """
        if not pattern:
            return
        
        if end_offset is None:
            end_offset = self.size
        
        pattern_len = len(pattern)
        overlap = pattern_len - 1
        count = 0
        
        for chunk_offset, chunk in self.iter_chunks(
            start_offset=start_offset,
            end_offset=end_offset
        ):
            # Search within chunk
            search_start = 0
            while True:
                pos = chunk.find(pattern, search_start)
                if pos == -1:
                    break
                
                absolute_offset = chunk_offset + pos
                if absolute_offset >= end_offset:
                    break
                
                yield absolute_offset
                count += 1
                
                if limit > 0 and count >= limit:
                    return
                
                search_start = pos + 1
    
    def close(self):
        """Close the source and release resources."""
        if self._mmap is not None:
            self._mmap.close()
            self._mmap = None
        
        if self._handle is not None:
            self._handle.close()
            self._handle = None
        
        if self._e01_handle is not None:
            self._e01_handle.close()
            self._e01_handle = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
    
    def __repr__(self):
        return (
            f"BlockReader(source='{self.source_path}', "
            f"size={self.size}, block_size={self.block_size})"
        )
