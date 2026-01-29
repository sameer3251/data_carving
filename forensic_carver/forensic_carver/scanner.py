"""
Multithreaded Scanner Module for ForensicCarver

High-performance parallel scanning engine.
"""

import os
import threading
from typing import Optional, List, Callable, Iterator, Any
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
from queue import Queue, Empty
import time

from .block_reader import BlockReader
from .file_carver import FileCarver, CarvedFile


@dataclass
class ScanChunk:
    """A chunk of data to scan."""
    chunk_id: int
    start_offset: int
    end_offset: int
    size: int


@dataclass
class ScanProgress:
    """Scanning progress information."""
    total_bytes: int
    scanned_bytes: int
    total_chunks: int
    completed_chunks: int
    files_found: int
    errors: int
    elapsed_time: float
    
    @property
    def percent_complete(self) -> float:
        if self.total_bytes == 0:
            return 100.0
        return (self.scanned_bytes / self.total_bytes) * 100
    
    @property
    def bytes_per_second(self) -> float:
        if self.elapsed_time == 0:
            return 0.0
        return self.scanned_bytes / self.elapsed_time
    
    @property
    def eta_seconds(self) -> float:
        if self.bytes_per_second == 0:
            return 0.0
        remaining = self.total_bytes - self.scanned_bytes
        return remaining / self.bytes_per_second


class MultithreadedScanner:
    """
    Multithreaded disk/image scanner for file recovery.
    
    Features:
    - Parallel chunk processing
    - Lock-free result collection
    - Progress tracking
    - Graceful cancellation
    """
    
    # Default chunk size: 100MB
    DEFAULT_CHUNK_SIZE = 100 * 1024 * 1024
    
    # Overlap between chunks to handle files at boundaries
    CHUNK_OVERLAP = 1 * 1024 * 1024  # 1MB overlap
    
    def __init__(
        self,
        num_threads: Optional[int] = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        progress_callback: Optional[Callable[[ScanProgress], None]] = None
    ):
        """
        Initialize scanner.
        
        Args:
            num_threads: Number of worker threads (default: CPU count)
            chunk_size: Size of chunks to process in parallel
            progress_callback: Callback for progress updates
        """
        self.num_threads = num_threads or os.cpu_count() or 4
        self.chunk_size = chunk_size
        self.progress_callback = progress_callback
        
        # State
        self._results: Queue = Queue()
        self._errors: Queue = Queue()
        self._cancelled = threading.Event()
        self._progress_lock = threading.Lock()
        self._progress = ScanProgress(
            total_bytes=0,
            scanned_bytes=0,
            total_chunks=0,
            completed_chunks=0,
            files_found=0,
            errors=0,
            elapsed_time=0.0
        )
        self._start_time = 0.0
        
        # Deduplication set (by start offset)
        self._seen_offsets: set = set()
        self._seen_lock = threading.Lock()
    
    def _create_chunks(
        self,
        total_size: int,
        start_offset: int = 0,
        end_offset: Optional[int] = None
    ) -> List[ScanChunk]:
        """Create list of chunks to process."""
        if end_offset is None:
            end_offset = total_size
        
        chunks = []
        chunk_id = 0
        offset = start_offset
        
        while offset < end_offset:
            chunk_end = min(offset + self.chunk_size, end_offset)
            
            chunks.append(ScanChunk(
                chunk_id=chunk_id,
                start_offset=offset,
                end_offset=chunk_end,
                size=chunk_end - offset
            ))
            
            # Move to next chunk with overlap
            offset = chunk_end - self.CHUNK_OVERLAP if chunk_end < end_offset else chunk_end
            chunk_id += 1
        
        return chunks
    
    def _process_chunk(
        self,
        reader: BlockReader,
        chunk: ScanChunk,
        carver: FileCarver
    ) -> List[CarvedFile]:
        """
        Process a single chunk.
        
        Args:
            reader: Block reader
            chunk: Chunk to process
            carver: File carver instance
            
        Returns:
            List of carved files
        """
        if self._cancelled.is_set():
            return []
        
        try:
            # Read chunk data with extra for footer scanning
            read_size = chunk.size + carver.signature_db.get_max_header_length()
            data = reader.read_at(chunk.start_offset, read_size)
            
            if not data:
                return []
            
            # Get carved files
            carved_files = []
            for carved in carver.scan_buffer(data, chunk.start_offset):
                # Deduplicate by offset
                with self._seen_lock:
                    if carved.start_offset in self._seen_offsets:
                        continue
                    self._seen_offsets.add(carved.start_offset)
                
                carved_files.append(carved)
            
            return carved_files
            
        except Exception as e:
            self._errors.put((chunk.chunk_id, str(e)))
            return []
    
    def _update_progress(
        self,
        scanned_bytes: int = 0,
        completed_chunks: int = 0,
        files_found: int = 0,
        errors: int = 0
    ):
        """Update progress counters."""
        with self._progress_lock:
            self._progress.scanned_bytes += scanned_bytes
            self._progress.completed_chunks += completed_chunks
            self._progress.files_found += files_found
            self._progress.errors += errors
            self._progress.elapsed_time = time.time() - self._start_time
            
            if self.progress_callback:
                self.progress_callback(self._progress)
    
    def scan(
        self,
        reader: BlockReader,
        carver: FileCarver,
        start_offset: int = 0,
        end_offset: Optional[int] = None
    ) -> Iterator[CarvedFile]:
        """
        Perform parallel scanning.
        
        Args:
            reader: Block reader for source
            carver: File carver instance
            start_offset: Starting offset
            end_offset: Ending offset (None = end of source)
            
        Yields:
            Carved files as they are found
        """
        # Reset state
        self._cancelled.clear()
        self._seen_offsets.clear()
        self._start_time = time.time()
        
        if end_offset is None:
            end_offset = reader.size
        
        # Create chunks
        chunks = self._create_chunks(reader.size, start_offset, end_offset)
        
        # Initialize progress
        with self._progress_lock:
            self._progress = ScanProgress(
                total_bytes=end_offset - start_offset,
                scanned_bytes=0,
                total_chunks=len(chunks),
                completed_chunks=0,
                files_found=0,
                errors=0,
                elapsed_time=0.0
            )
        
        # Process chunks in parallel
        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            # Submit all chunks
            futures: dict = {}
            for chunk in chunks:
                future = executor.submit(
                    self._process_chunk,
                    reader,
                    chunk,
                    carver
                )
                futures[future] = chunk
            
            # Collect results as they complete
            for future in as_completed(futures):
                if self._cancelled.is_set():
                    break
                
                chunk = futures[future]
                
                try:
                    carved_files = future.result()
                    
                    self._update_progress(
                        scanned_bytes=chunk.size,
                        completed_chunks=1,
                        files_found=len(carved_files)
                    )
                    
                    for carved in carved_files:
                        yield carved
                        
                except Exception as e:
                    self._update_progress(
                        scanned_bytes=chunk.size,
                        completed_chunks=1,
                        errors=1
                    )
    
    def scan_collect(
        self,
        reader: BlockReader,
        carver: FileCarver,
        start_offset: int = 0,
        end_offset: Optional[int] = None
    ) -> List[CarvedFile]:
        """
        Scan and collect all results (blocking).
        
        Args:
            reader: Block reader for source
            carver: File carver instance
            start_offset: Starting offset
            end_offset: Ending offset
            
        Returns:
            List of all carved files
        """
        return list(self.scan(reader, carver, start_offset, end_offset))
    
    def cancel(self):
        """Cancel ongoing scan."""
        self._cancelled.set()
    
    def is_cancelled(self) -> bool:
        """Check if scan was cancelled."""
        return self._cancelled.is_set()
    
    def get_progress(self) -> ScanProgress:
        """Get current progress."""
        with self._progress_lock:
            return ScanProgress(
                total_bytes=self._progress.total_bytes,
                scanned_bytes=self._progress.scanned_bytes,
                total_chunks=self._progress.total_chunks,
                completed_chunks=self._progress.completed_chunks,
                files_found=self._progress.files_found,
                errors=self._progress.errors,
                elapsed_time=time.time() - self._start_time if self._start_time else 0.0
            )
    
    def get_errors(self) -> List[tuple]:
        """Get all errors that occurred during scanning."""
        errors = []
        while not self._errors.empty():
            try:
                errors.append(self._errors.get_nowait())
            except Empty:
                break
        return errors


def format_progress(progress: ScanProgress) -> str:
    """Format progress for display."""
    percent = progress.percent_complete
    speed_mb = progress.bytes_per_second / (1024 * 1024)
    eta = progress.eta_seconds
    
    if eta < 60:
        eta_str = f"{eta:.0f}s"
    elif eta < 3600:
        eta_str = f"{eta / 60:.1f}m"
    else:
        eta_str = f"{eta / 3600:.1f}h"
    
    return (
        f"Progress: {percent:.1f}% | "
        f"Files: {progress.files_found} | "
        f"Speed: {speed_mb:.1f} MB/s | "
        f"ETA: {eta_str}"
    )
