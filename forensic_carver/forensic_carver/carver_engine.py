"""
Carver Engine Module for ForensicCarver

Main orchestration engine that coordinates all carving components.
"""

import os
import time
from typing import Optional, List, Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime

from .block_reader import BlockReader
from .signatures import SignatureDB, FileSignature
from .file_carver import FileCarver, CarvedFile, CarveStatus
from .block_chainer import BlockChainer
from .entropy import EntropyAnalyzer
from .hasher import HashValidator, FileHash, HashAlgorithm
from .scanner import MultithreadedScanner, ScanProgress


@dataclass
class RecoveredFile:
    """Complete information about a recovered file."""
    carved: CarvedFile
    file_hash: FileHash
    output_path: str
    is_duplicate: bool = False
    duplicate_of: Optional[str] = None
    
    @property
    def filename(self) -> str:
        return Path(self.output_path).name
    
    @property
    def file_type(self) -> str:
        return self.carved.signature.name
    
    @property
    def size(self) -> int:
        return self.carved.size


@dataclass
class CarveSession:
    """Information about a carving session."""
    source_path: str
    source_size: int
    output_dir: str
    start_time: datetime
    end_time: Optional[datetime] = None
    
    # Settings
    file_types: List[str] = field(default_factory=list)
    block_size: int = 512
    num_threads: int = 4
    
    # Results
    files_recovered: List[RecoveredFile] = field(default_factory=list)
    total_bytes_carved: int = 0
    duplicates_skipped: int = 0
    errors: List[str] = field(default_factory=list)
    
    @property
    def duration(self) -> float:
        if self.end_time is None:
            return (datetime.now() - self.start_time).total_seconds()
        return (self.end_time - self.start_time).total_seconds()
    
    @property
    def unique_files(self) -> int:
        return len([f for f in self.files_recovered if not f.is_duplicate])


class CarverEngine:
    """
    Main forensic carving engine.
    
    Orchestrates all components:
    - Block reading from various sources
    - Signature-based file carving
    - Fragmented file recovery
    - Entropy analysis
    - Hash validation and deduplication
    - Multithreaded scanning
    """
    
    def __init__(
        self,
        output_dir: str,
        file_types: Optional[List[str]] = None,
        block_size: int = 512,
        num_threads: Optional[int] = None,
        min_file_size: int = 100,
        max_file_size: Optional[int] = None,
        hash_algorithms: Optional[List[HashAlgorithm]] = None,
        skip_duplicates: bool = True,
        validate_content: bool = True,
        progress_callback: Optional[Callable[[ScanProgress], None]] = None
    ):
        """
        Initialize carver engine.
        
        Args:
            output_dir: Directory for recovered files
            file_types: List of file types to recover (None = all)
            block_size: Block size for scanning
            num_threads: Number of threads (None = auto)
            min_file_size: Minimum file size to recover
            max_file_size: Maximum file size to recover
            hash_algorithms: Hash algorithms to use
            skip_duplicates: Skip duplicate files
            validate_content: Validate carved file content
            progress_callback: Progress update callback
        """
        self.output_dir = output_dir
        self.file_types = file_types
        self.block_size = block_size
        self.num_threads = num_threads or os.cpu_count() or 4
        self.min_file_size = min_file_size
        self.max_file_size = max_file_size
        self.skip_duplicates = skip_duplicates
        self.progress_callback = progress_callback
        
        # Create output directory
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.signature_db = SignatureDB()
        
        # Filter signatures if specific types requested
        if file_types:
            self.signature_db = self.signature_db.filter_by_extensions(file_types)
        
        self.entropy_analyzer = EntropyAnalyzer()
        
        self.file_carver = FileCarver(
            signature_db=self.signature_db,
            entropy_analyzer=self.entropy_analyzer,
            min_file_size=min_file_size,
            max_file_size=max_file_size,
            validate_content=validate_content
        )
        
        self.block_chainer = BlockChainer(
            entropy_analyzer=self.entropy_analyzer
        )
        
        if hash_algorithms is None:
            hash_algorithms = [HashAlgorithm.MD5, HashAlgorithm.SHA256]
        
        self.hash_validator = HashValidator(algorithms=hash_algorithms)
        
        self.scanner = MultithreadedScanner(
            num_threads=self.num_threads,
            progress_callback=progress_callback
        )
        
        # Session tracking
        self._current_session: Optional[CarveSession] = None
    
    def carve(
        self,
        source_path: str,
        start_offset: int = 0,
        end_offset: Optional[int] = None
    ) -> CarveSession:
        """
        Perform carving operation on source.
        
        Args:
            source_path: Path to device or image
            start_offset: Starting offset
            end_offset: Ending offset (None = end of source)
            
        Returns:
            CarveSession with results
        """
        # Open source
        reader = BlockReader(source_path, block_size=self.block_size)
        
        try:
            # Initialize session
            session = CarveSession(
                source_path=source_path,
                source_size=reader.size,
                output_dir=self.output_dir,
                start_time=datetime.now(),
                file_types=self.file_types or [],
                block_size=self.block_size,
                num_threads=self.num_threads
            )
            self._current_session = session
            
            # Reset hash validator tracking
            self.hash_validator.reset_tracking()
            
            # Perform scanning
            for carved in self.scanner.scan(reader, self.file_carver, start_offset, end_offset):
                recovered = self._process_carved_file(carved)
                if recovered:
                    session.files_recovered.append(recovered)
                    session.total_bytes_carved += recovered.size
                    
                    if recovered.is_duplicate:
                        session.duplicates_skipped += 1
            
            # Collect errors
            for chunk_id, error in self.scanner.get_errors():
                session.errors.append(f"Chunk {chunk_id}: {error}")
            
            session.end_time = datetime.now()
            return session
            
        finally:
            reader.close()
    
    def _process_carved_file(self, carved: CarvedFile) -> Optional[RecoveredFile]:
        """
        Process a carved file: hash, dedupe, save.
        
        Args:
            carved: Carved file from scanner
            
        Returns:
            RecoveredFile if saved, None if skipped
        """
        if carved.data is None:
            return None
        
        # Calculate hash
        file_hash = self.hash_validator.hash_bytes(carved.data)
        
        # Check for duplicate
        is_duplicate, duplicate_of = self.hash_validator.check_duplicate(
            file_hash,
            f"offset_{carved.start_offset}",
            HashAlgorithm.SHA256
        )
        
        if is_duplicate and self.skip_duplicates:
            return RecoveredFile(
                carved=carved,
                file_hash=file_hash,
                output_path="",
                is_duplicate=True,
                duplicate_of=duplicate_of
            )
        
        # Save file
        output_path = self.file_carver.save_carved_file(
            carved,
            self.output_dir,
            create_subdirs=True
        )
        
        return RecoveredFile(
            carved=carved,
            file_hash=file_hash,
            output_path=output_path,
            is_duplicate=is_duplicate,
            duplicate_of=duplicate_of
        )
    
    def carve_iter(
        self,
        source_path: str,
        start_offset: int = 0,
        end_offset: Optional[int] = None
    ) -> Iterator[RecoveredFile]:
        """
        Iterate over recovered files as they are found.
        
        Args:
            source_path: Path to device or image
            start_offset: Starting offset
            end_offset: Ending offset
            
        Yields:
            RecoveredFile for each recovered file
        """
        reader = BlockReader(source_path, block_size=self.block_size)
        
        try:
            self.hash_validator.reset_tracking()
            
            for carved in self.scanner.scan(reader, self.file_carver, start_offset, end_offset):
                recovered = self._process_carved_file(carved)
                if recovered:
                    yield recovered
        finally:
            reader.close()
    
    def quick_scan(
        self,
        source_path: str,
        sample_size: int = 100 * 1024 * 1024,
        num_samples: int = 5
    ) -> dict:
        """
        Perform quick scan to estimate recoverable files.
        
        Args:
            source_path: Path to source
            sample_size: Size of each sample
            num_samples: Number of samples to take
            
        Returns:
            Dictionary with estimates
        """
        reader = BlockReader(source_path, block_size=self.block_size)
        
        try:
            source_size = reader.size
            
            # Calculate sample offsets (evenly distributed)
            offsets = []
            if source_size <= sample_size * num_samples:
                offsets = [0]
            else:
                step = (source_size - sample_size) // (num_samples - 1)
                for i in range(num_samples):
                    offsets.append(i * step)
            
            # Scan samples
            file_counts = {}
            total_headers = 0
            
            for offset in offsets:
                data = reader.read_at(offset, sample_size)
                headers = self.file_carver.find_headers(data, offset)
                total_headers += len(headers)
                
                for _, sig in headers:
                    name = sig.name
                    file_counts[name] = file_counts.get(name, 0) + 1
            
            # Estimate total
            sampled_bytes = len(offsets) * sample_size
            ratio = source_size / sampled_bytes if sampled_bytes > 0 else 1
            
            estimates = {
                'source_size': source_size,
                'sampled_bytes': sampled_bytes,
                'headers_found': total_headers,
                'estimated_total': int(total_headers * ratio),
                'by_type': {k: int(v * ratio) for k, v in file_counts.items()}
            }
            
            return estimates
            
        finally:
            reader.close()
    
    def get_session(self) -> Optional[CarveSession]:
        """Get current or last session."""
        return self._current_session
    
    def cancel(self):
        """Cancel ongoing operation."""
        self.scanner.cancel()
    
    def get_supported_types(self) -> List[dict]:
        """Get list of supported file types."""
        types = []
        for sig in self.signature_db:
            types.append({
                'name': sig.name,
                'extension': sig.extension,
                'category': sig.category.name,
                'description': sig.description
            })
        return types
