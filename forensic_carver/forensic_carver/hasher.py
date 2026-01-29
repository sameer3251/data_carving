"""
Hash Validator Module for ForensicCarver

Provides cryptographic hashing and deduplication for recovered files.
"""

import hashlib
import os
from typing import Optional, Dict, Set, Tuple, BinaryIO
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum, auto


class HashAlgorithm(Enum):
    """Supported hash algorithms."""
    MD5 = auto()
    SHA1 = auto()
    SHA256 = auto()
    SHA512 = auto()


@dataclass
class FileHash:
    """Hash information for a file."""
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    sha512: Optional[str] = None
    size: int = 0
    
    def get(self, algorithm: HashAlgorithm) -> Optional[str]:
        """Get hash value for specific algorithm."""
        return {
            HashAlgorithm.MD5: self.md5,
            HashAlgorithm.SHA1: self.sha1,
            HashAlgorithm.SHA256: self.sha256,
            HashAlgorithm.SHA512: self.sha512,
        }.get(algorithm)
    
    def as_dict(self) -> Dict[str, str]:
        """Return non-None hashes as dictionary."""
        result = {}
        if self.md5:
            result['md5'] = self.md5
        if self.sha1:
            result['sha1'] = self.sha1
        if self.sha256:
            result['sha256'] = self.sha256
        if self.sha512:
            result['sha512'] = self.sha512
        result['size'] = str(self.size)
        return result


@dataclass
class DuplicateInfo:
    """Information about duplicate files."""
    hash_value: str
    algorithm: HashAlgorithm
    original_path: str
    duplicate_paths: list = field(default_factory=list)


class HashValidator:
    """
    Hash calculator and validator for forensic file recovery.
    
    Provides:
    - MD5, SHA1, SHA256, SHA512 hashing
    - Streaming hash calculation for large files
    - Duplicate detection
    - Hash verification
    """
    
    # Default chunk size for streaming hash (1MB)
    DEFAULT_CHUNK_SIZE = 1024 * 1024
    
    def __init__(
        self,
        algorithms: Optional[list] = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE
    ):
        """
        Initialize hash validator.
        
        Args:
            algorithms: List of HashAlgorithm to use (default: MD5, SHA256)
            chunk_size: Chunk size for streaming hash calculation
        """
        if algorithms is None:
            self.algorithms = [HashAlgorithm.MD5, HashAlgorithm.SHA256]
        else:
            self.algorithms = algorithms
        
        self.chunk_size = chunk_size
        
        # Duplicate tracking
        self._hash_index: Dict[str, str] = {}  # hash -> first file path
        self._duplicates: Dict[str, DuplicateInfo] = {}  # hash -> duplicate info
    
    def _create_hasher(self, algorithm: HashAlgorithm):
        """Create a hashlib hasher for the algorithm."""
        return {
            HashAlgorithm.MD5: hashlib.md5,
            HashAlgorithm.SHA1: hashlib.sha1,
            HashAlgorithm.SHA256: hashlib.sha256,
            HashAlgorithm.SHA512: hashlib.sha512,
        }[algorithm]()
    
    def hash_bytes(self, data: bytes) -> FileHash:
        """
        Calculate hashes for byte data.
        
        Args:
            data: Bytes to hash
            
        Returns:
            FileHash with calculated hashes
        """
        result = FileHash(size=len(data))
        
        for alg in self.algorithms:
            hasher = self._create_hasher(alg)
            hasher.update(data)
            hash_value = hasher.hexdigest()
            
            if alg == HashAlgorithm.MD5:
                result.md5 = hash_value
            elif alg == HashAlgorithm.SHA1:
                result.sha1 = hash_value
            elif alg == HashAlgorithm.SHA256:
                result.sha256 = hash_value
            elif alg == HashAlgorithm.SHA512:
                result.sha512 = hash_value
        
        return result
    
    def hash_file(self, file_path: str) -> FileHash:
        """
        Calculate hashes for a file using streaming.
        
        Args:
            file_path: Path to file
            
        Returns:
            FileHash with calculated hashes
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        file_size = path.stat().st_size
        result = FileHash(size=file_size)
        
        # Create hashers for all algorithms
        hashers = {alg: self._create_hasher(alg) for alg in self.algorithms}
        
        # Stream file and update all hashers
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                for hasher in hashers.values():
                    hasher.update(chunk)
        
        # Get final hash values
        for alg, hasher in hashers.items():
            hash_value = hasher.hexdigest()
            if alg == HashAlgorithm.MD5:
                result.md5 = hash_value
            elif alg == HashAlgorithm.SHA1:
                result.sha1 = hash_value
            elif alg == HashAlgorithm.SHA256:
                result.sha256 = hash_value
            elif alg == HashAlgorithm.SHA512:
                result.sha512 = hash_value
        
        return result
    
    def hash_stream(self, stream: BinaryIO, size: Optional[int] = None) -> FileHash:
        """
        Calculate hashes from a binary stream.
        
        Args:
            stream: Binary readable stream
            size: Optional size limit to read
            
        Returns:
            FileHash with calculated hashes
        """
        hashers = {alg: self._create_hasher(alg) for alg in self.algorithms}
        total_read = 0
        
        while True:
            # Calculate how much to read
            if size is not None:
                remaining = size - total_read
                if remaining <= 0:
                    break
                read_size = min(self.chunk_size, remaining)
            else:
                read_size = self.chunk_size
            
            chunk = stream.read(read_size)
            if not chunk:
                break
            
            total_read += len(chunk)
            for hasher in hashers.values():
                hasher.update(chunk)
        
        result = FileHash(size=total_read)
        
        for alg, hasher in hashers.items():
            hash_value = hasher.hexdigest()
            if alg == HashAlgorithm.MD5:
                result.md5 = hash_value
            elif alg == HashAlgorithm.SHA1:
                result.sha1 = hash_value
            elif alg == HashAlgorithm.SHA256:
                result.sha256 = hash_value
            elif alg == HashAlgorithm.SHA512:
                result.sha512 = hash_value
        
        return result
    
    def verify_hash(
        self,
        file_path: str,
        expected_hash: str,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256
    ) -> bool:
        """
        Verify file against expected hash.
        
        Args:
            file_path: Path to file
            expected_hash: Expected hash value (hex string)
            algorithm: Hash algorithm to use
            
        Returns:
            True if hash matches
        """
        hasher = self._create_hasher(algorithm)
        
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
        
        actual_hash = hasher.hexdigest().lower()
        expected_hash = expected_hash.lower()
        
        return actual_hash == expected_hash
    
    def check_duplicate(
        self,
        file_hash: FileHash,
        file_path: str,
        use_algorithm: HashAlgorithm = HashAlgorithm.SHA256
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if file is a duplicate and track it.
        
        Args:
            file_hash: Pre-calculated FileHash
            file_path: Path to the file
            use_algorithm: Algorithm to use for duplicate detection
            
        Returns:
            Tuple of (is_duplicate, original_path if duplicate)
        """
        hash_value = file_hash.get(use_algorithm)
        if not hash_value:
            return False, None
        
        if hash_value in self._hash_index:
            original_path = self._hash_index[hash_value]
            
            # Track duplicate
            if hash_value not in self._duplicates:
                self._duplicates[hash_value] = DuplicateInfo(
                    hash_value=hash_value,
                    algorithm=use_algorithm,
                    original_path=original_path,
                    duplicate_paths=[file_path]
                )
            else:
                self._duplicates[hash_value].duplicate_paths.append(file_path)
            
            return True, original_path
        else:
            self._hash_index[hash_value] = file_path
            return False, None
    
    def get_duplicates(self) -> Dict[str, DuplicateInfo]:
        """Get all tracked duplicates."""
        return self._duplicates.copy()
    
    def get_unique_count(self) -> int:
        """Get count of unique files (by hash)."""
        return len(self._hash_index)
    
    def get_duplicate_count(self) -> int:
        """Get count of duplicate files."""
        return sum(len(d.duplicate_paths) for d in self._duplicates.values())
    
    def reset_tracking(self):
        """Reset duplicate tracking."""
        self._hash_index.clear()
        self._duplicates.clear()
    
    @staticmethod
    def quick_hash(data: bytes, algorithm: str = 'sha256') -> str:
        """
        Quick hash calculation for small data.
        
        Args:
            data: Bytes to hash
            algorithm: Algorithm name ('md5', 'sha1', 'sha256', 'sha512')
            
        Returns:
            Hex digest string
        """
        hasher = hashlib.new(algorithm)
        hasher.update(data)
        return hasher.hexdigest()
    
    @staticmethod
    def format_hash_chain(file_hash: FileHash) -> str:
        """
        Format hashes for forensic documentation.
        
        Args:
            file_hash: FileHash object
            
        Returns:
            Formatted string with all hashes
        """
        lines = [f"Size: {file_hash.size} bytes"]
        if file_hash.md5:
            lines.append(f"MD5:    {file_hash.md5}")
        if file_hash.sha1:
            lines.append(f"SHA1:   {file_hash.sha1}")
        if file_hash.sha256:
            lines.append(f"SHA256: {file_hash.sha256}")
        if file_hash.sha512:
            lines.append(f"SHA512: {file_hash.sha512}")
        return "\n".join(lines)
