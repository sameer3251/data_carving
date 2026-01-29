"""
Entropy Analyzer Module for ForensicCarver

Provides Shannon entropy calculation and block classification
to detect compressed, encrypted, or sparse data regions.
"""

import math
from typing import List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum, auto
from collections import Counter


class BlockType(Enum):
    """Classification of data blocks based on entropy."""
    SPARSE = auto()       # Mostly null bytes (entropy < 1.0)
    TEXT = auto()         # Text or structured data (1.0 - 5.0)
    BINARY = auto()       # Binary data (5.0 - 6.5)
    COMPRESSED = auto()   # Compressed data (6.5 - 7.5)
    ENCRYPTED = auto()    # Encrypted or random data (7.5 - 8.0)


@dataclass
class EntropyResult:
    """Result of entropy analysis."""
    entropy: float
    block_type: BlockType
    null_ratio: float      # Ratio of null bytes (0x00)
    unique_bytes: int      # Number of unique byte values
    most_common: List[Tuple[int, int]]  # Top 5 most common bytes with counts


class EntropyAnalyzer:
    """
    Analyzer for calculating Shannon entropy and classifying data blocks.
    
    Shannon entropy measures the randomness/information density of data:
    - 0.0: All identical bytes (completely predictable)
    - 8.0: Maximum entropy (completely random, like encrypted data)
    
    Entropy ranges for classification:
    - 0.0 - 1.0: Sparse data (mostly zeros or repeated bytes)
    - 1.0 - 5.0: Text or structured data
    - 5.0 - 6.5: Binary/mixed data
    - 6.5 - 7.5: Compressed data
    - 7.5 - 8.0: Encrypted/random data
    """
    
    # Entropy thresholds for classification
    THRESHOLD_SPARSE = 1.0
    THRESHOLD_TEXT = 5.0
    THRESHOLD_BINARY = 6.5
    THRESHOLD_COMPRESSED = 7.5
    
    # Pre-computed log2 table for performance
    _log2_table: Optional[List[float]] = None
    
    def __init__(
        self,
        sparse_threshold: float = 1.0,
        encrypted_threshold: float = 7.5,
        null_sparse_ratio: float = 0.9
    ):
        """
        Initialize the entropy analyzer.
        
        Args:
            sparse_threshold: Entropy threshold for sparse data
            encrypted_threshold: Entropy threshold for encrypted data
            null_sparse_ratio: Ratio of null bytes to consider block sparse
        """
        self.sparse_threshold = sparse_threshold
        self.encrypted_threshold = encrypted_threshold
        self.null_sparse_ratio = null_sparse_ratio
        
        # Initialize log2 lookup table
        self._init_log2_table()
    
    @classmethod
    def _init_log2_table(cls):
        """Initialize log2 lookup table for fast entropy calculation."""
        if cls._log2_table is None:
            cls._log2_table = [0.0]  # log2(0) = 0 by convention
            for i in range(1, 256 * 256 + 1):  # Cover all possible counts
                cls._log2_table.append(math.log2(i))
    
    def calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of the data.
        
        Formula: H = -Σ p(x) * log2(p(x)) for each byte value x
        
        Args:
            data: Bytes to analyze
            
        Returns:
            Entropy value between 0.0 and 8.0
        """
        if not data:
            return 0.0
        
        length = len(data)
        if length == 0:
            return 0.0
        
        # Count byte frequencies
        byte_counts = Counter(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def calculate_entropy_fast(self, data: bytes) -> float:
        """
        Fast entropy calculation using lookup table.
        
        Optimized version using pre-computed log2 values.
        
        Args:
            data: Bytes to analyze
            
        Returns:
            Entropy value between 0.0 and 8.0
        """
        if not data:
            return 0.0
        
        length = len(data)
        if length == 0:
            return 0.0
        
        # Count byte frequencies using array (faster than Counter for this)
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        
        # Calculate entropy using lookup table
        log2_table = self._log2_table
        log2_length = math.log2(length) if length > 0 else 0
        
        entropy = 0.0
        for count in counts:
            if count > 0:
                # H = -Σ (count/length) * log2(count/length)
                #   = -Σ (count/length) * (log2(count) - log2(length))
                #   = Σ (count/length) * (log2(length) - log2(count))
                #   = log2(length) - (1/length) * Σ count * log2(count)
                entropy += count * log2_table[count]
        
        entropy = log2_length - (entropy / length)
        
        return max(0.0, entropy)  # Avoid negative values from floating point errors
    
    def analyze(self, data: bytes) -> EntropyResult:
        """
        Perform full entropy analysis on data block.
        
        Args:
            data: Bytes to analyze
            
        Returns:
            EntropyResult with entropy, classification, and statistics
        """
        if not data:
            return EntropyResult(
                entropy=0.0,
                block_type=BlockType.SPARSE,
                null_ratio=1.0,
                unique_bytes=0,
                most_common=[]
            )
        
        length = len(data)
        
        # Count byte frequencies
        byte_counts = Counter(data)
        
        # Calculate null ratio
        null_count = byte_counts.get(0, 0)
        null_ratio = null_count / length
        
        # Quick check for sparse blocks
        if null_ratio >= self.null_sparse_ratio:
            return EntropyResult(
                entropy=0.0,
                block_type=BlockType.SPARSE,
                null_ratio=null_ratio,
                unique_bytes=len(byte_counts),
                most_common=byte_counts.most_common(5)
            )
        
        # Calculate entropy
        entropy = self.calculate_entropy_fast(data)
        
        # Classify block
        block_type = self._classify(entropy, null_ratio)
        
        return EntropyResult(
            entropy=entropy,
            block_type=block_type,
            null_ratio=null_ratio,
            unique_bytes=len(byte_counts),
            most_common=byte_counts.most_common(5)
        )
    
    def _classify(self, entropy: float, null_ratio: float) -> BlockType:
        """Classify block based on entropy value."""
        if entropy < self.THRESHOLD_SPARSE or null_ratio > 0.5:
            return BlockType.SPARSE
        elif entropy < self.THRESHOLD_TEXT:
            return BlockType.TEXT
        elif entropy < self.THRESHOLD_BINARY:
            return BlockType.BINARY
        elif entropy < self.THRESHOLD_COMPRESSED:
            return BlockType.COMPRESSED
        else:
            return BlockType.ENCRYPTED
    
    def is_sparse(self, data: bytes) -> bool:
        """Quick check if data block is sparse (mostly zeros)."""
        if not data:
            return True
        
        null_count = data.count(b'\x00')
        return (null_count / len(data)) >= self.null_sparse_ratio
    
    def is_encrypted_or_compressed(self, data: bytes) -> bool:
        """Quick check if data appears encrypted or compressed."""
        entropy = self.calculate_entropy_fast(data)
        return entropy >= self.THRESHOLD_BINARY
    
    def entropy_map(
        self,
        data: bytes,
        block_size: int = 256
    ) -> List[Tuple[int, float, BlockType]]:
        """
        Create an entropy map of the data.
        
        Divides data into blocks and calculates entropy for each.
        
        Args:
            data: Data to analyze
            block_size: Size of each analysis block
            
        Returns:
            List of (offset, entropy, block_type) tuples
        """
        results = []
        offset = 0
        
        while offset < len(data):
            block = data[offset:offset + block_size]
            if block:
                entropy = self.calculate_entropy_fast(block)
                block_type = self._classify(entropy, block.count(b'\x00') / len(block))
                results.append((offset, entropy, block_type))
            offset += block_size
        
        return results
    
    def find_high_entropy_regions(
        self,
        data: bytes,
        threshold: float = 7.0,
        block_size: int = 512,
        min_consecutive: int = 2
    ) -> List[Tuple[int, int, float]]:
        """
        Find regions with high entropy (likely compressed/encrypted).
        
        Args:
            data: Data to analyze
            threshold: Minimum entropy threshold
            block_size: Analysis block size
            min_consecutive: Minimum consecutive high-entropy blocks
            
        Returns:
            List of (start_offset, end_offset, avg_entropy) tuples
        """
        regions = []
        entropy_map = self.entropy_map(data, block_size)
        
        current_region_start = None
        current_entropies = []
        
        for offset, entropy, _ in entropy_map:
            if entropy >= threshold:
                if current_region_start is None:
                    current_region_start = offset
                    current_entropies = [entropy]
                else:
                    current_entropies.append(entropy)
            else:
                if current_region_start is not None:
                    if len(current_entropies) >= min_consecutive:
                        avg_entropy = sum(current_entropies) / len(current_entropies)
                        end_offset = current_region_start + len(current_entropies) * block_size
                        regions.append((current_region_start, end_offset, avg_entropy))
                    current_region_start = None
                    current_entropies = []
        
        # Handle region at end
        if current_region_start is not None and len(current_entropies) >= min_consecutive:
            avg_entropy = sum(current_entropies) / len(current_entropies)
            end_offset = current_region_start + len(current_entropies) * block_size
            regions.append((current_region_start, end_offset, avg_entropy))
        
        return regions
    
    def chi_squared_test(self, data: bytes) -> Tuple[float, bool]:
        """
        Perform chi-squared test for randomness.
        
        Used to detect truly random (encrypted) data vs compressed data.
        
        Args:
            data: Data to test
            
        Returns:
            Tuple of (chi_squared_value, is_random)
        """
        if len(data) < 256:
            return 0.0, False
        
        length = len(data)
        expected = length / 256  # Expected count per byte value
        
        # Count byte frequencies
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        
        # Calculate chi-squared statistic
        chi_squared = sum(
            ((count - expected) ** 2) / expected
            for count in counts
        )
        
        # Critical value for 255 degrees of freedom at 0.05 significance
        # is approximately 293.2
        is_random = chi_squared < 350  # Slightly relaxed threshold
        
        return chi_squared, is_random
    
    @staticmethod
    def describe_entropy(entropy: float) -> str:
        """Get human-readable description of entropy value."""
        if entropy < 1.0:
            return "Very low (sparse/null data)"
        elif entropy < 3.0:
            return "Low (simple text/patterns)"
        elif entropy < 5.0:
            return "Medium-low (structured data)"
        elif entropy < 6.5:
            return "Medium (binary data)"
        elif entropy < 7.5:
            return "High (compressed data)"
        elif entropy < 7.9:
            return "Very high (likely compressed)"
        else:
            return "Maximum (encrypted/random)"
