"""
Block Chainer Module for ForensicCarver

Handles fragmented file recovery using heuristic algorithms.
"""

from typing import Optional, List, Tuple, Iterator
from dataclasses import dataclass
from enum import Enum, auto

from .signatures import FileSignature, FooterType
from .entropy import EntropyAnalyzer


class FragmentType(Enum):
    """Type of file fragment."""
    HEADER = auto()      # Contains file header
    MIDDLE = auto()      # Middle fragment
    FOOTER = auto()      # Contains file footer
    UNKNOWN = auto()     # Cannot determine


@dataclass
class Fragment:
    """A file fragment with metadata."""
    offset: int
    size: int
    data: Optional[bytes]
    fragment_type: FragmentType
    entropy: float
    signature: Optional[FileSignature] = None
    
    @property
    def end_offset(self) -> int:
        return self.offset + self.size


@dataclass
class FragmentChain:
    """A chain of fragments forming a complete or partial file."""
    fragments: List[Fragment]
    signature: FileSignature
    total_size: int
    is_complete: bool
    gaps: List[Tuple[int, int]]  # List of (start, size) gaps
    confidence: float  # 0.0 to 1.0


class BlockChainer:
    """
    Heuristic-based block chainer for fragmented file recovery.
    
    Implements:
    1. Bifragment gap carving for 2-fragment files
    2. Entropy-based block matching
    3. Content continuity analysis
    4. Pattern-based chain validation
    """
    
    # Common gap sizes in bytes (based on filesystem cluster sizes)
    COMMON_GAP_SIZES = [
        512,           # 512B sector
        1024,          # 1KB
        4096,          # 4KB (common cluster size)
        8192,          # 8KB
        16384,         # 16KB
        32768,         # 32KB (FAT16/32)
        65536,         # 64KB (NTFS possible)
        1024 * 1024,   # 1MB (large allocation)
    ]
    
    def __init__(
        self,
        entropy_analyzer: Optional[EntropyAnalyzer] = None,
        entropy_variance_threshold: float = 0.5,
        min_confidence: float = 0.7
    ):
        """
        Initialize block chainer.
        
        Args:
            entropy_analyzer: Entropy analyzer for block comparison
            entropy_variance_threshold: Max entropy variance between adjacent blocks
            min_confidence: Minimum confidence for chain acceptance
        """
        self.entropy_analyzer = entropy_analyzer or EntropyAnalyzer()
        self.entropy_variance_threshold = entropy_variance_threshold
        self.min_confidence = min_confidence
    
    def analyze_fragment(
        self,
        data: bytes,
        offset: int,
        signature: Optional[FileSignature] = None
    ) -> Fragment:
        """
        Analyze a data fragment.
        
        Args:
            data: Fragment data
            offset: Offset in source
            signature: Optional signature for context
            
        Returns:
            Fragment with analysis results
        """
        entropy_result = self.entropy_analyzer.analyze(data)
        
        # Determine fragment type
        fragment_type = FragmentType.UNKNOWN
        
        if signature:
            # Check for header
            header_offset = signature.header_offset
            if len(data) > header_offset + len(signature.header):
                if data[header_offset:header_offset + len(signature.header)] == signature.header:
                    fragment_type = FragmentType.HEADER
            
            # Check for footer
            if signature.footer and signature.footer in data[-len(signature.footer) - 100:]:
                if fragment_type == FragmentType.HEADER:
                    # Has both - complete file in this fragment
                    pass
                else:
                    fragment_type = FragmentType.FOOTER
        
        if fragment_type == FragmentType.UNKNOWN:
            fragment_type = FragmentType.MIDDLE
        
        return Fragment(
            offset=offset,
            size=len(data),
            data=data,
            fragment_type=fragment_type,
            entropy=entropy_result.entropy,
            signature=signature
        )
    
    def bifragment_carve(
        self,
        header_fragment: Fragment,
        candidate_blocks: List[bytes],
        candidate_offsets: List[int],
        gap_sizes: Optional[List[int]] = None
    ) -> List[FragmentChain]:
        """
        Attempt bifragment gap carving.
        
        Used when a file is split into exactly 2 fragments with a gap.
        
        Args:
            header_fragment: Fragment containing file header
            candidate_blocks: List of potential continuation blocks
            candidate_offsets: Offsets of candidate blocks
            gap_sizes: Gap sizes to try (default: common sizes)
            
        Returns:
            List of valid fragment chains
        """
        if gap_sizes is None:
            gap_sizes = self.COMMON_GAP_SIZES
        
        if header_fragment.signature is None:
            return []
        
        chains = []
        signature = header_fragment.signature
        
        for block, offset in zip(candidate_blocks, candidate_offsets):
            # Skip blocks that appear before header
            if offset <= header_fragment.end_offset:
                continue
            
            # Check if gap size matches common sizes
            gap = offset - header_fragment.end_offset
            gap_match = any(
                abs(gap - common_gap) < 512  # Allow some tolerance
                for common_gap in gap_sizes
            )
            
            if not gap_match:
                continue
            
            # Check entropy continuity
            header_entropy = header_fragment.entropy
            block_entropy = self.entropy_analyzer.calculate_entropy_fast(block)
            
            entropy_diff = abs(header_entropy - block_entropy)
            if entropy_diff > self.entropy_variance_threshold:
                continue
            
            # Analyze continuation block
            cont_fragment = self.analyze_fragment(block, offset, signature)
            
            # Check for footer in continuation
            has_footer = cont_fragment.fragment_type == FragmentType.FOOTER
            
            # Calculate confidence
            confidence = 0.5  # Base confidence
            
            if gap in gap_sizes:
                confidence += 0.2  # Exact gap match bonus
            if entropy_diff < 0.2:
                confidence += 0.2  # Good entropy match
            if has_footer:
                confidence += 0.1  # Footer found
            
            # Create chain
            chain = FragmentChain(
                fragments=[header_fragment, cont_fragment],
                signature=signature,
                total_size=header_fragment.size + len(block),
                is_complete=has_footer,
                gaps=[(header_fragment.end_offset, gap)],
                confidence=confidence
            )
            
            if confidence >= self.min_confidence:
                chains.append(chain)
        
        return chains
    
    def entropy_chain(
        self,
        fragments: List[Fragment],
        target_entropy: float
    ) -> List[Fragment]:
        """
        Chain fragments based on entropy similarity.
        
        Args:
            fragments: List of unordered fragments
            target_entropy: Expected entropy for file type
            
        Returns:
            Ordered list of likely-related fragments
        """
        if not fragments:
            return []
        
        # Sort by entropy distance from target
        scored = []
        for frag in fragments:
            distance = abs(frag.entropy - target_entropy)
            scored.append((distance, frag))
        
        scored.sort(key=lambda x: x[0])
        
        # Take fragments within threshold
        chained = []
        for distance, frag in scored:
            if distance <= self.entropy_variance_threshold:
                chained.append(frag)
        
        # Sort by offset
        chained.sort(key=lambda f: f.offset)
        
        return chained
    
    def validate_chain(
        self,
        chain: FragmentChain
    ) -> Tuple[bool, float, str]:
        """
        Validate a fragment chain.
        
        Args:
            chain: Fragment chain to validate
            
        Returns:
            Tuple of (is_valid, confidence, notes)
        """
        if not chain.fragments:
            return False, 0.0, "Empty chain"
        
        notes_parts = []
        confidence = chain.confidence
        
        # Check first fragment has header
        first = chain.fragments[0]
        if first.fragment_type != FragmentType.HEADER:
            confidence -= 0.3
            notes_parts.append("Missing header")
        
        # Check last fragment has footer (if applicable)
        last = chain.fragments[-1]
        if chain.signature.footer_type == FooterType.FIXED_FOOTER:
            if last.fragment_type != FragmentType.FOOTER:
                confidence -= 0.2
                notes_parts.append("Missing footer")
        
        # Check entropy consistency
        if len(chain.fragments) > 1:
            entropies = [f.entropy for f in chain.fragments]
            variance = max(entropies) - min(entropies)
            if variance > self.entropy_variance_threshold:
                confidence -= 0.2
                notes_parts.append(f"High entropy variance ({variance:.2f})")
        
        # Check gaps are reasonable
        total_gap = sum(g[1] for g in chain.gaps)
        if total_gap > chain.total_size * 2:
            confidence -= 0.3
            notes_parts.append("Large gaps")
        
        confidence = max(0.0, min(1.0, confidence))
        is_valid = confidence >= self.min_confidence
        
        return is_valid, confidence, "; ".join(notes_parts) if notes_parts else "Valid"
    
    def reconstruct_file(
        self,
        chain: FragmentChain,
        fill_gaps: bool = True,
        gap_fill_byte: int = 0x00
    ) -> Optional[bytes]:
        """
        Reconstruct a file from fragment chain.
        
        Args:
            chain: Fragment chain
            fill_gaps: Fill gaps with null bytes
            gap_fill_byte: Byte value for gap filling
            
        Returns:
            Reconstructed file data, or None if cannot reconstruct
        """
        if not chain.fragments:
            return None
        
        # Check all fragments have data
        if any(f.data is None for f in chain.fragments):
            return None
        
        if not fill_gaps and chain.gaps:
            # Cannot reconstruct without gap filling
            return None
        
        # Sort fragments by offset
        sorted_fragments = sorted(chain.fragments, key=lambda f: f.offset)
        
        # Build file
        result = bytearray()
        current_offset = sorted_fragments[0].offset
        
        for frag in sorted_fragments:
            if frag.offset > current_offset:
                # Fill gap
                gap_size = frag.offset - current_offset
                result.extend(bytes([gap_fill_byte]) * gap_size)
            
            result.extend(frag.data)
            current_offset = frag.end_offset
        
        return bytes(result)
    
    def find_continuations(
        self,
        header_fragment: Fragment,
        search_data: bytes,
        search_base_offset: int,
        block_size: int = 4096,
        max_candidates: int = 10
    ) -> List[Tuple[int, bytes, float]]:
        """
        Find potential continuation blocks for a header fragment.
        
        Args:
            header_fragment: Fragment with file header
            search_data: Data to search for continuations
            search_base_offset: Base offset of search data
            block_size: Size of blocks to analyze
            max_candidates: Maximum candidates to return
            
        Returns:
            List of (offset, data, score) tuples
        """
        candidates = []
        header_entropy = header_fragment.entropy
        
        # Scan search data in blocks
        for i in range(0, len(search_data) - block_size, block_size):
            block = search_data[i:i + block_size]
            offset = search_base_offset + i
            
            # Skip if before or overlapping with header
            if offset < header_fragment.end_offset:
                continue
            
            # Calculate entropy
            block_entropy = self.entropy_analyzer.calculate_entropy_fast(block)
            
            # Check entropy similarity
            entropy_diff = abs(header_entropy - block_entropy)
            if entropy_diff > self.entropy_variance_threshold * 2:
                continue
            
            # Calculate score (lower is better)
            gap = offset - header_fragment.end_offset
            
            # Prefer common gap sizes
            gap_score = min(
                abs(gap - common) / common if common > 0 else float('inf')
                for common in self.COMMON_GAP_SIZES
            )
            
            # Combined score
            score = entropy_diff + gap_score * 0.1
            
            candidates.append((offset, block, score))
        
        # Sort by score and return top candidates
        candidates.sort(key=lambda x: x[2])
        return candidates[:max_candidates]
    
    def smart_chain(
        self,
        header_fragment: Fragment,
        available_fragments: List[Fragment]
    ) -> Optional[FragmentChain]:
        """
        Attempt to intelligently chain fragments.
        
        Uses multiple heuristics to find the best chain.
        
        Args:
            header_fragment: Starting fragment with header
            available_fragments: Other available fragments
            
        Returns:
            Best fragment chain, or None if cannot chain
        """
        if header_fragment.signature is None:
            return None
        
        signature = header_fragment.signature
        
        # Filter fragments by entropy similarity
        target_entropy = header_fragment.entropy
        compatible = [header_fragment]
        
        for frag in available_fragments:
            if frag.offset <= header_fragment.offset:
                continue
            
            entropy_diff = abs(frag.entropy - target_entropy)
            if entropy_diff <= self.entropy_variance_threshold:
                compatible.append(frag)
        
        if len(compatible) < 2:
            return None
        
        # Sort by offset
        compatible.sort(key=lambda f: f.offset)
        
        # Build chain
        chain_fragments = [compatible[0]]
        gaps = []
        
        for i in range(1, len(compatible)):
            prev = chain_fragments[-1]
            curr = compatible[i]
            
            gap = curr.offset - prev.end_offset
            if gap < 0:
                continue  # Overlapping
            
            if gap > 0:
                gaps.append((prev.end_offset, gap))
            
            chain_fragments.append(curr)
            
            # Check if we have footer
            if curr.fragment_type == FragmentType.FOOTER:
                break
        
        # Calculate total size
        total_size = sum(f.size for f in chain_fragments)
        
        # Check completeness
        is_complete = (
            chain_fragments[-1].fragment_type == FragmentType.FOOTER
            or signature.footer_type != FooterType.FIXED_FOOTER
        )
        
        # Calculate confidence
        confidence = 0.5
        if is_complete:
            confidence += 0.2
        if len(chain_fragments) == 2:
            confidence += 0.1  # Simple bifragment
        
        chain = FragmentChain(
            fragments=chain_fragments,
            signature=signature,
            total_size=total_size,
            is_complete=is_complete,
            gaps=gaps,
            confidence=confidence
        )
        
        # Validate
        is_valid, final_confidence, _ = self.validate_chain(chain)
        chain.confidence = final_confidence
        
        return chain if is_valid else None
