"""
File Carver Module for ForensicCarver

Core carving engine that extracts files based on signature matching.
"""

import os
import struct
from typing import Optional, List, Tuple, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum, auto

from .signatures import FileSignature, SignatureDB, FooterType, FileCategory
from .entropy import EntropyAnalyzer, BlockType


class CarveStatus(Enum):
    """Status of a carved file."""
    COMPLETE = auto()       # Full file recovered with header and footer
    TRUNCATED = auto()      # Header found but footer missing/truncated
    PARTIAL = auto()        # Partial recovery
    CORRUPTED = auto()      # Data appears corrupted
    ENCRYPTED = auto()      # High entropy suggests encryption


@dataclass
class CarvedFile:
    """Information about a carved file."""
    signature: FileSignature
    start_offset: int
    end_offset: int
    size: int
    status: CarveStatus
    data: Optional[bytes] = None  # Only populated if requested
    
    # Validation info
    entropy: float = 0.0
    is_valid: bool = True
    validation_notes: str = ""
    
    # Output info
    output_path: Optional[str] = None
    sequence_number: int = 0
    
    @property
    def extension(self) -> str:
        return self.signature.extension
    
    @property
    def file_type(self) -> str:
        return self.signature.name


class FileCarver:
    """
    Signature-based file carver.
    
    Scans raw data for file signatures and extracts complete or partial files.
    """
    
    def __init__(
        self,
        signature_db: Optional[SignatureDB] = None,
        entropy_analyzer: Optional[EntropyAnalyzer] = None,
        min_file_size: int = 100,
        max_file_size: Optional[int] = None,
        validate_content: bool = True
    ):
        """
        Initialize file carver.
        
        Args:
            signature_db: Signature database (default: all signatures)
            entropy_analyzer: Entropy analyzer for validation
            min_file_size: Minimum file size to extract
            max_file_size: Maximum file size (None = use signature's max)
            validate_content: Perform content validation
        """
        self.signature_db = signature_db or SignatureDB()
        self.entropy_analyzer = entropy_analyzer or EntropyAnalyzer()
        self.min_file_size = min_file_size
        self.max_file_size = max_file_size
        self.validate_content = validate_content
        
        # Statistics
        self.stats = {
            'headers_found': 0,
            'files_carved': 0,
            'bytes_carved': 0,
            'truncated': 0,
            'corrupted': 0,
        }
    
    def find_headers(
        self,
        data: bytes,
        base_offset: int = 0
    ) -> List[Tuple[int, FileSignature]]:
        """
        Find all file headers in a data block.
        
        Args:
            data: Data to scan
            base_offset: Base offset for calculating absolute positions
            
        Returns:
            List of (offset, signature) tuples
        """
        matches = []
        max_header_len = self.signature_db.get_max_header_length()
        
        # Scan every byte (could optimize with larger step for performance)
        for i in range(len(data) - max_header_len):
            sigs = self.signature_db.match_header(data[i:i + max_header_len])
            for sig in sigs:
                absolute_offset = base_offset + i
                matches.append((absolute_offset, sig))
                self.stats['headers_found'] += 1
        
        return matches
    
    def find_footer(
        self,
        data: bytes,
        signature: FileSignature,
        start_pos: int = 0
    ) -> Optional[int]:
        """
        Find footer position for a signature.
        
        Args:
            data: Data to search in
            signature: File signature with footer info
            start_pos: Position after header to start searching
            
        Returns:
            Position of footer end, or None if not found
        """
        if signature.footer is None:
            return None
        
        footer = signature.footer
        
        # Search for footer
        pos = data.find(footer, start_pos)
        
        if pos != -1:
            # Return position after footer
            return pos + len(footer)
        
        return None
    
    def calculate_size_from_structure(
        self,
        data: bytes,
        signature: FileSignature
    ) -> Optional[int]:
        """
        Calculate file size from internal structure.
        
        Args:
            data: Data starting at file header
            signature: File signature
            
        Returns:
            Calculated file size, or None if cannot determine
        """
        if len(data) < 16:
            return None
        
        name = signature.name.upper()
        
        # BMP: Size at offset 2 (4 bytes, little-endian)
        if name == "BMP":
            if len(data) >= 6:
                return struct.unpack('<I', data[2:6])[0]
        
        # ELF: Parse ELF header for section info
        elif name == "ELF":
            return self._parse_elf_size(data)
        
        # PE/EXE: Parse PE header
        elif name in ("EXE", "DLL"):
            return self._parse_pe_size(data)
        
        # WAV, AVI, WebP: RIFF container size at offset 4
        elif name in ("WAV", "AVI", "WEBP"):
            if len(data) >= 8:
                size = struct.unpack('<I', data[4:8])[0]
                return size + 8  # Add RIFF header size
        
        # MKV/WebM: EBML container - complex, use max_size
        elif name in ("MKV", "WEBM"):
            return None
        
        # GZIP: Has trailing size at end (need to find it)
        elif name == "GZIP":
            return None
        
        return None
    
    def _parse_elf_size(self, data: bytes) -> Optional[int]:
        """Parse ELF header to determine file size."""
        if len(data) < 52:  # Minimum ELF header size
            return None
        
        try:
            # Check ELF magic
            if data[:4] != b'\x7fELF':
                return None
            
            # Determine 32-bit or 64-bit
            ei_class = data[4]
            is_64bit = (ei_class == 2)
            endian = '<' if data[5] == 1 else '>'  # 1 = little, 2 = big
            
            if is_64bit:
                if len(data) < 64:
                    return None
                # e_shoff (section header offset) at 40
                # e_shentsize at 58, e_shnum at 60
                e_shoff = struct.unpack(endian + 'Q', data[40:48])[0]
                e_shentsize = struct.unpack(endian + 'H', data[58:60])[0]
                e_shnum = struct.unpack(endian + 'H', data[60:62])[0]
            else:
                if len(data) < 52:
                    return None
                # e_shoff at 32, e_shentsize at 46, e_shnum at 48
                e_shoff = struct.unpack(endian + 'I', data[32:36])[0]
                e_shentsize = struct.unpack(endian + 'H', data[46:48])[0]
                e_shnum = struct.unpack(endian + 'H', data[48:50])[0]
            
            # File size = section header offset + (entry size * number of entries)
            if e_shoff > 0 and e_shnum > 0:
                return e_shoff + (e_shentsize * e_shnum)
            
        except (struct.error, IndexError):
            pass
        
        return None
    
    def _parse_pe_size(self, data: bytes) -> Optional[int]:
        """Parse PE header to determine file size."""
        if len(data) < 64:
            return None
        
        try:
            # Check MZ magic
            if data[:2] != b'MZ':
                return None
            
            # PE header offset at 0x3C
            pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
            
            if pe_offset > len(data) - 24:
                return None
            
            # Check PE signature
            if data[pe_offset:pe_offset + 4] != b'PE\x00\x00':
                return None
            
            # Number of sections at PE + 6
            num_sections = struct.unpack('<H', data[pe_offset + 6:pe_offset + 8])[0]
            
            # Optional header size at PE + 20
            opt_header_size = struct.unpack('<H', data[pe_offset + 20:pe_offset + 22])[0]
            
            # Section headers start at PE + 24 + optional_header_size
            section_table_offset = pe_offset + 24 + opt_header_size
            
            # Each section header is 40 bytes
            # Find the section with highest raw data offset + size
            max_end = 0
            for i in range(num_sections):
                section_offset = section_table_offset + (i * 40)
                if section_offset + 40 > len(data):
                    break
                
                # SizeOfRawData at +16, PointerToRawData at +20
                raw_size = struct.unpack('<I', data[section_offset + 16:section_offset + 20])[0]
                raw_ptr = struct.unpack('<I', data[section_offset + 20:section_offset + 24])[0]
                
                end = raw_ptr + raw_size
                if end > max_end:
                    max_end = end
            
            return max_end if max_end > 0 else None
            
        except (struct.error, IndexError):
            pass
        
        return None
    
    def carve_at_offset(
        self,
        data: bytes,
        signature: FileSignature,
        offset: int = 0,
        relative_offset: int = 0
    ) -> Optional[CarvedFile]:
        """
        Attempt to carve a file at a specific offset.
        
        Args:
            data: Data buffer (should contain file start)
            signature: Detected file signature
            offset: Absolute offset in source
            relative_offset: Relative offset within data buffer
            
        Returns:
            CarvedFile if successful, None otherwise
        """
        file_data = data[relative_offset:]
        
        if len(file_data) < signature.min_size:
            return None
        
        max_size = self.max_file_size or signature.max_size
        
        # Limit data to max_size
        if len(file_data) > max_size:
            file_data = file_data[:max_size]
        
        end_pos = None
        status = CarveStatus.TRUNCATED
        
        # Determine end position based on footer type
        if signature.footer_type == FooterType.FIXED_FOOTER:
            end_pos = self.find_footer(
                file_data,
                signature,
                len(signature.header)
            )
            if end_pos is not None:
                status = CarveStatus.COMPLETE
        
        elif signature.footer_type == FooterType.STRUCTURE_BASED:
            end_pos = self.calculate_size_from_structure(file_data, signature)
            if end_pos is not None:
                status = CarveStatus.COMPLETE
        
        elif signature.footer_type == FooterType.ATOM_BASED:
            end_pos = self._parse_atom_container(file_data, signature)
            if end_pos is not None:
                status = CarveStatus.COMPLETE
        
        # Fallback to max_size
        if end_pos is None:
            end_pos = len(file_data)
            status = CarveStatus.TRUNCATED
        
        # Clamp to available data
        end_pos = min(end_pos, len(file_data))
        
        # Check minimum size
        if end_pos < signature.min_size:
            return None
        
        # Extract file data
        extracted_data = file_data[:end_pos]
        
        # Validate content
        if self.validate_content:
            entropy, is_valid, notes = self._validate_content(
                extracted_data, signature
            )
            if not is_valid:
                status = CarveStatus.CORRUPTED
        else:
            entropy = 0.0
            is_valid = True
            notes = ""
        
        return CarvedFile(
            signature=signature,
            start_offset=offset,
            end_offset=offset + end_pos,
            size=end_pos,
            status=status,
            data=extracted_data,
            entropy=entropy,
            is_valid=is_valid,
            validation_notes=notes
        )
    
    def _parse_atom_container(
        self,
        data: bytes,
        signature: FileSignature
    ) -> Optional[int]:
        """Parse atom/chunk-based container (MP4, MOV)."""
        if len(data) < 8:
            return None
        
        try:
            offset = 0
            max_offset = min(len(data), signature.max_size)
            
            while offset < max_offset - 8:
                # Atom size (4 bytes, big-endian) + type (4 bytes)
                atom_size = struct.unpack('>I', data[offset:offset + 4])[0]
                atom_type = data[offset + 4:offset + 8]
                
                if atom_size == 0:
                    # Atom extends to end of file
                    return max_offset
                elif atom_size == 1:
                    # Extended size (8 bytes after type)
                    if offset + 16 > len(data):
                        break
                    atom_size = struct.unpack('>Q', data[offset + 8:offset + 16])[0]
                
                if atom_size < 8 or offset + atom_size > max_offset:
                    break
                
                offset += atom_size
            
            return offset if offset > 8 else None
            
        except (struct.error, IndexError):
            pass
        
        return None
    
    def _validate_content(
        self,
        data: bytes,
        signature: FileSignature
    ) -> Tuple[float, bool, str]:
        """
        Validate carved file content.
        
        Returns:
            Tuple of (entropy, is_valid, validation_notes)
        """
        notes_parts = []
        is_valid = True
        
        # Calculate entropy
        result = self.entropy_analyzer.analyze(data)
        entropy = result.entropy
        
        # Check for sparse data (likely corrupt/empty)
        if result.block_type == BlockType.SPARSE:
            is_valid = False
            notes_parts.append("File appears sparse/empty")
        
        # Check entropy expectations based on file type
        if signature.category == FileCategory.IMAGE:
            if signature.name in ("JPEG", "PNG"):
                # Compressed images should have high entropy
                if entropy < 6.0:
                    notes_parts.append(f"Low entropy for image ({entropy:.2f})")
        
        elif signature.category == FileCategory.EXECUTABLE:
            # Executables typically have medium entropy
            if entropy > 7.5:
                notes_parts.append("Very high entropy (possibly packed/encrypted)")
        
        # Check for corruption in first bytes (should match header)
        if len(data) >= len(signature.header):
            if signature.header_offset == 0:
                if data[:len(signature.header)] != signature.header:
                    is_valid = False
                    notes_parts.append("Header mismatch")
        
        return entropy, is_valid, "; ".join(notes_parts)
    
    def scan_buffer(
        self,
        data: bytes,
        base_offset: int = 0
    ) -> Iterator[CarvedFile]:
        """
        Scan a buffer for all recoverable files.
        
        Args:
            data: Data buffer to scan
            base_offset: Base offset in source
            
        Yields:
            CarvedFile for each recovered file
        """
        # Find all headers
        headers = self.find_headers(data, base_offset)
        
        for offset, signature in headers:
            relative_offset = offset - base_offset
            
            # Skip if not enough data
            if relative_offset < 0 or relative_offset >= len(data):
                continue
            
            # Attempt to carve
            carved = self.carve_at_offset(
                data,
                signature,
                offset,
                relative_offset
            )
            
            if carved is not None:
                self.stats['files_carved'] += 1
                self.stats['bytes_carved'] += carved.size
                
                if carved.status == CarveStatus.TRUNCATED:
                    self.stats['truncated'] += 1
                elif carved.status == CarveStatus.CORRUPTED:
                    self.stats['corrupted'] += 1
                
                yield carved
    
    def save_carved_file(
        self,
        carved: CarvedFile,
        output_dir: str,
        create_subdirs: bool = True,
        prefix: str = ""
    ) -> str:
        """
        Save a carved file to disk.
        
        Args:
            carved: CarvedFile to save
            output_dir: Output directory
            create_subdirs: Create subdirectories by file type
            prefix: Filename prefix
            
        Returns:
            Path to saved file
        """
        if carved.data is None:
            raise ValueError("CarvedFile has no data")
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectory for file type
        if create_subdirs:
            type_dir = output_path / carved.signature.name.lower()
            type_dir.mkdir(exist_ok=True)
            output_path = type_dir
        
        # Generate filename
        filename = f"{prefix}{carved.start_offset:012x}.{carved.extension}"
        file_path = output_path / filename
        
        # Handle duplicates
        counter = 1
        while file_path.exists():
            filename = f"{prefix}{carved.start_offset:012x}_{counter}.{carved.extension}"
            file_path = output_path / filename
            counter += 1
        
        # Write file
        with open(file_path, 'wb') as f:
            f.write(carved.data)
        
        carved.output_path = str(file_path)
        return str(file_path)
    
    def reset_stats(self):
        """Reset statistics."""
        self.stats = {
            'headers_found': 0,
            'files_carved': 0,
            'bytes_carved': 0,
            'truncated': 0,
            'corrupted': 0,
        }
