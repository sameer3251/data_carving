"""
File Signature Database for ForensicCarver

Contains magic bytes, headers, footers, and metadata for supported file types.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Callable
from enum import Enum, auto


class FileCategory(Enum):
    """Categories for file types."""
    IMAGE = auto()
    DOCUMENT = auto()
    ARCHIVE = auto()
    MULTIMEDIA = auto()
    EXECUTABLE = auto()
    OTHER = auto()


class FooterType(Enum):
    """How to determine file end."""
    FIXED_FOOTER = auto()      # Has a known footer signature
    STRUCTURE_BASED = auto()   # Size determined from internal structure
    MAX_SIZE = auto()          # No footer, use max size limit
    ATOM_BASED = auto()        # Container format with atoms/chunks


@dataclass
class FileSignature:
    """File signature definition."""
    name: str
    extension: str
    category: FileCategory
    header: bytes
    header_offset: int = 0  # Offset where header appears (usually 0)
    footer: Optional[bytes] = None
    footer_type: FooterType = FooterType.MAX_SIZE
    min_size: int = 100
    max_size: int = 100 * 1024 * 1024  # 100MB default
    description: str = ""
    # Additional headers to validate (for disambiguation)
    secondary_headers: List[bytes] = field(default_factory=list)
    # Byte offset range to search for footer (relative to header match)
    footer_search_window: int = 0  # 0 means use max_size
    

class SignatureDB:
    """
    Database of file signatures for carving.
    
    Maintains a registry of file types with their magic bytes,
    headers, footers, and validation rules.
    """
    
    def __init__(self):
        self._signatures: List[FileSignature] = []
        self._header_map: dict = {}  # Maps first N bytes to signatures
        self._load_default_signatures()
    
    def _load_default_signatures(self):
        """Load the default set of file signatures."""
        
        # ============================================================
        # IMAGE FORMATS
        # ============================================================
        
        # JPEG/JFIF
        self.add_signature(FileSignature(
            name="JPEG",
            extension="jpg",
            category=FileCategory.IMAGE,
            header=bytes([0xFF, 0xD8, 0xFF]),
            footer=bytes([0xFF, 0xD9]),
            footer_type=FooterType.FIXED_FOOTER,
            min_size=100,
            max_size=50 * 1024 * 1024,  # 50MB
            description="JPEG Image File"
        ))
        
        # PNG
        self.add_signature(FileSignature(
            name="PNG",
            extension="png",
            category=FileCategory.IMAGE,
            header=bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
            footer=bytes([0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]),
            footer_type=FooterType.FIXED_FOOTER,
            min_size=100,
            max_size=100 * 1024 * 1024,  # 100MB
            description="PNG Image File"
        ))
        
        # GIF87a
        self.add_signature(FileSignature(
            name="GIF87a",
            extension="gif",
            category=FileCategory.IMAGE,
            header=b"GIF87a",
            footer=bytes([0x00, 0x3B]),
            footer_type=FooterType.FIXED_FOOTER,
            min_size=50,
            max_size=50 * 1024 * 1024,
            description="GIF Image (87a)"
        ))
        
        # GIF89a
        self.add_signature(FileSignature(
            name="GIF89a",
            extension="gif",
            category=FileCategory.IMAGE,
            header=b"GIF89a",
            footer=bytes([0x00, 0x3B]),
            footer_type=FooterType.FIXED_FOOTER,
            min_size=50,
            max_size=50 * 1024 * 1024,
            description="GIF Image (89a)"
        ))
        
        # BMP
        self.add_signature(FileSignature(
            name="BMP",
            extension="bmp",
            category=FileCategory.IMAGE,
            header=b"BM",
            footer_type=FooterType.STRUCTURE_BASED,  # Size in header at offset 2
            min_size=100,
            max_size=100 * 1024 * 1024,
            description="Bitmap Image File"
        ))
        
        # TIFF (Little Endian)
        self.add_signature(FileSignature(
            name="TIFF_LE",
            extension="tiff",
            category=FileCategory.IMAGE,
            header=bytes([0x49, 0x49, 0x2A, 0x00]),
            footer_type=FooterType.STRUCTURE_BASED,
            min_size=100,
            max_size=500 * 1024 * 1024,
            description="TIFF Image (Little Endian)"
        ))
        
        # TIFF (Big Endian)
        self.add_signature(FileSignature(
            name="TIFF_BE",
            extension="tiff",
            category=FileCategory.IMAGE,
            header=bytes([0x4D, 0x4D, 0x00, 0x2A]),
            footer_type=FooterType.STRUCTURE_BASED,
            min_size=100,
            max_size=500 * 1024 * 1024,
            description="TIFF Image (Big Endian)"
        ))
        
        # WebP
        self.add_signature(FileSignature(
            name="WebP",
            extension="webp",
            category=FileCategory.IMAGE,
            header=b"RIFF",
            secondary_headers=[b"WEBP"],  # At offset 8
            footer_type=FooterType.STRUCTURE_BASED,
            min_size=100,
            max_size=100 * 1024 * 1024,
            description="WebP Image File"
        ))
        
        # ============================================================
        # DOCUMENT FORMATS
        # ============================================================
        
        # PDF
        self.add_signature(FileSignature(
            name="PDF",
            extension="pdf",
            category=FileCategory.DOCUMENT,
            header=b"%PDF-",
            footer=b"%%EOF",
            footer_type=FooterType.FIXED_FOOTER,
            min_size=100,
            max_size=500 * 1024 * 1024,  # 500MB
            description="PDF Document"
        ))
        
        # Microsoft Office Open XML (DOCX, XLSX, PPTX) - They're ZIP files
        # DOCX
        self.add_signature(FileSignature(
            name="DOCX",
            extension="docx",
            category=FileCategory.DOCUMENT,
            header=bytes([0x50, 0x4B, 0x03, 0x04]),
            secondary_headers=[b"word/"],  # Contains word/ directory
            footer=bytes([0x50, 0x4B, 0x05, 0x06]),  # End of central directory
            footer_type=FooterType.FIXED_FOOTER,
            min_size=1000,
            max_size=200 * 1024 * 1024,
            description="Microsoft Word Document"
        ))
        
        # XLSX
        self.add_signature(FileSignature(
            name="XLSX",
            extension="xlsx",
            category=FileCategory.DOCUMENT,
            header=bytes([0x50, 0x4B, 0x03, 0x04]),
            secondary_headers=[b"xl/"],  # Contains xl/ directory
            footer=bytes([0x50, 0x4B, 0x05, 0x06]),
            footer_type=FooterType.FIXED_FOOTER,
            min_size=1000,
            max_size=200 * 1024 * 1024,
            description="Microsoft Excel Spreadsheet"
        ))
        
        # PPTX
        self.add_signature(FileSignature(
            name="PPTX",
            extension="pptx",
            category=FileCategory.DOCUMENT,
            header=bytes([0x50, 0x4B, 0x03, 0x04]),
            secondary_headers=[b"ppt/"],  # Contains ppt/ directory
            footer=bytes([0x50, 0x4B, 0x05, 0x06]),
            footer_type=FooterType.FIXED_FOOTER,
            min_size=1000,
            max_size=500 * 1024 * 1024,
            description="Microsoft PowerPoint Presentation"
        ))
        
        # ODF (OpenDocument Format)
        self.add_signature(FileSignature(
            name="ODF",
            extension="odt",
            category=FileCategory.DOCUMENT,
            header=bytes([0x50, 0x4B, 0x03, 0x04]),
            secondary_headers=[b"mimetype"],
            footer=bytes([0x50, 0x4B, 0x05, 0x06]),
            footer_type=FooterType.FIXED_FOOTER,
            min_size=1000,
            max_size=200 * 1024 * 1024,
            description="OpenDocument Format"
        ))
        
        # ============================================================
        # ARCHIVE FORMATS
        # ============================================================
        
        # ZIP
        self.add_signature(FileSignature(
            name="ZIP",
            extension="zip",
            category=FileCategory.ARCHIVE,
            header=bytes([0x50, 0x4B, 0x03, 0x04]),
            footer=bytes([0x50, 0x4B, 0x05, 0x06]),
            footer_type=FooterType.FIXED_FOOTER,
            min_size=100,
            max_size=4 * 1024 * 1024 * 1024,  # 4GB
            description="ZIP Archive"
        ))
        
        # RAR5
        self.add_signature(FileSignature(
            name="RAR5",
            extension="rar",
            category=FileCategory.ARCHIVE,
            header=bytes([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]),
            footer_type=FooterType.STRUCTURE_BASED,
            min_size=100,
            max_size=4 * 1024 * 1024 * 1024,
            description="RAR Archive (v5)"
        ))
        
        # RAR4
        self.add_signature(FileSignature(
            name="RAR4",
            extension="rar",
            category=FileCategory.ARCHIVE,
            header=bytes([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]),
            footer_type=FooterType.STRUCTURE_BASED,
            min_size=100,
            max_size=4 * 1024 * 1024 * 1024,
            description="RAR Archive (v4)"
        ))
        
        # 7-Zip
        self.add_signature(FileSignature(
            name="7Z",
            extension="7z",
            category=FileCategory.ARCHIVE,
            header=bytes([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]),
            footer_type=FooterType.STRUCTURE_BASED,
            min_size=100,
            max_size=4 * 1024 * 1024 * 1024,
            description="7-Zip Archive"
        ))
        
        # GZIP
        self.add_signature(FileSignature(
            name="GZIP",
            extension="gz",
            category=FileCategory.ARCHIVE,
            header=bytes([0x1F, 0x8B, 0x08]),
            footer_type=FooterType.STRUCTURE_BASED,
            min_size=20,
            max_size=4 * 1024 * 1024 * 1024,
            description="GZIP Compressed File"
        ))
        
        # BZIP2
        self.add_signature(FileSignature(
            name="BZIP2",
            extension="bz2",
            category=FileCategory.ARCHIVE,
            header=bytes([0x42, 0x5A, 0x68]),
            footer_type=FooterType.STRUCTURE_BASED,
            min_size=20,
            max_size=4 * 1024 * 1024 * 1024,
            description="BZIP2 Compressed File"
        ))
        
        # XZ
        self.add_signature(FileSignature(
            name="XZ",
            extension="xz",
            category=FileCategory.ARCHIVE,
            header=bytes([0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]),
            footer=bytes([0x59, 0x5A]),
            footer_type=FooterType.FIXED_FOOTER,
            min_size=20,
            max_size=4 * 1024 * 1024 * 1024,
            description="XZ Compressed File"
        ))
        
        # TAR
        self.add_signature(FileSignature(
            name="TAR",
            extension="tar",
            category=FileCategory.ARCHIVE,
            header=b"ustar",
            header_offset=257,  # ustar magic at offset 257
            footer_type=FooterType.STRUCTURE_BASED,
            min_size=512,
            max_size=4 * 1024 * 1024 * 1024,
            description="TAR Archive"
        ))
        
        # ============================================================
        # MULTIMEDIA FORMATS
        # ============================================================
        
        # MP4/M4A/M4V (ftyp atom)
        self.add_signature(FileSignature(
            name="MP4",
            extension="mp4",
            category=FileCategory.MULTIMEDIA,
            header=b"ftyp",
            header_offset=4,  # Size (4 bytes) + 'ftyp'
            footer_type=FooterType.ATOM_BASED,
            min_size=1000,
            max_size=10 * 1024 * 1024 * 1024,  # 10GB
            description="MP4 Video/Audio"
        ))
        
        # QuickTime MOV
        self.add_signature(FileSignature(
            name="MOV",
            extension="mov",
            category=FileCategory.MULTIMEDIA,
            header=b"moov",
            header_offset=4,
            footer_type=FooterType.ATOM_BASED,
            min_size=1000,
            max_size=10 * 1024 * 1024 * 1024,
            description="QuickTime Movie"
        ))
        
        # AVI
        self.add_signature(FileSignature(
            name="AVI",
            extension="avi",
            category=FileCategory.MULTIMEDIA,
            header=b"RIFF",
            secondary_headers=[b"AVI "],  # At offset 8
            footer_type=FooterType.STRUCTURE_BASED,
            min_size=1000,
            max_size=10 * 1024 * 1024 * 1024,
            description="AVI Video"
        ))
        
        # MKV (Matroska)
        self.add_signature(FileSignature(
            name="MKV",
            extension="mkv",
            category=FileCategory.MULTIMEDIA,
            header=bytes([0x1A, 0x45, 0xDF, 0xA3]),
            footer_type=FooterType.STRUCTURE_BASED,
            min_size=1000,
            max_size=50 * 1024 * 1024 * 1024,  # 50GB
            description="Matroska Video"
        ))
        
        # WebM (also Matroska-based)
        self.add_signature(FileSignature(
            name="WebM",
            extension="webm",
            category=FileCategory.MULTIMEDIA,
            header=bytes([0x1A, 0x45, 0xDF, 0xA3]),
            secondary_headers=[b"webm"],
            footer_type=FooterType.STRUCTURE_BASED,
            min_size=1000,
            max_size=10 * 1024 * 1024 * 1024,
            description="WebM Video"
        ))
        
        # FLV
        self.add_signature(FileSignature(
            name="FLV",
            extension="flv",
            category=FileCategory.MULTIMEDIA,
            header=b"FLV",
            footer_type=FooterType.STRUCTURE_BASED,
            min_size=1000,
            max_size=10 * 1024 * 1024 * 1024,
            description="Flash Video"
        ))
        
        # MP3 with ID3v2 tag
        self.add_signature(FileSignature(
            name="MP3_ID3",
            extension="mp3",
            category=FileCategory.MULTIMEDIA,
            header=b"ID3",
            footer_type=FooterType.STRUCTURE_BASED,
            min_size=100,
            max_size=100 * 1024 * 1024,
            description="MP3 Audio (ID3 tagged)"
        ))
        
        # MP3 frame sync
        self.add_signature(FileSignature(
            name="MP3",
            extension="mp3",
            category=FileCategory.MULTIMEDIA,
            header=bytes([0xFF, 0xFB]),  # Frame sync + MPEG1 Layer 3
            footer_type=FooterType.STRUCTURE_BASED,
            min_size=100,
            max_size=100 * 1024 * 1024,
            description="MP3 Audio"
        ))
        
        # WAV
        self.add_signature(FileSignature(
            name="WAV",
            extension="wav",
            category=FileCategory.MULTIMEDIA,
            header=b"RIFF",
            secondary_headers=[b"WAVE"],
            footer_type=FooterType.STRUCTURE_BASED,
            min_size=100,
            max_size=2 * 1024 * 1024 * 1024,
            description="WAV Audio"
        ))
        
        # FLAC
        self.add_signature(FileSignature(
            name="FLAC",
            extension="flac",
            category=FileCategory.MULTIMEDIA,
            header=b"fLaC",
            footer_type=FooterType.STRUCTURE_BASED,
            min_size=100,
            max_size=1 * 1024 * 1024 * 1024,
            description="FLAC Audio"
        ))
        
        # OGG (Vorbis/Opus)
        self.add_signature(FileSignature(
            name="OGG",
            extension="ogg",
            category=FileCategory.MULTIMEDIA,
            header=b"OggS",
            footer_type=FooterType.STRUCTURE_BASED,
            min_size=100,
            max_size=1 * 1024 * 1024 * 1024,
            description="OGG Audio"
        ))
        
        # ============================================================
        # EXECUTABLE FORMATS
        # ============================================================
        
        # ELF (Linux executables, shared objects)
        self.add_signature(FileSignature(
            name="ELF",
            extension="elf",
            category=FileCategory.EXECUTABLE,
            header=bytes([0x7F, 0x45, 0x4C, 0x46]),  # \x7FELF
            footer_type=FooterType.STRUCTURE_BASED,
            min_size=100,
            max_size=500 * 1024 * 1024,
            description="ELF Executable/Library"
        ))
        
        # Windows PE/EXE
        self.add_signature(FileSignature(
            name="EXE",
            extension="exe",
            category=FileCategory.EXECUTABLE,
            header=b"MZ",
            footer_type=FooterType.STRUCTURE_BASED,
            min_size=100,
            max_size=500 * 1024 * 1024,
            description="Windows Executable"
        ))
        
        # Windows DLL (same as EXE but different purpose)
        self.add_signature(FileSignature(
            name="DLL",
            extension="dll",
            category=FileCategory.EXECUTABLE,
            header=b"MZ",
            footer_type=FooterType.STRUCTURE_BASED,
            min_size=100,
            max_size=500 * 1024 * 1024,
            description="Windows DLL"
        ))
        
        # Mach-O (macOS executables) - 32-bit
        self.add_signature(FileSignature(
            name="MACHO32",
            extension="macho",
            category=FileCategory.EXECUTABLE,
            header=bytes([0xFE, 0xED, 0xFA, 0xCE]),
            footer_type=FooterType.STRUCTURE_BASED,
            min_size=100,
            max_size=500 * 1024 * 1024,
            description="Mach-O Executable (32-bit)"
        ))
        
        # Mach-O (macOS executables) - 64-bit
        self.add_signature(FileSignature(
            name="MACHO64",
            extension="macho",
            category=FileCategory.EXECUTABLE,
            header=bytes([0xFE, 0xED, 0xFA, 0xCF]),
            footer_type=FooterType.STRUCTURE_BASED,
            min_size=100,
            max_size=500 * 1024 * 1024,
            description="Mach-O Executable (64-bit)"
        ))
        
        # Java Class File
        self.add_signature(FileSignature(
            name="CLASS",
            extension="class",
            category=FileCategory.EXECUTABLE,
            header=bytes([0xCA, 0xFE, 0xBA, 0xBE]),
            footer_type=FooterType.STRUCTURE_BASED,
            min_size=100,
            max_size=50 * 1024 * 1024,
            description="Java Class File"
        ))
        
        # ============================================================
        # OTHER FORMATS
        # ============================================================
        
        # SQLite Database
        self.add_signature(FileSignature(
            name="SQLITE",
            extension="sqlite",
            category=FileCategory.OTHER,
            header=b"SQLite format 3\x00",
            footer_type=FooterType.STRUCTURE_BASED,
            min_size=1024,
            max_size=10 * 1024 * 1024 * 1024,
            description="SQLite Database"
        ))
        
        # XML
        self.add_signature(FileSignature(
            name="XML",
            extension="xml",
            category=FileCategory.OTHER,
            header=b"<?xml",
            footer_type=FooterType.MAX_SIZE,
            min_size=10,
            max_size=100 * 1024 * 1024,
            description="XML Document"
        ))
        
        # HTML
        self.add_signature(FileSignature(
            name="HTML",
            extension="html",
            category=FileCategory.OTHER,
            header=b"<!DOCTYPE html",
            footer_type=FooterType.MAX_SIZE,
            min_size=10,
            max_size=50 * 1024 * 1024,
            description="HTML Document"
        ))
        
        # Build the header map for fast lookups
        self._build_header_map()
    
    def add_signature(self, sig: FileSignature):
        """Add a signature to the database."""
        self._signatures.append(sig)
    
    def _build_header_map(self):
        """Build a map from header prefixes to signatures for fast lookup."""
        self._header_map = {}
        for sig in self._signatures:
            # Use first 2 bytes as key (handles most cases)
            if sig.header_offset == 0:
                key = sig.header[:2] if len(sig.header) >= 2 else sig.header
                if key not in self._header_map:
                    self._header_map[key] = []
                self._header_map[key].append(sig)
    
    def get_all_signatures(self) -> List[FileSignature]:
        """Return all registered signatures."""
        return self._signatures.copy()
    
    def get_by_category(self, category: FileCategory) -> List[FileSignature]:
        """Get signatures by category."""
        return [s for s in self._signatures if s.category == category]
    
    def get_by_extension(self, ext: str) -> List[FileSignature]:
        """Get signatures by file extension."""
        ext = ext.lower().lstrip(".")
        return [s for s in self._signatures if s.extension == ext]
    
    def get_by_name(self, name: str) -> Optional[FileSignature]:
        """Get signature by name."""
        name = name.upper()
        for sig in self._signatures:
            if sig.name.upper() == name:
                return sig
        return None
    
    def match_header(self, data: bytes, offset: int = 0) -> List[FileSignature]:
        """
        Find all signatures that match the given data.
        
        Args:
            data: Block of data to check (should be at least 16 bytes)
            offset: Offset in the source where this data came from
            
        Returns:
            List of matching FileSignature objects
        """
        matches = []
        
        # Quick lookup using first 2 bytes
        prefix = data[:2] if len(data) >= 2 else data
        candidates = self._header_map.get(prefix, [])
        
        for sig in candidates:
            if sig.header_offset != 0:
                continue  # Skip signatures with non-zero offset for now
            if data[:len(sig.header)] == sig.header:
                matches.append(sig)
        
        # Also check signatures with non-zero header offsets
        for sig in self._signatures:
            if sig.header_offset > 0 and sig.header_offset < len(data):
                check_pos = sig.header_offset
                if data[check_pos:check_pos + len(sig.header)] == sig.header:
                    matches.append(sig)
        
        return matches
    
    def get_max_header_length(self) -> int:
        """Get the maximum header length across all signatures."""
        max_len = 0
        for sig in self._signatures:
            total = sig.header_offset + len(sig.header)
            if total > max_len:
                max_len = total
        return max_len
    
    def filter_by_names(self, names: List[str]) -> "SignatureDB":
        """Create a new SignatureDB with only the specified signatures."""
        filtered = SignatureDB.__new__(SignatureDB)
        filtered._signatures = []
        filtered._header_map = {}
        
        names_upper = [n.upper() for n in names]
        for sig in self._signatures:
            if sig.name.upper() in names_upper:
                filtered._signatures.append(sig)
        
        filtered._build_header_map()
        return filtered
    
    def filter_by_extensions(self, extensions: List[str]) -> "SignatureDB":
        """Create a new SignatureDB with only the specified extensions."""
        filtered = SignatureDB.__new__(SignatureDB)
        filtered._signatures = []
        filtered._header_map = {}
        
        exts = [e.lower().lstrip(".") for e in extensions]
        for sig in self._signatures:
            if sig.extension in exts:
                filtered._signatures.append(sig)
        
        filtered._build_header_map()
        return filtered
    
    def __len__(self) -> int:
        return len(self._signatures)
    
    def __iter__(self):
        return iter(self._signatures)
