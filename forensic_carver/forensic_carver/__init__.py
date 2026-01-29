"""
ForensicCarver - Professional Data Carving & Recovery Tool

A high-performance, forensically-sound data carving tool for Kali Linux.
"""

__version__ = "1.0.0"
__author__ = "ForensicCarver Team"

from .carver_engine import CarverEngine
from .signatures import SignatureDB, FileSignature
from .file_carver import FileCarver
from .block_reader import BlockReader
from .entropy import EntropyAnalyzer
from .hasher import HashValidator

__all__ = [
    "CarverEngine",
    "SignatureDB",
    "FileSignature",
    "FileCarver",
    "BlockReader",
    "EntropyAnalyzer",
    "HashValidator",
]
