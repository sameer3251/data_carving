"""
Test Suite for ForensicCarver
"""

import pytest
import tempfile
import os
from pathlib import Path

# Import modules to test
from forensic_carver.signatures import SignatureDB, FileSignature, FileCategory, FooterType
from forensic_carver.entropy import EntropyAnalyzer, BlockType
from forensic_carver.hasher import HashValidator, HashAlgorithm
from forensic_carver.file_carver import FileCarver, CarveStatus


class TestSignatureDB:
    """Tests for signature database."""
    
    def test_load_default_signatures(self):
        """Test that default signatures are loaded."""
        db = SignatureDB()
        assert len(db) > 20, "Should have many default signatures"
    
    def test_jpeg_signature(self):
        """Test JPEG signature detection."""
        db = SignatureDB()
        
        # JPEG header
        jpeg_data = bytes([0xFF, 0xD8, 0xFF, 0xE0]) + b'\x00' * 100
        matches = db.match_header(jpeg_data)
        
        assert len(matches) > 0
        assert any(m.name == 'JPEG' for m in matches)
    
    def test_png_signature(self):
        """Test PNG signature detection."""
        db = SignatureDB()
        
        # PNG header
        png_data = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) + b'\x00' * 100
        matches = db.match_header(png_data)
        
        assert len(matches) > 0
        assert any(m.name == 'PNG' for m in matches)
    
    def test_pdf_signature(self):
        """Test PDF signature detection."""
        db = SignatureDB()
        
        pdf_data = b'%PDF-1.4' + b'\x00' * 100
        matches = db.match_header(pdf_data)
        
        assert len(matches) > 0
        assert any(m.name == 'PDF' for m in matches)
    
    def test_elf_signature(self):
        """Test ELF signature detection."""
        db = SignatureDB()
        
        elf_data = bytes([0x7F, 0x45, 0x4C, 0x46]) + b'\x00' * 100
        matches = db.match_header(elf_data)
        
        assert len(matches) > 0
        assert any(m.name == 'ELF' for m in matches)
    
    def test_filter_by_extension(self):
        """Test filtering by extension."""
        db = SignatureDB()
        filtered = db.filter_by_extensions(['jpg', 'png'])
        
        assert len(filtered) >= 2
        for sig in filtered:
            assert sig.extension in ('jpg', 'png')
    
    def test_get_by_category(self):
        """Test getting signatures by category."""
        db = SignatureDB()
        images = db.get_by_category(FileCategory.IMAGE)
        
        assert len(images) > 0
        for sig in images:
            assert sig.category == FileCategory.IMAGE


class TestEntropyAnalyzer:
    """Tests for entropy analyzer."""
    
    def test_null_entropy(self):
        """Test entropy of null bytes."""
        analyzer = EntropyAnalyzer()
        data = bytes(1000)  # All zeros
        
        result = analyzer.analyze(data)
        assert result.entropy < 0.1
        assert result.block_type == BlockType.SPARSE
    
    def test_random_entropy(self):
        """Test entropy of random data."""
        import random
        analyzer = EntropyAnalyzer()
        
        random.seed(42)
        data = bytes([random.randint(0, 255) for _ in range(10000)])
        
        result = analyzer.analyze(data)
        assert result.entropy > 7.5
        assert result.block_type == BlockType.ENCRYPTED
    
    def test_text_entropy(self):
        """Test entropy of text data."""
        analyzer = EntropyAnalyzer()
        data = b"The quick brown fox jumps over the lazy dog. " * 50
        
        result = analyzer.analyze(data)
        assert 3.0 < result.entropy < 5.5
        assert result.block_type == BlockType.TEXT
    
    def test_is_sparse(self):
        """Test sparse detection."""
        analyzer = EntropyAnalyzer()
        
        sparse = bytes(900) + bytes([0x41] * 100)
        assert analyzer.is_sparse(sparse) is True
        
        not_sparse = bytes([i % 256 for i in range(1000)])
        assert analyzer.is_sparse(not_sparse) is False


class TestHashValidator:
    """Tests for hash validator."""
    
    def test_hash_bytes(self):
        """Test hashing bytes."""
        validator = HashValidator()
        data = b"Hello, World!"
        
        result = validator.hash_bytes(data)
        
        assert result.md5 is not None
        assert result.sha256 is not None
        assert result.size == len(data)
    
    def test_hash_consistency(self):
        """Test that hashing is consistent."""
        validator = HashValidator()
        data = b"Test data for hashing"
        
        result1 = validator.hash_bytes(data)
        result2 = validator.hash_bytes(data)
        
        assert result1.md5 == result2.md5
        assert result1.sha256 == result2.sha256
    
    def test_duplicate_detection(self):
        """Test duplicate file detection."""
        validator = HashValidator()
        data = b"Duplicate content"
        
        hash1 = validator.hash_bytes(data)
        is_dup1, _ = validator.check_duplicate(hash1, "file1.txt")
        assert is_dup1 is False
        
        hash2 = validator.hash_bytes(data)
        is_dup2, original = validator.check_duplicate(hash2, "file2.txt")
        assert is_dup2 is True
        assert original == "file1.txt"
    
    def test_quick_hash(self):
        """Test quick hash static method."""
        data = b"Quick hash test"
        
        md5 = HashValidator.quick_hash(data, 'md5')
        sha256 = HashValidator.quick_hash(data, 'sha256')
        
        assert len(md5) == 32
        assert len(sha256) == 64


class TestFileCarver:
    """Tests for file carver."""
    
    def test_find_jpeg_header(self):
        """Test finding JPEG headers."""
        carver = FileCarver()
        
        # Create test data with JPEG header
        data = b'\x00' * 100 + bytes([0xFF, 0xD8, 0xFF, 0xE0]) + b'\x00' * 100
        
        headers = carver.find_headers(data, 0)
        
        assert len(headers) > 0
        offsets = [h[0] for h in headers]
        assert 100 in offsets
    
    def test_carve_complete_jpeg(self):
        """Test carving complete JPEG."""
        carver = FileCarver()
        
        # Minimal JPEG structure
        jpeg_data = (
            bytes([0xFF, 0xD8, 0xFF, 0xE0]) +  # SOI + APP0
            b'\x00\x10JFIF\x00' +               # JFIF marker
            b'\x01\x01\x00\x00\x01\x00\x01\x00\x00' +
            b'\x00' * 200 +                     # Some padding
            bytes([0xFF, 0xD9])                 # EOI
        )
        
        db = carver.signature_db
        jpeg_sigs = [s for s in db if s.name == 'JPEG']
        assert len(jpeg_sigs) > 0
        
        carved = carver.carve_at_offset(jpeg_data, jpeg_sigs[0], 0, 0)
        
        assert carved is not None
        assert carved.status == CarveStatus.COMPLETE
        assert carved.data.startswith(bytes([0xFF, 0xD8, 0xFF]))
        assert carved.data.endswith(bytes([0xFF, 0xD9]))


class TestIntegration:
    """Integration tests."""
    
    def test_create_and_carve_image(self):
        """Test creating a test image and carving from it."""
        from forensic_carver.carver_engine import CarverEngine
        from forensic_carver.block_reader import BlockReader
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test image
            image_path = os.path.join(tmpdir, "test.img")
            output_dir = os.path.join(tmpdir, "output")
            
            # Write test image with embedded files
            with open(image_path, 'wb') as f:
                # Write some padding
                f.write(b'\x00' * 1024)
                
                # Write minimal JPEG
                jpeg_start = f.tell()
                f.write(bytes([0xFF, 0xD8, 0xFF, 0xE0]))
                f.write(b'\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00')
                f.write(b'\x00' * 500)
                f.write(bytes([0xFF, 0xD9]))
                
                # More padding
                f.write(b'\x00' * 1024)
                
                # Write PNG
                png_start = f.tell()
                f.write(bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))
                f.write(b'\x00' * 500)
                f.write(bytes([0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]))
                
                # Final padding
                f.write(b'\x00' * 1024)
            
            # Carve
            engine = CarverEngine(
                output_dir=output_dir,
                file_types=['jpg', 'png'],
                min_file_size=50
            )
            
            session = engine.carve(image_path)
            
            # Verify results
            assert len(session.files_recovered) >= 2
            
            types_found = set(f.file_type for f in session.files_recovered)
            assert 'JPEG' in types_found or 'PNG' in types_found


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
