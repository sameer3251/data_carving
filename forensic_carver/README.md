# ForensicCarver

A professional forensic data carving and recovery tool for Kali Linux.

## Features

- **Raw disk access** in read-only forensic mode
- **Disk image support** (.dd, .img, .E01)
- **File signature carving** (JPEG, PNG, PDF, ZIP, DOCX, MP4, ELF, EXE, and more)
- **Fragmented file recovery** with heuristic block chaining
- **Entropy analysis** to detect compressed/encrypted data
- **Multithreaded scanning** for high performance
- **Hash validation** (MD5/SHA256) for forensic integrity
- **Detailed reports** (JSON, CSV, HTML)

## Installation

```bash
cd forensic_carver
pip install -e .
```

### Optional: E01 Support
```bash
sudo apt install libewf-dev
pip install pyewf
```

## Usage

```bash
# Scan raw disk (requires root)
sudo forensic-carver -i /dev/sdb -o ./recovered/

# Scan disk image
forensic-carver -i forensic.dd -o ./output/

# Specific file types only
forensic-carver -i image.img -o ./output/ -t jpeg,png,pdf

# Advanced options
forensic-carver -i /dev/nvme0n1p2 -o ./output/ \
  --block-size 4096 \
  --threads 8 \
  --min-size 1024 \
  --max-size 104857600 \
  --report json,html \
  --hash sha256 \
  --verbose
```

## CLI Options

| Option | Description |
|--------|-------------|
| `-i, --input` | Input device or image file |
| `-o, --output` | Output directory for recovered files |
| `-t, --types` | File types to recover (comma-separated) |
| `--block-size` | Block size in bytes (default: 512) |
| `--threads` | Number of threads (default: CPU count) |
| `--min-size` | Minimum file size to recover |
| `--max-size` | Maximum file size to recover |
| `--report` | Report formats: json, csv, html |
| `--hash` | Hash algorithm: md5, sha256, both |
| `-v, --verbose` | Verbose output |

## Supported File Types

- **Images**: JPEG, PNG, GIF, BMP, TIFF
- **Documents**: PDF, DOCX, XLSX, PPTX
- **Archives**: ZIP, RAR, 7Z, TAR.GZ
- **Multimedia**: MP4, AVI, MKV, MP3, WAV
- **Executables**: ELF, EXE/PE, Mach-O

## License

MIT License - For educational and forensic research purposes.
