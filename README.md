# data_carving
 # Install (on Kali)
cd forensic_carver
pip install -e .
# Basic scan
sudo forensic-carver -i /dev/sdb -o ./recovered/
# Scan disk image
forensic-carver -i forensic.dd -o ./output/
# Specific types only
forensic-carver -i image.img -o ./output/ -t jpg,png,pdf
# Full options
forensic-carver -i /dev/nvme0n1 -o ./output/ \
  --block-size 4096 \
  --threads 8 \
  --min-size 1KB \
  --report json,html \
  --hash sha256 \
  -v
# Quick scan (estimate files)
forensic-carver -i disk.dd -o ./output/ --quick-scan
# List supported types
forensic-carver --list-types
