meta:
  id: vfat_directory
  endian: le
  imports:
    - vfat_directory_rec
seq:
  - id: records
    type: vfat_directory_rec
    size: 32
    repeat: eos

