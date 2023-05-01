meta:
  id: linux_aarch64
  title: Linux ARM64 kernel image
  tags:
    - linux
  license: CC0-1.0
  endian: le
doc-ref: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/arm64/booting.rst?h=v5.11
seq:
  - id: code0
    type: u4
  - id: code1
    type: u4
  - id: ofs_text
    -orig-id: text_offset
    type: u8
  - id: effective_image_size
    -orig-id: image_size
    type: u8
  - id: flags
    size: 8
    type: flags
  - id: reserved_2
    -orig-id: res2
    type: u8
  - id: reserved_3
    -orig-id: res3
    type: u8
  - id: reserved_4
    -orig-id: res4
    type: u8
  - id: magic
    contents: ["ARM", 0x64]
  - id: reserved_5
    -orig-id: res5
    type: u4
types:
  flags:
    meta:
      bit-endian: le
    seq:
      - id: endianness
        type: b1
      - id: page_size
        type: b2
      - id: physical_placement
        type: b1
