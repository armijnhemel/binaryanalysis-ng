meta:
  id: linux_x86
  title: Linux x86 kernel image
  tags:
    - linux
  license: CC0-1.0
  endian: le
doc-ref: https://www.kernel.org/doc/Documentation/x86/boot.txt
seq:
  - id: common_header
    type: common_header

  - id: jump
    type: jump
  - id: magic
    contents: "HdrS"
  - id: version
    type: version
  - id: realmode_switch
    type: u4
  - id: start_sys_seg
    type: u2
  - id: kernel_version
    type: u2
  - id: type_of_loader
    type: u1
  - id: loadflags
    type: u1
  - id: setup_move_size
    type: u2
  - id: code32_start
    type: u4
  - id: ramdisk_image
    type: u4
  - id: ramdisk_size
    type: u4
  - id: bootsect_kludge
    type: u4
  - id: heap_end_ptr
    type: u2
  - id: ext_loader_ver
    type: u1
  - id: ext_loader_type
    type: u1
  - id: cmd_line_ptr
    type: u4
  - id: initrd_addr_max
    type: u4
  - id: kernel_alignment
    type: u4
  - id: relocatable_kernel
    type: u1
  - id: min_alignment
    type: u1
  - id: xloadflags
    type: u2
  - id: cmdline_size
    type: u4
  - id: hardware_subarch
    type: u4
    enum: hardware_subarchs
  - id: hardware_subarch_data
    size: 8
  - id: ofs_payload
    type: u4
  - id: len_payload
    type: u4
  - id: setup_data
    type: u8
  - id: pref_address
    type: u8
  - id: init_size
    type: u4
  - id: handover_offset
    type: u4
instances:
  setup_code_size:
    value: 'common_header.setup_sects == 0 ? 4*512 : common_header.setup_sects * 512'
  real_mode_code_size:
    # also start of the protected mode code
    value: setup_code_size + 512
  protected_mode_code_size:
    value: common_header.syssize * 2
  payload:
    pos: real_mode_code_size + ofs_payload
    size: len_payload
    if: ofs_payload != 0
types:
  common_header:
    seq:
      - id: reserved
        size: 0x1f1
      - id: setup_sects
        type: u1
      - id: root_flags
        type: u2
      - id: syssize
        type: u4
      - id: ram_size
        type: u2
      - id: vid_mode
        type: u2
      - id: root_dev
        type: u2
      - id: boot_flag
        contents: [0x55, 0xaa]
  jump:
    seq:
      - id: jump_instruction
        type: u1
        valid: 0xeb
      - id: signed_offset
        type: s1
    instances:
      header_length:
        value: signed_offset + 514
  version:
    seq:
      - id: minor
        type: u1
        valid: 2
      - id: major
        type: u1
        valid:
          min: 2
enums:
  hardware_subarchs:
    0:
      id: default
      doc: The default x86/PC environmen
    1:
      id: lguest
      doc: lguest
    2:
      id: xen
      doc: Xen
    3:
      id: moorestown
      doc: Moorestown MID
    4:
      id: ce4100
      doc: CE4100 TV Platform
