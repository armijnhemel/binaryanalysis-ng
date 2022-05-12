meta:
  id: art
  title: ART
  file-extension: art
  license: Apache-2.0
  ks-version: 0.9
  endian: le
  encoding: UTF-8
doc: |
  ART
doc-ref:
  - https://android.googlesource.com/platform/art/+/master/runtime/image.cc
  - https://android.googlesource.com/platform/art/+/master/runtime/image.h
seq:
  - id: magic
    contents: "art\n"
  - id: version
    type: strz
    size: 4
  - id: header
    type:
      switch-on: version
      cases:
        '"056"': header_056
        '"085"': header_085
types:
  header_056:
    doc-ref:
      - https://android.googlesource.com/platform/art/+/e47f60c482648172334aaca59e6c1ab7a3d42610/runtime/image.cc
      - https://android.googlesource.com/platform/art/+/e47f60c482648172334aaca59e6c1ab7a3d42610/runtime/image.h
    seq:
      - id: image_begin
        type: u4
        doc: Required base address for mapping the image.
      - id: image_size
        type: u4
        doc: Image size, not page aligned.
      - id: oat_checksum
        type: u4
        doc: Checksum of the oat file we link to for load time sanity check.
      - id: oat_file_begin
        type: u4
        doc: Start address for oat file. Will be before oat_data_begin_ for .so files.
      - id: oat_data_begin
        type: u4
        doc: Required oat address expected by image Method::GetCode() pointers.
      - id: oat_data_end
        type: u4
        doc: End of oat data address range for this image file.
      - id: oat_file_end
        type: u4
        doc: |
          End of oat file address range. will be after oat_data_end_ for
          .so files. Used for positioning a following alloc spaces.
      - id: boot_image_begin
        type: u4
        doc: Boot image begin (app image headers only).
      - id: boot_image_size
        type: u4
        doc: Boot image end (app image headers only).
      - id:  boot_oat_begin
        type: u4
        doc: Boot oat begin (app image headers only).
      - id:  boot_oat_size
        type: u4
        doc: Boot oat end (app image headers only).
      - id: patch_delta
        type: u4
        doc: The total delta that this image has been patched.
      - id: image_roots
        type: u4
        doc: Absolute address of an Object[] of objects needed to reinitialize from an image.
      - id: pointer_size
        type: u4
        doc: Pointer size, this affects the size of the ArtMethods.
      - id: compile_pic
        type: u4
        valid:
          any-of: [0, 1]
        doc: Boolean (0 or 1) to denote if the image was compiled with --compile-pic option
  header_085:
    doc-ref:
      - https://android.googlesource.com/platform/art/+/d0036ac18efcd7774775d521ae11178933041b95/runtime/image.h
      - https://android.googlesource.com/platform/art/+/d0036ac18efcd7774775d521ae11178933041b95/runtime/image.cc
    seq:
      - id: len_image_reservation
        -orig-id: image_reservation_size
        type: u4
      - id: num_components
        -orig-id: component_count
        type: u4
      - id: image_begin
        type: u4
      - id: len_image
        -orig-id: image_size
        type: u4
      - id: image_checksum
        type: u4
      - id: oat_checksum
        type: u4
        doc: Checksum of the oat file we link to for load time sanity check.
      - id: oat_file_begin
        type: u4
        doc: Required oat address expected by image Method::GetCode() pointers.
      - id: oat_data_begin
        type: u4
        doc: End of oat data address range for this image file.
      - id: oat_data_end
        type: u4
        doc: |
          End of oat file address range. will be after oat_data_end_ for
          .so files. Used for positioning a following alloc spaces.
      - id: oat_file_end
        type: u4
        doc: |
          Boot image begin and end (only applies to boot image
          extension and app image headers).
      - id: boot_image_begin
        type: u4
      - id: boot_image_size
        type: u4
        doc: |
          Includes heap (*.art) and code (.oat).
          Number of boot image components that this image depends on and their
          composite checksum (only applies to boot image extension and app
          image headers).
      - id: boot_image_component_count
        type: u4
      - id: boot_image_checksum
        type: u4
      - id: image_roots
        type: u4
        doc: |
          Absolute address of an Object[] of objects needed to reinitialize
          from an image.
      - id: pointer_size
        type: u4
        valid:
          any-of: [4, 8]
        doc: Pointer size, this affects the size of the ArtMethods.
      - id: image_sections
        type: image_sections
      - id: image_methods
        type: u8
        repeat: expr
        repeat-expr: 9
      - id: data_size
        type: u4
        doc: |
          Data size for the image data excluding the bitmap and the header.
          For compressed images, this is the compressed size in the file.
      - id: ofs_blocks
        type: u4
      - id: num_blocks
        type: u4
    types:
      image_sections:
        seq:
          - id: ofs_objects
            type: u4
          - id: len_objects
            type: u4
          - id: ofs_art_fields
            type: u4
          - id: len_art_fields
            type: u4
          - id: ofs_art_methods
            type: u4
          - id: len_art_methods
            type: u4
          - id: ofs_runtime_methods
            type: u4
          - id: len_runtime_methods
            type: u4
          - id: ofs_im_tables
            type: u4
          - id: len_im_tables
            type: u4
          - id: ofs_imt_conflict_tables
            type: u4
          - id: len_imt_conflict_tables
            type: u4
          - id: ofs_dex_cache_arrays
            type: u4
          - id: len_dex_cache_arrays
            type: u4
          - id: ofs_interned_strings
            type: u4
          - id: len_interned_strings
            type: u4
          - id: ofs_class_table
            type: u4
          - id: len_class_table
            type: u4
          - id: ofs_string_reference_offsets
            type: u4
          - id: len_string_reference_offsets
            type: u4
          - id: ofs_metadata
            type: u4
          - id: len_metadata
            type: u4
          - id: ofs_image_bitmap
            type: u4
          - id: len_image_bitmap
            type: u4
