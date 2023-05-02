meta:
  id: android_update
  title: Android Update images
  file-extension: .bin
  tags:
    - archive
    - android
  license: Apache-2.0
  endian: be
doc: |
  Format of payload.bin OTA update files. The payload is in Google Protobuf
  format. The structure of the payload data depend on the contents of the
  manifest. Parsing currently has to be done outside of Kaitai Struct.

doc-ref:
  - https://android.googlesource.com/platform/system/update_engine/+/refs/heads/master/README.md#Update-Payload-File-Specification
  - https://android.googlesource.com/platform/system/update_engine/+/refs/heads/master/update_metadata.proto
seq:
  - id: magic
    contents: "CrAU"
  - id: major_version
    type: u8
    valid:
      #any-of: [1, 2]
      any-of: [2]
  - id: len_manifest
    type: u8
  - id: len_manifest_signature
    type: u4
    if: major_version == 2
  - id: manifest
    size: len_manifest
  - id: manifest_signature
    size: len_manifest_signature
