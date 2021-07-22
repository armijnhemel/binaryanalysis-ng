meta:
  id: android_update
  title: Android Update images
  file-extension: .bin
  tags:
    - archive
    - android
  license: Apache-2.0
  imports:
    - /serialization/google_protobuf
  endian: be
doc: |
  Format of payload.bin OTA update files.

doc-ref:
  - https://android.googlesource.com/platform/system/update_engine/+/refs/heads/master/README.md#Update-Payload-File-Specification
  - https://android.googlesource.com/platform/system/update_engine/+/refs/heads/master/update_metadata.proto
seq:
  - id: magic
    contents: "CrAU"
  - id: major_version
    type: u8
  - id: len_manifest
    type: u8
  - id: len_manifest_signature
    type: u4
  - id: manifest
    type: google_protobuf
    size: len_manifest
  - id: manifest_signature
    type: google_protobuf
    size: len_manifest_signature
