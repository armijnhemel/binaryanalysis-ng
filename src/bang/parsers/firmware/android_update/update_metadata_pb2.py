# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: update_metadata.proto
# Protobuf Python Version: 5.28.3
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC,
    5,
    28,
    3,
    '',
    'update_metadata.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x15update_metadata.proto\x12\x16\x63hromeos_update_engine\"1\n\x06\x45xtent\x12\x13\n\x0bstart_block\x18\x01 \x01(\x04\x12\x12\n\nnum_blocks\x18\x02 \x01(\x04\"\x9f\x01\n\nSignatures\x12@\n\nsignatures\x18\x01 \x03(\x0b\x32,.chromeos_update_engine.Signatures.Signature\x1aO\n\tSignature\x12\x13\n\x07version\x18\x01 \x01(\rB\x02\x18\x01\x12\x0c\n\x04\x64\x61ta\x18\x02 \x01(\x0c\x12\x1f\n\x17unpadded_signature_size\x18\x03 \x01(\x07\"+\n\rPartitionInfo\x12\x0c\n\x04size\x18\x01 \x01(\x04\x12\x0c\n\x04hash\x18\x02 \x01(\x0c\"\x8f\x01\n\tImageInfo\x12\x11\n\x05\x62oard\x18\x01 \x01(\tB\x02\x18\x01\x12\x0f\n\x03key\x18\x02 \x01(\tB\x02\x18\x01\x12\x13\n\x07\x63hannel\x18\x03 \x01(\tB\x02\x18\x01\x12\x13\n\x07version\x18\x04 \x01(\tB\x02\x18\x01\x12\x19\n\rbuild_channel\x18\x05 \x01(\tB\x02\x18\x01\x12\x19\n\rbuild_version\x18\x06 \x01(\tB\x02\x18\x01\"\xee\x03\n\x10InstallOperation\x12;\n\x04type\x18\x01 \x02(\x0e\x32-.chromeos_update_engine.InstallOperation.Type\x12\x13\n\x0b\x64\x61ta_offset\x18\x02 \x01(\x04\x12\x13\n\x0b\x64\x61ta_length\x18\x03 \x01(\x04\x12\x33\n\x0bsrc_extents\x18\x04 \x03(\x0b\x32\x1e.chromeos_update_engine.Extent\x12\x12\n\nsrc_length\x18\x05 \x01(\x04\x12\x33\n\x0b\x64st_extents\x18\x06 \x03(\x0b\x32\x1e.chromeos_update_engine.Extent\x12\x12\n\ndst_length\x18\x07 \x01(\x04\x12\x18\n\x10\x64\x61ta_sha256_hash\x18\x08 \x01(\x0c\x12\x17\n\x0fsrc_sha256_hash\x18\t \x01(\x0c\"\xad\x01\n\x04Type\x12\x0b\n\x07REPLACE\x10\x00\x12\x0e\n\nREPLACE_BZ\x10\x01\x12\x0c\n\x04MOVE\x10\x02\x1a\x02\x08\x01\x12\x0e\n\x06\x42SDIFF\x10\x03\x1a\x02\x08\x01\x12\x0f\n\x0bSOURCE_COPY\x10\x04\x12\x11\n\rSOURCE_BSDIFF\x10\x05\x12\x0e\n\nREPLACE_XZ\x10\x08\x12\x08\n\x04ZERO\x10\x06\x12\x0b\n\x07\x44ISCARD\x10\x07\x12\x11\n\rBROTLI_BSDIFF\x10\n\x12\x0c\n\x08PUFFDIFF\x10\t\"\x81\x02\n\x11\x43owMergeOperation\x12<\n\x04type\x18\x01 \x01(\x0e\x32..chromeos_update_engine.CowMergeOperation.Type\x12\x32\n\nsrc_extent\x18\x02 \x01(\x0b\x32\x1e.chromeos_update_engine.Extent\x12\x32\n\ndst_extent\x18\x03 \x01(\x0b\x32\x1e.chromeos_update_engine.Extent\x12\x12\n\nsrc_offset\x18\x04 \x01(\r\"2\n\x04Type\x12\x0c\n\x08\x43OW_COPY\x10\x00\x12\x0b\n\x07\x43OW_XOR\x10\x01\x12\x0f\n\x0b\x43OW_REPLACE\x10\x02\"\xc8\x06\n\x0fPartitionUpdate\x12\x16\n\x0epartition_name\x18\x01 \x02(\t\x12\x17\n\x0frun_postinstall\x18\x02 \x01(\x08\x12\x18\n\x10postinstall_path\x18\x03 \x01(\t\x12\x17\n\x0f\x66ilesystem_type\x18\x04 \x01(\t\x12M\n\x17new_partition_signature\x18\x05 \x03(\x0b\x32,.chromeos_update_engine.Signatures.Signature\x12\x41\n\x12old_partition_info\x18\x06 \x01(\x0b\x32%.chromeos_update_engine.PartitionInfo\x12\x41\n\x12new_partition_info\x18\x07 \x01(\x0b\x32%.chromeos_update_engine.PartitionInfo\x12<\n\noperations\x18\x08 \x03(\x0b\x32(.chromeos_update_engine.InstallOperation\x12\x1c\n\x14postinstall_optional\x18\t \x01(\x08\x12=\n\x15hash_tree_data_extent\x18\n \x01(\x0b\x32\x1e.chromeos_update_engine.Extent\x12\x38\n\x10hash_tree_extent\x18\x0b \x01(\x0b\x32\x1e.chromeos_update_engine.Extent\x12\x1b\n\x13hash_tree_algorithm\x18\x0c \x01(\t\x12\x16\n\x0ehash_tree_salt\x18\r \x01(\x0c\x12\x37\n\x0f\x66\x65\x63_data_extent\x18\x0e \x01(\x0b\x32\x1e.chromeos_update_engine.Extent\x12\x32\n\nfec_extent\x18\x0f \x01(\x0b\x32\x1e.chromeos_update_engine.Extent\x12\x14\n\tfec_roots\x18\x10 \x01(\r:\x01\x32\x12\x0f\n\x07version\x18\x11 \x01(\t\x12\x43\n\x10merge_operations\x18\x12 \x03(\x0b\x32).chromeos_update_engine.CowMergeOperation\x12\x19\n\x11\x65stimate_cow_size\x18\x13 \x01(\x04\"L\n\x15\x44ynamicPartitionGroup\x12\x0c\n\x04name\x18\x01 \x02(\t\x12\x0c\n\x04size\x18\x02 \x01(\x04\x12\x17\n\x0fpartition_names\x18\x03 \x03(\t\"\xbe\x01\n\x18\x44ynamicPartitionMetadata\x12=\n\x06groups\x18\x01 \x03(\x0b\x32-.chromeos_update_engine.DynamicPartitionGroup\x12\x18\n\x10snapshot_enabled\x18\x02 \x01(\x08\x12\x14\n\x0cvabc_enabled\x18\x03 \x01(\x08\x12\x1e\n\x16vabc_compression_param\x18\x04 \x01(\t\x12\x13\n\x0b\x63ow_version\x18\x05 \x01(\r\"c\n\x08\x41pexInfo\x12\x14\n\x0cpackage_name\x18\x01 \x01(\t\x12\x0f\n\x07version\x18\x02 \x01(\x03\x12\x15\n\ris_compressed\x18\x03 \x01(\x08\x12\x19\n\x11\x64\x65\x63ompressed_size\x18\x04 \x01(\x03\"C\n\x0c\x41pexMetadata\x12\x33\n\tapex_info\x18\x01 \x03(\x0b\x32 .chromeos_update_engine.ApexInfo\"\x9e\x07\n\x14\x44\x65ltaArchiveManifest\x12H\n\x12install_operations\x18\x01 \x03(\x0b\x32(.chromeos_update_engine.InstallOperationB\x02\x18\x01\x12O\n\x19kernel_install_operations\x18\x02 \x03(\x0b\x32(.chromeos_update_engine.InstallOperationB\x02\x18\x01\x12\x18\n\nblock_size\x18\x03 \x01(\r:\x04\x34\x30\x39\x36\x12\x19\n\x11signatures_offset\x18\x04 \x01(\x04\x12\x17\n\x0fsignatures_size\x18\x05 \x01(\x04\x12\x42\n\x0fold_kernel_info\x18\x06 \x01(\x0b\x32%.chromeos_update_engine.PartitionInfoB\x02\x18\x01\x12\x42\n\x0fnew_kernel_info\x18\x07 \x01(\x0b\x32%.chromeos_update_engine.PartitionInfoB\x02\x18\x01\x12\x42\n\x0fold_rootfs_info\x18\x08 \x01(\x0b\x32%.chromeos_update_engine.PartitionInfoB\x02\x18\x01\x12\x42\n\x0fnew_rootfs_info\x18\t \x01(\x0b\x32%.chromeos_update_engine.PartitionInfoB\x02\x18\x01\x12=\n\x0eold_image_info\x18\n \x01(\x0b\x32!.chromeos_update_engine.ImageInfoB\x02\x18\x01\x12=\n\x0enew_image_info\x18\x0b \x01(\x0b\x32!.chromeos_update_engine.ImageInfoB\x02\x18\x01\x12\x18\n\rminor_version\x18\x0c \x01(\r:\x01\x30\x12;\n\npartitions\x18\r \x03(\x0b\x32\'.chromeos_update_engine.PartitionUpdate\x12\x15\n\rmax_timestamp\x18\x0e \x01(\x03\x12T\n\x1a\x64ynamic_partition_metadata\x18\x0f \x01(\x0b\x32\x30.chromeos_update_engine.DynamicPartitionMetadata\x12\x16\n\x0epartial_update\x18\x10 \x01(\x08\x12\x33\n\tapex_info\x18\x11 \x03(\x0b\x32 .chromeos_update_engine.ApexInfoB\x02H\x03')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'update_metadata_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  _globals['DESCRIPTOR']._loaded_options = None
  _globals['DESCRIPTOR']._serialized_options = b'H\003'
  _globals['_SIGNATURES_SIGNATURE'].fields_by_name['version']._loaded_options = None
  _globals['_SIGNATURES_SIGNATURE'].fields_by_name['version']._serialized_options = b'\030\001'
  _globals['_IMAGEINFO'].fields_by_name['board']._loaded_options = None
  _globals['_IMAGEINFO'].fields_by_name['board']._serialized_options = b'\030\001'
  _globals['_IMAGEINFO'].fields_by_name['key']._loaded_options = None
  _globals['_IMAGEINFO'].fields_by_name['key']._serialized_options = b'\030\001'
  _globals['_IMAGEINFO'].fields_by_name['channel']._loaded_options = None
  _globals['_IMAGEINFO'].fields_by_name['channel']._serialized_options = b'\030\001'
  _globals['_IMAGEINFO'].fields_by_name['version']._loaded_options = None
  _globals['_IMAGEINFO'].fields_by_name['version']._serialized_options = b'\030\001'
  _globals['_IMAGEINFO'].fields_by_name['build_channel']._loaded_options = None
  _globals['_IMAGEINFO'].fields_by_name['build_channel']._serialized_options = b'\030\001'
  _globals['_IMAGEINFO'].fields_by_name['build_version']._loaded_options = None
  _globals['_IMAGEINFO'].fields_by_name['build_version']._serialized_options = b'\030\001'
  _globals['_INSTALLOPERATION_TYPE'].values_by_name["MOVE"]._loaded_options = None
  _globals['_INSTALLOPERATION_TYPE'].values_by_name["MOVE"]._serialized_options = b'\010\001'
  _globals['_INSTALLOPERATION_TYPE'].values_by_name["BSDIFF"]._loaded_options = None
  _globals['_INSTALLOPERATION_TYPE'].values_by_name["BSDIFF"]._serialized_options = b'\010\001'
  _globals['_DELTAARCHIVEMANIFEST'].fields_by_name['install_operations']._loaded_options = None
  _globals['_DELTAARCHIVEMANIFEST'].fields_by_name['install_operations']._serialized_options = b'\030\001'
  _globals['_DELTAARCHIVEMANIFEST'].fields_by_name['kernel_install_operations']._loaded_options = None
  _globals['_DELTAARCHIVEMANIFEST'].fields_by_name['kernel_install_operations']._serialized_options = b'\030\001'
  _globals['_DELTAARCHIVEMANIFEST'].fields_by_name['old_kernel_info']._loaded_options = None
  _globals['_DELTAARCHIVEMANIFEST'].fields_by_name['old_kernel_info']._serialized_options = b'\030\001'
  _globals['_DELTAARCHIVEMANIFEST'].fields_by_name['new_kernel_info']._loaded_options = None
  _globals['_DELTAARCHIVEMANIFEST'].fields_by_name['new_kernel_info']._serialized_options = b'\030\001'
  _globals['_DELTAARCHIVEMANIFEST'].fields_by_name['old_rootfs_info']._loaded_options = None
  _globals['_DELTAARCHIVEMANIFEST'].fields_by_name['old_rootfs_info']._serialized_options = b'\030\001'
  _globals['_DELTAARCHIVEMANIFEST'].fields_by_name['new_rootfs_info']._loaded_options = None
  _globals['_DELTAARCHIVEMANIFEST'].fields_by_name['new_rootfs_info']._serialized_options = b'\030\001'
  _globals['_DELTAARCHIVEMANIFEST'].fields_by_name['old_image_info']._loaded_options = None
  _globals['_DELTAARCHIVEMANIFEST'].fields_by_name['old_image_info']._serialized_options = b'\030\001'
  _globals['_DELTAARCHIVEMANIFEST'].fields_by_name['new_image_info']._loaded_options = None
  _globals['_DELTAARCHIVEMANIFEST'].fields_by_name['new_image_info']._serialized_options = b'\030\001'
  _globals['_EXTENT']._serialized_start=49
  _globals['_EXTENT']._serialized_end=98
  _globals['_SIGNATURES']._serialized_start=101
  _globals['_SIGNATURES']._serialized_end=260
  _globals['_SIGNATURES_SIGNATURE']._serialized_start=181
  _globals['_SIGNATURES_SIGNATURE']._serialized_end=260
  _globals['_PARTITIONINFO']._serialized_start=262
  _globals['_PARTITIONINFO']._serialized_end=305
  _globals['_IMAGEINFO']._serialized_start=308
  _globals['_IMAGEINFO']._serialized_end=451
  _globals['_INSTALLOPERATION']._serialized_start=454
  _globals['_INSTALLOPERATION']._serialized_end=948
  _globals['_INSTALLOPERATION_TYPE']._serialized_start=775
  _globals['_INSTALLOPERATION_TYPE']._serialized_end=948
  _globals['_COWMERGEOPERATION']._serialized_start=951
  _globals['_COWMERGEOPERATION']._serialized_end=1208
  _globals['_COWMERGEOPERATION_TYPE']._serialized_start=1158
  _globals['_COWMERGEOPERATION_TYPE']._serialized_end=1208
  _globals['_PARTITIONUPDATE']._serialized_start=1211
  _globals['_PARTITIONUPDATE']._serialized_end=2051
  _globals['_DYNAMICPARTITIONGROUP']._serialized_start=2053
  _globals['_DYNAMICPARTITIONGROUP']._serialized_end=2129
  _globals['_DYNAMICPARTITIONMETADATA']._serialized_start=2132
  _globals['_DYNAMICPARTITIONMETADATA']._serialized_end=2322
  _globals['_APEXINFO']._serialized_start=2324
  _globals['_APEXINFO']._serialized_end=2423
  _globals['_APEXMETADATA']._serialized_start=2425
  _globals['_APEXMETADATA']._serialized_end=2492
  _globals['_DELTAARCHIVEMANIFEST']._serialized_start=2495
  _globals['_DELTAARCHIVEMANIFEST']._serialized_end=3421
# @@protoc_insertion_point(module_scope)
