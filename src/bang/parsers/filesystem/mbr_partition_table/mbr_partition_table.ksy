meta:
  id: mbr_partition_table
  title: MBR (Master Boot Record) partition table
  xref:
    forensicswiki: Master_boot_record
    wikidata: Q624752
  tags:
    - dos
  ks-version: 0.9
  license: CC0-1.0
  endian: le
doc: |
  MBR (Master Boot Record) partition table is a traditional way of
  MS-DOS to partition larger hard disc drives into distinct
  partitions.

  This table is stored in the end of the boot sector (first sector) of
  the drive, after the bootstrap code. Original DOS 2.0 specification
  allowed only 4 partitions per disc, but DOS 3.2 introduced concept
  of "extended partitions", which work as nested extra "boot records"
  which are pointed to by original ("primary") partitions in MBR.
seq:
  - id: bootstrap_code
    size: 0x1be
  - id: partitions
    type: partition_entry
    repeat: expr
    repeat-expr: 4
  - id: boot_signature
    contents: [0x55, 0xaa]
types:
  partition_entry:
    seq:
      - id: status
        type: u1
      - id: chs_start
        type: chs
      - id: partition_type
        type: u1
        enum: partition_type
        valid:
          any-of:
            - partition_type::empty
            - partition_type::fat12
            - partition_type::xenix_root
            - partition_type::xenix_usr
            - partition_type::fat16_below_32m
            - partition_type::extended
            - partition_type::fat16
            - partition_type::hpfs_ntfs_exfat
            - partition_type::aix
            - partition_type::aix_bootable
            - partition_type::os2_boot_manager
            - partition_type::w95_fat32
            - partition_type::w95_fat32_lba
            - partition_type::w95_fat16_lba
            - partition_type::w95_extended_lba
            - partition_type::opus
            - partition_type::hidden_fat12
            - partition_type::compaq_diagnostics
            - partition_type::hidden_fat16_below_32m
            - partition_type::hidden_fat16
            - partition_type::hidden_hpfs_ntfs
            - partition_type::ast_smartsleep
            - partition_type::hidden_w95_fat32
            - partition_type::hidden_w95_fat32_lba
            - partition_type::hidden_w95_fat16_lba
            - partition_type::nec_dos
            - partition_type::hidden_ntfs_winre
            - partition_type::plan9
            - partition_type::partitionmagic_recovery
            - partition_type::venix_80286
            - partition_type::ppc_prep_boot
            - partition_type::sfs
            - partition_type::qnx4
            - partition_type::qnx4_second_part
            - partition_type::qnx4_third_part
            - partition_type::ontrack_dm
            - partition_type::ontrack_dm6_aux1
            - partition_type::cpm
            - partition_type::ontrack_dm6_aux3
            - partition_type::ontrack_dm6
            - partition_type::ez_drive
            - partition_type::golden_bow
            - partition_type::priam_edisk
            - partition_type::speedstor
            - partition_type::gnu_hurd_or_sysv
            - partition_type::novell_netware_286
            - partition_type::novell_netware_386
            - partition_type::disksecure_multi_boot
            - partition_type::pc_ix
            - partition_type::old_minix
            - partition_type::minix_old_linux
            - partition_type::linux_swap_solaris
            - partition_type::linux
            - partition_type::os2_hidden_or_intel_hibenation
            - partition_type::linux_extended
            - partition_type::ntfs_volume_set_1
            - partition_type::ntfs_volume_set_2
            - partition_type::linux_plaintext
            - partition_type::linux_lvm
            - partition_type::amoeba
            - partition_type::amoeba_bbt
            - partition_type::bsd_os
            - partition_type::ibm_thinkpad_hibernation
            - partition_type::freebsd
            - partition_type::openbsd
            - partition_type::nextstep
            - partition_type::darwin_ufs
            - partition_type::netbsd
            - partition_type::darwin_boot
            - partition_type::hfs_hfsplus
            - partition_type::bsdi_fs
            - partition_type::bsdi_swap
            - partition_type::boot_wizard_hidden
            - partition_type::acronis_fat32_lba
            - partition_type::solaris_boot
            - partition_type::solaris
            - partition_type::drdos_sec_fat12
            - partition_type::drdos_sec_fat16_below_32m
            - partition_type::drdos_sec_fat16
            - partition_type::syrinx
            - partition_type::non_fs_data
            - partition_type::cpm_ctos
            - partition_type::dell_utility
            - partition_type::bootit
            - partition_type::dos_access
            - partition_type::dos_ro
            - partition_type::speedstore_extended
            - partition_type::rufus_alignment
            - partition_type::beos_fs
            - partition_type::gpt
            - partition_type::efi
            - partition_type::linux_parisc_boot
            - partition_type::speedstor_1
            - partition_type::dos_secondary
            - partition_type::speedstore_large_partition
            - partition_type::vmware_vmfs
            - partition_type::vmware_vmkcore
            - partition_type::linux_raid_autodetect
            - partition_type::lanstep
            - partition_type::xenix_bbt
      - id: chs_end
        type: chs
      - id: lba_start
        type: u4
      - id: num_sectors
        type: u4
  chs:
    seq:
      - id: head
        type: u1
      - id: b2
        type: u1
      - id: b3
        type: u1
    instances:
      sector:
        value: 'b2 & 0b111111'
      cylinder:
        value: 'b3 + ((b2 & 0b11000000) << 2)'
enums:
  # table from
  # https://git.kernel.org/pub/scm/utils/util-linux/util-linux.git/plain/include/pt-mbr-partnames.h
  partition_type:
    0x00:
      id: empty
    0x01:
      id: fat12
    0x02:
      id: xenix_root
    0x03:
      id: xenix_usr
    0x04:
      id: fat16_below_32m
    0x05:
      id: extended
      doc: DOS 3.3+ extended partition
    0x06:
      id: fat16
      doc: DOS 16-bit >=32M
    0x07:
      id: hpfs_ntfs_exfat
      doc: OS/2 IFS, eg, HPFS or NTFS or QNX or exFAT
    0x08:
      id: aix
      doc: AIX boot (AIX -- PS/2 port) or SplitDrive
    0x09:
      id: aix_bootable
      doc: AIX data or Coherent
    0x0a:
      id: os2_boot_manager
      doc: OS/2 Boot Manager
    0x0b:
      id: w95_fat32
    0x0c:
      id: w95_fat32_lba
      doc: LBA really is `Extended Int 13h
    0x0e:
      id: w95_fat16_lba
    0x0f:
      id: w95_extended_lba
    0x10:
      id: opus
    0x11:
      id: hidden_fat12
    0x12:
      id: compaq_diagnostics
    0x14:
      id: hidden_fat16_below_32m
    0x16:
      id: hidden_fat16
    0x17:
      id: hidden_hpfs_ntfs
    0x18:
      id: ast_smartsleep
    0x1b:
      id: hidden_w95_fat32
    0x1c:
      id: hidden_w95_fat32_lba
    0x1e:
      id: hidden_w95_fat16_lba
    0x24:
      id: nec_dos
    0x27:
      id: hidden_ntfs_winre
    0x39:
      id: plan9
    0x3c:
      id: partitionmagic_recovery
    0x40:
      id: venix_80286
    0x41:
      id: ppc_prep_boot
    0x42:
      id: sfs
    0x4d:
      id: qnx4
    0x4e:
      id: qnx4_second_part
    0x4f:
      id: qnx4_third_part
    0x50:
      id: ontrack_dm
    0x51:
      id: ontrack_dm6_aux1
      doc: or Novell
    0x52:
      id: cpm
      doc: CP/M or Microport SysV/AT
    0x53:
      id: ontrack_dm6_aux3
    0x54:
      id: ontrack_dm6
    0x55:
      id: ez_drive
    0x56:
      id: golden_bow
    0x5c:
      id: priam_edisk
    0x61:
      id: speedstor
    0x63:
      id: gnu_hurd_or_sysv
      doc: GNU HURD or Mach or Sys V/386 (such as ISC UNIX)
    0x64:
      id: novell_netware_286
    0x65:
      id: novell_netware_386
    0x70:
      id: disksecure_multi_boot
    0x75:
      id: pc_ix
      doc: PC/IX
    0x80:
      id: old_minix
      doc: Minix 1.4a and earlier
    0x81:
      id: minix_old_linux
      doc: Minix 1.4b and later
    0x82:
      id: linux_swap_solaris
      doc: Linux swap / Solaris
    0x83:
      id: linux
    0x84:
      id: os2_hidden_or_intel_hibenation
      doc: OS/2 hidden C drive, hibernation type Microsoft APM or hibernation Intel Rapid Start
    0x85:
      id: linux_extended
    0x86:
      id: ntfs_volume_set_1
    0x87:
      id: ntfs_volume_set_2
    0x88:
      id: linux_plaintext
    0x8e:
      id: linux_lvm
    0x93:
      id: amoeba
    0x94:
      id: amoeba_bbt
      doc: bad block table
    0x9f:
      id: bsd_os
      doc: BSDI
    0xa0:
      id: ibm_thinkpad_hibernation
    0xa5:
      id: freebsd
      doc: various BSD flavours
    0xa6:
      id: openbsd
    0xa7:
      id: nextstep
    0xa8:
      id: darwin_ufs
    0xa9:
      id: netbsd
    0xab:
      id: darwin_boot
    0xaf:
      id: hfs_hfsplus
    0xb7:
      id: bsdi_fs
    0xb8:
      id: bsdi_swap
    0xbb:
      id: boot_wizard_hidden
    0xbc:
      id: acronis_fat32_lba
      doc: hidden (+0xb0) Acronis Secure Zone (backup software)
    0xbe:
      id: solaris_boot
    0xbf:
      id: solaris
    0xc1:
      id: drdos_sec_fat12
    0xc4:
      id: drdos_sec_fat16_below_32m
    0xc6:
      id: drdos_sec_fat16
    0xc7:
      id: syrinx
    0xda:
      id: non_fs_data
    0xdb:
      id: cpm_ctos
      doc: CP/M or Concurrent CP/M or Concurrent DOS or CTOS
    0xde:
      id: dell_utility
      doc: Dell PowerEdge Server utilities
    0xdf:
      id: bootit
      doc: BootIt EMBRM
    0xe1:
      id: dos_access
      doc: DOS access or SpeedStor 12-bit FAT extended partition
    0xe3:
      id: dos_ro
      doc: DOS R/O or SpeedStor
    0xe4:
      id: speedstore_extended
      doc: SpeedStor 16-bit FAT extended partition < 1024 cyl.
    0xea:
      id: rufus_alignment
      doc: Rufus extra partition for alignment
    0xeb:
      id: beos_fs
    0xee:
      id: gpt
      doc: Intel EFI GUID Partition Table
    0xef:
      id: efi
      doc: Intel EFI System Partition
    0xf0:
      id: linux_parisc_boot
      doc: Linux/PA-RISC boot loader
    0xf1:
      id: speedstor_1
      doc: named speedstor_1 as there already is an entry speedstor
    0xf2:
      id: dos_secondary
      doc: DOS 3.3+ secondary
    0xf4:
      id: speedstore_large_partition
      doc: SpeedStor large partition
    0xfb:
      id: vmware_vmfs
      doc: VMware VMFS
    0xfc:
      id: vmware_vmkcore
      doc: VMware kernel dump partition
    0xfd:
      id: linux_raid_autodetect
      doc: Linux raid partition with autodetect using persistent superblock
    0xfe:
      id: lanstep
      doc: SpeedStor >1024 cyl. or LANstep
    0xff:
      id: xenix_bbt
      doc: Xenix Bad Block Table
