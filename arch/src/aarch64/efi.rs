// Copyright 2026 The Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

//! Synthesized EFI handoff that gives a direct-booted aarch64 guest its RSDP without firmware.

use std::result;

use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryRegion};

use super::layout;
use crate::GuestMemoryMmap;

const PAGE_SIZE: u64 = 0x1000;

// "IBI SYST"
const EFI_SYSTEM_TABLE_SIGNATURE: u64 = 0x5453_5953_2049_4249;
const EFI_2_70_SYSTEM_TABLE_REVISION: u32 = (2 << 16) | 70;
const EFI_SYSTEM_TABLE_SIZE: u64 = 0x78;
const EFI_MEMORY_DESCRIPTOR_VERSION: u32 = 1;
const EFI_MEMORY_DESCRIPTOR_SIZE: u64 = 40;
const EFI_MEMORY_WB: u64 = 0x8;

const EFI_BOOT_SERVICES_DATA: u32 = 4;
const EFI_RUNTIME_SERVICES_DATA: u32 = 6;
const EFI_CONVENTIONAL_MEMORY: u32 = 7;
const EFI_ACPI_RECLAIM_MEMORY: u32 = 9;

const CONFIG_ENTRY_SIZE: u64 = 16 + 8;
const CONFIG_ENTRY_COUNT: u64 = 4;

// GUID bytes: first three fields little-endian
const ACPI_20_TABLE_GUID: [u8; 16] = [
    0x71, 0xe8, 0x68, 0x88, 0xf1, 0xe4, 0xd3, 0x11, 0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81,
];
const EFI_RT_PROPERTIES_TABLE_GUID: [u8; 16] = [
    0x8a, 0x91, 0x66, 0xeb, 0xef, 0x7e, 0x2a, 0x40, 0x84, 0x2e, 0x93, 0x1d, 0x21, 0xc3, 0x8a, 0xe9,
];
const SMBIOS3_TABLE_GUID: [u8; 16] = [
    0x44, 0x15, 0xfd, 0xf2, 0x94, 0x97, 0x2c, 0x4a, 0x99, 0x2e, 0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94,
];
const LINUX_EFI_MEMRESERVE_TABLE_GUID: [u8; 16] = [
    0xc6, 0xb0, 0x8e, 0x88, 0xde, 0x8e, 0xf5, 0x4f, 0xa8, 0xf0, 0x9a, 0xee, 0x5c, 0xb9, 0x77, 0xc2,
];

const EFI_RT_PROPERTIES_TABLE_VERSION: u16 = 1;
const EFI_RT_PROPERTIES_TABLE_SIZE: u64 = 8;

const MEMRESERVE_HEADER_SIZE: u64 = 16;
const MEMRESERVE_ENTRY_SIZE: u64 = 16;

/// Values the stub FDT publishes for the EFI stub.
#[derive(Clone, Copy, Debug)]
pub struct EfiHandoff {
    pub systab_addr: u64,
    pub mmap_addr: u64,
    pub mmap_size: u32,
    pub mmap_desc_size: u32,
    pub mmap_desc_ver: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Writing EFI handoff structures to guest memory")]
    WriteEfiTables(#[source] vm_memory::GuestMemoryError),
    #[error("EFI metadata at {0:#x} overflows into the ACPI region at {1:#x}")]
    MetadataOverflow(u64, u64),
    #[error("EFI memory map of {0} bytes overflows its {1}-byte page into the system table")]
    MemoryMapOverflow(usize, u64),
}

type Result<T> = result::Result<T, Error>;

/// Writes the EFI handoff whose configuration table points at `rsdp_addr`.
pub fn write_efi_tables(
    guest_mem: &GuestMemoryMmap,
    rsdp_addr: GuestAddress,
) -> Result<EfiHandoff> {
    let efi_base = layout::EFI_START.raw_value();
    let acpi_base = layout::ACPI_START.raw_value();

    // page 0 holds the memory map, sized last; the rest starts on page 1
    let mut cursor = efi_base + PAGE_SIZE;

    let systab_addr = cursor;
    cursor += EFI_SYSTEM_TABLE_SIZE;

    let config_table_addr = cursor;
    cursor += CONFIG_ENTRY_COUNT * CONFIG_ENTRY_SIZE;

    let fw_vendor: Vec<u8> = "Cloud Hypervisor\0"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let fw_vendor_addr = cursor;
    cursor += fw_vendor.len() as u64;
    cursor = align_up(cursor, 8);

    let rt_props_addr = cursor;
    cursor += EFI_RT_PROPERTIES_TABLE_SIZE;

    // struct linux_efi_memreserve { i32 size; i32 count; u64 next; entry[] }
    let memreserve_addr = align_up(cursor, PAGE_SIZE);
    let memreserve_capacity = (PAGE_SIZE - MEMRESERVE_HEADER_SIZE) / MEMRESERVE_ENTRY_SIZE;
    cursor = memreserve_addr + PAGE_SIZE;

    if cursor > acpi_base {
        return Err(Error::MetadataOverflow(cursor, acpi_base));
    }

    // declares no runtime services so the kernel never calls firmware
    let mut rt_props = [0u8; EFI_RT_PROPERTIES_TABLE_SIZE as usize];
    rt_props[0..2].copy_from_slice(&EFI_RT_PROPERTIES_TABLE_VERSION.to_le_bytes());
    rt_props[2..4].copy_from_slice(&(EFI_RT_PROPERTIES_TABLE_SIZE as u16).to_le_bytes());
    guest_mem
        .write_slice(&rt_props, GuestAddress(rt_props_addr))
        .map_err(Error::WriteEfiTables)?;

    let mut config_entries = [0u8; (CONFIG_ENTRY_COUNT * CONFIG_ENTRY_SIZE) as usize];
    config_entries[0..16].copy_from_slice(&ACPI_20_TABLE_GUID);
    config_entries[16..24].copy_from_slice(&rsdp_addr.raw_value().to_le_bytes());
    config_entries[24..40].copy_from_slice(&EFI_RT_PROPERTIES_TABLE_GUID);
    config_entries[40..48].copy_from_slice(&rt_props_addr.to_le_bytes());
    // aarch64 locates DMI only via this entry
    config_entries[48..64].copy_from_slice(&SMBIOS3_TABLE_GUID);
    config_entries[64..72].copy_from_slice(&layout::SMBIOS_START.raw_value().to_le_bytes());
    // the GIC ITS needs this table for efi_mem_reserve_persistent()
    config_entries[72..88].copy_from_slice(&LINUX_EFI_MEMRESERVE_TABLE_GUID);
    config_entries[88..96].copy_from_slice(&memreserve_addr.to_le_bytes());
    guest_mem
        .write_slice(&config_entries, GuestAddress(config_table_addr))
        .map_err(Error::WriteEfiTables)?;

    guest_mem
        .write_slice(&fw_vendor, GuestAddress(fw_vendor_addr))
        .map_err(Error::WriteEfiTables)?;

    let mut memreserve = [0u8; MEMRESERVE_HEADER_SIZE as usize];
    memreserve[0..4].copy_from_slice(&(memreserve_capacity as i32).to_le_bytes());
    guest_mem
        .write_slice(&memreserve, GuestAddress(memreserve_addr))
        .map_err(Error::WriteEfiTables)?;

    let mut systab = [0u8; EFI_SYSTEM_TABLE_SIZE as usize];
    systab[0x00..0x08].copy_from_slice(&EFI_SYSTEM_TABLE_SIGNATURE.to_le_bytes());
    systab[0x08..0x0c].copy_from_slice(&EFI_2_70_SYSTEM_TABLE_REVISION.to_le_bytes());
    systab[0x0c..0x10].copy_from_slice(&(EFI_SYSTEM_TABLE_SIZE as u32).to_le_bytes());
    systab[0x18..0x20].copy_from_slice(&fw_vendor_addr.to_le_bytes());
    systab[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
    systab[0x68..0x70].copy_from_slice(&CONFIG_ENTRY_COUNT.to_le_bytes());
    systab[0x70..0x78].copy_from_slice(&config_table_addr.to_le_bytes());
    let checksum = crc32(&systab);
    systab[0x10..0x14].copy_from_slice(&checksum.to_le_bytes());
    guest_mem
        .write_slice(&systab, GuestAddress(systab_addr))
        .map_err(Error::WriteEfiTables)?;

    // no /memory node in the stub DT, so memblock is built from this map alone
    let reserved_start = layout::FDT_START.raw_value();
    let smbios_base = layout::SMBIOS_START.raw_value();
    let reserved_end = smbios_base + layout::SMBIOS_MAX_SIZE;
    let mut mmap = Vec::new();
    mmap.extend_from_slice(&memory_descriptor(
        EFI_BOOT_SERVICES_DATA,
        reserved_start,
        (efi_base - reserved_start) / PAGE_SIZE,
    ));
    // runtime-services data: the kernel appends to memreserve after boot services end
    mmap.extend_from_slice(&memory_descriptor(
        EFI_RUNTIME_SERVICES_DATA,
        efi_base,
        layout::EFI_MAX_SIZE / PAGE_SIZE,
    ));
    mmap.extend_from_slice(&memory_descriptor(
        EFI_ACPI_RECLAIM_MEMORY,
        acpi_base,
        layout::ACPI_MAX_SIZE / PAGE_SIZE,
    ));
    // runtime-services data: DMI is read after boot services end
    mmap.extend_from_slice(&memory_descriptor(
        EFI_RUNTIME_SERVICES_DATA,
        smbios_base,
        layout::SMBIOS_MAX_SIZE / PAGE_SIZE,
    ));
    for region in guest_mem.iter() {
        let start = region.start_addr().raw_value();
        let end = start + region.len();
        for (from, to) in subtract_reserved(start, end, reserved_start, reserved_end) {
            mmap.extend_from_slice(&memory_descriptor(
                EFI_CONVENTIONAL_MEMORY,
                from,
                (to - from) / PAGE_SIZE,
            ));
        }
    }

    if mmap.len() as u64 > PAGE_SIZE {
        return Err(Error::MemoryMapOverflow(mmap.len(), PAGE_SIZE));
    }
    guest_mem
        .write_slice(&mmap, layout::EFI_START)
        .map_err(Error::WriteEfiTables)?;

    Ok(EfiHandoff {
        systab_addr,
        mmap_addr: efi_base,
        mmap_size: mmap.len() as u32,
        mmap_desc_size: EFI_MEMORY_DESCRIPTOR_SIZE as u32,
        mmap_desc_ver: EFI_MEMORY_DESCRIPTOR_VERSION,
    })
}

fn align_up(value: u64, alignment: u64) -> u64 {
    (value + alignment - 1) & !(alignment - 1)
}

// UEFI 4.2: crc32 over header_size bytes with the crc32 field zeroed
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn memory_descriptor(
    typ: u32,
    physical_start: u64,
    pages: u64,
) -> [u8; EFI_MEMORY_DESCRIPTOR_SIZE as usize] {
    let mut out = [0u8; EFI_MEMORY_DESCRIPTOR_SIZE as usize];
    out[0..4].copy_from_slice(&typ.to_le_bytes());
    out[8..16].copy_from_slice(&physical_start.to_le_bytes());
    out[24..32].copy_from_slice(&pages.to_le_bytes());
    out[32..40].copy_from_slice(&EFI_MEMORY_WB.to_le_bytes());
    out
}

// Overlapping descriptors make the kernel reject the whole map
fn subtract_reserved(
    start: u64,
    end: u64,
    reserved_start: u64,
    reserved_end: u64,
) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    if end <= reserved_start || start >= reserved_end {
        out.push((start, end));
        return out;
    }
    if start < reserved_start {
        out.push((start, reserved_start));
    }
    if end > reserved_end {
        out.push((reserved_end, end));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_mem() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(
            layout::RAM_START,
            (layout::KERNEL_START.raw_value() - layout::RAM_START.raw_value() + 0x10_0000) as usize,
        )])
        .unwrap()
    }

    fn read(mem: &GuestMemoryMmap, addr: u64, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        mem.read_slice(&mut out, GuestAddress(addr)).unwrap();
        out
    }

    fn le64(bytes: &[u8]) -> u64 {
        u64::from_le_bytes(bytes.try_into().unwrap())
    }

    fn le32(bytes: &[u8]) -> u32 {
        u32::from_le_bytes(bytes.try_into().unwrap())
    }

    #[test]
    fn crc32_matches_known_vector() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn reserved_span_is_punched_out_of_ram() {
        assert_eq!(
            subtract_reserved(0x4000_0000, 0x8000_0000, 0x4000_0000, 0x4040_0000),
            vec![(0x4040_0000, 0x8000_0000)]
        );
        assert_eq!(
            subtract_reserved(0x3000_0000, 0x8000_0000, 0x4000_0000, 0x4040_0000),
            vec![(0x3000_0000, 0x4000_0000), (0x4040_0000, 0x8000_0000)]
        );
        assert!(subtract_reserved(0x4010_0000, 0x4030_0000, 0x4000_0000, 0x4040_0000).is_empty());
        assert_eq!(
            subtract_reserved(0x1_0000_0000, 0x2_0000_0000, 0x4000_0000, 0x4040_0000),
            vec![(0x1_0000_0000, 0x2_0000_0000)]
        );
        assert_eq!(
            subtract_reserved(0x4030_0000, 0x5000_0000, 0x4000_0000, 0x4040_0000),
            vec![(0x4040_0000, 0x5000_0000)]
        );
    }

    #[test]
    fn system_table_header_is_well_formed() {
        let mem = test_mem();
        let handoff = write_efi_tables(&mem, layout::RSDP_POINTER).unwrap();
        let systab = read(&mem, handoff.systab_addr, EFI_SYSTEM_TABLE_SIZE as usize);

        assert_eq!(le64(&systab[0x00..0x08]), EFI_SYSTEM_TABLE_SIGNATURE);
        assert_eq!(le32(&systab[0x08..0x0c]), EFI_2_70_SYSTEM_TABLE_REVISION);
        assert_eq!(le32(&systab[0x0c..0x10]), EFI_SYSTEM_TABLE_SIZE as u32);
        assert_eq!(le64(&systab[0x68..0x70]), CONFIG_ENTRY_COUNT);

        let stored = le32(&systab[0x10..0x14]);
        let mut zeroed = systab.clone();
        zeroed[0x10..0x14].fill(0);
        assert_eq!(stored, crc32(&zeroed));

        let vendor_addr = le64(&systab[0x18..0x20]);
        let vendor = read(&mem, vendor_addr, 34);
        let utf16: Vec<u16> = vendor
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .take_while(|c| *c != 0)
            .collect();
        assert_eq!(String::from_utf16(&utf16).unwrap(), "Cloud Hypervisor");
    }

    #[test]
    fn configuration_table_points_at_every_structure() {
        let mem = test_mem();
        let handoff = write_efi_tables(&mem, layout::RSDP_POINTER).unwrap();
        let systab = read(&mem, handoff.systab_addr, EFI_SYSTEM_TABLE_SIZE as usize);
        let table_addr = le64(&systab[0x70..0x78]);
        let entries = read(
            &mem,
            table_addr,
            (CONFIG_ENTRY_COUNT * CONFIG_ENTRY_SIZE) as usize,
        );

        let found: Vec<([u8; 16], u64)> = entries
            .as_chunks::<{ CONFIG_ENTRY_SIZE as usize }>()
            .0
            .iter()
            .map(|e| (e[0..16].try_into().unwrap(), le64(&e[16..24])))
            .collect();

        let lookup = |guid: [u8; 16]| {
            found
                .iter()
                .find(|(g, _)| *g == guid)
                .unwrap_or_else(|| panic!("missing configuration table entry"))
                .1
        };

        assert_eq!(lookup(ACPI_20_TABLE_GUID), layout::RSDP_POINTER.raw_value());
        assert_eq!(lookup(SMBIOS3_TABLE_GUID), layout::SMBIOS_START.raw_value());

        let rt_props = read(
            &mem,
            lookup(EFI_RT_PROPERTIES_TABLE_GUID),
            EFI_RT_PROPERTIES_TABLE_SIZE as usize,
        );
        assert_eq!(
            u16::from_le_bytes([rt_props[0], rt_props[1]]),
            EFI_RT_PROPERTIES_TABLE_VERSION
        );
        assert_eq!(le32(&rt_props[4..8]), 0);

        let memreserve = read(
            &mem,
            lookup(LINUX_EFI_MEMRESERVE_TABLE_GUID),
            MEMRESERVE_HEADER_SIZE as usize,
        );
        assert!(le32(&memreserve[0..4]) > 0, "no capacity for entries");
        assert_eq!(le32(&memreserve[4..8]), 0, "count must start at zero");
        assert_eq!(le64(&memreserve[8..16]), 0, "next must be null");
    }

    #[test]
    fn memory_map_covers_ram_without_overlapping() {
        let mem = test_mem();
        let handoff = write_efi_tables(&mem, layout::RSDP_POINTER).unwrap();
        assert_eq!(handoff.mmap_desc_size, EFI_MEMORY_DESCRIPTOR_SIZE as u32);
        assert_eq!(handoff.mmap_desc_ver, EFI_MEMORY_DESCRIPTOR_VERSION);

        let raw = read(&mem, handoff.mmap_addr, handoff.mmap_size as usize);
        let mut ranges: Vec<(u64, u64, u32)> = raw
            .as_chunks::<{ EFI_MEMORY_DESCRIPTOR_SIZE as usize }>()
            .0
            .iter()
            .map(|d| {
                let start = le64(&d[8..16]);
                (start, start + le64(&d[24..32]) * PAGE_SIZE, le32(&d[0..4]))
            })
            .collect();
        assert!(!ranges.is_empty());
        ranges.sort_by_key(|r| r.0);

        for pair in ranges.windows(2) {
            assert_eq!(pair[0].1, pair[1].0, "gap or overlap in the memory map");
        }
        assert_eq!(ranges[0].0, layout::FDT_START.raw_value());
        assert_eq!(ranges.last().unwrap().1, mem.last_addr().raw_value() + 1);

        let firmware_end = layout::SMBIOS_START.raw_value() + layout::SMBIOS_MAX_SIZE;
        for (start, end, typ) in &ranges {
            if *start < firmware_end {
                assert_ne!(*typ, EFI_CONVENTIONAL_MEMORY, "{start:#x}..{end:#x}");
            } else {
                assert_eq!(*typ, EFI_CONVENTIONAL_MEMORY, "{start:#x}..{end:#x}");
            }
        }
        let efi_region = ranges
            .iter()
            .find(|(s, _, _)| *s == layout::EFI_START.raw_value())
            .expect("EFI region missing from the map");
        assert_eq!(efi_region.2, EFI_RUNTIME_SERVICES_DATA);
        let smbios_region = ranges
            .iter()
            .find(|(s, _, _)| *s == layout::SMBIOS_START.raw_value())
            .expect("SMBIOS region missing from the map");
        assert_eq!(smbios_region.2, EFI_RUNTIME_SERVICES_DATA);
    }
}
