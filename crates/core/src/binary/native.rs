//! Native binary parsing using goblin. No subprocess needed.

use crate::binary::types::*;
use goblin::Object;
use std::path::Path;

/// Parse a binary file using goblin and extract metadata.
pub fn parse_binary(path: &Path) -> anyhow::Result<BinaryInfo> {
    let data = std::fs::read(path)?;
    let object = Object::parse(&data)?;

    match object {
        Object::Elf(elf) => parse_elf(&elf, &data),
        Object::PE(pe) => parse_pe(&pe, &data),
        Object::Mach(mach) => parse_mach(&mach, &data),
        _ => anyhow::bail!("Unsupported binary format"),
    }
}

fn parse_elf(elf: &goblin::elf::Elf, data: &[u8]) -> anyhow::Result<BinaryInfo> {
    let architecture = match elf.header.e_machine {
        goblin::elf::header::EM_X86_64 => "x86_64",
        goblin::elf::header::EM_386 => "x86",
        goblin::elf::header::EM_ARM => "ARM",
        goblin::elf::header::EM_AARCH64 => "AArch64",
        goblin::elf::header::EM_MIPS => "MIPS",
        goblin::elf::header::EM_RISCV => "RISC-V",
        _ => "unknown",
    };

    let is_stripped = elf.syms.is_empty();

    let sections = elf.section_headers.iter().filter_map(|sh| {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
        if name.is_empty() { return None; }
        let perms = format!("{}{}{}",
            if sh.sh_flags as u32 & goblin::elf::section_header::SHF_ALLOC as u32 != 0 { "A" } else { "-" },
            if sh.sh_flags as u32 & goblin::elf::section_header::SHF_WRITE as u32 != 0 { "W" } else { "-" },
            if sh.sh_flags as u32 & goblin::elf::section_header::SHF_EXECINSTR as u32 != 0 { "X" } else { "-" },
        );
        Some(SectionInfo {
            name,
            address: sh.sh_addr,
            size: sh.sh_size,
            permissions: perms,
        })
    }).collect();

    let symbols: Vec<SymbolInfo> = elf.syms.iter().filter_map(|sym| {
        let name = elf.strtab.get_at(sym.st_name).unwrap_or("").to_string();
        if name.is_empty() { return None; }
        Some(SymbolInfo {
            name,
            address: sym.st_value,
            size: sym.st_size,
            symbol_type: format!("{:?}", goblin::elf::sym::st_type(sym.st_info)),
            binding: format!("{:?}", goblin::elf::sym::st_bind(sym.st_info)),
        })
    }).collect();

    let imports: Vec<ImportInfo> = elf.dynsyms.iter().filter_map(|sym| {
        if sym.is_import() {
            let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("").to_string();
            if name.is_empty() { return None; }
            Some(ImportInfo { name, library: String::new() })
        } else {
            None
        }
    }).collect();

    let strings = extract_strings(data, 4);

    // Basic hardening detection for ELF
    let hardening = detect_elf_hardening(elf);

    Ok(BinaryInfo {
        format: BinaryFormat::Elf,
        architecture: architecture.to_string(),
        bits: if elf.is_64 { 64 } else { 32 },
        endianness: if elf.little_endian { "little".into() } else { "big".into() },
        is_stripped,
        entry_point: elf.header.e_entry,
        sections,
        symbols,
        imports,
        strings,
        hardening,
    })
}

fn parse_pe(pe: &goblin::pe::PE, data: &[u8]) -> anyhow::Result<BinaryInfo> {
    let architecture = if pe.is_64 { "x86_64" } else { "x86" };

    let sections = pe.sections.iter().map(|s| {
        let name = String::from_utf8_lossy(&s.name).trim_end_matches('\0').to_string();
        SectionInfo {
            name,
            address: s.virtual_address as u64,
            size: s.virtual_size as u64,
            permissions: format!("{:#x}", s.characteristics),
        }
    }).collect();

    let imports: Vec<ImportInfo> = pe.imports.iter().map(|imp| {
        ImportInfo {
            name: imp.name.to_string(),
            library: imp.dll.to_string(),
        }
    }).collect();

    let strings = extract_strings(data, 4);

    Ok(BinaryInfo {
        format: BinaryFormat::Pe,
        architecture: architecture.to_string(),
        bits: if pe.is_64 { 64 } else { 32 },
        endianness: "little".into(),
        is_stripped: false,
        entry_point: pe.entry as u64,
        sections,
        symbols: Vec::new(),
        imports,
        strings,
        hardening: HardeningInfo::default(),
    })
}

fn parse_mach(_mach: &goblin::mach::Mach, data: &[u8]) -> anyhow::Result<BinaryInfo> {
    let strings = extract_strings(data, 4);
    Ok(BinaryInfo {
        format: BinaryFormat::MachO,
        architecture: "unknown".into(),
        bits: 64,
        endianness: "little".into(),
        is_stripped: false,
        entry_point: 0,
        sections: Vec::new(),
        symbols: Vec::new(),
        imports: Vec::new(),
        strings,
        hardening: HardeningInfo::default(),
    })
}

/// Extract printable ASCII strings of minimum length from binary data.
fn extract_strings(data: &[u8], min_length: usize) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    let mut current = Vec::new();
    let mut start_offset = 0;

    for (i, &byte) in data.iter().enumerate() {
        if byte >= 0x20 && byte < 0x7f {
            if current.is_empty() {
                start_offset = i;
            }
            current.push(byte);
        } else {
            if current.len() >= min_length {
                strings.push(ExtractedString {
                    value: String::from_utf8_lossy(&current).to_string(),
                    offset: start_offset as u64,
                    encoding: StringEncoding::Ascii,
                });
            }
            current.clear();
        }
    }

    // Don't forget trailing string
    if current.len() >= min_length {
        strings.push(ExtractedString {
            value: String::from_utf8_lossy(&current).to_string(),
            offset: start_offset as u64,
            encoding: StringEncoding::Ascii,
        });
    }

    strings
}

/// Basic ELF hardening detection.
fn detect_elf_hardening(elf: &goblin::elf::Elf) -> HardeningInfo {
    let pie = if elf.header.e_type == goblin::elf::header::ET_DYN {
        HardeningStatus::Enabled
    } else {
        HardeningStatus::Disabled
    };

    // Check for NX via program headers
    let nx = if elf.program_headers.iter().any(|ph| {
        ph.p_type == goblin::elf::program_header::PT_GNU_STACK
            && ph.p_flags & goblin::elf::program_header::PF_X == 0
    }) {
        HardeningStatus::Enabled
    } else {
        HardeningStatus::Disabled
    };

    // Check for stack canary via __stack_chk_fail import
    let canary = if elf.dynsyms.iter().any(|sym| {
        elf.dynstrtab.get_at(sym.st_name).unwrap_or("") == "__stack_chk_fail"
    }) {
        HardeningStatus::Enabled
    } else {
        HardeningStatus::Disabled
    };

    // Check RELRO
    let has_relro = elf.program_headers.iter().any(|ph| {
        ph.p_type == goblin::elf::program_header::PT_GNU_RELRO
    });
    let has_bind_now = elf.dynamic.as_ref().map_or(false, |dyn_info| {
        dyn_info.dyns.iter().any(|d| d.d_tag == goblin::elf::dynamic::DT_BIND_NOW)
    });
    let relro = match (has_relro, has_bind_now) {
        (true, true) => RelroStatus::Full,
        (true, false) => RelroStatus::Partial,
        _ => RelroStatus::None,
    };

    // Check for Fortify via _chk function imports
    let fortify = if elf.dynsyms.iter().any(|sym| {
        let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("");
        name.ends_with("_chk")
    }) {
        HardeningStatus::Enabled
    } else {
        HardeningStatus::Disabled
    };

    HardeningInfo { pie, nx, canary, relro, fortify }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_strings() {
        let data = b"hello\x00world\x00ab\x00longer_string\x00";
        let strings = extract_strings(data, 4);
        assert_eq!(strings.len(), 3);
        assert_eq!(strings[0].value, "hello");
        assert_eq!(strings[1].value, "world");
        assert_eq!(strings[2].value, "longer_string");
    }

    #[test]
    fn test_extract_strings_min_length() {
        let data = b"ab\x00abcd\x00";
        let strings = extract_strings(data, 4);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "abcd");
    }
}
