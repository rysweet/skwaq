use serde::{Deserialize, Serialize};

/// Results from native binary parsing (goblin + checksec).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub format: BinaryFormat,
    pub architecture: String,
    pub bits: u32,
    pub endianness: String,
    pub is_stripped: bool,
    pub entry_point: u64,
    pub sections: Vec<SectionInfo>,
    pub symbols: Vec<SymbolInfo>,
    pub imports: Vec<ImportInfo>,
    pub strings: Vec<ExtractedString>,
    pub hardening: HardeningInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BinaryFormat {
    Elf,
    Pe,
    MachO,
    Unknown,
}

impl std::fmt::Display for BinaryFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Elf => write!(f, "ELF"),
            Self::Pe => write!(f, "PE"),
            Self::MachO => write!(f, "Mach-O"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub permissions: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub symbol_type: String,
    pub binding: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportInfo {
    pub name: String,
    pub library: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString {
    pub value: String,
    pub offset: u64,
    pub encoding: StringEncoding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StringEncoding {
    Ascii,
    Utf8,
    Utf16Le,
}

/// Binary hardening assessment (checksec results).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HardeningInfo {
    pub pie: HardeningStatus,
    pub nx: HardeningStatus,
    pub canary: HardeningStatus,
    pub relro: RelroStatus,
    pub fortify: HardeningStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub enum HardeningStatus {
    Enabled,
    Disabled,
    #[default]
    Unknown,
}

impl std::fmt::Display for HardeningStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Enabled => write!(f, "Yes"),
            Self::Disabled => write!(f, "No"),
            Self::Unknown => write!(f, "?"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum RelroStatus {
    Full,
    Partial,
    None,
    #[default]
    Unknown,
}

impl std::fmt::Display for RelroStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => write!(f, "Full"),
            Self::Partial => write!(f, "Partial"),
            Self::None => write!(f, "None"),
            Self::Unknown => write!(f, "?"),
        }
    }
}

/// Function extracted from Ghidra analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhidraFunction {
    pub name: String,
    pub address: String,
    pub size: u64,
    pub decompiled: Option<String>,
    pub calls: Vec<String>,
    pub called_by: Vec<String>,
    pub parameter_count: u32,
}

/// Full Ghidra analysis output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhidraAnalysis {
    pub functions: Vec<GhidraFunction>,
    pub strings: Vec<ExtractedString>,
    pub imports: Vec<ImportInfo>,
}
