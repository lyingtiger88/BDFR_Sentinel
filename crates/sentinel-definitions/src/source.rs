use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DefinitionFormat {
    Yara,
    ClamAvHash,
    ClamAvBytecode,
    Custom,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DefinitionLicense {
    OpenSource(String),
    RedistributionAllowed(String),
    LocalUseOnly(String),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionSource {
    pub id: String,
    pub name: String,
    pub format: DefinitionFormat,
    pub license: DefinitionLicense,
    pub enabled: bool,
}
