use anyhow::{bail, Context, Result};
use jni::objects::{JByteArray, JObject, JString};
use jni::sys::jstring;
use jni::JNIEnv;
use sentinel_core::{EngineRegistry, FileScanner, ScannerConfig};
use sentinel_definitions::{ClamHashDatabase, HashDefinitionEngine};
use sentinel_yara::{YaraEngine, YaraXBackend};
use std::path::{Path, PathBuf};

const MOBILE_MAX_FILE_SIZE: u64 = 32 * 1024 * 1024;

fn build_scanner(app_data_dir: &Path) -> Result<FileScanner> {
    let root = app_data_dir.join("verified-definitions");
    if !root.is_dir() {
        bail!("verified definitions directory is not installed");
    }

    let mut registry = EngineRegistry::new();
    let mut hashes = HashDefinitionEngine::new();

    let hdb = root.join("main.hdb");
    if hdb.is_file() {
        let text = std::fs::read_to_string(&hdb)
            .with_context(|| format!("cannot read {}", hdb.display()))?;
        hashes = hashes.with_hdb(ClamHashDatabase::parse_hdb(&text)?);
    }

    let hsb = root.join("main.hsb");
    if hsb.is_file() {
        let text = std::fs::read_to_string(&hsb)
            .with_context(|| format!("cannot read {}", hsb.display()))?;
        hashes = hashes.with_hsb(ClamHashDatabase::parse_hsb(&text)?);
    }

    if hashes.has_definitions() {
        registry.register(hashes);
    }

    let rules_dir = root.join("yara");
    if let Some(yara) = YaraXBackend::compile_directory(&rules_dir)
        .context("YARA-X rules could not be loaded")?
    {
        registry.register(YaraEngine::new(yara));
    }

    if registry.is_empty() {
        bail!("no usable signed definitions are installed; refusing to return a clean verdict");
    }

    Ok(FileScanner::new(
        ScannerConfig {
            max_file_size: MOBILE_MAX_FILE_SIZE,
            ..ScannerConfig::default()
        },
        registry,
    ))
}

fn scan_json(bytes: &[u8], label: &str, app_data_dir: &Path) -> Result<String> {
    if bytes.len() as u64 > MOBILE_MAX_FILE_SIZE {
        bail!("file exceeds the Android scan limit of {} MiB", MOBILE_MAX_FILE_SIZE / (1024 * 1024));
    }
    let root = app_data_dir.canonicalize().context("app data directory is unavailable")?;
    if !root.is_dir() {
        bail!("app data path is not a directory");
    }

    let scanner = build_scanner(&root)?;
    let report = scanner.scan_bytes(label, bytes)?;
    Ok(serde_json::to_string(&report)?)
}

/// JNI entry point. The Android host streams a user-selected SAF document into
/// a bounded byte array; Rust never resolves a content:// URI as a filesystem path.
#[no_mangle]
pub extern "system" fn Java_com_bdfr_sentinel_NativeScanner_scanBytes(
    mut env: JNIEnv,
    _this: JObject,
    data: JByteArray,
    label: JString,
    app_data_dir: JString,
) -> jstring {
    let response = (|| -> Result<String> {
        let bytes = env.convert_byte_array(data).context("cannot read scan buffer")?;
        let label: String = env.get_string(&label)?.to_string_lossy().into_owned();
        let app_data_dir: String = env.get_string(&app_data_dir)?.to_string_lossy().into_owned();
        scan_json(&bytes, &label, &PathBuf::from(app_data_dir))
    })()
    .unwrap_or_else(|error| {
        serde_json::json!({
            "status": "unavailable",
            "error": error.to_string()
        }).to_string()
    });

    env.new_string(response)
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}
