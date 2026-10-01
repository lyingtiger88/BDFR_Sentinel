use std::ffi::c_void;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmsiVerdict {
    Clean,
    Suspicious,
    Malicious,
}

#[derive(Debug, Error)]
pub enum AmsiError {
    #[error("AMSI is unavailable on this platform")]
    Unsupported,

    #[error("failed to load amsi.dll: {0}")]
    LoadLibrary(String),

    #[error("failed to resolve AMSI symbol: {0}")]
    Symbol(String),

    #[error("AmsiInitialize failed with HRESULT 0x{0:08x}")]
    Initialize(u32),

    #[error("AmsiScanBuffer failed with HRESULT 0x{0:08x}")]
    Scan(u32),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(windows)]
type AmsiInitializeFn = unsafe extern "system" fn(*const u16, *mut usize) -> i32;
#[cfg(windows)]
type AmsiUninitializeFn = unsafe extern "system" fn(usize);
#[cfg(windows)]
type AmsiScanBufferFn =
    unsafe extern "system" fn(usize, *const c_void, u32, *const u16, usize, *mut u32) -> i32;

#[cfg(windows)]
pub struct AmsiScanner {
    _library: libloading::Library,
    context: usize,
    uninitialize: AmsiUninitializeFn,
    scan_buffer: AmsiScanBufferFn,
}

#[cfg(windows)]
impl AmsiScanner {
    pub fn new() -> Result<Self, AmsiError> {
        let library = unsafe { libloading::Library::new("amsi.dll") }
            .map_err(|err| AmsiError::LoadLibrary(err.to_string()))?;

        let initialize: AmsiInitializeFn = unsafe {
            *library
                .get::<AmsiInitializeFn>(b"AmsiInitialize\0")
                .map_err(|err| AmsiError::Symbol(err.to_string()))?
        };
        let uninitialize: AmsiUninitializeFn = unsafe {
            *library
                .get::<AmsiUninitializeFn>(b"AmsiUninitialize\0")
                .map_err(|err| AmsiError::Symbol(err.to_string()))?
        };
        let scan_buffer: AmsiScanBufferFn = unsafe {
            *library
                .get::<AmsiScanBufferFn>(b"AmsiScanBuffer\0")
                .map_err(|err| AmsiError::Symbol(err.to_string()))?
        };

        let app_name = wide("BDFR Sentinel");
        let mut context = 0usize;
        let hr = unsafe { initialize(app_name.as_ptr(), &mut context) };

        if hr < 0 {
            return Err(AmsiError::Initialize(hr as u32));
        }

        Ok(Self {
            _library: library,
            context,
            uninitialize,
            scan_buffer,
        })
    }

    pub fn scan_bytes(&self, data: &[u8], content_name: &str) -> Result<AmsiVerdict, AmsiError> {
        if data.is_empty() {
            return Ok(AmsiVerdict::Clean);
        }

        let len: u32 = data.len().try_into().unwrap_or(u32::MAX);
        let content_name = wide(content_name);
        let mut result = 0u32;

        let hr = unsafe {
            (self.scan_buffer)(
                self.context,
                data.as_ptr().cast::<c_void>(),
                len,
                content_name.as_ptr(),
                0,
                &mut result,
            )
        };

        if hr < 0 {
            return Err(AmsiError::Scan(hr as u32));
        }

        Ok(classify_result(result))
    }

    pub fn scan_file<P: AsRef<Path>>(&self, path: P) -> Result<AmsiVerdict, AmsiError> {
        let path = path.as_ref();
        let data = std::fs::read(path)?;
        self.scan_bytes(&data, &path.display().to_string())
    }
}

#[cfg(windows)]
impl Drop for AmsiScanner {
    fn drop(&mut self) {
        if self.context != 0 {
            unsafe { (self.uninitialize)(self.context) };
        }
    }
}

#[cfg(not(windows))]
pub struct AmsiScanner;

#[cfg(not(windows))]
impl AmsiScanner {
    pub fn new() -> Result<Self, AmsiError> {
        Err(AmsiError::Unsupported)
    }

    pub fn scan_bytes(&self, _data: &[u8], _content_name: &str) -> Result<AmsiVerdict, AmsiError> {
        Err(AmsiError::Unsupported)
    }

    pub fn scan_file<P: AsRef<Path>>(&self, _path: P) -> Result<AmsiVerdict, AmsiError> {
        Err(AmsiError::Unsupported)
    }
}

fn classify_result(result: u32) -> AmsiVerdict {
    if result >= 0x8000 {
        AmsiVerdict::Malicious
    } else if (0x4000..=0x4fff).contains(&result) {
        AmsiVerdict::Suspicious
    } else {
        AmsiVerdict::Clean
    }
}

#[cfg(windows)]
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_amsi_result_ranges() {
        assert_eq!(classify_result(0), AmsiVerdict::Clean);
        assert_eq!(classify_result(1), AmsiVerdict::Clean);
        assert_eq!(classify_result(0x4000), AmsiVerdict::Suspicious);
        assert_eq!(classify_result(0x8000), AmsiVerdict::Malicious);
    }
}
