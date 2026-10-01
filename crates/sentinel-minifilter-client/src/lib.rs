use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use thiserror::Error;

const PROTOCOL_VERSION: u32 = 1;
const MAX_PATH_CHARS: usize = 1024;

#[derive(Debug, Clone)]
pub struct MinifilterRequest {
    pub process_id: u32,
    pub desired_access: u32,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MinifilterDecision {
    Allow = 0,
    Block = 1,
}

#[derive(Debug, Error)]
pub enum MinifilterClientError {
    #[error("minifilter communication is unsupported on this platform")]
    Unsupported,

    #[error("failed to load Filter Manager user-mode library: {0}")]
    LoadLibrary(String),

    #[error("failed to resolve Filter Manager symbol: {0}")]
    Symbol(String),

    #[error("failed to connect to BDFR Sentinel minifilter port: HRESULT 0x{0:08x}")]
    Connect(u32),

    #[error("failed to start minifilter broker thread: {0}")]
    Thread(String),
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::thread::{self, JoinHandle};

    type FilterConnectCommunicationPortFn = unsafe extern "system" fn(
        *const u16,
        u32,
        *const c_void,
        u16,
        *const c_void,
        *mut *mut c_void,
    ) -> i32;

    type FilterGetMessageFn =
        unsafe extern "system" fn(*mut c_void, *mut FilterMessageHeader, u32, *mut c_void) -> i32;

    type FilterReplyMessageFn =
        unsafe extern "system" fn(*mut c_void, *const FilterReplyHeader, u32) -> i32;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FilterMessageHeader {
        reply_length: u32,
        message_id: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FilterReplyHeader {
        status: i32,
        message_id: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ScanRequestWire {
        version: u32,
        process_id: u32,
        desired_access: u32,
        path: [u16; MAX_PATH_CHARS],
    }

    #[repr(C)]
    struct MessageBuffer {
        header: FilterMessageHeader,
        request: ScanRequestWire,
    }

    #[repr(C)]
    struct ScanReplyWire {
        version: u32,
        verdict: u32,
    }

    #[repr(C)]
    struct ReplyBuffer {
        header: FilterReplyHeader,
        reply: ScanReplyWire,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CloseHandle(handle: *mut c_void) -> i32;
        fn QueryDosDeviceW(
            device_name: *const u16,
            target_path: *mut u16,
            max_chars: u32,
        ) -> u32;
    }

    pub struct MinifilterBroker {
        handle: Arc<AtomicUsize>,
        worker: Option<JoinHandle<()>>,
    }

    impl MinifilterBroker {
        pub fn start<F>(on_request: F) -> Result<Self, MinifilterClientError>
        where
            F: Fn(MinifilterRequest) -> MinifilterDecision + Send + Sync + 'static,
        {
            let library = unsafe { libloading::Library::new("FltLib.dll") }
                .map_err(|err| MinifilterClientError::LoadLibrary(err.to_string()))?;

            let connect: FilterConnectCommunicationPortFn = unsafe {
                *library
                    .get::<FilterConnectCommunicationPortFn>(b"FilterConnectCommunicationPort\0")
                    .map_err(|err| MinifilterClientError::Symbol(err.to_string()))?
            };

            let get_message: FilterGetMessageFn = unsafe {
                *library
                    .get::<FilterGetMessageFn>(b"FilterGetMessage\0")
                    .map_err(|err| MinifilterClientError::Symbol(err.to_string()))?
            };

            let reply_message: FilterReplyMessageFn = unsafe {
                *library
                    .get::<FilterReplyMessageFn>(b"FilterReplyMessage\0")
                    .map_err(|err| MinifilterClientError::Symbol(err.to_string()))?
            };

            let port_name = wide(r"\BDFRSentinelPort");
            let mut raw_handle: *mut c_void = std::ptr::null_mut();
            let hr = unsafe {
                connect(
                    port_name.as_ptr(),
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    &mut raw_handle,
                )
            };

            if hr < 0 || raw_handle.is_null() {
                return Err(MinifilterClientError::Connect(hr as u32));
            }

            let handle = Arc::new(AtomicUsize::new(raw_handle as usize));
            let worker_handle = Arc::clone(&handle);
            let callback = Arc::new(on_request);

            let worker = thread::Builder::new()
                .name("bdfr-sentinel-minifilter-broker".to_string())
                .spawn(move || {
                    let _library = library;

                    loop {
                        let current = worker_handle.load(Ordering::Acquire);
                        if current == 0 {
                            break;
                        }

                        let mut message = MessageBuffer {
                            header: FilterMessageHeader {
                                reply_length: 0,
                                message_id: 0,
                            },
                            request: ScanRequestWire {
                                version: 0,
                                process_id: 0,
                                desired_access: 0,
                                path: [0; MAX_PATH_CHARS],
                            },
                        };

                        let hr = unsafe {
                            get_message(
                                current as *mut c_void,
                                &mut message.header,
                                size_of::<MessageBuffer>() as u32,
                                std::ptr::null_mut(),
                            )
                        };

                        if hr < 0 {
                            if worker_handle.load(Ordering::Acquire) == 0 {
                                break;
                            }
                            continue;
                        }

                        let request = decode_request(&message.request);
                        let decision = if message.request.version == PROTOCOL_VERSION {
                            callback(request)
                        } else {
                            MinifilterDecision::Allow
                        };

                        let reply = ReplyBuffer {
                            header: FilterReplyHeader {
                                status: 0,
                                message_id: message.header.message_id,
                            },
                            reply: ScanReplyWire {
                                version: PROTOCOL_VERSION,
                                verdict: decision as u32,
                            },
                        };

                        let _ = unsafe {
                            reply_message(
                                current as *mut c_void,
                                &reply.header,
                                size_of::<ReplyBuffer>() as u32,
                            )
                        };
                    }
                })
                .map_err(|err| MinifilterClientError::Thread(err.to_string()))?;

            Ok(Self {
                handle,
                worker: Some(worker),
            })
        }

        pub fn stop(&mut self) {
            let current = self.handle.swap(0, Ordering::AcqRel);
            if current != 0 {
                unsafe {
                    CloseHandle(current as *mut c_void);
                }
            }

            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    impl Drop for MinifilterBroker {
        fn drop(&mut self) {
            self.stop();
        }
    }

    fn decode_request(wire: &ScanRequestWire) -> MinifilterRequest {
        let len = wire
            .path
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(wire.path.len());
        let native_path = String::from_utf16_lossy(&wire.path[..len]);
        let path = native_to_dos_path(&native_path)
            .unwrap_or_else(|| PathBuf::from(native_path));

        MinifilterRequest {
            process_id: wire.process_id,
            desired_access: wire.desired_access,
            path,
        }
    }

    fn native_to_dos_path(native: &str) -> Option<PathBuf> {
        if !native.starts_with(r"\Device\") {
            return Some(PathBuf::from(native));
        }

        for letter in b'A'..=b'Z' {
            let drive = format!("{}:", letter as char);
            let drive_wide = wide(&drive);
            let mut buffer = vec![0u16; 1024];

            let written = unsafe {
                QueryDosDeviceW(
                    drive_wide.as_ptr(),
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                )
            };

            if written == 0 {
                continue;
            }

            let end = buffer
                .iter()
                .position(|value| *value == 0)
                .unwrap_or(written as usize);
            let target = String::from_utf16_lossy(&buffer[..end]);

            if native
                .to_ascii_lowercase()
                .starts_with(&target.to_ascii_lowercase())
            {
                let suffix = &native[target.len()..];
                return Some(PathBuf::from(format!("{drive}{suffix}")));
            }
        }

        None
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub use MinifilterBroker as PlatformBroker;
}

#[cfg(windows)]
pub use windows_impl::PlatformBroker as MinifilterBroker;

#[cfg(not(windows))]
pub struct MinifilterBroker;

#[cfg(not(windows))]
impl MinifilterBroker {
    pub fn start<F>(_on_request: F) -> Result<Self, MinifilterClientError>
    where
        F: Fn(MinifilterRequest) -> MinifilterDecision + Send + Sync + 'static,
    {
        Err(MinifilterClientError::Unsupported)
    }

    pub fn stop(&mut self) {}
}
