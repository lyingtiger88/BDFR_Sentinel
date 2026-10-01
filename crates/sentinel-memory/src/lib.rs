use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRegionSignal {
    pub pid: u32,
    pub base_address: usize,
    pub region_size: usize,
    pub protection: u32,
}

#[derive(Debug, Error)]
pub enum MemoryInspectError {
    #[error("failed to open process {pid}")]
    OpenProcess { pid: u32 },

    #[error("memory inspection is unsupported on this platform")]
    Unsupported,
}

#[cfg(windows)]
mod windows_impl {
    use super::{MemoryInspectError, MemoryRegionSignal};
    use std::ffi::c_void;
    use std::mem::size_of;

    const PROCESS_VM_READ: u32 = 0x0010;
    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    const MEM_COMMIT: u32 = 0x1000;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

    #[repr(C)]
    struct MemoryBasicInformation {
        base_address: *mut c_void,
        allocation_base: *mut c_void,
        allocation_protect: u32,
        partition_id: u16,
        region_size: usize,
        state: u32,
        protect: u32,
        kind: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(
            desired_access: u32,
            inherit_handle: i32,
            process_id: u32,
        ) -> *mut c_void;
        fn VirtualQueryEx(
            process: *mut c_void,
            address: *const c_void,
            buffer: *mut MemoryBasicInformation,
            length: usize,
        ) -> usize;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    struct Handle(*mut c_void);

    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    pub fn executable_writable_regions(
        pid: u32,
    ) -> Result<Vec<MemoryRegionSignal>, MemoryInspectError> {
        let raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                0,
                pid,
            )
        };

        if raw.is_null() {
            return Err(MemoryInspectError::OpenProcess { pid });
        }

        let handle = Handle(raw);
        let mut address = 0usize;
        let mut out = Vec::new();

        loop {
            let mut info = MemoryBasicInformation {
                base_address: std::ptr::null_mut(),
                allocation_base: std::ptr::null_mut(),
                allocation_protect: 0,
                partition_id: 0,
                region_size: 0,
                state: 0,
                protect: 0,
                kind: 0,
            };

            let queried = unsafe {
                VirtualQueryEx(
                    handle.0,
                    address as *const c_void,
                    &mut info,
                    size_of::<MemoryBasicInformation>(),
                )
            };

            if queried == 0 {
                break;
            }

            if info.state == MEM_COMMIT
                && matches!(
                    info.protect,
                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
                )
            {
                out.push(MemoryRegionSignal {
                    pid,
                    base_address: info.base_address as usize,
                    region_size: info.region_size,
                    protection: info.protect,
                });
            }

            let next = (info.base_address as usize).saturating_add(info.region_size);
            if next <= address {
                break;
            }
            address = next;
        }

        Ok(out)
    }
}

#[cfg(windows)]
pub use windows_impl::executable_writable_regions;

#[cfg(not(windows))]
pub fn executable_writable_regions(
    _pid: u32,
) -> Result<Vec<MemoryRegionSignal>, MemoryInspectError> {
    Err(MemoryInspectError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_is_serializable() {
        let signal = MemoryRegionSignal {
            pid: 1,
            base_address: 0x1000,
            region_size: 4096,
            protection: 0x40,
        };
        assert_eq!(signal.region_size, 4096);
    }
}
