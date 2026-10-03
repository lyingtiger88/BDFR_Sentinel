use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::warn;

pub struct RemovableMonitor {
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl RemovableMonitor {
    pub fn start<F>(interval: Duration, on_drive: F) -> Self
    where
        F: Fn(PathBuf) + Send + Sync + 'static,
    {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_worker = Arc::clone(&stop);
        let callback = Arc::new(on_drive);

        let worker = thread::Builder::new()
            .name("bdfr-sentinel-removable".to_string())
            .spawn(move || {
                let mut known = removable_drives();

                while !stop_worker.load(Ordering::Relaxed) {
                    let current = removable_drives();
                    for drive in current.difference(&known) {
                        callback(drive.clone());
                    }
                    known = current;

                    let mut slept = Duration::ZERO;
                    while slept < interval && !stop_worker.load(Ordering::Relaxed) {
                        let slice = Duration::from_millis(250).min(interval - slept);
                        thread::sleep(slice);
                        slept += slice;
                    }
                }
            })
            .map_err(|err| {
                warn!(error = %err, "failed to start removable drive monitor");
                err
            })
            .ok();

        Self { stop, worker }
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for RemovableMonitor {
    fn drop(&mut self) {
        self.stop();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(windows)]
fn removable_drives() -> HashSet<PathBuf> {
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
    const DRIVE_REMOVABLE_TYPE: u32 = 2;

    let mask = unsafe { GetLogicalDrives() };
    let mut drives = HashSet::new();

    for index in 0..26u32 {
        if mask & (1u32 << index) == 0 {
            continue;
        }

        let letter = (b'A' + index as u8) as char;
        let root = format!("{letter}:\\");
        let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
        let drive_type = unsafe { GetDriveTypeW(wide.as_ptr()) };

        if drive_type == DRIVE_REMOVABLE_TYPE {
            drives.insert(PathBuf::from(root));
        }
    }

    drives
}

#[cfg(not(windows))]
fn removable_drives() -> HashSet<PathBuf> {
    HashSet::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removable_drive_query_is_safe() {
        let _ = removable_drives();
    }
}
