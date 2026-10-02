use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::warn;

const WATCH_KEYS: &[&str] = &[
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryEventKind {
    Added,
    Modified,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryEvent {
    pub kind: RegistryEventKind,
    pub key: String,
    pub name: String,
    pub value: Option<String>,
}

pub struct RegistryTelemetry {
    stop: Arc<AtomicBool>,
    workers: Vec<thread::JoinHandle<()>>,
}

impl RegistryTelemetry {
    pub fn start<F>(_poll_interval: Duration, on_event: F) -> Self
    where
        F: Fn(RegistryEvent) + Send + Sync + 'static,
    {
        let stop = Arc::new(AtomicBool::new(false));
        let callback = Arc::new(on_event);
        let mut workers = Vec::new();

        #[cfg(windows)]
        {
            for key in WATCH_KEYS {
                let stop_worker = Arc::clone(&stop);
                let callback = Arc::clone(&callback);
                let key = (*key).to_string();

                match thread::Builder::new()
                    .name("bdfr-sentinel-registry-notify".to_string())
                    .spawn(move || watch_registry_key(&key, stop_worker, callback))
                {
                    Ok(worker) => workers.push(worker),
                    Err(err) => {
                        warn!(error = %err, key = %key, "failed to start registry notification worker")
                    }
                }
            }
        }

        #[cfg(not(windows))]
        {
            let stop_worker = Arc::clone(&stop);
            match thread::Builder::new()
                .name("bdfr-sentinel-registry-telemetry".to_string())
                .spawn(move || {
                    while !stop_worker.load(Ordering::Relaxed) {
                        thread::sleep(Duration::from_secs(1));
                    }
                    drop(callback);
                }) {
                Ok(worker) => workers.push(worker),
                Err(err) => warn!(error = %err, "failed to start registry telemetry worker"),
            }
        }

        Self { stop, workers }
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for RegistryTelemetry {
    fn drop(&mut self) {
        self.stop();
        while let Some(worker) = self.workers.pop() {
            let _ = worker.join();
        }
    }
}

#[cfg(windows)]
fn watch_registry_key<F>(key: &str, stop: Arc<AtomicBool>, callback: Arc<F>)
where
    F: Fn(RegistryEvent) + Send + Sync + 'static,
{
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegNotifyChangeKeyValue, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_NOTIFY,
        REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME,
    };
    use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

    let Some(subkey) = key.strip_prefix(r"HKLM\") else {
        return;
    };

    let wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let mut handle: HKEY = ptr::null_mut();

    let open_status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            wide.as_ptr(),
            0,
            KEY_NOTIFY,
            &mut handle,
        )
    };
    if open_status != ERROR_SUCCESS || handle.is_null() {
        warn!(key = %key, status = open_status, "failed to open registry key for notifications");
        return;
    }

    let event = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
    if event.is_null() {
        unsafe {
            RegCloseKey(handle);
        }
        warn!(key = %key, "failed to create registry notification event");
        return;
    }

    while !stop.load(Ordering::Relaxed) {
        let status = unsafe {
            RegNotifyChangeKeyValue(
                handle,
                0,
                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                event,
                1,
            )
        };

        if status != ERROR_SUCCESS {
            warn!(key = %key, status, "registry notification registration failed");
            break;
        }

        match unsafe { WaitForSingleObject(event, 1000) } {
            WAIT_OBJECT_0 => callback(RegistryEvent {
                kind: RegistryEventKind::Modified,
                key: key.to_string(),
                name: "*".to_string(),
                value: None,
            }),
            WAIT_TIMEOUT => {}
            _ => break,
        }
    }

    unsafe {
        CloseHandle(event);
        RegCloseKey(handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watched_keys_include_run_and_runonce() {
        assert!(WATCH_KEYS.iter().any(|key| key.ends_with(r"\Run")));
        assert!(WATCH_KEYS.iter().any(|key| key.ends_with(r"\RunOnce")));
    }
}
