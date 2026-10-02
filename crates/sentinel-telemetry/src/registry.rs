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
    worker: Option<thread::JoinHandle<()>>,
}

impl RegistryTelemetry {
    pub fn start<F>(_poll_interval: Duration, on_event: F) -> Self
    where
        F: Fn(RegistryEvent) + Send + Sync + 'static,
    {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_worker = Arc::clone(&stop);
        let callback = Arc::new(on_event);

        #[cfg(windows)]
        let worker = thread::Builder::new()
            .name("bdfr-sentinel-registry-notify".to_string())
            .spawn(move || watch_registry_keys(stop_worker, callback))
            .map_err(|err| {
                warn!(error = %err, "failed to start registry notification worker");
                err
            })
            .ok();

        #[cfg(not(windows))]
        let worker = thread::Builder::new()
            .name("bdfr-sentinel-registry-telemetry".to_string())
            .spawn(move || {
                while !stop_worker.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_secs(1));
                }
                drop(callback);
            })
            .map_err(|err| {
                warn!(error = %err, "failed to start registry telemetry worker");
                err
            })
            .ok();

        Self { stop, worker }
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for RegistryTelemetry {
    fn drop(&mut self) {
        self.stop();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(windows)]
fn watch_registry_keys<F>(stop: Arc<AtomicBool>, callback: Arc<F>)
where
    F: Fn(RegistryEvent) + Send + Sync + 'static,
{
    use std::ptr;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_SUCCESS, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegNotifyChangeKeyValue, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_NOTIFY,
        REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME,
    };
    use windows_sys::Win32::System::Threading::{CreateEventW, WaitForMultipleObjects};

    struct Watch {
        key: String,
        registry_key: HKEY,
        event: HANDLE,
    }

    let mut watches = Vec::new();

    for key in WATCH_KEYS {
        let Some(subkey) = key.strip_prefix(r"HKLM\") else {
            continue;
        };

        let wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
        let mut registry_key: HKEY = ptr::null_mut();
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                wide.as_ptr(),
                0,
                KEY_NOTIFY,
                &mut registry_key,
            )
        };

        if status != ERROR_SUCCESS || registry_key.is_null() {
            warn!(key = %key, status, "failed to open registry key for notifications");
            continue;
        }

        let event = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
        if event.is_null() {
            unsafe {
                RegCloseKey(registry_key);
            }
            warn!(key = %key, "failed to create registry notification event");
            continue;
        }

        let watch = Watch {
            key: (*key).to_string(),
            registry_key,
            event,
        };

        if !arm_registry_watch(&watch) {
            unsafe {
                CloseHandle(event);
                RegCloseKey(registry_key);
            }
            continue;
        }

        watches.push(watch);
    }

    if watches.is_empty() {
        return;
    }

    let handles: Vec<HANDLE> = watches.iter().map(|watch| watch.event).collect();

    while !stop.load(Ordering::Relaxed) {
        let result =
            unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, 1000) };

        if result == WAIT_TIMEOUT {
            continue;
        }

        let upper = WAIT_OBJECT_0 + handles.len() as u32;
        if result < WAIT_OBJECT_0 || result >= upper {
            break;
        }

        let index = (result - WAIT_OBJECT_0) as usize;
        let watch = &watches[index];

        callback(RegistryEvent {
            kind: RegistryEventKind::Modified,
            key: watch.key.clone(),
            name: "*".to_string(),
            value: None,
        });

        if !arm_registry_watch(watch) {
            break;
        }
    }

    for watch in watches {
        unsafe {
            CloseHandle(watch.event);
            RegCloseKey(watch.registry_key);
        }
    }

    fn arm_registry_watch(watch: &Watch) -> bool {
        let status = unsafe {
            RegNotifyChangeKeyValue(
                watch.registry_key,
                0,
                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                watch.event,
                1,
            )
        };

        if status != ERROR_SUCCESS {
            warn!(
                key = %watch.key,
                status,
                "registry notification registration failed"
            );
            false
        } else {
            true
        }
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
