use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EtwProcessEvent {
    pub process_id: u32,
    pub parent_process_id: u32,
    pub image_name: String,
}

#[derive(Debug, Error)]
pub enum EtwError {
    #[error("ETW is unsupported on this platform")]
    Unsupported,

    #[error("failed to start ETW process trace: {0}")]
    Start(String),
}

#[cfg(windows)]
mod windows_impl {
    use super::{EtwError, EtwProcessEvent};
    use ferrisetw::parser::Parser;
    use ferrisetw::provider::Provider;
    use ferrisetw::trace::{TraceTrait, UserTrace};
    use std::sync::Arc;

    const KERNEL_PROCESS_PROVIDER: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";

    pub struct EtwProcessTelemetry {
        trace: Option<UserTrace>,
    }

    impl EtwProcessTelemetry {
        pub fn start<F>(on_process_start: F) -> Result<Self, EtwError>
        where
            F: Fn(EtwProcessEvent) + Send + Sync + 'static,
        {
            let callback = Arc::new(on_process_start);

            let provider = Provider::by_guid(KERNEL_PROCESS_PROVIDER)
                .add_callback(move |record, schema_locator| {
                    if record.event_id() != 1 {
                        return;
                    }

                    let Ok(schema) = schema_locator.event_schema(record) else {
                        return;
                    };

                    let parser = Parser::create(record, &schema);
                    let Ok(process_id) = parser.try_parse::<u32>("ProcessID") else {
                        return;
                    };

                    let parent_process_id = parser
                        .try_parse::<u32>("ParentProcessID")
                        .unwrap_or_default();
                    let image_name = parser
                        .try_parse::<String>("ImageName")
                        .unwrap_or_default();

                    callback(EtwProcessEvent {
                        process_id,
                        parent_process_id,
                        image_name,
                    });
                })
                .build();

            let trace = UserTrace::new()
                .named(format!("BDFRSentinel-{}", std::process::id()))
                .enable(provider)
                .start_and_process()
                .map_err(|err| EtwError::Start(format!("{err:?}")))?;

            Ok(Self { trace: Some(trace) })
        }

        pub fn stop(&mut self) {
            if let Some(mut trace) = self.trace.take() {
                let _ = trace.stop();
            }
        }
    }

    impl Drop for EtwProcessTelemetry {
        fn drop(&mut self) {
            self.stop();
        }
    }

    pub use EtwProcessTelemetry as PlatformEtwProcessTelemetry;
}

#[cfg(windows)]
pub use windows_impl::PlatformEtwProcessTelemetry as EtwProcessTelemetry;

#[cfg(not(windows))]
pub struct EtwProcessTelemetry;

#[cfg(not(windows))]
impl EtwProcessTelemetry {
    pub fn start<F>(_on_process_start: F) -> Result<Self, EtwError>
    where
        F: Fn(EtwProcessEvent) + Send + Sync + 'static,
    {
        Err(EtwError::Unsupported)
    }

    pub fn stop(&mut self) {}
}
