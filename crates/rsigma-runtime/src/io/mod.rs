mod file;
#[cfg(feature = "nats")]
mod nats_sink;
#[cfg(feature = "nats")]
mod nats_source;
mod stdin;
mod stdout;

pub use file::FileSink;
#[cfg(feature = "nats")]
pub use nats_sink::NatsSink;
#[cfg(feature = "nats")]
pub use nats_source::NatsSource;
pub use stdin::StdinSource;
pub use stdout::StdoutSink;

use std::sync::Arc;

use rsigma_eval::ProcessResult;

use crate::error::RuntimeError;
use crate::metrics::MetricsHook;

/// Contract for event input adapters.
///
/// Each source reads events from a specific input (stdin, HTTP, NATS) and
/// yields raw strings (typically JSON lines). Sources are used as concrete
/// types (not `dyn`), so `async fn` is valid without object-safety concerns.
pub trait EventSource: Send + 'static {
    /// Receive the next event as a raw string.
    /// Returns `None` when the source is exhausted or shutting down.
    fn recv(&mut self) -> impl std::future::Future<Output = Option<String>> + Send;
}

/// Enum dispatch for output adapters.
///
/// Uses enum dispatch instead of `dyn Trait` because:
/// - Async trait methods are not object-safe
/// - `FanOut(Vec<Sink>)` requires a sized, concrete type
pub enum Sink {
    /// Write NDJSON to stdout.
    Stdout(StdoutSink),
    /// Append NDJSON to a file.
    File(FileSink),
    /// Publish NDJSON to a NATS subject.
    #[cfg(feature = "nats")]
    Nats(NatsSink),
    /// Fan out to multiple sinks.
    FanOut(Vec<Sink>),
}

impl Sink {
    /// Serialize and deliver a ProcessResult to this sink.
    ///
    /// Synchronous sinks (Stdout, File) use `block_in_place` to avoid blocking
    /// the Tokio runtime. Uses `Box::pin` for the FanOut case to handle
    /// recursive async.
    pub fn send<'a>(
        &'a mut self,
        result: &'a ProcessResult,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>>
    {
        Box::pin(async move {
            match self {
                Sink::Stdout(s) => {
                    let s = &*s;
                    let result = result;
                    tokio::task::block_in_place(|| s.send(result))
                }
                Sink::File(s) => {
                    let s = &mut *s;
                    let result = result;
                    tokio::task::block_in_place(|| s.send(result))
                }
                #[cfg(feature = "nats")]
                Sink::Nats(s) => s.send(result).await,
                Sink::FanOut(sinks) => {
                    for sink in sinks {
                        sink.send(result).await?;
                    }
                    Ok(())
                }
            }
        })
    }
}

/// Spawn an EventSource as a tokio task wired to a shared event channel.
///
/// The source reads events in a loop via `recv()` and forwards them to
/// `event_tx`. When the source is exhausted or the channel is closed,
/// the task completes. Tracks input queue depth and back-pressure metrics
/// via the provided `MetricsHook`.
pub fn spawn_source<S: EventSource>(
    mut source: S,
    event_tx: tokio::sync::mpsc::Sender<String>,
    metrics: Option<Arc<dyn MetricsHook>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(line) = source.recv().await {
            if let Some(ref m) = metrics {
                match event_tx.try_send(line) {
                    Ok(()) => {
                        m.on_input_queue_depth_change(1);
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Full(line)) => {
                        m.on_back_pressure();
                        m.on_input_queue_depth_change(1);
                        if event_tx.send(line).await.is_err() {
                            tracing::debug!("Event channel closed, source shutting down");
                            break;
                        }
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        tracing::debug!("Event channel closed, source shutting down");
                        break;
                    }
                }
            } else if event_tx.send(line).await.is_err() {
                tracing::debug!("Event channel closed, source shutting down");
                break;
            }
        }
    })
}
