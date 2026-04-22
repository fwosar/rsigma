/// Errors from the rsigma runtime (streaming I/O, processing, engine operations).
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// I/O error (stdin read, file write, etc.)
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialization error in a sink.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
