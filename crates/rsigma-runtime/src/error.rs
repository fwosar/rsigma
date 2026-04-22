/// Errors from the rsigma runtime (streaming I/O, processing, engine operations).
#[derive(Debug)]
pub enum RuntimeError {
    /// I/O error (stdin read, file write, etc.)
    Io(std::io::Error),
    /// JSON serialization error in a sink.
    Serialization(serde_json::Error),
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuntimeError::Io(e) => write!(f, "I/O error: {e}"),
            RuntimeError::Serialization(e) => write!(f, "serialization error: {e}"),
        }
    }
}

impl std::error::Error for RuntimeError {}

impl From<std::io::Error> for RuntimeError {
    fn from(e: std::io::Error) -> Self {
        RuntimeError::Io(e)
    }
}

impl From<serde_json::Error> for RuntimeError {
    fn from(e: serde_json::Error) -> Self {
        RuntimeError::Serialization(e)
    }
}
