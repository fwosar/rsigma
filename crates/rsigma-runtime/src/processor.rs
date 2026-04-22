use std::sync::{Arc, Mutex};
use std::time::Instant;

use arc_swap::ArcSwap;
use rsigma_eval::{JsonEvent, ProcessResult};

use crate::engine::RuntimeEngine;
use crate::metrics::MetricsHook;

/// Thread-safe handle to the engine, swappable atomically for hot-reload.
///
/// Uses `ArcSwap<Mutex<RuntimeEngine>>` so that:
/// - Detection + correlation processing can acquire `&mut RuntimeEngine` via
///   the inner `Mutex`.
/// - Hot-reload swaps the entire engine atomically without blocking in-flight
///   batches (they hold an `Arc` to the old engine until their batch completes).
pub struct LogProcessor {
    engine: Arc<ArcSwap<Mutex<RuntimeEngine>>>,
    metrics: Arc<dyn MetricsHook>,
}

impl LogProcessor {
    /// Create a new processor wrapping the given engine and metrics hook.
    pub fn new(engine: RuntimeEngine, metrics: Arc<dyn MetricsHook>) -> Self {
        LogProcessor {
            engine: Arc::new(ArcSwap::from_pointee(Mutex::new(engine))),
            metrics,
        }
    }

    /// Atomically replace the engine with a new one.
    ///
    /// In-flight batches continue against the old engine (they hold an `Arc`
    /// snapshot). New batches see the replacement on their next call to
    /// `process_batch_lines`.
    pub fn swap_engine(&self, new_engine: RuntimeEngine) {
        self.engine.store(Arc::new(Mutex::new(new_engine)));
    }

    /// Load a snapshot of the current engine for use during reload.
    ///
    /// The caller can lock the returned guard to export state, build a new
    /// engine, import state, and then call `swap_engine`.
    pub fn engine_snapshot(&self) -> arc_swap::Guard<Arc<Mutex<RuntimeEngine>>> {
        self.engine.load()
    }

    /// Process a batch of raw input lines through the engine.
    ///
    /// 1. Parses each line as JSON; on error, increments parse error metrics.
    /// 2. Applies the `event_filter` closure to extract payloads.
    /// 3. Evaluates all payloads via `RuntimeEngine::process_batch`.
    /// 4. Merges per-payload results back into per-line results.
    /// 5. Updates metrics (events processed, latency, match counts).
    ///
    /// Returns one `ProcessResult` per input line.
    pub fn process_batch_lines(
        &self,
        batch: &[String],
        event_filter: &dyn Fn(&serde_json::Value) -> Vec<serde_json::Value>,
    ) -> Vec<ProcessResult> {
        let engine_guard = self.engine.load();
        let mut engine = engine_guard.lock().unwrap();

        // Phase 1: Parse JSON and apply event filters, tracking line origin.
        let mut parsed: Vec<(usize, Vec<serde_json::Value>)> = Vec::with_capacity(batch.len());
        for (line_idx, line) in batch.iter().enumerate() {
            match serde_json::from_str::<serde_json::Value>(line) {
                Ok(value) => {
                    let payloads = event_filter(&value);
                    if !payloads.is_empty() {
                        parsed.push((line_idx, payloads));
                    }
                }
                Err(e) => {
                    self.metrics.on_parse_error();
                    tracing::debug!(error = %e, "Invalid JSON on input");
                }
            }
        }

        // Flatten: (line_idx, &Value) for each payload across all lines
        let mut flat: Vec<(usize, &serde_json::Value)> = Vec::new();
        for (line_idx, payloads) in &parsed {
            for payload in payloads {
                flat.push((*line_idx, payload));
            }
        }

        if flat.is_empty() {
            return (0..batch.len())
                .map(|_| ProcessResult {
                    detections: vec![],
                    correlations: vec![],
                })
                .collect();
        }

        // Phase 2: Batch evaluation — parallel detection + sequential correlation
        let events: Vec<JsonEvent> = flat.iter().map(|(_, v)| JsonEvent::borrow(v)).collect();
        let event_refs: Vec<&JsonEvent> = events.iter().collect();

        let start = Instant::now();
        let batch_results = engine.process_batch(&event_refs);
        let elapsed = start.elapsed().as_secs_f64();
        let per_event_latency = elapsed / event_refs.len() as f64;

        // Update correlation state metrics while we still hold the lock
        let stats = engine.stats();
        self.metrics
            .set_correlation_state_entries(stats.state_entries as u64);

        // Phase 3: Merge results per input line and update metrics
        let mut line_results: Vec<ProcessResult> = (0..batch.len())
            .map(|_| ProcessResult {
                detections: vec![],
                correlations: vec![],
            })
            .collect();

        for ((line_idx, _), result) in flat.iter().zip(batch_results) {
            self.metrics.on_events_processed(1);
            self.metrics.observe_processing_latency(per_event_latency);
            self.metrics
                .on_detection_matches(result.detections.len() as u64);
            self.metrics
                .on_correlation_matches(result.correlations.len() as u64);

            line_results[*line_idx].detections.extend(result.detections);
            line_results[*line_idx]
                .correlations
                .extend(result.correlations);
        }

        line_results
    }

    /// Reload rules without blocking in-flight event processing.
    ///
    /// Builds a fresh `RuntimeEngine` with the same configuration as the
    /// current one, loads rules into it, imports the old engine's correlation
    /// state, and atomically swaps. In-flight batches that already hold an
    /// `Arc` to the old engine finish undisturbed.
    pub fn reload_rules(&self) -> Result<crate::engine::EngineStats, String> {
        let (old_state, rules_path, pipelines, corr_config, include_event) = {
            let snapshot = self.engine.load();
            let old = snapshot.lock().unwrap();
            (
                old.export_state(),
                old.rules_path().to_path_buf(),
                old.pipelines().to_vec(),
                old.corr_config().clone(),
                old.include_event(),
            )
        };

        let mut new_engine = RuntimeEngine::new(rules_path, pipelines, corr_config, include_event);
        let stats = new_engine.load_rules()?;

        if let Some(state) = old_state {
            new_engine.import_state(&state);
        }

        self.swap_engine(new_engine);
        Ok(stats)
    }

    /// Return the rules path from the current engine.
    pub fn rules_path(&self) -> std::path::PathBuf {
        let snapshot = self.engine.load();
        let engine = snapshot.lock().unwrap();
        engine.rules_path().to_path_buf()
    }

    /// Return a reference to the metrics hook.
    pub fn metrics(&self) -> &dyn MetricsHook {
        &*self.metrics
    }

    /// Export correlation state from the current engine.
    pub fn export_state(&self) -> Option<rsigma_eval::CorrelationSnapshot> {
        let snapshot = self.engine.load();
        let engine = snapshot.lock().unwrap();
        engine.export_state()
    }

    /// Import correlation state into the current engine.
    pub fn import_state(&self, snapshot: &rsigma_eval::CorrelationSnapshot) -> bool {
        let guard = self.engine.load();
        let mut engine = guard.lock().unwrap();
        engine.import_state(snapshot)
    }

    /// Return summary statistics about the current engine.
    pub fn stats(&self) -> crate::engine::EngineStats {
        let snapshot = self.engine.load();
        let engine = snapshot.lock().unwrap();
        engine.stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::NoopMetrics;
    use rsigma_eval::CorrelationConfig;

    fn identity_filter(v: &serde_json::Value) -> Vec<serde_json::Value> {
        vec![v.clone()]
    }

    fn make_processor(rules_yaml: &str) -> LogProcessor {
        let dir = tempfile::tempdir().unwrap();
        let rule_path = dir.path().join("test.yml");
        std::fs::write(&rule_path, rules_yaml).unwrap();

        let mut engine = RuntimeEngine::new(rule_path, vec![], CorrelationConfig::default(), false);
        engine.load_rules().unwrap();
        // Leak the tempdir so the path stays valid
        std::mem::forget(dir);
        LogProcessor::new(engine, Arc::new(NoopMetrics))
    }

    #[test]
    fn process_batch_lines_valid_json() {
        let proc = make_processor(
            r#"
title: Test Rule
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
"#,
        );

        let batch = vec![
            r#"{"EventID": 1}"#.to_string(),
            r#"{"EventID": 2}"#.to_string(),
        ];
        let results = proc.process_batch_lines(&batch, &identity_filter);
        assert_eq!(results.len(), 2);
        assert!(!results[0].detections.is_empty(), "EventID=1 should match");
        assert!(
            results[1].detections.is_empty(),
            "EventID=2 should not match"
        );
    }

    #[test]
    fn process_batch_lines_invalid_json() {
        let proc = make_processor(
            r#"
title: Test Rule
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
"#,
        );

        let batch = vec!["not json".to_string(), r#"{"EventID": 1}"#.to_string()];
        let results = proc.process_batch_lines(&batch, &identity_filter);
        assert_eq!(results.len(), 2);
        assert!(
            results[0].detections.is_empty(),
            "invalid JSON produces empty result"
        );
        assert!(
            !results[1].detections.is_empty(),
            "valid line still matches"
        );
    }

    #[test]
    fn swap_engine_replaces_rules() {
        let dir = tempfile::tempdir().unwrap();
        let rule_path = dir.path().join("test.yml");
        std::fs::write(
            &rule_path,
            r#"
title: Rule A
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
"#,
        )
        .unwrap();

        let mut engine = RuntimeEngine::new(
            rule_path.clone(),
            vec![],
            CorrelationConfig::default(),
            false,
        );
        engine.load_rules().unwrap();
        let proc = LogProcessor::new(engine, Arc::new(NoopMetrics));

        let batch = vec![r#"{"EventID": 1}"#.to_string()];
        assert!(
            !proc.process_batch_lines(&batch, &identity_filter)[0]
                .detections
                .is_empty()
        );

        // Swap to a rule that matches EventID: 99
        std::fs::write(
            &rule_path,
            r#"
title: Rule B
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 99
    condition: selection
"#,
        )
        .unwrap();

        let mut new_engine =
            RuntimeEngine::new(rule_path, vec![], CorrelationConfig::default(), false);
        new_engine.load_rules().unwrap();
        proc.swap_engine(new_engine);

        assert!(
            proc.process_batch_lines(&batch, &identity_filter)[0]
                .detections
                .is_empty()
        );

        let batch2 = vec![r#"{"EventID": 99}"#.to_string()];
        assert!(
            !proc.process_batch_lines(&batch2, &identity_filter)[0]
                .detections
                .is_empty()
        );

        std::mem::forget(dir);
    }
}
