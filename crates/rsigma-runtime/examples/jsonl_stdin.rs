//! Read NDJSON events from stdin, evaluate Sigma rules, print detections to stdout.
//!
//! Usage:
//!   echo '{"CommandLine":"cmd /c whoami"}' | cargo run -p rsigma-runtime --example jsonl_stdin -- rules/
//!   cat events.ndjson | cargo run -p rsigma-runtime --example jsonl_stdin -- rules/

use std::io::{self, BufRead};
use std::sync::Arc;

use rsigma_eval::CorrelationConfig;
use rsigma_runtime::{InputFormat, LogProcessor, NoopMetrics, RuntimeEngine};

fn main() {
    let rules_path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: jsonl_stdin <RULES_PATH>");
        std::process::exit(1);
    });

    let mut engine = RuntimeEngine::new(
        rules_path.into(),
        vec![],
        CorrelationConfig::default(),
        false,
    );
    if let Err(e) = engine.load_rules() {
        eprintln!("Error loading rules: {e}");
        std::process::exit(1);
    }

    let stats = engine.stats();
    eprintln!(
        "Loaded {} detection rules, {} correlation rules",
        stats.detection_rules, stats.correlation_rules
    );

    let processor = LogProcessor::new(engine, Arc::new(NoopMetrics));

    let stdin = io::stdin();
    let mut batch = Vec::with_capacity(64);

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Read error: {e}");
                break;
            }
        };

        batch.push(line);

        if batch.len() >= 64 {
            flush_batch(&processor, &mut batch);
        }
    }

    if !batch.is_empty() {
        flush_batch(&processor, &mut batch);
    }
}

fn flush_batch(processor: &LogProcessor, batch: &mut Vec<String>) {
    let results = processor.process_batch_with_format(batch, &InputFormat::Json, None);

    for (i, result) in results.iter().enumerate() {
        for det in &result.detections {
            println!(
                "DETECTION line={} rule=\"{}\" level={:?} id={:?}",
                i, det.rule_title, det.level, det.rule_id,
            );
        }
        for corr in &result.correlations {
            println!(
                "CORRELATION line={} rule=\"{}\" level={:?} id={:?}",
                i, corr.rule_title, corr.level, corr.rule_id,
            );
        }
    }

    batch.clear();
}
