//! Tail a syslog file, parse each line, and print Sigma detections.
//!
//! Usage:
//!   cargo run -p rsigma-runtime --example tail_syslog -- rules/ /var/log/syslog
//!
//! The example reads the file from the current position to EOF once, processes
//! it in 64-line batches, and prints any detections. In a real deployment you'd
//! wrap this in a loop with `notify` or `inotify` to watch for new writes.

use std::io::{self, BufRead, BufReader};
use std::sync::Arc;

use rsigma_eval::CorrelationConfig;
use rsigma_runtime::input::SyslogConfig;
use rsigma_runtime::{InputFormat, LogProcessor, NoopMetrics, RuntimeEngine};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: tail_syslog <RULES_PATH> <SYSLOG_FILE>");
        std::process::exit(1);
    }

    let rules_path = &args[1];
    let syslog_file = &args[2];

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
    let format = InputFormat::Syslog(SyslogConfig::default());

    let reader: Box<dyn BufRead> = if syslog_file == "-" {
        Box::new(BufReader::new(io::stdin()))
    } else {
        let file = std::fs::File::open(syslog_file).unwrap_or_else(|e| {
            eprintln!("Error opening {syslog_file}: {e}");
            std::process::exit(1);
        });
        Box::new(BufReader::new(file))
    };

    let mut batch = Vec::with_capacity(64);
    let mut line_offset: usize = 0;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Read error: {e}");
                break;
            }
        };

        batch.push(line);

        if batch.len() >= 64 {
            flush_batch(&processor, &format, &mut batch, line_offset);
            line_offset += 64;
        }
    }

    if !batch.is_empty() {
        let count = batch.len();
        flush_batch(&processor, &format, &mut batch, line_offset);
        line_offset += count;
    }

    eprintln!("Processed {line_offset} lines");
}

fn flush_batch(
    processor: &LogProcessor,
    format: &InputFormat,
    batch: &mut Vec<String>,
    line_offset: usize,
) {
    let results = processor.process_batch_with_format(batch, format, None);

    for (i, result) in results.iter().enumerate() {
        let line_no = line_offset + i + 1;
        for det in &result.detections {
            println!(
                "DETECTION line={line_no} rule=\"{}\" level={:?} id={:?}",
                det.rule_title, det.level, det.rule_id,
            );
        }
        for corr in &result.correlations {
            println!(
                "CORRELATION line={line_no} rule=\"{}\" level={:?} id={:?}",
                corr.rule_title, corr.level, corr.rule_id,
            );
        }
    }

    batch.clear();
}
