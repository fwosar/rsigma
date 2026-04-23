# Benchmarks

rsigma ships two benchmark suites built on [Criterion.rs](https://bheisler.github.io/criterion.rs/book/):

| Suite | Crate | What it measures |
|-------|-------|-----------------|
| `eval` / `correlation` | `rsigma-eval` | Rule compilation, single-event evaluation, throughput, batch parallelism, wildcard/regex cost, correlation engines |
| `runtime_throughput` | `rsigma-runtime` | Full `LogProcessor` pipeline — format parsing, dispatch, batch evaluation — across JSON, syslog, plain text, and auto-detect |

## Running benchmarks

```bash
# All eval benchmarks
cargo bench -p rsigma-eval

# All runtime benchmarks
cargo bench -p rsigma-runtime

# A specific benchmark group
cargo bench -p rsigma-runtime -- runtime_json

# Compare against a baseline
cargo bench -p rsigma-runtime -- --save-baseline before
# ... make changes ...
cargo bench -p rsigma-runtime -- --baseline before
```

## Benchmark groups

### rsigma-eval

| Group | Description |
|-------|-------------|
| `compile_rules` | Time to compile 100–5000 rules into an `Engine` |
| `eval_single_event` | Evaluate one event against 100–5000 rules |
| `eval_throughput` | Throughput: 1K–100K events against 100 rules |
| `eval_batch` | Sequential vs parallel `evaluate_batch` |
| `eval_wildcard` | Wildcard-heavy rules (contains, startswith, endswith) |
| `eval_regex` | Regex-heavy rules |
| `correlation_event_count` | event_count correlation processing |
| `correlation_temporal` | Temporal correlation processing |
| `correlation_throughput` | End-to-end detection + correlation throughput |
| `correlation_batch` | Sequential vs batch correlation processing |
| `correlation_state_pressure` | Many unique group keys stressing the state map |

### rsigma-runtime

| Group | Description |
|-------|-------------|
| `runtime_json` | `LogProcessor` throughput with JSON input (1K–10K events, 100 rules) |
| `runtime_syslog` | `LogProcessor` throughput with syslog input |
| `runtime_plain` | `LogProcessor` throughput with plain text input |
| `runtime_auto` | `LogProcessor` throughput with auto-detect (JSON lines) |
| `runtime_vs_raw` | Overhead comparison: raw `Engine::evaluate` vs `LogProcessor` pipeline |
| `runtime_rule_scaling` | `LogProcessor` throughput scaling across 100–1000 rules |

## Baseline results (v0.7.0)

Recorded on Apple M4 Pro, macOS, `cargo bench -p rsigma-runtime` with
`--release` (Criterion default). 100 synthetic detection rules, seeded RNG
for reproducibility.

### Runtime throughput (LogProcessor pipeline)

| Group | Events | Median | Throughput |
|-------|-------:|-------:|-----------:|
| `runtime_json` | 1,000 | 1.05 ms | 955 Kelem/s |
| `runtime_json` | 10,000 | 8.71 ms | 1.15 Melem/s |
| `runtime_syslog` | 1,000 | 796 µs | 1.26 Melem/s |
| `runtime_syslog` | 10,000 | 7.15 ms | 1.40 Melem/s |
| `runtime_plain` | 1,000 | 180 µs | 5.54 Melem/s |
| `runtime_plain` | 10,000 | 918 µs | 10.89 Melem/s |
| `runtime_auto` | 1,000 | 1.04 ms | 966 Kelem/s |
| `runtime_auto` | 10,000 | 9.13 ms | 1.09 Melem/s |

### Raw engine vs LogProcessor overhead (10K events, 100 rules)

| Mode | Median | Throughput |
|------|-------:|-----------:|
| Raw `Engine::evaluate` (pre-parsed) | 10.37 ms | 965 Kelem/s |
| `LogProcessor` JSON | 8.87 ms | 1.13 Melem/s |
| `LogProcessor` auto-detect | 8.79 ms | 1.14 Melem/s |

The `LogProcessor` pipeline is faster than raw sequential `Engine::evaluate`
because it uses `evaluate_batch` (parallel via rayon) internally.

### Rule-count scaling (1K JSON events)

| Rules | Median | Throughput |
|------:|-------:|-----------:|
| 100 | 1.04 ms | 965 Kelem/s |
| 500 | 1.04 ms | 963 Kelem/s |
| 1,000 | 1.05 ms | 954 Kelem/s |

Throughput is near-constant from 100 to 1,000 rules thanks to the logsource
index pruning most rules before evaluation.

## Regression policy

- **Threshold**: a regression of **> 5%** in any benchmark group's median runtime
  is considered significant and should be investigated before merging.
- **How to check**: Criterion saves baselines in `target/criterion/`. Use
  `--baseline` to compare before/after.
- **CI**: benchmarks are not run in CI (too noisy). Run locally on a consistent
  machine before and after performance-sensitive changes.

## Interpreting results

- `runtime_vs_raw` compares sequential `Engine::evaluate` (one event at a
  time, pre-parsed) against the `LogProcessor` pipeline (which includes JSON
  parsing but uses `evaluate_batch` for parallel detection via rayon). The
  pipeline is typically *faster* overall because batch parallelism outweighs
  the parsing overhead.
- `runtime_auto` vs `runtime_json` shows the cost of format auto-detection.
  For homogeneous high-volume streams, specifying `--input-format json` (etc.)
  explicitly avoids the auto-detect probe overhead.
- Plain text is the fastest format because there is no structured parsing —
  lines are wrapped directly into `PlainEvent` for keyword matching.
- Syslog throughput is higher than JSON because the `syslog_loose` parser +
  `KvEvent` construction is cheaper than `serde_json` deserialization for
  these synthetic payloads. Real-world results may vary with message complexity.
- Rule-count scaling is near-flat from 100 to 1,000 rules because the
  logsource index prunes non-matching rules before evaluation.
