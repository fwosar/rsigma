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

## Regression policy

- **Threshold**: a regression of **> 5%** in any benchmark group's median runtime
  is considered significant and should be investigated before merging.
- **How to check**: Criterion saves baselines in `target/criterion/`. Use
  `--baseline` to compare before/after.
- **CI**: benchmarks are not run in CI (too noisy). Run locally on a consistent
  machine before and after performance-sensitive changes.

## Interpreting results

- `runtime_vs_raw` shows the overhead of the `LogProcessor` abstraction
  (JSON parsing, format dispatch, metrics hooks, `ArcSwap` loads) compared to
  calling `Engine::evaluate` directly on pre-parsed events. Expect 1.5–3x
  overhead from JSON parsing alone.
- `runtime_auto` vs `runtime_json` shows the cost of format auto-detection.
  For homogeneous high-volume streams, specifying `--input-format json` (etc.)
  explicitly avoids this overhead.
- Syslog throughput is lower than JSON because `syslog_loose` parsing and
  year resolution add per-line work.
