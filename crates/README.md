# crates

This directory contains `rsigma`'s various crates.

| Crate | Description |
|-------|-------------|
| [`rsigma-parser`][rsigma-parser-dir] | Parser for Sigma detection rules, correlations, and filters. |
| [`rsigma-eval`][rsigma-eval-dir] | Evaluator for Sigma detection rules — match rules against events. |
| [`rsigma-runtime`][rsigma-runtime-dir] | Streaming runtime — input adapters, log processor, hot-reload. |
| [`rsigma`][rsigma-cli-dir] | CLI for parsing, validating, evaluating rules, and running a detection daemon. |
| [`rsigma-lsp`][rsigma-lsp-dir] | Language Server Protocol (LSP) server for Sigma detection rules. |

[rsigma-parser-dir]: ./rsigma-parser
[rsigma-eval-dir]: ./rsigma-eval
[rsigma-runtime-dir]: ./rsigma-runtime
[rsigma-cli-dir]: ./rsigma-cli
[rsigma-lsp-dir]: ./rsigma-lsp
