// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

use clap::Parser;
use mcpsec::{run_benchmark, BenchmarkConfig, BenchmarkResult, GatewayConfig, OutputFormat};

#[derive(Parser)]
#[command(name = "mcpsec", about = "MCP Security Benchmark Framework")]
struct Cli {
    /// Base URL of the gateway under test
    #[arg(long, required_unless_present = "list")]
    target: Option<String>,

    /// Path to the evaluate endpoint
    #[arg(long, default_value = "/api/evaluate")]
    evaluate_path: String,

    /// Bearer token for authentication
    #[arg(long)]
    auth: Option<String>,

    /// Output file path (stdout if not specified)
    #[arg(long, short)]
    output: Option<String>,

    /// Output format: json, markdown, or ocsf
    #[arg(long, default_value = "json")]
    format: String,

    /// Per-request timeout in seconds
    #[arg(long, default_value = "30")]
    timeout: u64,

    /// Number of concurrent test requests (1 = sequential, recommended for stateful tests)
    #[arg(long, default_value = "1")]
    concurrency: usize,

    /// Filter by attack classes (comma-separated, e.g., "A1,A4,A9")
    #[arg(long, value_delimiter = ',')]
    classes: Vec<String>,

    /// List all test cases without running them
    #[arg(long)]
    list: bool,

    /// Compare results against a baseline JSON file and report regressions
    #[arg(long)]
    compare: Option<String>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // --list: print all test cases and exit
    if cli.list {
        print_test_list(&cli.classes);
        return;
    }

    let target = match cli.target {
        Some(t) => t,
        None => {
            eprintln!("Error: --target is required when not using --list");
            std::process::exit(1);
        }
    };

    let format = match cli.format.as_str() {
        "markdown" | "md" => OutputFormat::Markdown,
        "ocsf" => OutputFormat::Ocsf,
        _ => OutputFormat::Json,
    };

    let config = BenchmarkConfig {
        gateway: GatewayConfig {
            base_url: target,
            evaluate_path: cli.evaluate_path,
            auth_header: cli.auth,
        },
        format,
        timeout_secs: cli.timeout,
        concurrency: cli.concurrency,
        class_filter: cli.classes,
    };

    let result = run_benchmark(&config).await;

    // Print summary to stderr
    eprintln!(
        "MCPSEC: {}/{} passed ({:.1}%) — Tier {}: {}",
        result.summary.passed,
        result.summary.total_tests,
        result.overall_score,
        result.tier,
        result.tier_name,
    );

    // --compare: show regression report
    if let Some(baseline_path) = &cli.compare {
        match load_baseline(baseline_path) {
            Ok(baseline) => {
                let cmp = mcpsec::compare::compare(&baseline, &result);
                eprint!("{}", mcpsec::compare::format_comparison(&cmp));
                if !cmp.regressions.is_empty() {
                    eprintln!(
                        "\n{} regression(s) detected. Exiting with status 1.",
                        cmp.regressions.len()
                    );
                    // Still write the output before exiting
                    write_output(&result, format, cli.output.as_deref());
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("Warning: could not load baseline '{baseline_path}': {e}");
            }
        }
    }

    write_output(&result, format, cli.output.as_deref());
}

fn write_output(result: &BenchmarkResult, format: OutputFormat, path: Option<&str>) {
    let output = match format {
        OutputFormat::Json => mcpsec::report::to_json(result),
        OutputFormat::Markdown => mcpsec::report::to_markdown(result),
        OutputFormat::Ocsf => mcpsec::report::to_ocsf(result),
    };

    if let Some(path) = path {
        if let Err(e) = std::fs::write(path, &output) {
            eprintln!("Failed to write output file '{path}': {e}");
            std::process::exit(1);
        }
        eprintln!("Results written to {path}");
    } else {
        println!("{output}");
    }
}

fn load_baseline(path: &str) -> Result<BenchmarkResult, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("read error: {e}"))?;
    serde_json::from_str(&content).map_err(|e| format!("parse error: {e}"))
}

fn print_test_list(class_filter: &[String]) {
    let all = mcpsec::attacks::all_tests();
    let tests = mcpsec::runner::filter_tests_by_class(all, class_filter);

    println!(
        "{:<8} {:<16} {:<50} CHECK",
        "ID", "CLASS PREFIX", "NAME"
    );
    println!("{}", "-".repeat(100));

    let mut current_class = String::new();
    for test in &tests {
        let prefix = test.id.split('.').next().unwrap_or(test.id);
        if prefix != current_class {
            if !current_class.is_empty() {
                println!();
            }
            current_class = prefix.to_string();
        }

        let check_name = check_fn_name(test.check_fn);
        println!(
            "{:<8} {:<16} {:<50} {}",
            test.id,
            test.class.chars().take(15).collect::<String>(),
            test.name.chars().take(49).collect::<String>(),
            check_name,
        );
    }
    println!("\nTotal: {} tests", tests.len());
}

fn check_fn_name(f: fn(&serde_json::Value, u16) -> bool) -> &'static str {
    // Use std::ptr::fn_addr_eq to avoid unpredictable_function_pointer_comparisons warnings.
    // This is a best-effort label for display purposes only.
    if std::ptr::fn_addr_eq(f, mcpsec::attacks::is_deny as fn(&serde_json::Value, u16) -> bool) {
        "is_deny"
    } else if std::ptr::fn_addr_eq(
        f,
        mcpsec::attacks::is_allow as fn(&serde_json::Value, u16) -> bool,
    ) {
        "is_allow"
    } else if std::ptr::fn_addr_eq(
        f,
        mcpsec::attacks::has_injection as fn(&serde_json::Value, u16) -> bool,
    ) {
        "has_injection"
    } else if std::ptr::fn_addr_eq(
        f,
        mcpsec::attacks::has_dlp as fn(&serde_json::Value, u16) -> bool,
    ) {
        "has_dlp"
    } else if std::ptr::fn_addr_eq(
        f,
        mcpsec::attacks::is_clean as fn(&serde_json::Value, u16) -> bool,
    ) {
        "is_clean"
    } else {
        "custom"
    }
}
