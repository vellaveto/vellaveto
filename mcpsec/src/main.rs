use clap::Parser;
use mcpsec::{run_benchmark, BenchmarkConfig, GatewayConfig, OutputFormat};

#[derive(Parser)]
#[command(name = "mcpsec", about = "MCP Security Benchmark Framework")]
struct Cli {
    /// Base URL of the gateway under test
    #[arg(long)]
    target: String,

    /// Path to the evaluate endpoint
    #[arg(long, default_value = "/api/evaluate")]
    evaluate_path: String,

    /// Bearer token for authentication
    #[arg(long)]
    auth: Option<String>,

    /// Output file path (stdout if not specified)
    #[arg(long, short)]
    output: Option<String>,

    /// Output format: json or markdown
    #[arg(long, default_value = "json")]
    format: String,

    /// Per-request timeout in seconds
    #[arg(long, default_value = "30")]
    timeout: u64,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let format = match cli.format.as_str() {
        "markdown" | "md" => OutputFormat::Markdown,
        _ => OutputFormat::Json,
    };

    let config = BenchmarkConfig {
        gateway: GatewayConfig {
            base_url: cli.target,
            evaluate_path: cli.evaluate_path,
            auth_header: cli.auth,
        },
        format,
        timeout_secs: cli.timeout,
        concurrency: 1,
    };

    let result = run_benchmark(&config).await;

    let output = match format {
        OutputFormat::Json => mcpsec::report::to_json(&result),
        OutputFormat::Markdown => mcpsec::report::to_markdown(&result),
    };

    if let Some(path) = cli.output {
        if let Err(e) = std::fs::write(&path, &output) {
            eprintln!("Failed to write output file '{path}': {e}");
            std::process::exit(1);
        }
        eprintln!("Results written to {path}");
    } else {
        println!("{output}");
    }
}
