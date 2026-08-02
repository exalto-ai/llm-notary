//! Commands for inspecting the local SQLite capture catalog.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::{
    catalog::{CaptureSummary, Catalog},
    cli::config::load_agent_config,
};

#[derive(Subcommand, Debug)]
pub enum CapturesCommand {
    /// List locally cataloged captures and optionally search their previews.
    List(ListArgs),
    /// Show one capture and its retained local artifacts.
    Show(ShowArgs),
}

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Agent configuration file. Defaults to the standard path.
    #[arg(long)]
    config: Option<PathBuf>,
    /// SQLite FTS5 query matched against prompt and output previews.
    #[arg(long)]
    query: Option<String>,
    /// Restrict results to one requested model.
    #[arg(long)]
    model: Option<String>,
}

#[derive(Args, Debug)]
pub struct ShowArgs {
    /// Capture ID returned by the local administration API.
    capture_id: String,
    /// Agent configuration file. Defaults to the standard path.
    #[arg(long)]
    config: Option<PathBuf>,
}

pub fn run(command: CapturesCommand) -> Result<()> {
    match command {
        CapturesCommand::List(args) => list(args),
        CapturesCommand::Show(args) => show(args),
    }
}

fn list(args: ListArgs) -> Result<()> {
    let catalog = open_catalog(args.config.as_deref())?;
    let captures = catalog.list_captures(args.query.as_deref(), args.model.as_deref())?;
    println!("ID\tCREATED_MS\tPROVIDER\tMODEL\tSTATUS\tPROMPT\tOUTPUT");
    for capture in captures {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            capture.capture_id,
            capture.created_at_unix_ms,
            capture.provider,
            capture.requested_model.as_deref().unwrap_or(""),
            capture.capture_state,
            single_line(&capture.prompt_preview),
            single_line(&capture.output_preview),
        );
    }
    Ok(())
}

fn show(args: ShowArgs) -> Result<()> {
    let catalog = open_catalog(args.config.as_deref())?;
    let capture = catalog.capture(&args.capture_id)?.ok_or_else(|| {
        anyhow::anyhow!("capture {} is not in the local catalog", args.capture_id)
    })?;
    print_capture(&capture);
    println!("ARTIFACTS");
    for artifact in catalog.artifacts(&args.capture_id)? {
        println!(
            "{}\t{}\t{}\t{}",
            artifact.kind,
            artifact.size_bytes,
            artifact.sha256,
            artifact.path.display()
        );
    }
    Ok(())
}

fn open_catalog(path: Option<&Path>) -> Result<Catalog> {
    let (config, path) = load_agent_config(path)?;
    Catalog::open_for_config(&config)
        .with_context(|| format!("opening catalog configured by {}", path.display()))
}

fn print_capture(capture: &CaptureSummary) {
    println!("capture_id: {}", capture.capture_id);
    println!("provider: {}", capture.provider);
    println!("operation: {}", capture.operation);
    println!("created_at_unix_ms: {}", capture.created_at_unix_ms);
    if let Some(completed_at) = capture.completed_at_unix_ms {
        println!("completed_at_unix_ms: {completed_at}");
    }
    println!("capture_state: {}", capture.capture_state);
    println!("finalization_state: {}", capture.finalization_state);
    if let Some(model) = &capture.requested_model {
        println!("requested_model: {model}");
    }
    if let Some(model) = &capture.response_model {
        println!("response_model: {model}");
    }
    if let Some(status) = capture.http_status {
        println!("http_status: {status}");
    }
    println!("streaming: {}", capture.streaming);
    println!("request_bytes: {}", capture.request_bytes);
    if let Some(response_bytes) = capture.response_bytes {
        println!("response_bytes: {response_bytes}");
    }
    if let Some(duration_ms) = capture.duration_ms {
        println!("duration_ms: {duration_ms}");
    }
    println!("prompt_preview: {}", capture.prompt_preview);
    println!("output_preview: {}", capture.output_preview);
}

fn single_line(value: &str) -> String {
    value.replace(['\r', '\n', '\t'], " ")
}

#[cfg(test)]
mod tests {
    use super::single_line;

    #[test]
    fn tabular_output_does_not_break_on_preview_whitespace() {
        assert_eq!(single_line("one\ntwo\tthree"), "one two three");
    }
}
