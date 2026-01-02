//! KernelLens CLI - Linux Kernel Analysis Tool
//!
//! A powerful command-line interface for analyzing compiled Linux kernels,
//! especially Android production kernels extracted from boot.img.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use kernel_core::{BootImage, Decompressor, ElfBuilder, KallsymsFinder};

// ============================================================
// CLI Argument Definitions
// ============================================================

/// KernelLens - Linux Kernel Analysis Suite
#[derive(Parser, Debug)]
#[command(
    name = "kernel-lens",
    author,
    version,
    about = "Analyze and visualize Linux kernel binaries",
    long_about = r#"
KernelLens is a Windows-native tool for reverse engineering Linux kernels.

It can:
  • Extract kernels from Android boot.img files
  • Decompress LZ4/Gzip/Zstd compressed kernels
  • Recover symbols from kallsyms data structures
  • Generate debuggable ELF files for IDA/Ghidra

Examples:
  kernel-lens analyze boot.img -o vmlinux.elf
  kernel-lens info boot.img
  kernel-lens extract boot.img --kernel kernel.bin --ramdisk ramdisk.cpio
"#
)]
struct Cli {
    /// Enable verbose output (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Display information about a boot image
    Info {
        /// Path to boot.img file
        #[arg(value_name = "FILE")]
        input: PathBuf,

        /// Output format (text, json)
        #[arg(short, long, default_value = "text")]
        format: OutputFormat,
    },

    /// Extract components from a boot image
    Extract {
        /// Path to boot.img file
        #[arg(value_name = "FILE")]
        input: PathBuf,

        /// Output path for kernel
        #[arg(short, long)]
        kernel: Option<PathBuf>,

        /// Output path for ramdisk
        #[arg(short, long)]
        ramdisk: Option<PathBuf>,

        /// Decompress kernel if compressed
        #[arg(short, long)]
        decompress: bool,
    },

    /// Full analysis: extract, decompress, recover symbols, generate ELF
    Analyze {
        /// Path to boot.img or raw kernel binary
        #[arg(value_name = "FILE")]
        input: PathBuf,

        /// Output path for ELF file
        #[arg(short, long, default_value = "vmlinux.elf")]
        output: PathBuf,

        /// Also export symbols as JSON
        #[arg(long)]
        export_symbols: Option<PathBuf>,
    },

    /// List recovered symbols from a kernel
    Symbols {
        /// Path to kernel binary
        #[arg(value_name = "FILE")]
        input: PathBuf,

        /// Filter symbols by prefix
        #[arg(short, long)]
        filter: Option<String>,

        /// Output format (text, json)
        #[arg(short = 'F', long, default_value = "text")]
        format: OutputFormat,
    },
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

// ============================================================
// Main Entry Point
// ============================================================

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging based on verbosity
    init_logging(cli.verbose);

    // Dispatch to subcommand handlers
    match cli.command {
        Commands::Info { input, format } => cmd_info(input, format),
        Commands::Extract { input, kernel, ramdisk, decompress } => {
            cmd_extract(input, kernel, ramdisk, decompress)
        },
        Commands::Analyze { input, output, export_symbols } => {
            cmd_analyze(input, output, export_symbols)
        },
        Commands::Symbols { input, filter, format } => cmd_symbols(input, filter, format),
    }
}

// ============================================================
// Command Implementations
// ============================================================

fn cmd_info(input: PathBuf, format: OutputFormat) -> Result<()> {
    let boot_img = BootImage::from_file(&input).context("Failed to parse boot image")?;

    match format {
        OutputFormat::Text => {
            println!("{}", style("Boot Image Information").bold().cyan());
            println!("{}", style("─".repeat(40)).dim());
            println!("  Version:      {:?}", boot_img.header.version);
            println!(
                "  Kernel Size:  {} bytes ({:.2} MB)",
                boot_img.header.kernel_size,
                boot_img.header.kernel_size as f64 / 1024.0 / 1024.0
            );
            println!("  Ramdisk Size: {} bytes", boot_img.header.ramdisk_size);
            println!("  Page Size:    {} bytes", boot_img.header.page_size);
            println!(
                "  Command Line: {}",
                if boot_img.header.cmdline.is_empty() {
                    "(empty)".to_string()
                } else {
                    boot_img.header.cmdline.clone()
                }
            );
        },
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&boot_img.header)?;
            println!("{}", json);
        },
    }

    Ok(())
}

fn cmd_extract(
    input: PathBuf,
    kernel_out: Option<PathBuf>,
    ramdisk_out: Option<PathBuf>,
    decompress: bool,
) -> Result<()> {
    let boot_img = BootImage::from_file(&input).context("Failed to parse boot image")?;

    let pb = create_progress_bar("Extracting");

    // Extract kernel
    if let Some(kernel_path) = kernel_out {
        pb.set_message("Extracting kernel...");
        let kernel_data = boot_img.extract_kernel()?;

        let output_data = if decompress {
            pb.set_message("Decompressing kernel...");
            Decompressor::decompress(kernel_data)?
        } else {
            kernel_data.to_vec()
        };

        std::fs::write(&kernel_path, &output_data).context("Failed to write kernel")?;

        pb.println(format!(
            "{} Kernel saved to {} ({} bytes)",
            style("✓").green(),
            kernel_path.display(),
            output_data.len()
        ));
    }

    // Extract ramdisk
    if let Some(ramdisk_path) = ramdisk_out {
        pb.set_message("Extracting ramdisk...");
        let ramdisk_data = boot_img.extract_ramdisk()?;

        std::fs::write(&ramdisk_path, ramdisk_data).context("Failed to write ramdisk")?;

        pb.println(format!(
            "{} Ramdisk saved to {} ({} bytes)",
            style("✓").green(),
            ramdisk_path.display(),
            ramdisk_data.len()
        ));
    }

    pb.finish_with_message("Extraction complete");
    Ok(())
}

fn cmd_analyze(input: PathBuf, output: PathBuf, export_symbols: Option<PathBuf>) -> Result<()> {
    let pb = create_progress_bar("Analyzing");

    // Step 1: Load and parse input
    pb.set_message("Loading input file...");
    let raw_data = std::fs::read(&input).context("Failed to read input file")?;

    // Detect if this is a boot.img or raw kernel
    let kernel_data = if raw_data.starts_with(b"ANDROID!") {
        pb.set_message("Parsing boot image...");
        let boot_img = BootImage::from_bytes(raw_data)?;
        let kernel = boot_img.extract_kernel()?;

        pb.set_message("Decompressing kernel...");
        Decompressor::decompress(kernel)?
    } else {
        pb.set_message("Decompressing kernel...");
        Decompressor::decompress(&raw_data)?
    };

    pb.println(format!("{} Kernel size: {} bytes", style("→").blue(), kernel_data.len()));

    // Step 2: Find kallsyms
    pb.set_message("Searching for kallsyms...");
    let symbols = KallsymsFinder::new(&kernel_data)?.into_result();

    pb.println(format!(
        "{} Found {} symbols (base: {:#x})",
        style("→").blue(),
        symbols.symbol_count,
        symbols.kernel_base
    ));

    // Step 3: Generate ELF
    pb.set_message("Building ELF file...");
    let elf_data = ElfBuilder::new(&kernel_data, &symbols).build()?;

    std::fs::write(&output, &elf_data).context("Failed to write ELF file")?;

    pb.println(format!(
        "{} ELF saved to {} ({} bytes)",
        style("✓").green(),
        output.display(),
        elf_data.len()
    ));

    // Optional: Export symbols as JSON
    if let Some(symbols_path) = export_symbols {
        let json = serde_json::to_string_pretty(&symbols)?;
        std::fs::write(&symbols_path, json)?;
        pb.println(format!(
            "{} Symbols exported to {}",
            style("✓").green(),
            symbols_path.display()
        ));
    }

    pb.finish_with_message("Analysis complete!");
    Ok(())
}

fn cmd_symbols(input: PathBuf, filter: Option<String>, format: OutputFormat) -> Result<()> {
    let data = std::fs::read(&input).context("Failed to read input")?;
    let decompressed = Decompressor::decompress(&data)?;

    let result = KallsymsFinder::new(&decompressed)?.into_result();

    let symbols: Vec<_> = result
        .symbols
        .iter()
        .filter(|s| filter.as_ref().map(|f| s.name.contains(f)).unwrap_or(true))
        .collect();

    match format {
        OutputFormat::Text => {
            println!("{} ({} symbols)", style("Kernel Symbols").bold().cyan(), symbols.len());
            println!("{}", style("─".repeat(80)).dim());

            for sym in &symbols {
                println!("{:016x} {} {}", sym.address, sym.sym_type, sym.name);
            }
        },
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&symbols)?;
            println!("{}", json);
        },
    }

    Ok(())
}

// ============================================================
// Helpers
// ============================================================

fn init_logging(verbosity: u8) {
    let filter = match verbosity {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false))
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()))
        .init();
}

fn create_progress_bar(prefix: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} [{elapsed_precise}] {msg}")
            .unwrap(),
    );
    pb.set_message(prefix.to_string());
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb
}
