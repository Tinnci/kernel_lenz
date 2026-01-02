//! # xtask - Build Automation for KernelLens
//!
//! This crate provides cross-platform build automation tasks,
//! replacing traditional Makefiles and shell scripts.
//!
//! ## Why xtask?
//!
//! - Cross-platform (works on Windows/Linux/macOS)
//! - Written in Rust (type-safe, IDE support)
//! - Integrated with Cargo ecosystem
//!
//! ## Usage
//!
//! ```bash
//! # From project root
//! cargo xtask build-cli
//! cargo xtask build-ffi
//! cargo xtask run-app
//! ```

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use xshell::{cmd, Shell};

// ============================================================
// CLI Definition
// ============================================================

#[derive(Parser)]
#[command(name = "xtask", about = "KernelLens build automation")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build the CLI tool (kernel-lens.exe)
    BuildCli {
        /// Build in release mode
        #[arg(short, long)]
        release: bool,
    },

    /// Build the FFI library for Flutter
    BuildFfi {
        /// Build in release mode
        #[arg(short, long)]
        release: bool,
    },

    /// Build everything and run the Flutter app
    RunApp,

    /// Run all tests
    Test {
        /// Run tests for specific crate
        #[arg(short, long)]
        package: Option<String>,
    },

    /// Format all code
    Fmt,

    /// Run clippy lints
    Lint,

    /// Clean all build artifacts
    Clean,

    /// Generate documentation
    Doc {
        /// Open in browser after generation
        #[arg(short, long)]
        open: bool,
    },

    /// Initialize Flutter project (first-time setup)
    InitFlutter,
}

// ============================================================
// Main Entry
// ============================================================

fn main() -> Result<()> {
    let cli = Cli::parse();
    let sh = Shell::new()?;

    // Change to project root
    let project_root = project_root()?;
    sh.change_dir(&project_root);

    match cli.command {
        Commands::BuildCli { release } => build_cli(&sh, release),
        Commands::BuildFfi { release } => build_ffi(&sh, release),
        Commands::RunApp => run_app(&sh),
        Commands::Test { package } => run_tests(&sh, package),
        Commands::Fmt => run_fmt(&sh),
        Commands::Lint => run_lint(&sh),
        Commands::Clean => clean(&sh),
        Commands::Doc { open } => build_doc(&sh, open),
        Commands::InitFlutter => init_flutter(&sh),
    }
}

// ============================================================
// Task Implementations
// ============================================================

fn build_cli(sh: &Shell, release: bool) -> Result<()> {
    println!("🔨 Building kernel-lens CLI...");

    let mut args = vec!["build", "-p", "kernel_cli"];

    if release {
        args.push("--release");
    }

    cmd!(sh, "cargo {args...}").run()?;

    let profile = if release { "release" } else { "debug" };
    let exe_path = project_root()?.join("target").join(profile).join("kernel-lens.exe");

    println!("✅ Built: {}", exe_path.display());
    Ok(())
}

fn build_ffi(sh: &Shell, release: bool) -> Result<()> {
    println!("🔨 Building FFI library...");

    let mut args = vec!["build", "-p", "kernel_ffi"];

    if release {
        args.push("--release");
    }

    cmd!(sh, "cargo {args...}").run()?;

    // Copy DLL to Flutter windows directory if it exists
    let profile = if release { "release" } else { "debug" };
    let dll_path = project_root()?.join("target").join(profile).join("kernel_ffi.dll");

    let flutter_dir = project_root()?.join("app").join("windows").join("runner");

    if flutter_dir.exists() && dll_path.exists() {
        let dest = flutter_dir.join("kernel_ffi.dll");
        std::fs::copy(&dll_path, &dest)?;
        println!("📦 Copied DLL to: {}", dest.display());
    }

    println!("✅ FFI library built successfully");
    Ok(())
}

fn run_app(sh: &Shell) -> Result<()> {
    // First build FFI
    build_ffi(sh, true)?;

    // Check if Flutter app exists
    let app_dir = project_root()?.join("app");
    if !app_dir.exists() {
        bail!(
            "Flutter app not found at {}. Run 'cargo xtask init-flutter' first.",
            app_dir.display()
        );
    }

    // Run Flutter
    println!("🚀 Starting Flutter app...");
    sh.change_dir(&app_dir);
    cmd!(sh, "flutter run -d windows").run()?;

    Ok(())
}

fn run_tests(sh: &Shell, package: Option<String>) -> Result<()> {
    println!("🧪 Running tests...");

    match package {
        Some(pkg) => {
            cmd!(sh, "cargo test -p {pkg}").run()?;
        }
        None => {
            cmd!(sh, "cargo test --workspace").run()?;
        }
    }

    println!("✅ All tests passed");
    Ok(())
}

fn run_fmt(sh: &Shell) -> Result<()> {
    println!("🎨 Formatting code...");
    cmd!(sh, "cargo fmt --all").run()?;
    println!("✅ Code formatted");
    Ok(())
}

fn run_lint(sh: &Shell) -> Result<()> {
    println!("🔍 Running clippy...");
    cmd!(sh, "cargo clippy --workspace -- -D warnings").run()?;
    println!("✅ No lint errors");
    Ok(())
}

fn clean(sh: &Shell) -> Result<()> {
    println!("🧹 Cleaning build artifacts...");
    cmd!(sh, "cargo clean").run()?;

    // Also clean Flutter if present
    let app_dir = project_root()?.join("app");
    if app_dir.exists() {
        sh.change_dir(&app_dir);
        let _ = cmd!(sh, "flutter clean").run();
    }

    println!("✅ Cleaned");
    Ok(())
}

fn build_doc(sh: &Shell, open: bool) -> Result<()> {
    println!("📚 Building documentation...");

    let mut args = vec!["doc", "--workspace", "--no-deps"];
    if open {
        args.push("--open");
    }

    cmd!(sh, "cargo {args...}").run()?;
    println!("✅ Documentation built");
    Ok(())
}

fn init_flutter(sh: &Shell) -> Result<()> {
    println!("🎯 Initializing Flutter project...");

    // Check Flutter is installed
    which::which("flutter").context(
        "Flutter not found. Please install Flutter: https://docs.flutter.dev/get-started/install",
    )?;

    let app_dir = project_root()?.join("app");

    if app_dir.exists() {
        println!("⚠️  Flutter app directory already exists at {}", app_dir.display());
        println!("   Delete it first if you want to reinitialize.");
        return Ok(());
    }

    // Create Flutter project
    let root = project_root()?;
    sh.change_dir(&root);
    cmd!(sh, "flutter create --org com.kernellens --project-name kernel_lens_app ./app").run()?;

    println!("✅ Flutter project created at {}", app_dir.display());
    println!();
    println!("Next steps:");
    println!("  1. Add flutter_rust_bridge to app/pubspec.yaml");
    println!("  2. Run: flutter_rust_bridge_codegen create");
    println!("  3. Run: cargo xtask run-app");

    Ok(())
}

// ============================================================
// Helpers
// ============================================================

fn project_root() -> Result<PathBuf> {
    // xtask is in crates/xtask, so go up two levels
    let xtask_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = xtask_dir
        .parent() // crates/
        .and_then(|p| p.parent()) // project root
        .context("Could not find project root")?;

    Ok(root.to_path_buf())
}
