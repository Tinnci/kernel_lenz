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

    /// Integrate flutter_rust_bridge into the Flutter app
    IntegrateBridge,

    /// Generate Rust-Dart bindings
    Codegen,

    /// Run fuzz tests (requires nightly and cargo-fuzz)
    Fuzz {
        /// Target to fuzz (kallsyms_scanner, kallsyms_decoder, boot_image, decompressor)
        #[arg(value_name = "TARGET")]
        target: String,

        /// Maximum total time of a single run (seconds)
        #[arg(short, long, default_value = "60")]
        max_time: u32,
    },

    /// Check development environment
    Doctor,
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
        Commands::IntegrateBridge => integrate_bridge(&sh),
        Commands::Codegen => run_codegen(&sh),
        Commands::Fuzz { target, max_time } => run_fuzz(&sh, &target, max_time),
        Commands::Doctor => run_doctor(&sh),
    }
}

// ============================================================
// Task Implementations
// ============================================================

fn run_doctor(sh: &Shell) -> Result<()> {
    println!("🩺 Checking development environment...");
    println!();

    let mut tools = vec![
        ("cargo", "Rust toolchain", "https://rustup.rs/"),
        ("flutter", "Flutter SDK", "https://docs.flutter.dev/get-started/install"),
        ("flutter_rust_bridge_codegen", "FRB Codegen", "cargo install flutter_rust_bridge_codegen"),
        ("cmake", "CMake", "https://cmake.org/download/"),
    ];

    if cfg!(windows) {
        // precise fix for Windows where flutter is a .bat
        tools[1].0 = "flutter.bat"; 
    }

    let mut all_ok = true;

    for (cmd_name, nice_name, install_hint) in tools {
        print!("checking {}... ", nice_name);
        match cmd!(sh, "{cmd_name} --version").quiet().read() {
            Ok(version) => {
                let v = version.lines().next().unwrap_or("unknown");
                println!("✅ {}", v);
            }
            Err(_) => {
                println!("❌ Not found");
                println!("   👉 Please install via: {}", install_hint);
                all_ok = false;
            }
        }
    }

    println!();
    if all_ok {
        println!("✨ Environment matches 2026 standards. Ready to build!");
    } else {
        println!("⚠️  Some tools are missing. Please fix the issues above.");
    }
    
    Ok(())
}

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
        },
        None => {
            cmd!(sh, "cargo test --workspace").run()?;
        },
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

fn run_fuzz(sh: &Shell, target: &str, max_time: u32) -> Result<()> {
    println!("🔥 Running fuzz test: {}", target);
    println!("   Max time: {}s", max_time);

    // Validate target name
    let valid_targets =
        ["fuzz_kallsyms_scanner", "fuzz_kallsyms_decoder", "fuzz_boot_image", "fuzz_decompressor"];
    let target_name =
        if target.starts_with("fuzz_") { target.to_string() } else { format!("fuzz_{}", target) };

    if !valid_targets.contains(&target_name.as_str()) {
        bail!("Unknown fuzz target: {}\nValid targets: {:?}", target, valid_targets);
    }

    // Change to fuzz directory
    let fuzz_dir = project_root()?.join("crates").join("kernel_core").join("fuzz");
    sh.change_dir(&fuzz_dir);

    // Run cargo fuzz (requires nightly)
    let max_time_str = max_time.to_string();
    cmd!(sh, "cargo +nightly fuzz run {target_name} -- -max_total_time={max_time_str}").run()?;

    println!("✅ Fuzz test completed");
    Ok(())
}

fn integrate_bridge(sh: &Shell) -> Result<()> {
    println!("🔗 Integrating flutter_rust_bridge...");

    // Ensure codegen is installed
    if cmd!(sh, "flutter_rust_bridge_codegen --version").run().is_err() {
        println!("📦 Installing flutter_rust_bridge_codegen...");
        cmd!(sh, "cargo install flutter_rust_bridge_codegen --version 2.3.0").run()?;
    }

    sh.change_dir(project_root()?);
    cmd!(sh, "flutter_rust_bridge_codegen integrate").run()?;

    println!("✅ Bridge integrated successfully");
    Ok(())
}

fn run_codegen(sh: &Shell) -> Result<()> {
    println!("⚙️  Generating Rust-Dart bindings...");

    let app_dir = project_root()?.join("app");
    sh.change_dir(&app_dir);

    // In FRB V2, codegen is often automatic, but we provide this for manual sync
    cmd!(sh, "flutter_rust_bridge_codegen generate").run()?;

    println!("✅ Bindings generated");
    Ok(())
}
