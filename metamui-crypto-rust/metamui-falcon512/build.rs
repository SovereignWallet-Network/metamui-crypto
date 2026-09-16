// Build script for MetaMUI Falcon-512
//
// This script:
// - Links Metal GPU framework (macOS only, when metal feature is enabled)
// - Configures platform-specific optimizations

use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // CARGO_CFG_TARGET_OS, not `#[cfg(target_os = ...)]`: inside a build script
    // the cfg attribute describes the machine doing the BUILDING, not the
    // machine being built for. Gating on it meant cross-compiling from macOS
    // to Linux with the `metal` feature emitted a link line for Apple's Metal
    // framework, and building on Linux FOR macOS emitted none. The rest of
    // this file already reads the env var; this was the one place that did not.
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos")
        && env::var("CARGO_FEATURE_METAL").is_ok()
    {
        link_metal();
    }

    configure_platform();
}

fn link_metal() {
    println!("cargo:rustc-link-lib=framework=Metal");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rerun-if-changed=src/metal/shaders/falcon_ntt.metal");
    println!("cargo:rerun-if-changed=src/metal/shaders/falcon_verify.metal");
    eprintln!("Metal GPU support enabled for Falcon-512");
}

fn configure_platform() {
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    match target_arch.as_str() {
        "x86_64" => {
            println!("cargo:rustc-env=TARGET_ARCH=x86_64");
            if env::var("CARGO_FEATURE_AVX512").is_ok() {
                println!("cargo:rustc-env=AVX512_ENABLED=1");
            }
        }
        "aarch64" => {
            println!("cargo:rustc-env=TARGET_ARCH=aarch64");
            println!("cargo:rustc-env=NEON_AVAILABLE=1");
            if target_os == "macos" {
                println!("cargo:rustc-env=APPLE_SILICON=1");
            }
        }
        _ => {
            println!("cargo:rustc-env=TARGET_ARCH=generic");
        }
    }

    if env::var("CARGO_FEATURE_METAL").is_ok() && target_os == "macos" {
        println!("cargo:rustc-env=METAL_ENABLED=1");
    }
}
