// Copyright (c) 2023 Daniel Fox Franke
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

use std::path::PathBuf;

fn have_posix() -> bool {
    std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap().as_str() == "unix"
}

fn have_unwinder() -> bool {
    !["l4re", "none", "espidf"].contains(&std::env::var("CARGO_CFG_TARGET_OS").unwrap().as_str())
}

fn main() {
    if !have_posix() {
        eprintln!("Your platform is missing this crate's requisite POSIX signal support");
        std::process::exit(1);
    }

    let mut build = cc::Build::new();
    println!("cargo:rerun-if-changed=src/hwexception.c");

    build.flag_if_supported("-fvisibility=hidden");
    build.file("src/hwexception.c");

    let sysdeps = PathBuf::from(format!(
        "src/sysdeps/{}-{}-{}.c",
        std::env::var("CARGO_CFG_TARGET_ARCH").unwrap(),
        std::env::var("CARGO_CFG_TARGET_OS").unwrap(),
        std::env::var("CARGO_CFG_TARGET_ENV").unwrap()
    ));

    if sysdeps.exists() {
        println!("cargo:rerun-if-changed={}", sysdeps.to_str().unwrap());
        build.file(&sysdeps);
    } else {
        println!("cargo:rerun-if-changed=src/sysdeps/unsupported.c");
        build.file("src/sysdeps/unsupported.c");
    }

    if have_unwinder() {
        build.define("HAVE_UNWINDER", "1");
    }

    // Shut up a warning on some platforms about _FORTIFY_SOURCE needing
    // optimization
    if ["", "0"].contains(&std::env::var("OPT_LEVEL").unwrap().as_str()) {
        build.opt_level_str("g");
    }

    build.compile("hw-exception-cc");
    println!("cargo:rustc-link-lib=hw-exception-cc");
}
