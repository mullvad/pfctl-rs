extern crate bindgen;

use std::env;
use std::path::Path;

#[cfg(target_os = "macos")]
fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR missing from environment");
    println!("OUT_DIR: {}", out_dir);

    let _ = bindgen::builder()
        .header("ffi/pfvar.h")
        .clang_arg("-DPRIVATE")
        .clang_arg("-I/usr/include")
        .clang_arg("-I/System/Library/Frameworks/Kernel.framework/Versions/A/Headers")
        .whitelist_type("pf_status")
        .whitelist_type("pfioc_rule")
        .whitelist_type("pfioc_pooladdr")
        .whitelist_type("pfioc_trans")
        .whitelist_type("pfioc_states")
        .whitelist_type("pfioc_state_kill")
        .whitelist_var("PF_.*")
        .generate()
        .expect("Unable to generate bindings for pfvar.h")
        .write_to_file(Path::new(&out_dir).join("pfvar.rs"))
        .expect("Unable to write pfvar.rs");
}

#[cfg(not(target_os = "macos"))]
fn main() {
    panic!("This crate can only be built on macOS");
}
