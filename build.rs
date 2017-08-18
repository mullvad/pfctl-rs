extern crate bindgen;

use std::env;
use std::path::Path;
use std::process::Command;
use std::str;

fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR missing from environment");
    println!("OUT_DIR: {}", out_dir);
    let sdk_path = get_macos_sdk_path();
    println!("sdk_path: {}", sdk_path);

    let _ = bindgen::builder()
        .header("ffi/pfvar.h")
        .unstable_rust(false)
        .clang_arg("-DPRIVATE")
        .clang_arg(format!("-I{}/usr/include", sdk_path))
        .clang_arg(
            format!(
                "-I{}/System/Library/Frameworks/Kernel.framework/Versions/A/Headers",
                sdk_path
            ),
        )
        .whitelisted_type("pf_status")
        .whitelisted_type("pfioc_rule")
        .whitelisted_type("pfioc_pooladdr")
        .whitelisted_type("pfioc_trans")
        .whitelisted_type("pfioc_states")
        .whitelisted_type("pfioc_state_kill")
        .whitelisted_var("PF_.*")
        .generate()
        .expect("Unable to generate bindings for pfvar.h")
        .write_to_file(Path::new(&out_dir).join("pfvar.rs"))
        .expect("Unable to write pfvar.rs");
}

fn get_macos_sdk_path() -> String {
    let output = Command::new("xcodebuild")
        .args(&["-sdk", "macosx", "Path", "-version"])
        .output()
        .expect("Unable to get macOS SDK path with \"xcodebuild\"");
    let stdout = str::from_utf8(&output.stdout).expect("xcodebuild did not print valid utf-8");
    stdout.trim().to_owned()
}
