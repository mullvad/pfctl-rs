use std::ffi::OsStr;
use std::process::Command;
use std::str;

mod errors {
    error_chain!{}
}
use self::errors::*;

static PF_BIN: &'static str = "/sbin/pfctl";

pub fn is_enabled() -> Result<bool> {
    let output = get_command()
        .arg("-s")
        .arg("info")
        .output()
        .chain_err(|| "Failed to run pfctl")?;
    let str = str_from_stdout(&output.stdout)?;

    if str.starts_with("Status: Enabled") {
        Ok(true)
    } else if str.starts_with("Status: Disabled") {
        Ok(false)
    } else {
        bail!("Invalid response.");
    }
}

pub fn enable_firewall() -> Result<()> {
    let output = get_command()
        .arg("-e")
        .output()
        .chain_err(|| "Failed to run pfctl")?;

    // pfctl outputs to stderr for that command
    let stderr = str_from_stdout(&output.stderr)?;

    ensure!(
        stderr.contains("pfctl: pf already enabled") || stderr.contains("pf enabled"),
        "Invalid response."
    );
    Ok(())
}

pub fn disable_firewall() -> Result<()> {
    let output = get_command()
        .arg("-d")
        .output()
        .chain_err(|| "Failed to run pfctl")?;

    // pfctl outputs to stderr for that command
    let stderr = str_from_stdout(&output.stderr)?;

    ensure!(
        stderr.contains("pfctl: pf not enabled") || stderr.contains("pf disabled"),
        "Invalid response."
    );
    Ok(())
}

pub fn get_rules<S: AsRef<OsStr>>(anchor_name: S) -> Result<String> {
    let output = get_command()
        .arg("-a")
        .arg(anchor_name)
        .arg("-sr")
        .output()
        .chain_err(|| "Failed to run pfctl")?;
    str_from_stdout(&output.stdout)
}

pub fn flush_rules<S: AsRef<OsStr>>(anchor_name: S) -> Result<()> {
    let output = get_command()
        .arg("-a")
        .arg(anchor_name)
        .arg("-F")
        .arg("all")
        .output()
        .chain_err(|| "Failed to run pfctl")?;
    let str = str_from_stdout(&output.stderr)?;
    ensure!(str.contains("rules cleared"), "Invalid response.");
    Ok(())
}

fn get_command() -> Command {
    Command::new(PF_BIN)
}

fn str_from_stdout(stdout: &[u8]) -> Result<String> {
    str::from_utf8(stdout)
        .map(|v| v.trim().to_owned())
        .chain_err(|| "Failed to convert buffer to string.")
}
