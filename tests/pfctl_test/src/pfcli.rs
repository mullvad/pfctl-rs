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

pub fn get_anchors() -> Result<Vec<String>> {
    let output = get_command()
        .arg("-s")
        .arg("Anchors")
        .output()
        .chain_err(|| "Failed to run pfctl")?;
    let output = str_from_stdout(&output.stdout)?;
    let names = output
        .lines()
        .map(|x| x.trim().to_owned())
        .collect();
    Ok(names)
}

pub fn get_rules<S: AsRef<OsStr>>(anchor_name: S) -> Result<Vec<String>> {
    let output = get_command()
        .arg("-a")
        .arg(anchor_name.as_ref())
        .arg("-sr")
        .output()
        .chain_err(|| "Failed to run pfctl")?;
    let output = str_from_stdout(&output.stdout)?;
    let rules = output
        .lines()
        .map(|x| x.trim().to_owned())
        .collect();
    Ok(rules)
}

pub fn get_states<S: AsRef<OsStr>>(anchor_name: S) -> Result<Vec<String>> {
    let output = get_command()
        .arg("-a")
        .arg(anchor_name.as_ref())
        .arg("-s")
        .arg("states")
        .output()
        .chain_err(|| "Failed to run pfctl")?;
    let output = str_from_stdout(&output.stdout)?;
    let rules = output
        .lines()
        .map(|x| x.trim().to_owned())
        .collect();
    Ok(rules)
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlushOptions {
    All,
    Rules,
    Nat,
    States,
}

impl From<FlushOptions> for &'static str {
    fn from(option: FlushOptions) -> &'static str {
        match option {
            FlushOptions::All => "all", // in practice it clears everything except states
            FlushOptions::Rules => "rules",
            FlushOptions::Nat => "nat",
            FlushOptions::States => "states",
        }
    }
}

pub fn flush_rules<S: AsRef<OsStr>>(anchor_name: S, options: FlushOptions) -> Result<()> {
    let flush_arg: &'static str = options.into();
    let output = get_command()
        .arg("-a")
        .arg(anchor_name.as_ref())
        .arg("-F")
        .arg(flush_arg)
        .output()
        .chain_err(|| "Failed to run pfctl")?;
    let output = str_from_stdout(&output.stderr)?;

    if options == FlushOptions::All || options == FlushOptions::Rules {
        ensure!(output.contains("rules cleared"), "Invalid response.");
    }

    if options == FlushOptions::All || options == FlushOptions::Nat {
        ensure!(output.contains("nat cleared"), "Invalid response.");
    }

    if options == FlushOptions::States {
        ensure!(output.contains("states cleared"), "Invalid response.");
    }

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
