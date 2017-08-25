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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QueryKind {
    /// Anchors. Use '*' to query anchors in main ruleset
    Anchors,
    /// Filter rules
    Rules,
    /// Redirect rules
    Nat,
    /// States
    States,
}

/// This is a constant value that represents main ruleset in PF
pub static MAIN_RULESET: &'static str = "*";

impl From<QueryKind> for &'static str {
    fn from(kind: QueryKind) -> &'static str {
        match kind {
            QueryKind::Anchors => "Anchors",
            QueryKind::Rules => "rules",
            QueryKind::Nat => "nat",
            QueryKind::States => "states",
        }
    }
}

pub fn query_state<S: AsRef<OsStr>>(anchor_name: S, kind: QueryKind) -> Result<Vec<String>> {
    let kind_str: &'static str = kind.into();
    let output = get_command()
        .arg("-a")
        .arg(anchor_name)
        .arg("-s")
        .arg(kind_str)
        .output()
        .chain_err(|| "Failed to run pfctl")?;
    let output = str_from_stdout(&output.stdout)?;
    let lines = output
        .lines()
        .map(|x| x.trim().to_owned())
        .collect();
    Ok(lines)
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
