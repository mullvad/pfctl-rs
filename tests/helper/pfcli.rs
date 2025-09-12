use std::{process::Command, str};

static PF_BIN: &str = "/sbin/pfctl";

pub fn is_enabled() -> bool {
    let output = get_command()
        .arg("-s")
        .arg("info")
        .output()
        .expect("Failed to run pfctl");
    let str = str_from_stdout(&output.stdout);

    if str.starts_with("Status: Enabled") {
        true
    } else if str.starts_with("Status: Disabled") {
        false
    } else {
        let stderr = str_from_stdout(&output.stderr);
        panic!(
            "Invalid output from pfctl ({}), stdout:\n{str}\nstderr:\n{stderr}",
            output.status
        );
    }
}

pub fn enable_firewall() {
    let output = get_command()
        .arg("-e")
        .output()
        .expect("Failed to run pfctl");

    // pfctl outputs to stderr for that command
    let stderr = str_from_stdout(&output.stderr);
    assert!(stderr.contains("pfctl: pf already enabled") || stderr.contains("pf enabled"));
}

pub fn disable_firewall() {
    let output = get_command()
        .arg("-d")
        .output()
        .expect("Failed to run pfctl");

    // pfctl outputs to stderr for that command
    let stderr = str_from_stdout(&output.stderr);
    assert!(stderr.contains("pfctl: pf not enabled") || stderr.contains("pf disabled"));
}

fn get_rules_internal(anchor_name: &str, param_kind: &str) -> Vec<String> {
    let output = get_command()
        .arg("-a")
        .arg(anchor_name)
        .arg("-s")
        .arg(param_kind)
        .output()
        .expect("Failed to run pfctl");
    let output = str_from_stdout(&output.stdout);
    output.lines().map(|x| x.trim().to_owned()).collect()
}

/// List anchors.
/// Pass parent anchor's name to obtain nested anchors.
/// Otherwise, pass None to obtain anchors from main ruleset.
pub fn get_anchors(parent_anchor: Option<&str>) -> Vec<String> {
    get_rules_internal(parent_anchor.unwrap_or("*"), "Anchors")
}

/// Get filter rules in anchor
pub fn get_rules(anchor_name: &str) -> Vec<String> {
    get_rules_internal(anchor_name, "rules")
}

/// Get nat rules in anchor
pub fn get_nat_rules(anchor_name: &str) -> Vec<String> {
    get_rules_internal(anchor_name, "nat")
}

/// Get global table of states
pub fn get_all_states() -> Vec<String> {
    let output = get_command()
        .arg("-s")
        .arg("states")
        .output()
        .expect("Failed to run pfctl");
    let output = str_from_stdout(&output.stdout);
    output.lines().map(|x| x.trim().to_owned()).collect()
}

/// Get flags set on interface `iface`
pub fn get_interface_flags(iface: &str) -> Vec<String> {
    let output = get_command()
        .arg("-sI")
        .arg("-v")
        .args(["-i", iface])
        .output()
        .expect("Failed to run pfctl");
    let output = str_from_stdout(&output.stdout);
    output.lines().map(|x| x.trim().to_owned()).collect()
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

pub fn flush_rules(anchor_name: &str, options: FlushOptions) {
    let flush_arg: &'static str = options.into();
    let output = get_command()
        .arg("-a")
        .arg(anchor_name)
        .arg("-F")
        .arg(flush_arg)
        .output()
        .expect("Failed to run pfctl");
    let output = str_from_stdout(&output.stderr);

    if options == FlushOptions::All || options == FlushOptions::Rules {
        assert!(output.contains("rules cleared"), "Invalid response.");
    }
    if options == FlushOptions::All || options == FlushOptions::Nat {
        assert!(output.contains("nat cleared"), "Invalid response.");
    }
    if options == FlushOptions::States {
        assert!(output.contains("states cleared"), "Invalid response.");
    }
}

fn get_command() -> Command {
    Command::new(PF_BIN)
}

fn str_from_stdout(stdout: &[u8]) -> String {
    str::from_utf8(stdout)
        .map(|v| v.trim().to_owned())
        .expect("pfctl output not valid UTF-8")
}
