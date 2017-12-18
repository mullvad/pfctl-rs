# pfctl

Library for interfacing with the Packet Filter (PF) firewall on macOS.

Allows controlling the PF firewall on macOS through ioctl syscalls and the `/dev/pf` device.

PF is the firewall used in most (all?) BSD systems, but this crate only supports the macOS
variant for now. If it can be made to work on more BSD systems that would be great, but no work
has been put into that so far.

Reading and writing to `/dev/pf` requires root permissions. So any program using this crate
must run as the superuser, otherwise creating the `PfCtl` instance will fail with a
"Permission denied" error.

## Usage and examples

A lot of examples of how to use the various features of this crate can be found in the
integration tests in `tests/`.

Here is a simple example showing how to enable the firewall and add a packet filtering rule:

```rust
extern crate pfctl;

// Create a PfCtl instance to control PF with:
let mut pf = pfctl::PfCtl::new().unwrap();

// Enable the firewall, equivalent to the command "pfctl -e":
pf.try_enable().unwrap();

// Add an anchor rule for packet filtering rules into PF. This will fail if it already exists,
// use `try_add_anchor` to avoid that:
let anchor_name = "testing-out-pfctl";
pf.add_anchor(anchor_name, pfctl::AnchorKind::Filter).unwrap();

// Create a packet filtering rule matching all packets on the "lo0" interface and allowing
// them to pass:
let rule = pfctl::FilterRuleBuilder::default()
    .action(pfctl::FilterRuleAction::Pass)
    .interface("lo0")
    .build()
    .unwrap();

// Add the filterig rule to the anchor we just created.
pf.add_rule(anchor_name, &rule).unwrap();
```


License: MIT/Apache-2.0
