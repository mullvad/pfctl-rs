pub extern crate scopeguard;

#[macro_use]
extern crate error_chain;

pub mod pfcli;

mod errors {
    error_chain!{}
}
use self::errors::*;

// A helper class to restore pf state after each test
pub struct PfState {
    pub pf_enabled: bool,
}

impl PfState {
    pub fn new() -> Self {
        PfState { pf_enabled: false }
    }

    pub fn save(&mut self) -> Result<()> {
        self.pf_enabled = pfcli::is_enabled().chain_err(|| "Cannot query pf state")?;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<()> {
        let is_enabled = pfcli::is_enabled().chain_err(|| "Cannot query pf state")?;

        match (self.pf_enabled, is_enabled) {
            (false, true) => pfcli::disable_firewall().chain_err(|| "Cannot disable firewall"),
            (true, false) => pfcli::enable_firewall().chain_err(|| "Cannot enable firewall"),
            _ => Ok(()),
        }
    }
}

#[macro_export]
macro_rules! test {
    ($name:ident $block:block) => (
        #[test]
        fn $name() {
            let mut pf_state = $crate::PfState::new();
            pf_state.save().unwrap();

            let _guard1 = $crate::scopeguard::guard((), |_| pf_state.restore().unwrap());
            let _guard2 = $crate::scopeguard::guard((), |_| after_each());

            before_each();
            $block;
        }
    )
}
