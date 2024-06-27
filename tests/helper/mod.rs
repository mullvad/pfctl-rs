pub use scopeguard;

pub mod pfcli;

// A helper class to restore pf state after each test
pub struct PfState {
    pub pf_enabled: bool,
}

impl PfState {
    pub fn new() -> Self {
        PfState { pf_enabled: false }
    }

    pub fn save(&mut self) {
        self.pf_enabled = pfcli::is_enabled();
    }

    pub fn restore(&mut self) {
        let is_enabled = pfcli::is_enabled();

        match (self.pf_enabled, is_enabled) {
            (false, true) => pfcli::disable_firewall(),
            (true, false) => pfcli::enable_firewall(),
            _ => (),
        }
    }
}

#[macro_export]
macro_rules! test {
    ($name:ident $block:block) => {
        #[test]
        fn $name() {
            let mut pf_state = helper::PfState::new();
            pf_state.save();

            let _guard1 = helper::scopeguard::guard((), |_| pf_state.restore());
            let _guard2 = helper::scopeguard::guard((), |_| after_each());

            before_each();
            $block;
        }
    };
}
