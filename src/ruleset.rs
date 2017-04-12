use ffi;

/// Enum describing the kinds of rulesets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RulesetKind {
    Filter,
    Redirect,
}

impl From<RulesetKind> for i32 {
    fn from(ruleset_kind: RulesetKind) -> Self {
        match ruleset_kind {
            RulesetKind::Filter => ffi::pfvar::PF_RULESET_FILTER as i32,
            RulesetKind::Redirect => ffi::pfvar::PF_RULESET_RDR as i32,
        }
    }
}
