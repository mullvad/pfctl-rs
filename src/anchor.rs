use ffi;

/// Enum describing the kinds of anchor
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnchorKind {
    Filter,
    Redirect,
}

impl From<AnchorKind> for u8 {
    fn from(anchor_kind: AnchorKind) -> u8 {
        match anchor_kind {
            AnchorKind::Filter => ffi::pfvar::PF_PASS as u8,
            AnchorKind::Redirect => ffi::pfvar::PF_RDR as u8,
        }
    }
}
