use conversion::ToFfi;
use ffi;

/// Enum describing the kinds of anchor
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnchorKind {
    Filter,
    Redirect,
}

impl ToFfi<u8> for AnchorKind {
    fn to_ffi(&self) -> u8 {
        match *self {
            AnchorKind::Filter => ffi::pfvar::PF_PASS as u8,
            AnchorKind::Redirect => ffi::pfvar::PF_RDR as u8,
        }
    }
}

