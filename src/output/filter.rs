use crate::model::result::ScanResult;
use crate::model::PortState;

/// Bitfield-style filter: which PortStates to include in output.
#[derive(Debug, Clone)]
pub struct FilterMode {
    pub open: bool,
    pub closed: bool,
    pub filtered: bool,
    pub unknown: bool,
}

impl FilterMode {
    /// Default: show open + filtered + unknown.
    pub fn default_filter() -> Self {
        Self {
            open: true,
            closed: false,
            filtered: true,
            unknown: true,
        }
    }

    /// Build from CLI args. If any --show-* flag is set, show only those states.
    /// If none set, use default (open + filtered + unknown).
    pub fn from_args(open_only: bool, show_closed: bool, show_filtered: bool, show_unknown: bool) -> Self {
        if !open_only && !show_closed && !show_filtered && !show_unknown {
            // No flags → default
            return Self::default_filter();
        }
        // At least one flag → show only flagged states
        Self {
            open: open_only,
            closed: show_closed,
            filtered: show_filtered,
            unknown: show_unknown,
        }
    }

    /// Check if a given PortState should be included in output.
    pub fn includes(&self, state: PortState) -> bool {
        match state {
            PortState::Open => self.open,
            PortState::Closed => self.closed,
            PortState::Filtered => self.filtered,
            PortState::Unknown => self.unknown,
            PortState::Unreachable => false, // never show in details
            PortState::Pending => false,     // internal only
        }
    }

    /// Returns true if only open is shown (used for realtime output gating).
    pub fn is_open_only(&self) -> bool {
        self.open && !self.closed && !self.filtered && !self.unknown
    }
}

/// Filter a ScanResult based on the filter mode.
pub fn filter_results<'a>(
    result: &'a ScanResult,
    mode: &FilterMode,
) -> Vec<&'a crate::model::result::ProbeResult> {
    result
        .results
        .iter()
        .filter(|r| mode.includes(r.state))
        .collect()
}
