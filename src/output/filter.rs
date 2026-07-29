use crate::model::result::ScanResult;

/// Output filtering mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterMode {
    /// Show only open ports (user passed --open).
    OpenOnly,
    /// Default: show open, filtered, unknown in details.
    Default,
}

/// Filter a ScanResult based on the filter mode.
///
/// Returns (detail_results, summary) where detail_results contains
/// only the ProbeResults that should appear in output.
pub fn filter_results(result: &ScanResult, mode: FilterMode) -> Vec<&crate::model::result::ProbeResult> {
    use crate::model::PortState;

    result
        .results
        .iter()
        .filter(|r| match mode {
            FilterMode::OpenOnly => matches!(r.state, PortState::Open),
            FilterMode::Default => matches!(
                r.state,
                PortState::Open | PortState::Filtered | PortState::Unknown
            ),
        })
        .collect()
}
