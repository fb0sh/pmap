/// The conclusion about a port's status after probing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortState {
    /// No probing has been done yet (internal only, never in output).
    Pending,
    /// Port accepted a connection or replied with SYN-ACK.
    Open,
    /// Port explicitly refused (ConnectionRefused or RST).
    Closed,
    /// Probe was dropped by firewall or intermediate device.
    Filtered,
    /// Host or network unreachable (ICMP).
    Unreachable,
    /// No conclusion after retries.
    Unknown,
}
