/// How certain we are about a PortState judgment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    /// Connect success, or SYN-ACK + Connect verification.
    Confirmed,
    /// Strong evidence (valid SYN-ACK, valid RST, explicit ICMP).
    High,
    /// Two strong evidence sources conflict; strongest state kept but downgraded.
    Medium,
    /// Weak evidence (timeout, no response).
    Low,
}
