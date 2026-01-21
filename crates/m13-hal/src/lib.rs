#![no_std]
#![forbid(unsafe_code)]

use m13_core::{M13Error, M13Result};

/// Physical Link Metadata (Spec §4.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkProperties {
    pub mtu: usize,
    pub bandwidth_bps: u64,
    pub is_reliable: bool,
}

/// Abstract Address (IPv4/IPv6 agnostic)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PeerAddr {
    V4([u8; 4], u16),
    V6([u8; 16], u16),
    None, // For Promiscuous/Sniffer modes
}

/// The Network Interface (Section 4.2.1).
/// INVARIANT: Must be Non-Blocking.
pub trait PhysicalInterface: Send + Sync {
    fn properties(&self) -> LinkProperties;

    /// Send to a specific peer (Hub Mode) or default target (Node Mode).
    fn send(&mut self, frame: &[u8], target: Option<PeerAddr>) -> nb::Result<usize, M13Error>;

    /// Receive data AND the source address.
    /// Returns: (bytes_read, source_addr)
    fn recv<'a>(&mut self, buffer: &'a mut [u8]) -> nb::Result<(usize, PeerAddr), M13Error>;
}

/// The Security Module (Section 4.2.2).
pub trait SecurityModule: Send + Sync {
    fn get_random_bytes(&mut self, buf: &mut [u8]) -> M13Result<()>;
    fn sign_digest(&mut self, digest: &[u8], signature: &mut [u8]) -> M13Result<usize>;
    fn panic_and_sanitize(&self) -> !;
}

/// The Wall Clock (Section 7.2.1).
pub trait PlatformClock: Send + Sync {
    fn now_us(&self) -> u64;
    fn ptp_ns(&self) -> Option<u64>;
}
