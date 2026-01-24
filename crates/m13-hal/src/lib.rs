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

// Helper to keep the interface cleaner in no_std
#[derive(Debug, Clone, Copy, Default)]
pub struct M13Endpoint {
    // Placeholder if we wanted full endpoint details, 
    // but PeerAddr is our primary enum.
    // For batching, we usually map PeerAddr directly.
    // We will stick to PeerAddr for consistency with existing code.
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

    // [VECTOR EXTENSION]
    // Default implementation falls back to scalar loop (for non-Linux support)
    fn recv_batch<'a>(
        &mut self, 
        buffers: &mut [&mut [u8]], 
        meta: &mut [(usize, PeerAddr)]
    ) -> nb::Result<usize, M13Error> {
        let mut count = 0;
        for (i, buf) in buffers.iter_mut().enumerate() {
            if i >= meta.len() { break; }
            match self.recv(buf) {
                Ok((len, ep)) => {
                    meta[i] = (len, ep);
                    count += 1;
                },
                Err(_) => break,
            }
        }
        if count > 0 { Ok(count) } else { Err(nb::Error::WouldBlock) }
    }
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
