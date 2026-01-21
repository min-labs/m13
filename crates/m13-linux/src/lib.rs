#![allow(unused)]

use std::io::{self, Read, Write};
use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::process::Command;
use tun::Device;
use std::net::{UdpSocket, SocketAddr, IpAddr};
use std::time::Instant;

use m13_hal::{PhysicalInterface, LinkProperties, SecurityModule, PlatformClock, PeerAddr};
use m13_core::{M13Error, M13Result};

#[cfg(target_os = "macos")]
const BSD_AF_INET: [u8; 4] = [0, 0, 0, 2];

// [FIX] Standalone helpers instead of illegal impls
fn to_peer_addr(addr: SocketAddr) -> PeerAddr {
    match addr {
        SocketAddr::V4(v4) => PeerAddr::V4(v4.ip().octets(), v4.port()),
        SocketAddr::V6(v6) => PeerAddr::V6(v6.ip().octets(), v6.port()),
    }
}

fn to_socket_addr(peer: &PeerAddr) -> Option<SocketAddr> {
    match peer {
        PeerAddr::V4(ip, port) => Some(SocketAddr::new(IpAddr::from(*ip), *port)),
        PeerAddr::V6(ip, port) => Some(SocketAddr::new(IpAddr::from(*ip), *port)),
        PeerAddr::None => None,
    }
}

pub struct TunDevice {
    file: File,
    name: String,
    raw_fd: RawFd,
    local_ip: String,
    peer_ip: String,
}

impl TunDevice {
    pub fn new(name: &str, ip: &str, dest: &str) -> anyhow::Result<Self> {
        let mut config = tun::Configuration::default();
        config
            .name(name)
            .address(ip)
            .destination(dest)
            .netmask("255.255.255.0")
            .mtu(1280)
            .up();

        #[cfg(target_os = "linux")]
        config.platform(|c| { c.packet_information(false); });

        let dev = tun::create(&config).map_err(|e| anyhow::anyhow!(e))?;
        let name = dev.name().to_string();
        
        let raw_fd = dev.as_raw_fd();
        let file = unsafe { File::from_raw_fd(raw_fd) };
        std::mem::forget(dev); 

        unsafe {
            let mut flags = libc::fcntl(raw_fd, libc::F_GETFL, 0);
            flags |= libc::O_NONBLOCK;
            libc::fcntl(raw_fd, libc::F_SETFL, flags);
        }

        Ok(Self { 
            file, name, raw_fd,
            local_ip: ip.to_string(),
            peer_ip: dest.to_string(),
        })
    }

    pub fn fd(&self) -> RawFd { self.raw_fd }
    pub fn name(&self) -> &str { &self.name }

    pub fn shutdown(&self) {
        #[cfg(target_os = "macos")]
        {
            let _ = Command::new("ifconfig")
                .args(&[&self.name, "delete", &self.local_ip, &self.peer_ip])
                .status();
        }
    }

    pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.file.read(buf) {
            Ok(n) => {
                #[cfg(target_os = "macos")]
                {
                    if n > 4 {
                        buf.copy_within(4..n, 0);
                        return Ok(n - 4);
                    }
                    Ok(0)
                }
                #[cfg(not(target_os = "macos"))]
                Ok(n)
            },
            Err(e) => Err(e),
        }
    }

    pub fn write(&mut self, packet: &[u8]) -> std::io::Result<()> {
        #[cfg(target_os = "macos")]
        {
            let mut out = Vec::with_capacity(4 + packet.len());
            out.extend_from_slice(&BSD_AF_INET);
            out.extend_from_slice(packet);
            self.file.write_all(&out)
        }
        #[cfg(not(target_os = "macos"))]
        self.file.write_all(packet)
    }
}

pub struct LinuxPhy {
    socket: UdpSocket,
    default_target: Option<std::net::SocketAddr>,
}

impl LinuxPhy {
    pub fn new(socket: UdpSocket, target: Option<std::net::SocketAddr>) -> Self {
        Self { socket, default_target: target }
    }
}

impl PhysicalInterface for LinuxPhy {
    fn properties(&self) -> LinkProperties {
        LinkProperties { mtu: 1400, bandwidth_bps: 1_000_000_000, is_reliable: false }
    }

    fn send(&mut self, frame: &[u8], target: Option<PeerAddr>) -> nb::Result<usize, M13Error> {
        // [FIX] Use helper function instead of .to_socket_addr()
        let dest = target.and_then(|p| to_socket_addr(&p))
                         .or(self.default_target);

        match dest {
            Some(addr) => {
                match self.socket.send_to(frame, addr) {
                    Ok(n) => Ok(n),
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Err(nb::Error::WouldBlock),
                    Err(_) => Err(nb::Error::Other(M13Error::HalError)),
                }
            },
            None => Ok(0), 
        }
    }

    fn recv<'a>(&mut self, buf: &'a mut [u8]) -> nb::Result<(usize, PeerAddr), M13Error> {
        match self.socket.recv_from(buf) {
            Ok((n, src)) => {
                // [FIX] Use helper function instead of PeerAddr::from()
                Ok((n, to_peer_addr(src)))
            },
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Err(nb::Error::WouldBlock),
            Err(_) => Err(nb::Error::Other(M13Error::HalError)),
        }
    }
}

pub struct LinuxHsm;
impl SecurityModule for LinuxHsm {
    fn get_random_bytes(&mut self, buf: &mut [u8]) -> M13Result<()> {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(buf);
        Ok(())
    }
    fn sign_digest(&mut self, _: &[u8], sig: &mut [u8]) -> M13Result<usize> {
        sig.fill(0xAA); Ok(64)
    }
    fn panic_and_sanitize(&self) -> ! { std::process::abort(); }
}

pub struct LinuxClock(Instant);
impl LinuxClock { pub fn new() -> Self { Self(Instant::now()) } }
impl PlatformClock for LinuxClock {
    fn now_us(&self) -> u64 { self.0.elapsed().as_micros() as u64 }
    fn ptp_ns(&self) -> Option<u64> { None }
}

pub fn poll_both(tun_fd: RawFd, udp_fd: RawFd, timeout_ms: i32) -> (bool, bool) {
    let mut fds = [
        libc::pollfd { fd: tun_fd, events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: udp_fd, events: libc::POLLIN, revents: 0 },
    ];
    let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout_ms) };
    if ret > 0 {
        let tun_ready = (fds[0].revents & libc::POLLIN) != 0;
        let udp_ready = (fds[1].revents & libc::POLLIN) != 0;
        (tun_ready, udp_ready)
    } else { (false, false) }
}

pub mod setup;
