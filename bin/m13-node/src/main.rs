use clap::Parser;
#[cfg(target_os = "macos")]
use m13_linux::setup;
use m13_linux::{TunDevice, LinuxPhy, LinuxHsm, LinuxClock, poll_both};
use m13_ulk::{M13Kernel, KernelConfig};
use m13_mem::SlabAllocator;
use m13_pqc::DsaKeypair;
use std::net::UdpSocket;
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use log::{info, warn};

#[derive(Parser)]
struct Cli {
    #[arg(long)] hub: String,
    #[arg(long, default_value = "0.0.0.0:0")] bind: String,
    #[arg(long, default_value = "utun8")] iface: String, 
    #[arg(long, default_value = "10.13.13.2")] vip: String, 
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();
    info!(">>> M13 NODE: v0.2.10 (WAKE-UP BURST) <<<");
    info!("Identity: {} on {}", cli.vip, cli.iface);

    let mut tun = TunDevice::new(&cli.iface, &cli.vip, "10.13.13.1")?;
    
    #[cfg(target_os = "macos")]
    setup::configure_node(tun.name(), &cli.hub, "10.13.13.1")?;

    let socket = UdpSocket::bind(&cli.bind)?;
    socket.set_nonblocking(true)?;

    let target = cli.hub.parse().ok();
    
    // [FIX] WAKE-UP BURST: Open the Cloud/NAT path immediately
    if let Some(dest) = target {
        info!(">>> [PHY] FIRING WAKE-UP BURST (5 pkts) to {}...", dest);
        for _ in 0..5 {
            // Send 32 bytes of garbage (0xAA).
            // Hub will reject this as "WireFormatError", but the NETWORK will open the route.
            let _ = socket.send_to(&[0xAA; 32], dest);
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    let phy = LinuxPhy::new(socket.try_clone()?, target);
    let mem = SlabAllocator::new(2048);
    
    let mut rng = rand::thread_rng();
    let identity = DsaKeypair::generate(&mut rng)?; 

    let config = KernelConfig {
        is_hub: false,
        enable_encryption: true,
    };

    let mut kernel = M13Kernel::new(
        Box::new(phy), Box::new(LinuxHsm), Box::new(LinuxClock::new()), 
        mem, config, identity
    );

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        warn!("Signal received. Stopping...");
        r.store(false, Ordering::SeqCst);
    })?;

    info!("Node Kernel Active. Initiating Handshake...");
    let mut buf = [0u8; 1500];
    let mut tunnel_confirmed = false;

    while running.load(Ordering::SeqCst) {
        let (tun_ready, _udp_ready) = poll_both(tun.fd(), socket.as_raw_fd(), 5);

        if tun_ready {
            if let Ok(n) = tun.read(&mut buf) {
                if n > 0 { 
                    let _ = kernel.send_payload(&buf[..n]);
                }
            }
        }

        kernel.poll();

        while let Some(packet) = kernel.pop_ingress() {
            if !tunnel_confirmed {
                info!(">>> [NODE] TUNNEL ACTIVE (Round Trip Confirmed).");
                tunnel_confirmed = true;
            }
            let _ = tun.write(&packet);
        }
    }

    #[cfg(target_os = "macos")]
    setup::cleanup_node(tun.name());
    tun.shutdown();
    Ok(())
}
